import time
import os
import sys
import json
import warnings
import socket
import threading
import subprocess
import platform
import psutil
from collections import defaultdict
from datetime import datetime, timedelta

# Suppress ES security warnings
warnings.filterwarnings("ignore", message=".*Elasticsearch built-in security features are not enabled.*")

# === Imports Setup ===
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from collector.host_collector.log_parser import HostLogParser
except ImportError:
    sys.path.append(current_dir)
    from log_parser import HostLogParser

try:
    from elasticsearch import Elasticsearch
except ImportError:
    print("[-] Error: 'elasticsearch' module missing.")
    sys.exit(1)

# === Configuration ===
LOG_FILE = "/var/log/audit/audit.log"
STATE_FILE = os.path.join(current_dir, "agent_state.json")
ES_HOST = "http://localhost:9200"

# Memory Scanner Configuration
MEM_SCANNER_BIN = os.path.join(current_dir, "mem_scanner/bin/scanner")
if platform.system() == 'Windows':
    MEM_SCANNER_BIN = "" # Disabled on Windows
    
# === Behavior Analysis & Memory Monitoring ===
class BehaviorAnalyzer:
    def __init__(self, es_client, index_name_func):
        self.es = es_client
        self.get_index_name = index_name_func
        self.pid_events = defaultdict(list)  # {pid: [(syscall, timestamp)]}
        self.scan_history = {} # {pid: last_scan_timestamp}
        self.lock = threading.Lock()
        
        # High Risk Sequence Definitions
        self.sequences = [
            # Sequence 1: Ptrace Injection
            {
                "events": ["ptrace", "write"],
                "window": 5.0,
                "name": "Ptrace Injection"
            },
            # Sequence 2: Fileless Execution
            {
                "events": ["memfd_create", "execve"], 
                "window": 5.0,
                "name": "Fileless Execution"
            },
            # Sequence 3: Memory Tampering
            {
                "events": ["write", "mprotect"],
                "window": 5.0,
                "name": "Memory Tampering"
            }
        ]

    def record_event(self, pid, syscall):
        if not MEM_SCANNER_BIN or not os.path.exists(MEM_SCANNER_BIN):
            return

        now = time.time()
        with self.lock:
            # Add event to history
            self.pid_events[pid].append((syscall, now))
            
            # Prune old events (> 10s)
            self.pid_events[pid] = [e for e in self.pid_events[pid] if now - e[1] < 10.0]
            
            # Check sequences
            self._check_sequences(pid)

    def _check_sequences(self, pid):
        events = [e[0] for e in self.pid_events[pid]]
        
        should_scan = False
        reason = ""
        
        # Check explicit sequences
        for seq in self.sequences:
            required = seq["events"]
            # Simple check: do all required events exist in recent history in order?
            # This is a simplified subsequence check
            last_idx = -1
            found_count = 0
            for req_evt in required:
                try:
                    idx = events.index(req_evt, last_idx + 1)
                    last_idx = idx
                    found_count += 1
                except ValueError:
                    break
            
            if found_count == len(required):
                should_scan = True
                reason = seq["name"]
                break
        
        # Check single high-risk syscalls
        if not should_scan:
            if "ptrace" in events:
                should_scan = True
                reason = "Suspicious Ptrace"
            elif "memfd_create" in events:
                should_scan = True
                reason = "Memfd Creation"
        
        if should_scan:
            self._trigger_scan(pid, reason)

    def _trigger_scan(self, pid, reason):
        now = time.time()
        last_scan = self.scan_history.get(pid, 0)
        
        # Debounce: 5 seconds
        if now - last_scan < 5.0:
            return
            
        self.scan_history[pid] = now
        
        # Run scan in background thread to avoid blocking main loop
        threading.Thread(target=self._run_scan, args=(pid, reason), daemon=True).start()

    def _run_scan(self, pid, reason):
        try:
            # Timeout is crucial to prevent zombie processes
            result = subprocess.run(
                [MEM_SCANNER_BIN, "--pid", str(pid)],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    self._ingest_scan_result(data, reason)
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            pass # Scan took too long, ignore
        except Exception as e:
            print(f"[-] Scan error for PID {pid}: {e}")

    def _ingest_scan_result(self, data, reason):
        # Convert to UnifiedEvent format
        doc = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "host": {"name": socket.gethostname()},
            "event": {
                "category": "memory",
                "action": "anomaly_detected",
                "severity": 10, # Memory anomalies are always critical
                "reason": reason
            },
            "process": {
                "pid": data.get("pid"),
                "executable": data.get("exe")
            },
            "memory": {
                "anomalies": data.get("anomalies", [])
            }
        }
        
        try:
            index = self.get_index_name()
            self.es.index(index=index, document=doc)
            print(f"[!] Memory Anomaly Detected (PID {data.get('pid')}): {reason}")
        except Exception as e:
            print(f"[-] ES Index Error: {e}")

    def run_periodic_scan(self):
        """Run full scan periodically if load is low"""
        while True:
            time.sleep(300) # 5 minutes default
            
            if not MEM_SCANNER_BIN or not os.path.exists(MEM_SCANNER_BIN):
                continue
                
            # Smart Load Check
            try:
                if psutil.cpu_percent() > 80.0:
                    time.sleep(300) # Wait another 5 mins if busy
                    continue
            except ImportError:
                pass # psutil missing, ignore check
                
            try:
                # Run full scan
                result = subprocess.run(
                    [MEM_SCANNER_BIN, "--scan-all"],
                    capture_output=True,
                    text=True,
                    timeout=60 # Full scan might take longer
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        try:
                            data = json.loads(line)
                            self._ingest_scan_result(data, "Periodic Scan")
                        except:
                            continue
            except Exception as e:
                print(f"[-] Periodic scan error: {e}")



# === State & Lock Management ===
def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_state(inode, offset, is_running, pid):
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump({
                "inode": inode,
                "offset": offset,
                "is_running": is_running,
                "pid": pid
            }, f)
    except Exception as e:
        print(f"[-] Error saving state: {e}")

def acquire_lock():
    state = load_state()
    is_running = state.get("is_running", False)
    lock_pid = state.get("pid", -1)
    current_pid = os.getpid()
    
    if is_running:
        try:
            os.kill(lock_pid, 0)
            print(f"[-] Error: Agent already running (PID: {lock_pid}).")
            sys.exit(1)
        except OSError:
            print(f"[!] Warning: Stale lock (PID {lock_pid}) detected. Taking over.")
    
    inode = state.get("inode")
    offset = state.get("offset", 0)
    save_state(inode, offset, True, current_pid)
    return inode, offset

def release_lock(inode, offset):
    save_state(inode, offset, False, 0)

# === Helper Functions ===
def clean_dict(d):
    if not isinstance(d, dict):
        return d
    cleaned = {}
    for k, v in d.items():
        if isinstance(v, dict):
            nested = clean_dict(v)
            if nested:
                cleaned[k] = nested
        elif isinstance(v, list):
            if v:
                cleaned[k] = v
        elif v not in [None, ""]:
            cleaned[k] = v
    return cleaned

def make_raw_doc(line_str):
    return {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "message": line_str,
        "event": {
            "category": "raw_log",
            "dataset": "unknown"
        }
    }

def get_inode(filepath):
    try:
        return os.stat(filepath).st_ino
    except FileNotFoundError:
        return None

# === Main Logic ===
def main():
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("[-] Error: Must run as root.")
        sys.exit(1)

    try:
        es = Elasticsearch(ES_HOST)
        if not es.ping():
            print("[-] Warning: Could not connect to ES.")
    except Exception as e:
        print(f"[-] Error connecting to ES: {e}")
        sys.exit(1)

    saved_inode, saved_offset = acquire_lock()
    parser = HostLogParser()
    
    # Index naming (Beijing Time)
    from datetime import timedelta
    beijing_time = datetime.utcnow() + timedelta(hours=8)
    index_name = f"unified-logs-{beijing_time.strftime('%Y.%m.%d')}"

    while not os.path.exists(LOG_FILE):
        time.sleep(2)

    current_inode = get_inode(LOG_FILE)
    file_obj = open(LOG_FILE, 'r')
    
    if saved_inode == current_inode:
        file_obj.seek(saved_offset)
    else:
        file_obj.seek(0)

    lines_processed = 0
    current_pid = os.getpid()

    # Noise List
    NOISE_PROCS = {'sleep', 'date', 'uptime', 'awk', 'sed', 'head', 'tail', 'cut', 'tr'}

    # === Initialize Behavior Analyzer ===
    analyzer = BehaviorAnalyzer(es, lambda: index_name)
    threading.Thread(target=analyzer.run_periodic_scan, daemon=True).start()

    try:
        while True:
            line = file_obj.readline()

            if not line:
                try:
                    new_inode = get_inode(LOG_FILE)
                    if new_inode != current_inode:
                        file_obj.close()
                        file_obj = open(LOG_FILE, 'r')
                        current_inode = new_inode
                        file_obj.seek(0)
                        save_state(current_inode, 0, True, current_pid)
                        continue
                except:
                    pass
                time.sleep(0.1)
                continue

            try:
                line_str = line.decode('utf-8').strip()
            except:
                line_str = line.strip()

            if not line_str:
                continue

            if "type=" in line_str or "msg=audit" in line_str:
                event = parser.parse(line_str, log_type="auditd")
                if event:
                    doc = event.to_dict()
                    doc = clean_dict(doc)
                    
                    # === Smart Filtering ===
                    process = doc.get('process', {})
                    event_info = doc.get('event', {})
                    user = doc.get('user', {})
                    
                    proc_name = process.get('name', '')
                    cmd_line = process.get('command_line', '')
                    action = event_info.get('action', '')
                    user_name = user.get('name', '')
                    
                    # === Behavior Hook ===
                    # Extract PID and Syscall for analysis
                    try:
                        pid = int(process.get('pid', 0))
                        syscall = ""
                        # Try to extract syscall from action or raw log if available
                        # Action usually maps to syscall for SYSCALL events
                        if doc.get('event', {}).get('category') == 'process':
                            # Infer from action or raw event
                            # Simplified mapping:
                            if action == 'process_started': syscall = 'execve'
                            elif 'ptrace' in line_str: syscall = 'ptrace' # Fallback to raw check
                            elif 'memfd_create' in line_str: syscall = 'memfd_create'
                            elif 'mprotect' in line_str: syscall = 'mprotect'
                        
                        # Direct SYSCALL parsing from parser output if available
                        # (assuming parser enriches this info in future, for now fallback to string match)
                        
                        if pid > 0 and syscall:
                            analyzer.record_event(pid, syscall)
                    except:
                        pass
                    
                    # 1. Drop process_started without cmd_line

                    if action == 'process_started' and not cmd_line:
                        continue

                    # 2. Noise Filtering
                    should_ingest = True
                    if proc_name in NOISE_PROCS:
                        should_ingest = False
                        
                        # Exception A: Sleep > 60s
                        if proc_name == 'sleep':
                            # check args or command_line
                            # simple heuristic: check command_line for large numbers?
                            # or strictly parse args if available. 
                            # cmd_line ex: "sleep 100"
                            try:
                                parts = cmd_line.split()
                                for p in parts:
                                    if p.isdigit() and int(p) > 60:
                                        should_ingest = True
                                        break
                            except:
                                pass
                        
                        # Exception B: Web User
                        if user_name in ['www-data', 'apache']:
                            should_ingest = True
                            
                        # Exception C: Root user running non-preset command
                        # (If we are here, it IS a preset/noise command. So this rule doesn't save it
                        # unless the rule means "If Root runs it, we keep it"? 
                        # The user text: "或者是 Root 用户执行的非系统预设命令" -> "OR Root executing non-preset".
                        # This implies if Root executes "sleep" (preset), we DO NOT keep it.
                        # So this exception does not apply inside the "if proc_name in NOISE_PROCS" block.
                        # It applies to the general case (which is already True).
                        # So we don't need to do anything here for Root.
                        pass

                    if should_ingest:
                        # === Alignment Logic (Group 1) ===
                        # 1. Hostname Enforce
                        if 'host' not in doc: doc['host'] = {}
                        doc['host']['name'] = socket.gethostname()
                        
                        # 2. Severity Enforce (Int 1-10)
                        # Default from parser is 1 (Success) or 4 (Failure)
                        current_severity = doc.get('event', {}).get('severity', 1)
                        
                        # High Risk Rules
                        is_sensitive = any(s in cmd_line for s in ['/etc/passwd', '/etc/shadow', '.ssh', 'authorized_keys'])
                        is_root_active = (str(doc.get('user', {}).get('id')) == '0') and (action != 'process_started')
                        
                        if is_sensitive:
                            current_severity = 10
                        elif is_root_active:
                            current_severity = 8
                        
                        if 'event' not in doc: doc['event'] = {}
                        doc['event']['severity'] = int(current_severity)

                        try:
                            es.index(index=index_name, document=doc)
                        except:
                            pass
            else:
                # Raw logs are noise in Production? Usually yes, unless critical.
                # User didn't specify, but "Smart Agent" usually implies "Only Parsed".
                # But to be safe, I'll ingest raw if it looks important? 
                # The user said "Smart Filtering... Drop... Noise Filter". 
                # It didn't say "Drop Raw". 
                # I will keep Raw for now to avoid data loss of unknown formats.
                raw_doc = make_raw_doc(line_str)
                try:
                    es.index(index=index_name, document=raw_doc)
                except:
                    pass

            lines_processed += 1
            if lines_processed % 50 == 0:
                save_state(current_inode, file_obj.tell(), True, current_pid)

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[-] Critical Error: {e}")
    finally:
        if 'current_inode' in locals() and 'file_obj' in locals():
            release_lock(current_inode, file_obj.tell())
            file_obj.close()
        else:
            release_lock(saved_inode, saved_offset)

if __name__ == "__main__":
    main()
