import time
import os
import sys
import json
import warnings
from datetime import datetime

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
    print("[-] Error: 'elasticsearch' module missing. Please run: pip install elasticsearch")
    sys.exit(1)

# === Configuration ===
LOG_FILE = "/var/log/audit/audit.log"
STATE_FILE = os.path.join(current_dir, "agent_state.json")
ES_HOST = "http://localhost:9200"
ENABLE_ES_WRITE = True

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
    print(f"[+] Lock acquired (PID: {current_pid}).")
    return inode, offset

def release_lock(inode, offset):
    save_state(inode, offset, False, 0)
    print("[+] Lock released.")

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

def get_display_summary(doc):
    process = doc.get('process', {})
    event = doc.get('event', {})
    
    cmd = process.get('command_line')
    if cmd and cmd != "Unknown":
        return f"CMD: {cmd}"
    
    action = event.get('action')
    if action:
        return f"ACTION: {action}"
        
    return "Event: (Details hidden)"

# === Main Logic ===
def main():
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("[-] Error: Must run as root.")
        sys.exit(1)

    print(f"[*] Connecting to Elasticsearch at {ES_HOST}...")
    try:
        es = Elasticsearch(ES_HOST)
        if not es.ping():
            print("[-] Warning: Could not connect to ES.")
        else:
            print("[+] Connected to ES.")
    except Exception as e:
        print(f"[-] Error connecting to ES: {e}")
        sys.exit(1)

    saved_inode, saved_offset = acquire_lock()
    parser = HostLogParser()
    
    # Index naming (Beijing Time)
    from datetime import timedelta
    beijing_time = datetime.utcnow() + timedelta(hours=8)
    index_name = f"unified-logs-{beijing_time.strftime('%Y.%m.%d')}"
    
    print(f"[*] Monitoring: {LOG_FILE}")
    print("[*] Visual Mode: Whitelist & Highlights Active.")

    while not os.path.exists(LOG_FILE):
        time.sleep(2)

    current_inode = get_inode(LOG_FILE)
    file_obj = open(LOG_FILE, 'r')
    
    if saved_inode == current_inode:
        print(f"[+] Resuming from offset {saved_offset}...")
        file_obj.seek(saved_offset)
    else:
        print("[+] Starting from beginning...")
        file_obj.seek(0)

    lines_processed = 0
    current_pid = os.getpid()

    # Visual Filter Configuration
    WATCH_LIST = ['cat', 'vim', 'nano', 'sudo', 'su', 'ssh', 'scp', 
                  'wget', 'curl', 'nc', 'nmap', 'chmod', 'chown', 
                  'useradd', 'passwd', 'python', 'python3', 'bash', 'sh']

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
                    
                    # === Visual Filtering ===
                    process = doc.get('process', {})
                    proc_name = process.get('name', '')
                    cmd_line = process.get('command_line', '')
                    summary = get_display_summary(doc)
                    
                    should_print = False
                    
                    if "process_started" in summary:
                        should_print = False
                    else:
                        is_watched_proc = proc_name in WATCH_LIST
                        is_sensitive_file = any(s in cmd_line for s in ['/etc/passwd', '/etc/shadow', '.ssh', 'authorized_keys'])
                        is_root_activity = (str(doc.get('user', {}).get('id')) == '0') and (doc.get('event', {}).get('action') != 'process_started')
                        is_failed = doc.get('event', {}).get('outcome') == 'failure'
                        
                        if is_watched_proc or is_sensitive_file or is_root_activity or is_failed:
                            should_print = True
                            
                        if should_print:
                            RED = '\033[91m'
                            YELLOW = '\033[93m'
                            CYAN = '\033[96m'
                            GREEN = '\033[92m'
                            RESET = '\033[0m'
                            
                            if is_sensitive_file:
                                print(f"{RED}[!] 🛑 SENSITIVE: {summary}{RESET}")
                            elif is_failed:
                                print(f"{YELLOW}[?] ⚠️ FAILED: {summary}{RESET}")
                            elif is_root_activity:
                                print(f"{CYAN}[*] ⚡ ROOT: {summary}{RESET}")
                            else:
                                print(f"{GREEN}[+] 🟢 WATCHED: {summary}{RESET}")

                    if ENABLE_ES_WRITE:
                        try:
                            es.index(index=index_name, document=doc)
                        except Exception as e:
                            print(f"[-] ES Write Error: {e}")
            else:
                if ENABLE_ES_WRITE:
                    raw_doc = make_raw_doc(line_str)
                    try:
                        es.index(index=index_name, document=raw_doc)
                    except Exception as e:
                        print(f"[-] ES Write Error (Raw): {e}")

            lines_processed += 1
            if lines_processed % 10 == 0:
                save_state(current_inode, file_obj.tell(), True, current_pid)

    except KeyboardInterrupt:
        print("\n[*] Stopping...")
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
