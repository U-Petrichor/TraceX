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
import hashlib
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
# Allow configuration via environment variable for distributed deployment
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")

# Memory Scanner Configuration
_PROD_SCANNER = "/opt/tracex/bin/mem_scanner"
_DEV_SCANNER = os.path.join(current_dir, "mem_scanner/bin/scanner")

if os.path.exists(_PROD_SCANNER):
    MEM_SCANNER_BIN = _PROD_SCANNER
    print(f"[*] Memory Scanner: Found in PRODUCTION path: {MEM_SCANNER_BIN}")
elif os.path.exists(_DEV_SCANNER):
    MEM_SCANNER_BIN = _DEV_SCANNER
    print(f"[*] Memory Scanner: Found in DEVELOPMENT path: {MEM_SCANNER_BIN}")
else:
    # Default to Dev path even if missing, to let checks fail naturally later or show specific error
    MEM_SCANNER_BIN = _DEV_SCANNER
    print(f"[!] Warning: MemScanner binary not found in Prod ({_PROD_SCANNER}) or Dev ({_DEV_SCANNER}) paths.")

if platform.system() == 'Windows':
    MEM_SCANNER_BIN = "" # Disabled on Windows

# === Index Naming Helper ===
def get_current_index_name():
    """
    Generate index name based on Beijing Time (UTC+8).
    Format: unified-logs-YYYY.MM.DD
    Matches TraceX v5.1 standard.
    """
    beijing_time = datetime.utcnow() + timedelta(hours=8)
    return f"unified-logs-{beijing_time.strftime('%Y.%m.%d')}"
    
# === 行为分析与内存监控类 ===
class BehaviorAnalyzer:
    """
    行为分析器：基于系统调用序列检测内存威胁
    功能：
    1. 实时分析系统调用序列 (Ptrace, Memfd, Mprotect)
    2. 触发内存扫描 (调用 mem_scanner)
    3. 异常结果入库 (Elasticsearch)
    """
    def __init__(self, es_client, index_name_func):
        self.es = es_client
        self.get_index_name = index_name_func
        self.pid_events = defaultdict(list)  # 存储 PID 对应的事件列表 {pid: [(syscall, timestamp)]}
        self.scan_history = {} # 记录扫描历史，防止重复扫描 {pid: last_scan_timestamp}
        self.alert_history = {} # 记录报警历史，防止告警风暴 {pid: last_alert_timestamp}
        self.lock = threading.Lock()
        
        # 定义高危行为序列
        self.sequences = [
            # 序列 1: Ptrace 注入 (常见于调试器攻击/进程注入)
            {
                "events": ["ptrace", "write"],
                "window": 5.0,
                "name": "Ptrace Injection"
            },
            # 序列 2: 无文件执行 (Memfd + Execve)
            {
                "events": ["memfd_create", "execve"], 
                "window": 5.0,
                "name": "Fileless Execution"
            },
            # 序列 3: 内存篡改 (写入 + 修改权限)
            {
                "events": ["write", "mprotect"],
                "window": 5.0,
                "name": "Memory Tampering"
            }
        ]

    def record_event(self, pid, syscall):
        """记录系统调用事件并检查威胁序列"""
        if not MEM_SCANNER_BIN or not os.path.exists(MEM_SCANNER_BIN):
            return

        now = time.time()
        with self.lock:
            # 添加事件到历史记录
            self.pid_events[pid].append((syscall, now))
            
            # 清理过期事件 (只保留最近 10 秒内的)
            self.pid_events[pid] = [e for e in self.pid_events[pid] if now - e[1] < 10.0]
            
            # 检查是否匹配高危序列
            self._check_sequences(pid)

    def _check_sequences(self, pid):
        """核心逻辑：匹配系统调用序列"""
        events = [e[0] for e in self.pid_events[pid]]
        
        should_scan = False
        reason = ""
        
        # 1. 检查定义的有序序列
        for seq in self.sequences:
            required = seq["events"]
            # 简单检查：所需事件是否按顺序出现在近期历史中
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
        
        # 2. 检查单次高危调用
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
        """触发内存扫描器 (mem_scanner)"""
        now = time.time()
        last_scan = self.scan_history.get(pid, 0)
        
        # 防抖动：5秒内不重复扫描同一进程
        if now - last_scan < 5.0:
            return
            
        self.scan_history[pid] = now
        
        # 在后台线程运行扫描，避免阻塞主日志处理循环
        threading.Thread(target=self._run_scan, args=(pid, reason), daemon=True).start()

    def _run_scan(self, pid, reason):
        """执行外部扫描二进制文件"""
        try:
            # 设置超时非常重要，防止产生僵尸进程
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
            pass # 扫描超时，忽略
        except Exception as e:
            print(f"[-] Scan error for PID {pid}: {e}")

    def _ingest_scan_result(self, data, reason):
        """处理扫描结果并上报到 ES"""
        pid = data.get("pid")
        raw_anomalies = data.get("anomalies", [])
        
        # 过滤异常：只保留 HIGH 或 CRITICAL 级别的风险
        anomalies = [
            a for a in raw_anomalies 
            if a.get("risk_level") in ["HIGH", "CRITICAL"]
        ]
        
        if not anomalies:
            return

        try:
            sig_str = json.dumps(anomalies, sort_keys=True)
            signature = hashlib.md5(sig_str.encode('utf-8')).hexdigest()
        except:
            signature = str(anomalies)

        now = time.time()
        last_alert_time, last_signature = self.alert_history.get(pid, (0, ""))
        
        # 5分钟内相同的告警去重
        if signature == last_signature and (now - last_alert_time < 300):
            return

        self.alert_history[pid] = (now, signature)

        # 转换为 UnifiedEvent 格式
        doc = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "host": {"name": socket.gethostname()},
            "event": {
                "category": "memory",
                "action": "anomaly_detected",
                "severity": 10, # 内存异常默认为最高危
                "reason": reason
            },
            "process": {
                "pid": data.get("pid"),
                "executable": data.get("exe")
            },
            "memory": {
                "anomalies": anomalies
            }
        }
        
        try:
            index = self.get_index_name()
            self.es.index(index=index, document=doc)
            print(f"[!] Memory Anomaly Detected (PID {data.get('pid')}): {reason}")
        except Exception as e:
            print(f"[-] ES Index Error: {e}")

    def run_periodic_scan(self):
        """周期性全盘扫描 (当系统负载较低时)"""
        time.sleep(2)
        
        while True:
            if not MEM_SCANNER_BIN or not os.path.exists(MEM_SCANNER_BIN):
                time.sleep(300)
                continue
                
            # 智能负载检查：如果 CPU > 80% 则暂停扫描
            try:
                if psutil.cpu_percent() > 80.0:
                    time.sleep(300) 
                    continue
            except ImportError:
                pass 
                
            try:
                # 运行全盘扫描模式
                result = subprocess.run(
                    [MEM_SCANNER_BIN, "--scan-all"],
                    capture_output=True,
                    text=True,
                    timeout=60
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
            
            time.sleep(300)

# === 状态与文件锁管理 ===
def load_state():
    """加载断点续传状态"""
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
    analyzer = BehaviorAnalyzer(es, get_current_index_name)
    threading.Thread(target=analyzer.run_periodic_scan, daemon=True).start()
    
    print(f"[+] Auditd Agent Started. Index target: {get_current_index_name()}")

    try:
        while True:
            # [FIX] Get dynamic index name inside the loop to ensure rotation and correct naming
            current_index_name = get_current_index_name()
            
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
                    try:
                        pid = int(process.get('pid', 0))
                        syscall = ""
                        if doc.get('event', {}).get('category') == 'process':
                            if action == 'process_started': syscall = 'execve'
                            elif 'ptrace' in line_str: syscall = 'ptrace'
                            elif 'memfd_create' in line_str: syscall = 'memfd_create'
                            elif 'mprotect' in line_str: syscall = 'mprotect'
                        
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
                        if proc_name == 'sleep':
                            try:
                                parts = cmd_line.split()
                                for p in parts:
                                    if p.isdigit() and int(p) > 60:
                                        should_ingest = True
                                        break
                            except:
                                pass
                        if user_name in ['www-data', 'apache']:
                            should_ingest = True
                        pass

                    if should_ingest:
                        # === Alignment Logic (Group 1) ===
                        if 'host' not in doc: doc['host'] = {}
                        doc['host']['name'] = socket.gethostname()
                        
                        current_severity = doc.get('event', {}).get('severity', 1)
                        is_sensitive = any(s in cmd_line for s in ['/etc/passwd', '/etc/shadow', '.ssh', 'authorized_keys'])
                        is_root_active = (str(doc.get('user', {}).get('id')) == '0') and (action != 'process_started')
                        
                        if is_sensitive:
                            current_severity = 10
                        elif is_root_active:
                            current_severity = 8
                        
                        if 'event' not in doc: doc['event'] = {}
                        doc['event']['severity'] = int(current_severity)

                        try:
                            # [FIX] Use the dynamic index name here
                            es.index(index=current_index_name, document=doc)
                        except:
                            pass
            else:
                # Ingest Raw Logs
                raw_doc = make_raw_doc(line_str)
                try:
                    # [FIX] Use the dynamic index name here
                    es.index(index=current_index_name, document=raw_doc)
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
