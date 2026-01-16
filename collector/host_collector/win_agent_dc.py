import os
import sys
import time
import json
import socket
import logging
import requests
import subprocess
import threading
import platform
import ctypes
from datetime import datetime, timedelta

# === Path Setup ===
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# === Imports ===
# Import WinMemoryScanner from local or package
try:
    from win_mem_scanner import WinMemoryScanner
except ImportError:
    try:
        from collector.host_collector.win_mem_scanner import WinMemoryScanner
    except ImportError:
        print("CRITICAL: Cannot find win_mem_scanner module.")
        # Optional: sys.exit(1) if memory scanning is mandatory
        pass

# Import Schema and LogParser
try:
    from collector.common.schema import (
        UnifiedEvent, EventInfo, HostInfo, HostOS, 
        MemoryInfo, MemoryAnomaly, DetectionInfo, ProcessInfo
    )
    from collector.host_collector.log_parser import HostLogParser
except ImportError as e:
    print(f"CRITICAL: Failed to import Schema or LogParser. Error: {e}")
    sys.exit(1)

# === Configuration ===
ES_HOST = "http://182.92.114.32:9200"
SCAN_INTERVAL = 60

# === Logging ===
logger = logging.getLogger("WinAgent-DC")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# === System Info Helper ===
class SystemInfoCollector:
    """Collects static system information"""
    def __init__(self):
        self.hostname = socket.gethostname()
        self.ip = self._get_local_ip()
        self.os_info = self._get_os_info()

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return [ip]
        except Exception:
            return ["127.0.0.1"]

    def _get_os_info(self):
        try:
            return HostOS(
                family="windows",
                name=f"Windows {platform.release()}",
                version=platform.version()
            )
        except Exception:
            return HostOS(family="windows", name="Unknown", version="0.0")

# === WinAgentDC (独立实现) ===
class WinAgentDC:
    """
    TraceX Windows Agent for Domain Controllers (DC) - 独立版本
    
    功能特点:
    1. 内存扫描 (Memory Scanning): 调用 WinMemoryScanner 检测异常
    2. 安全日志监控 (Security Log Monitoring): 通过 PowerShell 实时抓取安全日志
    3. 独立逻辑: 不继承自 win_agent.py，避免依赖冲突
    """
    def __init__(self):
        self.sys_info = SystemInfoCollector()
        self.mem_scanner = WinMemoryScanner() if 'WinMemoryScanner' in globals() else None
        self.session = requests.Session()
        self.log_parser = HostLogParser()
        self.last_event_time = datetime.utcnow() - timedelta(minutes=1)
        logger.info(f"WinAgent DC (Standalone) initialized on {self.sys_info.hostname}")

    def get_index_name(self):
        # 统一使用北京时间命名索引
        return f"unified-logs-{datetime.utcnow().strftime('%Y.%m.%d')}"
    
    def _sanitize_payload(self, payload: dict) -> dict:
        """清理 Payload 中的空 IP 字段，避免 ES 报错"""
        if "source" in payload and isinstance(payload["source"], dict):
            if payload["source"].get("ip") == "":
                payload["source"]["ip"] = None
        if "destination" in payload and isinstance(payload["destination"], dict):
            if payload["destination"].get("ip") == "":
                payload["destination"]["ip"] = None
        return payload

    # --- 内存扫描逻辑 (复制并适配) ---
    def enum_processes(self):
        """枚举当前系统所有进程 PID"""
        psapi = ctypes.windll.psapi
        arr = (ctypes.c_ulong * 1024)()
        cb = ctypes.sizeof(arr)
        cb_needed = ctypes.c_ulong()
        if psapi.EnumProcesses(ctypes.byref(arr), cb, ctypes.byref(cb_needed)):
            count = cb_needed.value // ctypes.sizeof(ctypes.c_ulong)
            return [arr[i] for i in range(count)]
        return []

    def send_memory_alert(self, pid: int, anomalies: list):
        """构建并发送内存异常告警"""
        utc_now = datetime.utcnow()
        timestamp_str = utc_now.isoformat() + "Z"
        
        schema_anomalies = []
        for a in anomalies:
            schema_anomalies.append(MemoryAnomaly(
                type=a["type"],
                address=a["address"],
                size=a["size"],
                perms=a["perms"],
                path=a["path"],
                is_elf=a["is_elf"],
                risk_level=a["risk_level"],
                confidence=a["confidence"],
                details=a["details"]
            ))

        event = UnifiedEvent(
            timestamp=timestamp_str,
            event=EventInfo(
                category="host",
                type="info",
                action="memory_scan",
                severity=8,
                dataset="win_memory_scanner"
            ),
            host=HostInfo(
                name=self.sys_info.hostname,
                hostname=self.sys_info.hostname,
                ip=self.sys_info.ip,
                os=self.sys_info.os_info
            ),
            process=ProcessInfo(
                pid=pid,
                name="<unknown>",
                start_time=timestamp_str
            ),
            memory=MemoryInfo(anomalies=schema_anomalies),
            detection=DetectionInfo(
                rules=["WinMemoryScanner"],
                severity="high",
                confidence=0.9
            ),
            message=f"Detected {len(anomalies)} memory anomalies in PID {pid}"
        )
        
        url = f"{ES_HOST}/{self.get_index_name()}/_doc"
        payload = self._sanitize_payload(event.to_dict())
        try:
            self.session.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=5)
            logger.warning(f"MEMORY ALERT SENT: PID {pid}")
        except Exception:
            pass

    def run_memory_scanner(self):
        """运行内存扫描循环 (主线程)"""
        if not self.mem_scanner:
            logger.warning("Memory Scanner not available. Skipping.")
            return

        logger.info("Starting Memory Scanner (Main Thread)...")
        while True:
            try:
                pids = self.enum_processes()
                for pid in pids:
                    if pid <= 4: continue
                    anomalies = self.mem_scanner.scan_pid(pid)
                    if anomalies:
                        self.send_memory_alert(pid, anomalies)
                time.sleep(SCAN_INTERVAL)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Memory Scan Error: {e}")
                time.sleep(SCAN_INTERVAL)

    # --- 安全日志逻辑 (优化版) ---
    def _get_powershell_events(self, start_time: datetime):
        """
        使用 PowerShell 获取 Windows 安全日志
        关注事件 ID: 4624 (登录成功), 4625 (登录失败), 4768 (Kerberos TGT), 4776 (NTLM 验证) 等
        """
        ps_script = f"""
        $ids = @(4624, 4625, 4768, 4776, 4720, 4726)
        $time = (Get-Date).AddSeconds(-15)
        Get-WinEvent -FilterHashtable @{{LogName='Security'; ID=$ids; StartTime=$time}} -ErrorAction SilentlyContinue | 
        ForEach-Object {{
            $evt = $_
            $xml = [xml]$evt.ToXml()
            $data = @{{}}
            if ($xml.Event.EventData.Data) {{
                $xml.Event.EventData.Data | ForEach-Object {{ 
                    if ($_.Name) {{ $data[$_.Name] = $_.'#text' }}
                }}
            }}
            @{{
                TimeCreated = $evt.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')
                Id = $evt.Id
                Message = $evt.Message
                EventData = $data
            }}
        }} | ConvertTo-Json -Compress -Depth 2
        """

        try:
            cmd = ["powershell", "-Command", ps_script]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            data = result.stdout.strip()
            if not data: return []
            return json.loads(data) if data.startswith('[') else [json.loads(data)]
        except:
            return []

    def process_logs(self):
        try:
            events = self._get_powershell_events(self.last_event_time)
            processed_count = 0
            
            for evt in events:
                raw_log = {
                    "EventID": evt.get("Id"),
                    "TimeCreated": evt.get("TimeCreated"),
                    "EventData": evt.get("EventData", {}),
                    "Message": evt.get("Message"),
                    "System": {"EventID": evt.get("Id")}
                }
                
                unified_event = self.log_parser.parse(raw_log, log_type="windows")
                if not unified_event: continue
                
                # === [User Request: 字段修改为"对应登录机器的信息"] ===
                # 默认情况下，HostInfo 是 DC 自己的
                dc_host_info = HostInfo(
                    name=self.sys_info.hostname,
                    hostname=self.sys_info.hostname,
                    ip=self.sys_info.ip,
                    os=self.sys_info.os_info
                )
                
                # 如果 LogParser 解析出了 Source IP (即 PC-1 的 IP)
                # 并且这个 IP 不是本地 IP，则说明这是远程机器的操作
                # 用户希望这条日志看起来属于那台远程机器
                if unified_event.source.ip and unified_event.source.ip not in ["-", "::1", "127.0.0.1", "127.0.0.1"]:
                    # 将 Host 字段改写为 Source 机器的信息
                    # 注意：我们不知道远程机器的 Hostname/OS，只能填 IP
                    unified_event.host.name = f"Remote-Host-{unified_event.source.ip}" # 临时名称
                    unified_event.host.hostname = unified_event.source.ip # 用 IP 代替 Hostname
                    unified_event.host.ip = [unified_event.source.ip] # 这是一个 List
                    
                    # OS 未知，可以留空或填 unknown
                    unified_event.host.os = HostOS(family="unknown", name="unknown", version="")
                else:
                    # 如果是本地登录或无法识别 IP，则归属给 DC
                    unified_event.host = dc_host_info

                # Terminal Output
                print(f"\n[!] 捕获安全事件: {unified_event.event.action}")
                print(f"    - 用户: {unified_event.user.name}")
                print(f"    - 来源: {unified_event.source.ip}")
                print(f"    - 归属主机 (Host): {unified_event.host.ip}") 
                print(f"    - 时间: {unified_event.timestamp}")
                print("-" * 40)
                
                # Send
                url = f"{ES_HOST}/{self.get_index_name()}/_doc"
                payload = self._sanitize_payload(unified_event.to_dict())
                try:
                    resp = self.session.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=2)
                    if resp.status_code in [200, 201]:
                        print(f"[+] 发送成功: Status {resp.status_code}")
                        processed_count += 1
                    else:
                        print(f"[-] 发送失败: {resp.status_code} - {resp.text}")
                except Exception as e:
                    print(f"[-] 发送异常: {e}")

        except Exception as e:
            logger.error(f"Process logs error: {e}")

    def run_log_monitoring(self):
        logger.info("Starting Security Log Monitor (Background)...")
        while True:
            try:
                self.process_logs()
                time.sleep(10)
            except:
                time.sleep(10)

    def run(self):
        # Start Log Monitor
        t = threading.Thread(target=self.run_log_monitoring, daemon=True)
        t.start()
        
        # Start Memory Scanner (Blocking)
        self.run_memory_scanner()

if __name__ == "__main__":
    agent = WinAgentDC()
    agent.run()
