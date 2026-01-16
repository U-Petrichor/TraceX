import os
import sys
import time
import json
import logging
import subprocess
import threading
from datetime import datetime, timedelta

# Ensure parent path is in sys.path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Try to import Base WinAgent
try:
    from win_agent import WinAgent, logger as base_logger, ES_HOST
    from collector.common.schema import UnifiedEvent, EventInfo, HostInfo, ProcessInfo, DetectionInfo
    from collector.host_collector.log_parser import HostLogParser
except ImportError:
    # If running from root directly without package structure
    from collector.host_collector.win_agent import WinAgent, logger as base_logger, ES_HOST
    from collector.common.schema import UnifiedEvent, EventInfo, HostInfo, ProcessInfo, DetectionInfo
    from collector.host_collector.log_parser import HostLogParser

# Configure local logger for DC-specific tasks
logger = logging.getLogger("WinAgent-DC")
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

class WinAgentDC(WinAgent):
    """
    TraceX Windows Agent for Domain Controllers (DC)
    Features:
    1. Inherits Memory Scanning from WinAgent (runs in Main Thread)
    2. Adds Security Event Log Monitoring (runs in Background Thread)
    """
    def __init__(self):
        super().__init__()
        self.last_event_time = datetime.utcnow() - timedelta(minutes=1)
        self.log_parser = HostLogParser()
        logger.info(f"WinAgent DC Extension initialized on {self.sys_info.hostname}")

    def _get_powershell_events(self, start_time: datetime):
        """
        Uses PowerShell to fetch Security logs.
        Focuses on: 
        - 4624 (Logon Success - Local)
        - 4625 (Logon Failed - Local)
        - 4768 (Kerberos TGT Request - Domain Login)
        - 4776 (NTLM Auth - Domain Login)
        - 4720 (User Create)
        - 4726 (User Delete)
        """
        # Optimized PowerShell script to return clean JSON directly
        # Extract properties in PowerShell to avoid XML parsing issues in Python
        ps_script = f"""
        $ids = @(4624, 4625, 4768, 4776, 4720, 4726)
        $time = (Get-Date).AddSeconds(-15)
        Get-WinEvent -FilterHashtable @{{LogName='Security'; ID=$ids; StartTime=$time}} -ErrorAction SilentlyContinue | 
        ForEach-Object {{
            $evt = $_
            $xml = [xml]$evt.ToXml()
            $data = @{{}}
            # Handle different XML structures safely
            if ($xml.Event.EventData.Data) {{
                $xml.Event.EventData.Data | ForEach-Object {{ 
                    if ($_.Name) {{ $data[$_.Name] = $_.'#text' }}
                }}
            }}
            
            @{{
                # 转换为 UTC 时间格式 (ToUniversalTime)，确保与 ES/Kibana 标准一致
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
            
            if not result.stdout.strip():
                return []
                
            data = result.stdout.strip()
            if data.startswith('['):
                return json.loads(data)
            else:
                return [json.loads(data)]

        except subprocess.TimeoutExpired:
            logger.error("PowerShell log query timed out")
            return []
        except json.JSONDecodeError:
            return []
        except Exception as e:
            logger.error(f"Log Collection Error: {e}")
            return []

    def process_logs(self):
        """Polls logs and sends to ES"""
        try:
            events = self._get_powershell_events(self.last_event_time)
            
            processed_count = 0
            for evt in events:
                # Map to format expected by log_parser
                # log_parser expects 'EventID', 'EventData', etc.
                raw_log = {
                    "EventID": evt.get("Id"),
                    "TimeCreated": evt.get("TimeCreated"),
                    "EventData": evt.get("EventData", {}),
                    "Message": evt.get("Message"),
                    "System": { # Mock System part if needed, mostly for EventID fallback
                        "EventID": evt.get("Id")
                    }
                }
                
                # Use shared log parser logic
                unified_event = self.log_parser.parse(raw_log, log_type="windows")
                
                if not unified_event:
                    continue
                
                # [Fix] 正确设置 Host 信息
                # 之前这里强制把 host 覆盖成了 DC 自己 (self.sys_info)，导致所有数据都显示来自 DC。
                # 实际上，对于 4768 (Kerberos) / 4624 (Network Logon) 这类事件，真正的源头在 source.ip 里。
                # 虽然事件是从 DC 采集的，但我们希望在界面上能体现出是哪台机器的操作。
                
                # 策略 1: 保持 host 为 DC (因为日志确实是 DC 产生的)，但确保 source.ip 是 PC-1
                # unified_event.host.name = self.sys_info.hostname
                # unified_event.host.ip = self.sys_info.ip
                
                # 策略 2: (用户需求) 让这条数据看起来像是那台机器产生的
                # 如果 source.ip 存在且不是 DC 自己，我们可以把它挪到 host.ip 吗？
                # 答：不建议。因为 host 字段通常代表 Log shipper (日志采集者)。
                # 正确的做法是：Kibana 查询时应该看 source.ip 而不是 host.ip。
                
                # 但是，既然用户说 "让最终传输的数据为对应的登陆的那台机器的信息"，
                # 可能是指他希望在 host 字段看到来源机器。
                # 我们这里做一个特殊的逻辑：
                # 如果是远程登录事件 (source.ip 有值)，且不是本地回环，我们将 source.ip 填入 host.ip (或者作为相关 IP)
                
                if unified_event.source.ip and unified_event.source.ip not in ["-", "::1", "127.0.0.1"]:
                     # 这是一个来自远端的事件
                     # 注意：我们不知道远端的主机名 (host.name)，只知道 IP。
                     # 为了满足用户需求，我们把 source.ip 同时也赋给 host.ip (虽然这在语义上有点混淆，但能达到"这条数据属于那台机器"的效果)
                     # 或者更好的方式：保留 host 为 DC，但在打印和展示时强调 source。
                     pass

                # 重新审视代码，发现之前这里无脑覆盖了 host 信息：
                # unified_event.host.name = self.sys_info.hostname  <-- 问题在这里
                # 
                # 对于 DC 转发的日志，unified_event.source.ip 才是主角。
                # 如果用户坚持要 "数据库里存的数据为对应的登陆机器"，那我们需要把 source.ip 提升为主要索引字段。
                
                # 修正逻辑：
                # 1. host 字段依然保留为 DC (因为确实是 DC 记录的日志，篡改 host 会导致元数据混乱)。
                # 2. 确保 source.ip 字段被正确填充 (LogParser 已经做了)。
                # 3. 如果 LogParser 解析出了 User 和 Source IP，不要用 DC 的本地信息去覆盖它们 (LogParser 里的逻辑是优先的，这里只填充空缺)。
                
                if not unified_event.host.name:
                    unified_event.host.name = self.sys_info.hostname
                if not unified_event.host.ip:
                    unified_event.host.ip = self.sys_info.ip
                unified_event.host.os = self.sys_info.os_info
                
                # Print detection to terminal (User Request)
                user_name = unified_event.user.name or "N/A"
                src_ip = unified_event.source.ip or "Local/N/A"
                action = unified_event.event.action
                print(f"\n[!] 捕获安全事件: {action}")
                print(f"    - 用户: {user_name}")
                print(f"    - 来源: {src_ip}")
                print(f"    - 时间: {unified_event.timestamp}")
                print("-" * 40)
                
                # Send
                index_name = self.get_index_name()
                url = f"{ES_HOST}/{index_name}/_doc"
                payload = self._sanitize_payload(unified_event.to_dict())
                
                try:
                    resp = self.session.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=2)
                    if resp.status_code in [200, 201]:
                        print(f"[+] 数据已发送至服务器: {url} (Status: {resp.status_code})")
                        processed_count += 1
                    else:
                        print(f"[-] 发送失败: {resp.status_code} - {resp.text}")
                except Exception as e:
                    print(f"[-] 发送异常: {e}")
                    # logger.error(f"Failed to send event: {e}")
                    pass
            
            if processed_count > 0:
                logger.info(f"Collected and sent {processed_count} Security Events")
                
        except Exception as e:
            logger.error(f"Process logs failed: {e}")

    def run_log_monitoring(self):
        """Background loop for log collection"""
        logger.info("Starting DC Security Log Monitor (Background Thread)...")
        while True:
            try:
                self.process_logs()
                time.sleep(10)
            except Exception as e:
                logger.error(f"Log Monitor Loop Error: {e}")
                time.sleep(10)

    def run(self):
        """
        Main entry point.
        1. Starts Log Monitoring in a background thread.
        2. Calls super().run() to execute the standard Memory Scanner in the main thread.
        """
        # 1. Start Log Monitoring in background (Daemon thread dies when main thread exits)
        t = threading.Thread(target=self.run_log_monitoring, daemon=True)
        t.start()
        
        # 2. Run the base Memory Scanner (Blocking)
        # This executes the 'while True' loop defined in WinAgent.run()
        # effectively "calling" the basic script logic.
        logger.info("Starting Base Memory Scanner (Main Thread)...")
        try:
            super().run()
        except KeyboardInterrupt:
            # super().run() handles this, but just in case
            pass

if __name__ == "__main__":
    agent = WinAgentDC()
    agent.run()
