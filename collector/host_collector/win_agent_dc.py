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
except ImportError:
    # If running from root directly without package structure
    from collector.host_collector.win_agent import WinAgent, logger as base_logger, ES_HOST
    from collector.common.schema import UnifiedEvent, EventInfo, HostInfo, ProcessInfo, DetectionInfo

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
        logger.info(f"WinAgent DC Extension initialized on {self.sys_info.hostname}")

    def _get_powershell_events(self, start_time: datetime):
        """
        Uses PowerShell to fetch Security logs.
        Focuses on: 4624 (Logon), 4625 (Fail), 4720 (User Create), 4726 (User Delete)
        """
        ps_script = f"""
        $ids = @(4624, 4625, 4720, 4726)
        $time = (Get-Date).AddSeconds(-15)
        Get-WinEvent -FilterHashtable @{{LogName='Security'; ID=$ids; StartTime=$time}} -ErrorAction SilentlyContinue | 
        Select-Object TimeCreated, Id, Message, @{{N='Account';E={{$_.Properties[5].Value}}}} | 
        ConvertTo-Json -Compress
        """
        
        try:
            # Run PowerShell
            cmd = ["powershell", "-Command", ps_script]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if not result.stdout.strip():
                return []
                
            data = result.stdout.strip()
            if data.startswith('{'):
                events = [json.loads(data)]
            else:
                events = json.loads(data)
                
            return events
            
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
                event_id = evt.get("Id")
                timestamp_str = datetime.utcnow().isoformat() + "Z"
                
                # Determine Severity and Type
                severity = 1
                action = "unknown"
                category = "iam"
                
                if event_id == 4624:
                    action = "login-success"
                    severity = 1
                elif event_id == 4625:
                    action = "login-failed"
                    severity = 5 # Medium risk
                elif event_id == 4720:
                    action = "user-created"
                    severity = 5
                elif event_id == 4726:
                    action = "user-deleted"
                    severity = 5
                
                # Construct UnifiedEvent
                unified = UnifiedEvent(
                    timestamp=timestamp_str,
                    event=EventInfo(
                        category=category,
                        type="info",
                        action=action,
                        severity=severity,
                        dataset="win_security_log"
                    ),
                    host=HostInfo(
                        name=self.sys_info.hostname,
                        hostname=self.sys_info.hostname,
                        ip=self.sys_info.ip,
                        os=self.sys_info.os_info
                    ),
                    message=f"Event {event_id}: {evt.get('Message', '')[:100]}..."
                )
                
                # Send
                index_name = self.get_index_name()
                url = f"{ES_HOST}/{index_name}/_doc"
                payload = self._sanitize_payload(unified.to_dict())
                
                try:
                    self.session.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=2)
                    processed_count += 1
                except Exception:
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
