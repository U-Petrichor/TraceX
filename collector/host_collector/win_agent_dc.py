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
                TimeCreated = $evt.TimeCreated
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
                    
                # Supplement HostInfo (since parser might not know local host details if raw log doesn't have them)
                unified_event.host.name = self.sys_info.hostname
                unified_event.host.ip = self.sys_info.ip
                unified_event.host.os = self.sys_info.os_info
                
                # Send
                index_name = self.get_index_name()
                url = f"{ES_HOST}/{index_name}/_doc"
                payload = self._sanitize_payload(unified_event.to_dict())
                
                try:
                    self.session.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=2)
                    processed_count += 1
                except Exception as e:
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
