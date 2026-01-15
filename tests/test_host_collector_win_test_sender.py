import os
import sys
import time
import random
import logging
import requests
import socket
import platform
from datetime import datetime

# === Path Setup for Schema Import ===
# Adjust path to find project root from tests/
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir) # tests/ -> root
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from collector.common.schema import (
        UnifiedEvent, EventInfo, HostInfo, HostOS, 
        ProcessInfo, ProcessParent, ProcessUser,
        MemoryInfo, MemoryAnomaly, DetectionInfo
    )
except ImportError as e:
    print(f"CRITICAL: Failed to import Schema. Error: {e}")
    sys.exit(1)

# === Configuration ===
ES_HOST = "http://182.92.114.32:9200"
LOG_INTERVAL = 5

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("WinMockSender")

class SystemInfoCollector:
    """Collects static system information (Windows)"""
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

class WinMockSender:
    """Generates and sends MOCK events to test connectivity"""
    def __init__(self):
        self.sys_info = SystemInfoCollector()
        self.session = requests.Session()
        logger.info(f"Mock Sender initialized for host: {self.sys_info.hostname}")

    def generate_mock_event(self) -> UnifiedEvent:
        """Generates a simulated Process Creation event with Random Memory Anomaly"""
        
        # 1. Mock Process Data
        mock_procs = [
            ("powershell.exe", "C:\\Windows\\System32\\powershell.exe", "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ls"),
            ("cmd.exe", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami"),
            ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p"),
            ("notepad.exe", "C:\\Windows\\System32\\notepad.exe", "notepad.exe secret.txt")
        ]
        proc_name, proc_exe, proc_cmd = random.choice(mock_procs)
        pid = random.randint(1000, 9999)
        
        # 2. Build UnifiedEvent
        utc_now = datetime.utcnow()
        timestamp_str = utc_now.isoformat() + "Z"

        # 3. Simulate Memory Scan Result
        mem_info = MemoryInfo()
        if random.random() < 0.3: # 30% chance to simulate a threat
            mem_info.anomalies.append(MemoryAnomaly(
                type="RWX_REGION",
                address="0x7ff0001000",
                size=4096,
                perms="RWX",
                path="[Private]",
                risk_level="CRITICAL",
                confidence=0.95,
                details="Simulated RWX Memory Detection (WinMock)"
            ))
            detection_info = DetectionInfo(
                rules=["Windows Memory Scanner (Mock)"],
                confidence=0.9,
                severity="high"
            )
        else:
            detection_info = DetectionInfo()

        event = UnifiedEvent(
            timestamp=timestamp_str,
            event=EventInfo(
                category="process",
                action="creation",
                type="start",
                outcome="success",
                severity=1,
                dataset="windows_mock"
            ),
            host=HostInfo(
                name=self.sys_info.hostname,
                hostname=self.sys_info.hostname,
                ip=self.sys_info.ip,
                os=self.sys_info.os_info
            ),
            process=ProcessInfo(
                pid=pid,
                name=proc_name,
                executable=proc_exe,
                command_line=proc_cmd,
                parent=ProcessParent(pid=random.randint(400, 900), name="explorer.exe"),
                user=ProcessUser(name="SYSTEM", id="S-1-5-18"),
                start_time=timestamp_str
            ),
            memory=mem_info, 
            detection=detection_info,
            message=f"Process started: {proc_cmd}"
        )
        return event

    def get_index_name(self):
        return f"unified-logs-{datetime.utcnow().strftime('%Y.%m.%d')}"

    def _sanitize_payload(self, payload: dict) -> dict:
        """Fix empty IP strings for ES"""
        if "source" in payload and isinstance(payload["source"], dict):
            if payload["source"].get("ip") == "":
                payload["source"]["ip"] = None
        if "destination" in payload and isinstance(payload["destination"], dict):
            if payload["destination"].get("ip") == "":
                payload["destination"]["ip"] = None
        return payload

    def send_to_es(self, event: UnifiedEvent):
        index_name = self.get_index_name()
        url = f"{ES_HOST}/{index_name}/_doc"
        payload = self._sanitize_payload(event.to_dict())

        try:
            response = self.session.post(
                url, json=payload, headers={"Content-Type": "application/json"}, timeout=5
            )
            if response.status_code in [200, 201]:
                logger.info(f"Sent MOCK event [{event.event.id}] to [{index_name}]")
            else:
                logger.error(f"Failed. Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            logger.warning(f"Network error: {e}")

    def run(self):
        logger.info("Starting MOCK data sender...")
        while True:
            try:
                event = self.generate_mock_event()
                self.send_to_es(event)
                time.sleep(LOG_INTERVAL)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error: {e}")
                time.sleep(5)

if __name__ == "__main__":
    sender = WinMockSender()
    sender.run()
