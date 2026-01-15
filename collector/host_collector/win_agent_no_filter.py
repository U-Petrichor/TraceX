import os
import sys
import time
import json
import socket
import platform
import logging
import requests
import ctypes
from datetime import datetime
from ctypes import wintypes

# === Import Custom Modules ===
# 1. Memory Scanner Library
try:
    from win_mem_scanner import WinMemoryScanner
except ImportError:
    # If run from root
    try:
        from collector.host_collector.win_mem_scanner import WinMemoryScanner
    except ImportError:
         print("CRITICAL: Cannot find win_mem_scanner module.")
         sys.exit(1)

# === Path Setup for Schema Import ===
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from collector.common.schema import (
        UnifiedEvent, EventInfo, HostInfo, HostOS, 
        MemoryInfo, MemoryAnomaly, DetectionInfo,
        ProcessInfo
    )
except ImportError as e:
    print(f"CRITICAL: Failed to import Schema. Error: {e}")
    sys.exit(1)

# === Configuration ===
ES_HOST = "http://182.92.114.32:9200"
SCAN_INTERVAL = 60 # Full scan every 60 seconds

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("WinAgentNoFilter")

# === Helper: Process Enumeration (ctypes) ===
psapi = ctypes.windll.psapi
kernel32 = ctypes.windll.kernel32

def enum_processes():
    """Returns a list of PIDs using EnumProcesses"""
    # Allocate array for PIDs
    arr = (ctypes.c_ulong * 1024)()
    cb = ctypes.sizeof(arr)
    cb_needed = ctypes.c_ulong()
    
    if psapi.EnumProcesses(ctypes.byref(arr), cb, ctypes.byref(cb_needed)):
        count = cb_needed.value // ctypes.sizeof(ctypes.c_ulong)
        return [arr[i] for i in range(count)]
    return []

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

class WinAgentNoFilter:
    """
    TraceX Windows Agent (No Filter Version)
    Records scan results for ALL processes, regardless of anomalies.
    """
    def __init__(self):
        self.sys_info = SystemInfoCollector()
        self.mem_scanner = WinMemoryScanner()
        self.session = requests.Session()
        logger.info(f"WinAgent (No Filter) initialized on {self.sys_info.hostname}")

    def get_index_name(self):
        return f"unified-logs-{datetime.utcnow().strftime('%Y.%m.%d')}"
    
    def _sanitize_payload(self, payload: dict) -> dict:
        if "source" in payload and isinstance(payload["source"], dict):
            if payload["source"].get("ip") == "":
                payload["source"]["ip"] = None
        if "destination" in payload and isinstance(payload["destination"], dict):
            if payload["destination"].get("ip") == "":
                payload["destination"]["ip"] = None
        return payload

    def send_scan_result(self, pid: int, anomalies: list):
        """Constructs and sends an event for scan results (Clean or Anomalous)"""
        utc_now = datetime.utcnow()
        timestamp_str = utc_now.isoformat() + "Z"
        
        is_suspicious = len(anomalies) > 0
        
        # Convert dict anomalies (from scanner) to Schema objects
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
                severity=8 if is_suspicious else 1, # High if suspicious, else Low/Info
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
                name="<unknown>", # Without OpenProcess query we might not know name here easily
                start_time=timestamp_str
            ),
            memory=MemoryInfo(anomalies=schema_anomalies),
            detection=DetectionInfo(
                rules=["WinMemoryScanner"],
                severity="high" if is_suspicious else "info",
                confidence=0.9 if is_suspicious else 1.0
            ),
            message=f"Detected {len(anomalies)} memory anomalies in PID {pid}" if is_suspicious else f"Scan clean for PID {pid}"
        )
        
        # Send
        index_name = self.get_index_name()
        url = f"{ES_HOST}/{index_name}/_doc"
        payload = self._sanitize_payload(event.to_dict())
        
        try:
            # We use a short timeout and maybe don't log success for every clean event to avoid spamming local console,
            # but user asked for "no filter" so we send everything to ES.
            self.session.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=1)
            # Only log locally if suspicious or maybe every 100th packet to show it's alive? 
            # For now, let's keep it simple.
            if is_suspicious:
                logger.warning(f"ALERT SENT: Found memory anomalies in PID {pid}")
            # else:
            #    logger.debug(f"Sent clean report for PID {pid}") 
        except Exception as e:
            logger.error(f"Failed to send event: {e}")

    def run(self):
        logger.info("Agent running (No Filter Mode). Scanning memory every 60s...")
        
        while True:
            try:
                # 1. Get PIDs
                pids = enum_processes()
                logger.info(f"Scanning {len(pids)} processes...")
                
                # 2. Scan each PID
                for pid in pids:
                    # REMOVED: Skipping System/Idle processes
                    # if pid <= 4: continue
                        
                    anomalies = self.mem_scanner.scan_pid(pid)
                    
                    # ALWAYS send result
                    self.send_scan_result(pid, anomalies)
                
                logger.info("Scan complete.")
                time.sleep(SCAN_INTERVAL)
            except KeyboardInterrupt:
                logger.info("Agent stopped by user.")
                break
            except Exception as e:
                logger.error(f"Global Loop Error: {e}")
                time.sleep(5)

if __name__ == "__main__":
    agent = WinAgentNoFilter()
    agent.run()
