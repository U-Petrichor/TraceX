import os
import sys
import time
import json
import uuid
import socket
import platform
import random
import logging
import requests
import ctypes
from datetime import datetime
from ctypes import wintypes

# === Path Setup for Schema Import ===
# Ensure we can import from collector.common.schema
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from collector.common.schema import (
        UnifiedEvent, EventInfo, HostInfo, HostOS, 
        ProcessInfo, ProcessParent, ProcessUser,
        MemoryInfo, MemoryAnomaly, DetectionInfo
    )
except ImportError as e:
    print(f"CRITICAL: Failed to import Schema. Ensure project structure is correct. Error: {e}")
    sys.exit(1)

# === Configuration ===
ES_HOST = "http://182.92.114.32:9200"
LOG_INTERVAL = 5  # Seconds between mock events

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("WinAgent")

# === Windows API Definitions ===
kernel32 = ctypes.windll.kernel32

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20

class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", wintypes.LPVOID),
        ("lpMaximumApplicationAddress", wintypes.LPVOID),
        ("dwActiveProcessorMask", wintypes.DWORD * 2),  # ULONG_PTR on 64bit
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

class WinMemoryScanner:
    """Windows Memory Anomaly Scanner (Analogous to Linux mem_scanner)"""
    def __init__(self):
        self.sys_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(ctypes.byref(self.sys_info))

    def scan_pid(self, pid: int) -> list:
        anomalies = []
        process_handle = None
        try:
            process_handle = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
                False, 
                pid
            )
            if not process_handle:
                return []

            address = 0
            # Use lpMaximumApplicationAddress for user space limit
            max_addr = self.sys_info.lpMaximumApplicationAddress
            
            mbi = MEMORY_BASIC_INFORMATION()
            mbi_size = ctypes.sizeof(mbi)

            while address < ctypes.addressof(max_addr): # Logic simplified, iterating by query
                if kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size) == 0:
                    break

                # 1. Check for RWX (Read-Write-Execute) Memory
                # Often used by shellcode or unpacked malware
                if mbi.State == MEM_COMMIT and (mbi.Protect == PAGE_EXECUTE_READWRITE):
                    
                    # Read first few bytes to check for PE header (MZ)
                    header = self._read_memory(process_handle, mbi.BaseAddress, 2)
                    is_pe = (header == b'MZ')
                    
                    risk = "CRITICAL" if mbi.Type == MEM_PRIVATE else "HIGH"
                    
                    anomalies.append(MemoryAnomaly(
                        type="RWX_REGION",
                        address=hex(mbi.BaseAddress if mbi.BaseAddress else 0),
                        size=mbi.RegionSize,
                        perms="RWX",
                        path="[Private]" if mbi.Type == MEM_PRIVATE else "[Mapped]",
                        is_elf=False, # Windows uses PE
                        risk_level=risk,
                        confidence=0.9,
                        details=f"Detected RWX memory region. PE Header: {is_pe}"
                    ))

                # 2. Check for Executable Private Memory (Code Injection / Shellcode)
                # Normal code is usually MEM_IMAGE (mapped from disk)
                # MEM_PRIVATE + EXECUTE_READ usually means JIT or Shellcode
                elif mbi.State == MEM_COMMIT and (mbi.Protect == PAGE_EXECUTE_READ) and (mbi.Type == MEM_PRIVATE):
                     anomalies.append(MemoryAnomaly(
                        type="PRIVATE_EXEC",
                        address=hex(mbi.BaseAddress if mbi.BaseAddress else 0),
                        size=mbi.RegionSize,
                        perms="RX",
                        path="[Private]",
                        is_elf=False,
                        risk_level="MEDIUM",
                        confidence=0.7,
                        details="Detected Private Executable memory (Potential Shellcode/JIT)"
                    ))

                address += mbi.RegionSize
                
        except Exception as e:
            # Access denied or process exited is common
            pass
        finally:
            if process_handle:
                kernel32.CloseHandle(process_handle)
        
        return anomalies

    def _read_memory(self, handle, address, size):
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
            return buffer.raw
        return b''

class SystemInfoCollector:
    """Collects static system information (Windows)"""
    def __init__(self):
        self.hostname = socket.gethostname()
        self.ip = self._get_local_ip()
        self.os_info = self._get_os_info()

    def _get_local_ip(self):
        try:
            # Connect to external server to get the interface IP used for routing
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return [ip]
        except Exception:
            return ["127.0.0.1"]

    def _get_os_info(self):
        try:
            # platform.system() -> 'Windows'
            # platform.release() -> '10', 'Server', etc.
            # platform.version() -> '10.0.19041'
            return HostOS(
                family="windows",
                name=f"Windows {platform.release()}",
                version=platform.version()
            )
        except Exception:
            return HostOS(family="windows", name="Unknown", version="0.0")

class WinAgent:
    """Windows Collection Agent with Mock Data Generation"""
    def __init__(self):
        self.sys_info = SystemInfoCollector()
        self.mem_scanner = WinMemoryScanner() # Initialize Scanner
        self.session = requests.Session()
        logger.info(f"Agent initialized for host: {self.sys_info.hostname} ({self.sys_info.ip})")

    def generate_mock_event(self) -> UnifiedEvent:
        """Generates a simulated Process Creation event"""
        
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
        # Timestamp must be UTC ISO8601 string
        utc_now = datetime.utcnow()
        timestamp_str = utc_now.isoformat() + "Z"

        # 3. Simulate Memory Scan (Triggered randomly for demo)
        # In production, this would scan the actual PID. 
        # Since we are mocking the process, we scan self (the agent) or just simulate anomalies.
        # For demonstration of the TOOL, we will simulate a scan result attached to this event.
        
        mem_info = MemoryInfo()
        # Randomly inject a fake memory anomaly to demonstrate schema compliance
        if random.random() < 0.3: # 30% chance to simulate a threat
            mem_info.anomalies.append(MemoryAnomaly(
                type="RWX_REGION",
                address="0x7ff0001000",
                size=4096,
                perms="RWX",
                path="[Private]",
                risk_level="CRITICAL",
                confidence=0.95,
                details="Simulated RWX Memory Detection (WinAgent)"
            ))
            
            # Add Detection Info
            detection_info = DetectionInfo(
                rules=["Windows Memory Scanner"],
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
            memory=mem_info, # Attach Memory Info
            detection=detection_info,
            message=f"Process started: {proc_cmd}"
        )
        return event

    def get_index_name(self):
        """Generate index name: unified-logs-{YYYY.MM.DD} (UTC)"""
        return f"unified-logs-{datetime.utcnow().strftime('%Y.%m.%d')}"

    def send_to_es(self, event: UnifiedEvent):
        """Send event to Elasticsearch with retry logic"""
        index_name = self.get_index_name()
        url = f"{ES_HOST}/{index_name}/_doc"
        
        # Convert UnifiedEvent to dict using its built-in method
        payload = event.to_dict()

        try:
            response = self.session.post(
                url, 
                json=payload, 
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Sent event [{event.event.id}] to index [{index_name}]")
            else:
                logger.error(f"Failed to send event. Status: {response.status_code}, Response: {response.text}")
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"Network error connecting to ES ({ES_HOST}): {e}. Retrying later...")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

    def run(self):
        """Main Loop"""
        logger.info("WinAgent started. Press Ctrl+C to stop.")
        
        # Optional: Demo scanning self on startup
        try:
            my_pid = os.getpid()
            logger.info(f"Performing self-diagnostic memory scan (PID: {my_pid})...")
            anomalies = self.mem_scanner.scan_pid(my_pid)
            if anomalies:
                logger.warning(f"Self-scan found anomalies: {len(anomalies)}")
            else:
                logger.info("Self-scan clean.")
        except Exception as e:
            logger.error(f"Self-scan failed: {e}")

        while True:
            try:
                # 1. Generate Data
                event = self.generate_mock_event()
                
                # 2. Send to Cloud
                self.send_to_es(event)
                
                # 3. Wait
                time.sleep(LOG_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("Agent stopped by user.")
                break
            except Exception as e:
                logger.error(f"Main loop error: {e}")
                time.sleep(5)

if __name__ == "__main__":
    agent = WinAgent()
    agent.run()
