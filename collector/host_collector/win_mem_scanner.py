import ctypes
from ctypes import wintypes

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
        ("dwActiveProcessorMask", wintypes.DWORD * 2),
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
    """Windows Memory Anomaly Scanner (Library)"""
    def __init__(self):
        self.sys_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(ctypes.byref(self.sys_info))

    def scan_pid(self, pid: int) -> list:
        """
        Scans a specific PID for memory anomalies (RWX, Private Exec).
        Returns a list of dicts (compatible with Schema MemoryAnomaly).
        """
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
            max_addr = self.sys_info.lpMaximumApplicationAddress
            
            mbi = MEMORY_BASIC_INFORMATION()
            mbi_size = ctypes.sizeof(mbi)

            while address < ctypes.addressof(max_addr):
                if kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size) == 0:
                    break

                # 1. Check for RWX (Read-Write-Execute) Memory
                if mbi.State == MEM_COMMIT and (mbi.Protect == PAGE_EXECUTE_READWRITE):
                    header = self._read_memory(process_handle, mbi.BaseAddress, 2)
                    is_pe = (header == b'MZ')
                    
                    risk = "CRITICAL" if mbi.Type == MEM_PRIVATE else "HIGH"
                    
                    # Return dicts to avoid dependency on Schema here (keep it pure lib)
                    # Or use Schema objects if we import it. Let's use dicts for loose coupling or Schema if available.
                    # To keep this file independent, we return dicts, Agent converts to Schema.
                    anomalies.append({
                        "type": "RWX_REGION",
                        "address": hex(mbi.BaseAddress if mbi.BaseAddress else 0),
                        "size": mbi.RegionSize,
                        "perms": "RWX",
                        "path": "[Private]" if mbi.Type == MEM_PRIVATE else "[Mapped]",
                        "is_elf": False,
                        "risk_level": risk,
                        "confidence": 0.9,
                        "details": f"Detected RWX memory region. PE Header: {is_pe}"
                    })

                # 2. Check for Executable Private Memory
                elif mbi.State == MEM_COMMIT and (mbi.Protect == PAGE_EXECUTE_READ) and (mbi.Type == MEM_PRIVATE):
                     anomalies.append({
                        "type": "PRIVATE_EXEC",
                        "address": hex(mbi.BaseAddress if mbi.BaseAddress else 0),
                        "size": mbi.RegionSize,
                        "perms": "RX",
                        "path": "[Private]",
                        "is_elf": False,
                        "risk_level": "MEDIUM",
                        "confidence": 0.7,
                        "details": "Detected Private Executable memory (Potential Shellcode/JIT)"
                    })

                address += mbi.RegionSize
                
        except Exception:
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
