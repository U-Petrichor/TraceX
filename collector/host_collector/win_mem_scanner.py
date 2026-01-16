import ctypes
from ctypes import wintypes

# === Windows API 定义 ===
kernel32 = ctypes.windll.kernel32

# 进程访问权限标志
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
# 内存状态标志
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
# 内存保护标志
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20

# 系统信息结构体 (GetSystemInfo)
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

# 内存基本信息结构体 (VirtualQueryEx)
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
    """
    Windows 内存异常扫描器 (纯 Python 实现)
    功能：
    1. 遍历指定进程的虚拟内存空间 (VirtualQueryEx)
    2. 识别高危内存属性 (RWX 可读可写可执行, Private Exec 私有可执行)
    3. 辅助检测 PE 头 (ReadProcessMemory)
    """
    def __init__(self):
        self.sys_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(ctypes.byref(self.sys_info))

    def scan_pid(self, pid: int) -> list:
        """
        扫描指定 PID 的内存异常
        :param pid: 进程 ID
        :return: 异常列表 (字典格式)
        """
        anomalies = []
        process_handle = None
        try:
            # 打开进程句柄 (需要 QUERY_INFORMATION 和 VM_READ 权限)
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

            # 遍历内存区域
            while address < ctypes.addressof(max_addr):
                if kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size) == 0:
                    break

                # 1. 检查 RWX (Read-Write-Execute) 内存
                # RWX 内存是典型的 Shellcode 注入特征
                if mbi.State == MEM_COMMIT and (mbi.Protect == PAGE_EXECUTE_READWRITE):
                    header = self._read_memory(process_handle, mbi.BaseAddress, 2)
                    is_pe = (header == b'MZ') # 检查是否为 PE 文件头
                    
                    risk = "CRITICAL" if mbi.Type == MEM_PRIVATE else "HIGH"
                    
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

                # 2. 检查私有可执行内存 (Private Executable)
                # 通常合法的可执行代码应该是 MEM_IMAGE (映射的文件)，MEM_PRIVATE 且可执行通常可疑
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
        """读取目标进程内存"""
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
            return buffer.raw
        return b''
