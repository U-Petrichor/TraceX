import ctypes
import os
import sys
import time
import mmap

# Constants for syscalls (x86_64)
__NR_memfd_create = 319
MFD_CLOEXEC = 0x0001

# Constants for mmap
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
MAP_SHARED = 0x01
MAP_ANONYMOUS = 0x20

def simulate_attack():
    print(f"[+] Starting Memory Attack Simulation (PID: {os.getpid()})")
    
    # Generate unique timestamp for this run
    ts = int(time.time())
    
    # 1. Create memfd with unique name
    libc = ctypes.CDLL(None)
    syscall = libc.syscall
    
    print("[*] invoking memfd_create...")
    # Append timestamp to name to ensure unique path in scanner report
    # This ensures auditd_agent generates a unique alert signature
    name = f"malicious_payload_{ts}".encode('utf-8')
    fd = syscall(__NR_memfd_create, name, MFD_CLOEXEC)
    
    if fd < 0:
        print("[-] memfd_create failed")
        sys.exit(1)
        
    print(f"[+] memfd created (fd={fd}, name={name.decode()})")

    # 2. Write fake ELF header to it
    # \x7fELF...
    # Also embed timestamp in payload for unique content
    payload = b"\x7fELF\x02\x01\x01\x00" + b"\x90" * 1024 
    payload += f"TIMESTAMP={ts}".encode('utf-8')
    
    os.write(fd, payload)
    print(f"[+] Wrote {len(payload)} bytes to memfd (Fake ELF header + TS)")

    # 3. Mmap it as RWX (Read + Write + Execute)
    # This is a huge red flag for our scanner
    print("[*] Mapping memory as RWX...")
    
    # Python's mmap module is high-level, let's use it for convenience
    # Note: Python's mmap usually doesn't allow setting PROT_EXEC easily on all platforms without ctypes,
    # but we can try to rely on the fact that we have the fd.
    # Actually, let's use libc mmap to be precise about PROT_EXEC | PROT_WRITE
    
    # void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    mmap_func = libc.mmap
    mmap_func.restype = ctypes.c_void_p
    mmap_func.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long)
    
    length = 4096
    addr = mmap_func(None, length, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0)
    
    if addr == -1 or addr == 0xffffffffffffffff:
        print("[-] mmap failed")
        sys.exit(1)
        
    print(f"[+] Mapped RWX memory at {hex(addr)}")
    print("[!] ATTACK SIMULATED. Sleeping for 300 seconds to allow scanning...")
    print("[!] Press Ctrl+C to stop.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        os.close(fd)

if __name__ == "__main__":
    simulate_attack()
