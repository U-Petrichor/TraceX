import ctypes
import time
import socket
import sys
import os
import subprocess
import threading

# 定义 Windows API
kernel32 = ctypes.windll.kernel32

# 内存权限常量
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40  # 关键特征：可读可写可执行 (RWX)

def simulate_memory_injection():
    print(f"\n[+] [Step 1] 正在进程 {os.getpid()} 中模拟无文件攻击 (Fileless Attack)...")
    print("[*] 正在申请 RWX (Read-Write-Execute) 隐蔽内存区域...")
    
    # 1. 申请一块 RWX 内存 (这是 TraceX 内存扫描最敏感的特征)
    # VirtualAlloc 返回的是整数地址，但在 64位 Python 中可能是个很大的数
    # ctypes 需要明确指明返回类型为 void pointer (c_void_p)
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ptr = kernel32.VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    
    if not ptr:
        print("[-] 内存申请失败！")
        return

    print(f"[!] 成功申请高危内存段，地址: {hex(ptr)}")
    
    # 2. 模拟写入 Shellcode (用 0x90 NOP Sled 填充)
    print("[*] 正在注入模拟 Shellcode Payload...")
    shellcode = b'\x90' * 1024
    ctypes.memmove(ptr, shellcode, len(shellcode))
    
    print("[!] Payload 注入完成，RWX 内存区域已就绪。")
    print("[!] TraceX Host Agent 应该在 60秒内检测到此【内存异常】...")

def simulate_lateral_movement():
    print(f"\n[+] [Step 2] 正在模拟横向移动 (Lateral Movement)...")
    target_ip = "192.168.52.10" # DC IP
    print(f"[*] 目标: 域控 DC ({target_ip})")
    
    # 1. 模拟网络连通性探测 (ICMP)
    print(f"[*] 正在探测目标存活 (Ping)...")
    subprocess.run(["ping", "-n", "2", target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 2. 模拟尝试访问共享资源 (触发 4624/4625/4768)
    # 这会产生 Kerberos Ticket 请求或 NTLM 认证
    print(f"[*] 正在尝试通过 SMB 访问目标共享 (触发认证日志)...")
    cmd = f"net use \\\\{target_ip}\\IPC$ /user:zhangsan P@ssw0rd123"
    # 我们不关心是否成功，只关心是否产生了日志
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print(f"[!] 横向移动动作已执行。")
    print("[!] TraceX DC Agent 应该检测到来自本机的【异常登录/访问】...")

def main():
    print("="*60)
    print("      TraceX 终极溯源测试 - 攻击模拟器 (Attacker)")
    print("="*60)
    print(f"[*] 攻击源主机: {socket.gethostname()} ({socket.gethostbyname(socket.gethostname())})")
    
    # 启动内存攻击
    simulate_memory_injection()
    
    # 稍微等待一下，模拟攻击者的思考时间
    time.sleep(5)
    
    # 启动横向移动
    simulate_lateral_movement()
    
    print("\n" + "="*60)
    print("[*] 攻击模拟结束。进程将保持存活，以便 Agent 扫描内存...")
    print("[*] 请勿关闭此窗口，直到溯源验证完成。")
    print("="*60)
    
    while True:
        time.sleep(10)

if __name__ == "__main__":
    main()