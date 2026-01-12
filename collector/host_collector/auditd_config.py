import os
import subprocess

class AuditdConfig:
    """Auditd 规则配置管理器"""
    
    # 定义审计规则
    RULES = [
        # 监控程序执行 (execve 系统调用)
        "-a always,exit -F arch=b64 -S execve -k process_exec",
        "-a always,exit -F arch=b32 -S execve -k process_exec",
        
        # 监控网络连接 (connect 系统调用)
        "-a always,exit -F arch=b64 -S connect -k network_connect",
        "-a always,exit -F arch=b32 -S connect -k network_connect",
        
        # 监控敏感文件访问
        "-w /etc/passwd -p wa -k identity_theft",
        "-w /etc/shadow -p wa -k identity_theft"
    ]

    def apply_rules(self):
        """应用规则到系统"""
        print("[*] 正在应用 Auditd 规则...")
        
        # 1. 清除旧规则
        subprocess.run(["auditctl", "-D"], check=False)
        
        # 2. 添加新规则
        for rule in self.RULES:
            try:
                # 拆分命令字符串
                cmd = ["auditctl"] + rule.split()
                subprocess.run(cmd, check=True)
                print(f"  [+] 规则已添加: {rule}")
            except subprocess.CalledProcessError:
                print(f"  [-] 规则添加失败: {rule}")
        
        print("[*] Auditd 规则配置完成")

if __name__ == "__main__":
    config = AuditdConfig()
    config.apply_rules()