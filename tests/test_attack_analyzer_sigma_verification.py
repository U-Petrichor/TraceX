# tests/test_attack_analyzer_sigma_verification.py
import unittest
import sys
import os
import yaml
import shutil
from datetime import datetime

# 添加项目根目录到路径
sys.path.append(os.getcwd())

# 模拟 ECS 事件结构
def create_mock_event(cmd_line, executable="/bin/bash"):
    return {
        "@timestamp": datetime.utcnow().isoformat(),
        "event": {
            "category": "process",
            "dataset": "auditd", # 模拟 Auditd 数据
            "id": "evt_test_123"
        },
        "process": {
            "command_line": cmd_line,
            "executable": executable,
            "name": os.path.basename(executable),
            "pid": 1001
        },
        "raw": {
            "type": "EXECVE"
        },
        "host": {"name": "test-host"}
    }

class TestSigmaAttackPipeline(unittest.TestCase):

    def setUp(self):
        print(f"\n🛡️ [SigmaEngine] 开始测试: {self._testMethodName}")
        
        # 1. 创建临时的规则目录
        self.test_rules_dir = "tests/temp_rules"
        if not os.path.exists(self.test_rules_dir):
            os.makedirs(self.test_rules_dir)

        # 2. 动态创建一个测试用的 Sigma 规则 (检测 base64 命令)
        self.dummy_rule = {
            "title": "Test Base64 Execution",
            "id": "test-rule-001",
            "status": "experimental",
            "description": "Detects use of base64 decoding",
            "logsource": {"category": "process_creation", "product": "linux"},
            "detection": {
                "selection": {
                    "CommandLine|contains": "base64 -d"
                },
                "condition": "selection"
            },
            "level": "high",
            "tags": ["attack.execution", "attack.t1059"]
        }
        
        with open(f"{self.test_rules_dir}/test_rule.yml", "w") as f:
            yaml.dump(self.dummy_rule, f)

    def tearDown(self):
        # 清理临时文件
        if os.path.exists(self.test_rules_dir):
            shutil.rmtree(self.test_rules_dir)

    # =========================================================
    # 1. 测试规则加载 (RuleLoader)
    # =========================================================
    def test_rule_loader(self):
        try:
            from analyzer.attack_analyzer.rule_loader import RuleLoader
        except ImportError:
            self.skipTest("RuleLoader 模块未找到")

        loader = RuleLoader(rules_dir=self.test_rules_dir)
        loader.load_all()
        # 获取针对 Linux Process Creation 的规则
        rules = loader.get_rules_for_logsource(product="linux", category="process_creation")
        
        print(f"   Loaded {len(rules)} matching rules.")
        self.assertTrue(len(rules) > 0, "RuleLoader 未能加载测试规则")
        self.assertEqual(rules[0].title, "Test Base64 Execution") # 注意：这里访问的是对象属性 .title
        print("   ✅ RuleLoader 验证通过")

    # =========================================================
    # 2. 测试字段映射 (FieldMapper)
    # =========================================================
    def test_field_mapper(self):
        try:
            from analyzer.attack_analyzer.field_mapper import FieldMapper
        except ImportError:
            self.skipTest("FieldMapper 模块未找到")

        mapper = FieldMapper()
        # 模拟 Auditd 日志
        ecs_event = create_mock_event("sudo base64 -d /tmp/secret", "/usr/bin/sudo")
        logsource = {"product": "linux", "category": "process_creation"}
        
        sigma_log = mapper.map_event(ecs_event, logsource)
        print(f"   Mapped Log: {sigma_log}")
        
        # 验证 ECS command_line 是否被映射为 Sigma 的 CommandLine
        self.assertIn("CommandLine", sigma_log)
        self.assertEqual(sigma_log["CommandLine"], "sudo base64 -d /tmp/secret")
        print("   ✅ FieldMapper 验证通过")

    # =========================================================
    # 3. 集成测试：完整分析器 (AttackAnalyzer)
    # =========================================================
    def test_full_analyzer_pipeline(self):
        try:
            from analyzer.attack_analyzer import AttackAnalyzer
        except ImportError:
            self.fail("无法导入 AttackAnalyzer 主入口")

        # 实例化分析器，传入我们的临时规则目录
        analyzer = AttackAnalyzer(rules_dir=self.test_rules_dir)
        
        # 构造一个肯定会命中的事件
        malicious_event = create_mock_event("echo 'bad' | base64 -d")
        
        # 执行分析
        result = analyzer.analyze_event(malicious_event)
        
        print(f"   Analysis Result: {result}")
        
        # 验证结果
        self.assertTrue(result['detected'], "分析器未能检测到 Base64 威胁")
        self.assertIn("Test Base64 Execution", result['matched_rules'], "未能匹配到正确的规则标题")
        
        # 验证 ATT&CK 标签转换
        techniques = result.get('techniques', [])
        self.assertTrue(len(techniques) > 0, "未能生成 ATT&CK 技术节点")
        self.assertEqual(techniques[0]['technique']['id'], "T1059")
        
        print("   ✅ AttackAnalyzer 全管线集成测试通过")

if __name__ == '__main__':
    unittest.main()
