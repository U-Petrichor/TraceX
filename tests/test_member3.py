# test/test_member3.py (V3.0 Forensic Mode)
# --------------------------------------------------------------------------------
# TraceX v5.2 终极取证自检脚本
# --------------------------------------------------------------------------------

import unittest
import os
import sys
import logging
import json
import random
from collections import Counter
from datetime import datetime
from unittest.mock import MagicMock, patch

# ------------------- 路径配置 -------------------
# 1. 获取当前脚本目录 (test/)
current_test_dir = os.path.dirname(os.path.abspath(__file__))

# 2. 获取项目根目录 (TraceX/)
project_root = os.path.dirname(current_test_dir)

# 3. 将项目根目录加入 sys.path，支持 "from analyzer.attack_analyzer import ..."
sys.path.insert(0, project_root)

# 4. 指向真实的规则目录 (analyzer/attack_analyzer/rules)
rules_dir_path = os.path.join(project_root, 'analyzer', 'attack_analyzer', 'rules')

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("TraceX-Forensic")

try:
    from analyzer.attack_analyzer.context_engine import ContextEngine
    from analyzer.attack_analyzer.attack_tagger import AttackAnalyzer
    from analyzer.attack_analyzer.field_mapper import FieldMapper
    from analyzer.attack_analyzer.rule_loader import RuleLoader
except ImportError as e:
    logger.critical(f"❌ 导入失败: {e}\n当前路径: {sys.path}")
    sys.exit(1)

# ------------------- 探针规则 -------------------
TEST_RULE_FILENAME = "deploy_check_marker_rule.yml"
TEST_RULE_CONTENT = """
title: Deployment Check Probe
id: deploy-check-001
status: test
description: Probe rule
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/deploy_check_probe'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059
"""

class TraceXForensicTests(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        print("\n" + "█"*80)
        print("  TraceX v5.2 SYSTEM FORENSIC CHECK (V3.0)")
        print("█"*80)
        print(f"[*] 项目根目录: {project_root}")
        
        cls.rules_dir = rules_dir_path
        if not os.path.exists(cls.rules_dir):
             os.makedirs(cls.rules_dir, exist_ok=True)
        
        cls.probe_rule_path = os.path.join(cls.rules_dir, TEST_RULE_FILENAME)
        with open(cls.probe_rule_path, 'w') as f: f.write(TEST_RULE_CONTENT)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.probe_rule_path): os.remove(cls.probe_rule_path)

    def print_section(self, title):
        print(f"\n{'='*20} [ {title} ] {'='*20}")

    def test_03_logic_verification(self):
        self.print_section("TEST 3: 评分逻辑白盒验证 (v5.2)")
        mock_es = MagicMock()
        engine = ContextEngine(mock_es)
        
        # 构造一个符合 v5.2 逻辑的事件
        event = {
            "file": {"path": "/var/www/html/shell.php", "extension": "php"},
            "event": {"action": "write", "dataset": "linux_auditd"},
            "detection": {
                "confidence": 0.8,   # 基础分 80
                "rules": ["Generic Rule"]
            },
            "threat": {"technique": {"id": "T1105"}}
        }
        
        # 1. 强制单独计算 Heuristic 分数
        heuristic_score = engine._check_heuristics(event)
        print(f"[*] [内部状态] Heuristic 模块计算得分: {heuristic_score} (期望: 90 [WebShell规则])")
        
        # 2. 模拟计算 Sigma 分数
        sigma_score = event['detection']['confidence'] * 100
        print(f"[*] [内部状态] Sigma 模块计算得分: {sigma_score} (期望: 80.0)")
        
        # 3. 运行完整评估
        final = engine.evaluate_threat(event)
        print(f"[*] [最终输出] 最终得分: {final['score']}")
        print(f"[*] [最终输出] 判定理由: {final['reasons']}")
        
        # 期望：Max(80, 90) = 90
        if heuristic_score == 90 and final['score'] == 90:
            print("[+] CHECK: 评分逻辑 (Max(80, 90) = 90) 执行正确 -> PASS")
            if "Heuristic Suspicious Behavior" in str(final['reasons']):
                print("[+] CHECK: 理由包含启发式标签 -> PASS")
        else:
            self.fail(f"评分逻辑异常: 期望90, 实际{final['score']}")

    def test_04_query_dsl_dump(self):
        self.print_section("TEST 4: ES 查询 DSL 完整导出 (Multi-Index)")
        mock_es = MagicMock()
        mock_es.search.return_value = {"hits": {"hits": []}}
        wrapper = MagicMock(); wrapper.es = mock_es
        engine = ContextEngine(wrapper)
        
        anchor = {
            "@timestamp": "2023-11-11T10:00:00.000Z",
            "host": {"name": "web01"}, # 必填
            "file": {"path": "/var/www/html/shell.php", "name": "shell.php"}
        }
        
        engine.find_related_events(anchor)
        
        # 抓取参数
        call_args = mock_es.search.call_args
        target_indices = call_args[1]['index']
        query_body = call_args[1]['body']
        
        print(f"[*] 目标索引模式: {target_indices}")
        print("[*] 生成的 Elasticsearch Query DSL:")
        print(json.dumps(query_body, indent=2))
        
        if "network-flows*" in target_indices and "honeypot-logs*" in target_indices:
             print("[+] CHECK: 索引范围正确 (包含 network/honeypot) -> PASS")
        else:
             print("[-] CHECK: 索引范围可能遗漏 -> WARNING")

    def test_05_upstream_artifact_dump(self):
        self.print_section("TEST 5: 上游威胁全链路产物导出")
        analyzer = AttackAnalyzer(self.rules_dir)
        analyzer.initialize()
        
        # 模拟组员2的高危告警
        upstream_event = {
            "event": {"dataset": "cowrie", "severity": 8, "id": "TEST-COWRIE-001"},
            "threat": {
                "technique": {"id": "T1071", "name": "Application Layer Protocol"}
            },
            "@timestamp": datetime.now().isoformat(),
            "message": "CMD: curl http://evil.com"
        }
        
        result = analyzer.analyze_event(upstream_event)
        
        print(f"[*] 检测状态: {result['detected']}")
        print(f"[*] 匹配规则: {result['matched_rules']}")
        print(f"[*] 提取技术: {json.dumps(result['techniques'], indent=2)}")
        
        # 验证虚拟规则生成
        if any("Upstream Detection" in r for r in result['matched_rules']):
            print("[+] CHECK: 虚拟规则生成成功 -> PASS")
        else:
            print("[-] CHECK: 未生成虚拟规则 -> FAIL")

if __name__ == '__main__':
    unittest.main(verbosity=0)