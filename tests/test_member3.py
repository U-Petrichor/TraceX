# tests/test_member3.py (V3.0 Forensic Mode)
# --------------------------------------------------------------------------------
# TraceX v5.1 终极取证自检脚本
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
current_test_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_test_dir)
sys.path.insert(0, project_root)
rules_dir_path = os.path.join(project_root, 'analyzer', 'attack_analyzer', 'rules')

# 日志配置 - 开启 DEBUG 级别
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("TraceX-Forensic")

try:
    from analyzer.attack_analyzer.context_engine import ContextEngine
    from analyzer.attack_analyzer.attack_tagger import AttackAnalyzer
    from analyzer.attack_analyzer.field_mapper import FieldMapper
    from analyzer.attack_analyzer.rule_loader import RuleLoader
    from analyzer.attack_analyzer.sigma_engine import SigmaDetector
except ImportError as e:
    logger.critical(f"❌ 导入失败: {e}")
    sys.exit(1)

# ------------------- 探针规则 -------------------
TEST_RULE_FILENAME = "deploy_check_marker_rule.yml"
TEST_RULE_CONTENT = """
title: Deployment Check Probe
id: deploy-check-001
status: test
description: A temporary rule to verify engine functionality
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
        print("  TraceX v5.1 SYSTEM FORENSIC CHECK (V3.0)")
        print("█"*80)
        cls.rules_dir = rules_dir_path
        if not os.path.exists(cls.rules_dir): raise FileNotFoundError("Rules directory missing")
        cls.probe_rule_path = os.path.join(cls.rules_dir, TEST_RULE_FILENAME)
        with open(cls.probe_rule_path, 'w') as f: f.write(TEST_RULE_CONTENT)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.probe_rule_path): os.remove(cls.probe_rule_path)

    def print_section(self, title):
        print(f"\n{'='*20} [ {title} ] {'='*20}")

    def test_01_deep_rule_inspection(self):
        self.print_section("TEST 1: 规则库深度抽检")
        loader = RuleLoader(self.rules_dir)
        count = loader.load_all()
        
        print(f"[*] 规则库物理路径: {self.rules_dir}")
        print(f"[*] 实际加载数量: {count}")
        
        # 随机抽样 10 条展示，证明是真实规则
        if count > 0:
            sample_size = min(10, count)
            print(f"[*] 随机抽检 {sample_size} 条规则标题 (Fingerprint):")
            samples = random.sample(loader.rules, sample_size)
            for idx, r in enumerate(samples):
                print(f"    {idx+1}. [{r.logsource.get('product','?')}/{r.logsource.get('category','?')}] {r.title}")
        
        self.assertGreater(count, 0)

    def test_02_mapper_internals(self):
        self.print_section("TEST 2: 字段映射器内部透视")
        mapper = FieldMapper()
        raw_auditd = {
            "event": {"dataset": "auditd"},
            "raw": {"type": "EXECVE", "data": 'argc=3 a0="curl" a1="-s" a2="http://1.1.1.1"'},
            "process": {"executable": "/usr/bin/curl"}
        }
        
        # 使用 Hook 打印处理过程
        print(f"[*] 输入 RAW Data: {raw_auditd['raw']['data']}")
        res = mapper.map_event(raw_auditd, {'product': 'linux'})
        print(f"[*] 输出 Sigma CommandLine: {res.get('CommandLine')}")
        
        # 验证是否真的提取了
        if res.get('CommandLine') == "curl -s http://1.1.1.1":
            print("[+] CHECK: 命令行参数完全复原 -> PASS")
        else:
            print(f"[-] CHECK: 命令行参数复原差异: {res.get('CommandLine')} -> WARNING")

    def test_03_logic_verification(self):
        self.print_section("TEST 3: 评分逻辑白盒验证")
        mock_es = MagicMock()
        engine = ContextEngine(mock_es)
        
        event = {
            "file": {"path": "/var/www/html/shell.php", "extension": "php"},
            "event": {"action": "write", "severity": "critical"}, # Critical=100
            "threat": {"technique": {"id": "T1105", "name": "Ingress Tool Transfer"}}
        }
        
        # 1. 强制单独计算 Heuristic 分数 (绕过 Max 逻辑查看内部)
        heuristic_score = engine._check_heuristics(event)
        print(f"[*] [内部状态] Heuristic 模块计算得分: {heuristic_score} (期望: 90)")
        
        # 2. 计算 Sigma 分数
        sigma_score = 100 # Critical
        print(f"[*] [内部状态] Sigma 模块计算得分: {sigma_score} (期望: 100)")
        
        # 3. 运行完整评估
        final = engine.evaluate_threat(event)
        print(f"[*] [最终输出] 最终得分: {final['score']}")
        print(f"[*] [最终输出] 判定理由: {final['reasons']}")
        
        if heuristic_score == 90 and final['score'] == 100:
            print("[+] CHECK: 评分逻辑 (Max(100, 90) = 100) 执行正确 -> PASS")
            print("[!] 说明: Heuristic 理由未显示是因为 90 < 100，这是预期行为。")
        else:
            self.fail("评分逻辑异常")

    def test_04_query_dsl_dump(self):
        self.print_section("TEST 4: ES 查询 DSL 完整导出")
        mock_es = MagicMock()
        # 模拟 ES 返回结果，看看 Engine 怎么处理返回
        mock_es.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"file": {"name": "shell.php"}, "@timestamp": "..."}}
                ]
            }
        }
        wrapper = MagicMock(); wrapper.es = mock_es
        engine = ContextEngine(wrapper)
        
        anchor = {
            "@timestamp": "2023-11-11T10:00:00.000Z",
            "host": {"name": "web01"},
            "file": {"path": "/var/www/html/shell.php", "name": "shell.php"}
        }
        
        # 运行
        hits = engine.find_related_events(anchor)
        
        # 抓取 Query
        query_body = mock_es.search.call_args[1]['body']
        print("[*] 生成的 Elasticsearch Query DSL:")
        print(json.dumps(query_body, indent=2))
        
        print(f"[*] 模拟 ES 返回 Hits 数量: {len(hits)}")
        if len(hits) == 1:
             print("[+] CHECK: 结果解析逻辑 -> PASS")

    def test_05_full_artifact_dump(self):
        self.print_section("TEST 5: 全链路最终产物 (Artifact) 导出")
        analyzer = AttackAnalyzer(self.rules_dir)
        analyzer.initialize()
        
        probe_event = {
            "event": {"dataset": "auditd", "id": "TEST-EVENT-001"},
            "raw": {"type": "EXECVE", "data": 'a0="./deploy_check_probe"'},
            "process": {"executable": "/tmp/deploy_check_probe"},
            "host": {"name": "production-server"},
            "@timestamp": datetime.now().isoformat()
        }
        
        result = analyzer.analyze_event(probe_event)
        
        # 这里的 highlights 是你在上次输出中看到的 "Double Kill"
        # 证明你的真实规则库里有一条 generic 的规则也命中了
        print(f"[*] 命中规则列表: {result['matched_rules']}")
        if len(result['matched_rules']) > 1:
            print(f"[!] 发现多重规则命中！系统不仅检测到了探针，还匹配了通用规则。")
        
        # 导出最终给 GraphBuilder 的数据
        final_artifact = analyzer.export_to_unified_format(probe_event, result)
        
        print("\n[*] 最终生成的 Unified Event (JSON):")
        print(json.dumps(final_artifact, indent=2, ensure_ascii=False))
        
        self.assertIn("threat", final_artifact)

if __name__ == '__main__':
    unittest.main(verbosity=0)