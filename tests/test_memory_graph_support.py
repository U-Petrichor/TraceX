# tests/test_memory_graph_support.py
"""
内存异常事件图构建支持测试 (v5.2)

测试内容：
1. AtlasMapper 能正确为内存事件生成语义标签
2. GraphBuilder 能为内存事件生成正确的节点ID
3. GraphBuilder 能正确构建内存异常节点和进程节点之间的关系边
4. 完整的溯源场景测试
"""
import unittest
import sys
import os

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.graph_analyzer.graph_builder import GraphBuilder
from analyzer.graph_analyzer.atlas_mapper import AtlasMapper


class TestMemoryGraphSupport(unittest.TestCase):
    """内存异常事件图构建支持测试"""
    
    def setUp(self):
        """测试前准备"""
        self.mapper = AtlasMapper()
        self.builder = GraphBuilder()
        
        # 模拟内存异常事件 - MEMFD_EXEC (无文件攻击)
        self.memory_event_memfd = {
            'timestamp': '2026-01-14T10:30:00.000Z',
            'event': {
                'id': 'mem-001',
                'category': 'memory',
                'action': 'anomaly_detected',
                'severity': 10
            },
            'host': {'name': 'victim-host'},
            'process': {
                'pid': 1234,
                'name': 'evil_binary',
                'executable': '/tmp/evil_binary'
            },
            'memory': {
                'anomalies': [
                    {
                        'type': 'MEMFD_EXEC',
                        'risk_level': 'CRITICAL',
                        'address': '7f1234560000',
                        'perms': 'rwxp',
                        'is_elf': True,
                        'details': 'Fileless execution detected'
                    }
                ]
            }
        }
        
        # 模拟内存异常事件 - RWX_REGION (代码注入)
        self.memory_event_rwx = {
            'timestamp': '2026-01-14T10:31:00.000Z',
            'event': {
                'id': 'mem-002',
                'category': 'memory',
                'action': 'anomaly_detected',
                'severity': 8
            },
            'host': {'name': 'victim-host'},
            'process': {
                'pid': 5678,
                'name': 'suspicious_proc',
                'executable': '/usr/bin/python3'
            },
            'memory': {
                'anomalies': [
                    {
                        'type': 'RWX_REGION',
                        'risk_level': 'HIGH',
                        'address': '7f9876540000',
                        'perms': 'rwxp',
                        'is_elf': False,
                        'details': 'Suspicious RWX memory region'
                    }
                ]
            }
        }
        
        # 模拟进程事件（与内存异常关联）
        self.process_event = {
            'timestamp': '2026-01-14T10:29:55.000Z',
            'event': {
                'id': 'proc-001',
                'category': 'process',
                'action': 'process_started'
            },
            'host': {'name': 'victim-host'},
            'process': {
                'pid': 1234,
                'name': 'evil_binary',
                'executable': '/tmp/evil_binary',
                'command_line': '/tmp/evil_binary --stealth',
                'parent': {
                    'pid': 1000,
                    'name': 'bash',
                    'executable': '/bin/bash'
                }
            }
        }
    
    def test_atlas_mapper_memfd_exec(self):
        """测试 AtlasMapper 对 MEMFD_EXEC 类型的标签映射"""
        label = self.mapper.get_label(self.memory_event_memfd)
        self.assertEqual(label, 'FILELESS_ATTACK', 
                        f'MEMFD_EXEC 应映射为 FILELESS_ATTACK，实际: {label}')
        print(f'✓ MEMFD_EXEC 标签: {label}')
    
    def test_atlas_mapper_rwx_region(self):
        """测试 AtlasMapper 对 RWX_REGION 类型的标签映射"""
        label = self.mapper.get_label(self.memory_event_rwx)
        self.assertEqual(label, 'CODE_INJECTION',
                        f'RWX_REGION 应映射为 CODE_INJECTION，实际: {label}')
        print(f'✓ RWX_REGION 标签: {label}')
    
    def test_atlas_mapper_unknown_type(self):
        """测试 AtlasMapper 对未知类型的处理"""
        unknown_event = {
            'event': {'category': 'memory'},
            'memory': {
                'anomalies': [{'type': 'UNKNOWN_TYPE', 'risk_level': 'MEDIUM'}]
            }
        }
        label = self.mapper.get_label(unknown_event)
        self.assertEqual(label, 'MEMORY_ANOMALY',
                        f'未知类型应映射为 MEMORY_ANOMALY，实际: {label}')
        print(f'✓ 未知类型标签: {label}')
    
    def test_atlas_mapper_critical_risk(self):
        """测试 AtlasMapper 对高风险但未知类型的处理"""
        critical_event = {
            'event': {'category': 'memory'},
            'memory': {
                'anomalies': [{'type': 'NEW_ATTACK_TYPE', 'risk_level': 'CRITICAL'}]
            }
        }
        label = self.mapper.get_label(critical_event)
        self.assertEqual(label, 'CRITICAL_MEMORY_ANOMALY',
                        f'CRITICAL 风险应映射为 CRITICAL_MEMORY_ANOMALY，实际: {label}')
        print(f'✓ CRITICAL 风险标签: {label}')
    
    def test_graph_builder_node_id_generation(self):
        """测试 GraphBuilder 内存事件节点ID生成"""
        node_id = self.builder.generate_node_id(self.memory_event_memfd)
        self.assertIsNotNone(node_id)
        self.assertTrue(len(node_id) == 32, 'MD5 哈希应为32位')
        print(f'✓ 节点ID: {node_id}')
    
    def test_graph_builder_memory_node_creation(self):
        """测试 GraphBuilder 内存异常节点创建"""
        graph = self.builder.build_from_events([self.memory_event_memfd])
        
        memory_nodes = [n for n in graph['nodes'] if n['type'] == 'memory_anomaly']
        self.assertGreaterEqual(len(memory_nodes), 1, '应创建至少1个内存异常节点')
        
        # 验证节点属性
        mem_node = memory_nodes[0]
        self.assertEqual(mem_node['atlas_label'], 'FILELESS_ATTACK')
        self.assertEqual(mem_node['properties']['pid'], 1234)
        self.assertIn('MEMFD_EXEC', mem_node['properties']['anomaly_types'])
        print(f'✓ 内存节点: {mem_node["label"]}')
        print(f'  属性: {mem_node["properties"]}')
    
    def test_graph_builder_process_node_creation(self):
        """测试 GraphBuilder 关联进程节点创建"""
        graph = self.builder.build_from_events([self.memory_event_memfd])
        
        process_nodes = [n for n in graph['nodes'] if n['type'] == 'process']
        self.assertGreaterEqual(len(process_nodes), 1, '应创建至少1个进程节点')
        
        # 验证进程节点
        proc_node = process_nodes[0]
        self.assertEqual(proc_node['properties']['pid'], 1234)
        print(f'✓ 进程节点: {proc_node["label"]}')
    
    def test_graph_builder_edge_creation(self):
        """测试 GraphBuilder 边关系创建"""
        self.builder.reset()
        graph = self.builder.build_from_events([self.memory_event_memfd])
        
        triggered_edges = [e for e in graph['edges'] if e['relation'] == 'triggered_anomaly']
        self.assertGreaterEqual(len(triggered_edges), 1, '应创建至少1条 triggered_anomaly 边')
        
        # 验证边属性
        edge = triggered_edges[0]
        self.assertEqual(edge['properties']['anomaly_type'], 'MEMFD_EXEC')
        self.assertEqual(edge['properties']['risk_level'], 'CRITICAL')
        print(f'✓ 边关系: {edge["relation"]}')
        print(f'  属性: {edge["properties"]}')
    
    def test_full_attack_chain_with_memory(self):
        """测试完整攻击链（包含内存异常）"""
        self.builder.reset()
        
        # 构建包含进程和内存异常的图
        events = [self.process_event, self.memory_event_memfd]
        graph = self.builder.build_from_events(events)
        
        print(f'\n=== 完整攻击链图谱 ===')
        print(f'节点数: {len(graph["nodes"])}')
        print(f'边数: {len(graph["edges"])}')
        
        # 验证节点类型
        node_types = {n['type'] for n in graph['nodes']}
        self.assertIn('process', node_types)
        self.assertIn('memory_anomaly', node_types)
        print(f'节点类型: {node_types}')
        
        # 验证边关系类型
        edge_relations = {e['relation'] for e in graph['edges']}
        self.assertIn('triggered_anomaly', edge_relations)
        print(f'边关系类型: {edge_relations}')
        
        # 打印详细图结构
        print('\n--- 节点列表 ---')
        for node in graph['nodes']:
            print(f'  [{node["type"]}] {node["label"]} (ATLAS: {node["atlas_label"]})')
        
        print('\n--- 边列表 ---')
        for edge in graph['edges']:
            print(f'  {edge["source"][:8]}... --[{edge["relation"]}]--> {edge["target"][:8]}...')
    
    def test_multiple_memory_anomalies(self):
        """测试多个内存异常事件"""
        self.builder.reset()
        
        events = [self.memory_event_memfd, self.memory_event_rwx]
        graph = self.builder.build_from_events(events)
        
        memory_nodes = [n for n in graph['nodes'] if n['type'] == 'memory_anomaly']
        self.assertEqual(len(memory_nodes), 2, '应创建2个内存异常节点')
        
        # 验证两个节点有不同的标签
        labels = {n['atlas_label'] for n in memory_nodes}
        self.assertIn('FILELESS_ATTACK', labels)
        self.assertIn('CODE_INJECTION', labels)
        print(f'✓ 多内存异常测试通过，标签: {labels}')
    
    def test_memory_event_without_pid(self):
        """测试无 PID 的内存事件处理"""
        self.builder.reset()
        
        event_no_pid = {
            'timestamp': '2026-01-14T10:30:00.000Z',
            'event': {
                'id': 'mem-no-pid',
                'category': 'memory',
                'action': 'anomaly_detected'
            },
            'host': {'name': 'test-host'},
            'memory': {
                'anomalies': [{'type': 'SUSPICIOUS_MEMORY', 'risk_level': 'LOW'}]
            }
        }
        
        graph = self.builder.build_from_events([event_no_pid])
        
        # 应该只有内存节点，没有进程节点（因为没有 PID）
        memory_nodes = [n for n in graph['nodes'] if n['type'] == 'memory_anomaly']
        process_nodes = [n for n in graph['nodes'] if n['type'] == 'process']
        
        self.assertEqual(len(memory_nodes), 1, '应创建1个内存异常节点')
        self.assertEqual(len(process_nodes), 0, '无 PID 时不应创建进程节点')
        self.assertEqual(len(graph['edges']), 0, '无 PID 时不应创建边')
        print('✓ 无 PID 内存事件处理正确')


class TestMemoryGraphIntegration(unittest.TestCase):
    """内存事件与其他事件类型的集成测试"""
    
    def setUp(self):
        self.builder = GraphBuilder()
    
    def test_memory_with_network_events(self):
        """测试内存事件与网络事件的组合"""
        self.builder.reset()
        
        network_event = {
            'timestamp': '2026-01-14T10:32:00.000Z',
            'event': {
                'id': 'net-001',
                'category': 'network'
            },
            'host': {'name': 'victim-host'},
            'source': {'ip': '192.168.1.100', 'port': 54321},
            'destination': {'ip': '10.0.0.1', 'port': 443},
            'network': {'protocol': 'https'}
        }
        
        memory_event = {
            'timestamp': '2026-01-14T10:30:00.000Z',
            'event': {
                'id': 'mem-003',
                'category': 'memory'
            },
            'host': {'name': 'victim-host'},
            'process': {'pid': 9999, 'executable': '/usr/bin/curl'},
            'memory': {
                'anomalies': [{'type': 'RWX_REGION', 'risk_level': 'HIGH'}]
            }
        }
        
        graph = self.builder.build_from_events([network_event, memory_event])
        
        node_types = {n['type'] for n in graph['nodes']}
        self.assertIn('network', node_types)
        self.assertIn('memory_anomaly', node_types)
        print(f'✓ 内存+网络事件组合测试通过，节点类型: {node_types}')


def run_tests():
    """运行所有测试"""
    print('=' * 60)
    print('内存异常事件图构建支持测试 (v5.2)')
    print('=' * 60)
    
    # 创建测试套件
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # 添加测试类
    suite.addTests(loader.loadTestsFromTestCase(TestMemoryGraphSupport))
    suite.addTests(loader.loadTestsFromTestCase(TestMemoryGraphIntegration))
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # 打印摘要
    print('\n' + '=' * 60)
    if result.wasSuccessful():
        print('✅ 所有测试通过！内存异常事件现在可以正确参与图构建和溯源。')
    else:
        print(f'❌ 测试失败: {len(result.failures)} 个失败, {len(result.errors)} 个错误')
    print('=' * 60)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
