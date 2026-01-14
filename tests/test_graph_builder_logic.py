# tests/test_graph_builder_logic.py
import unittest
import sys
import os
import shutil

# 确保能导入项目根目录下的模块
sys.path.append(os.getcwd())

from analyzer.graph_analyzer.graph_builder import GraphBuilder
from analyzer.graph_analyzer.pid_cache import PIDCache

class TestGraphBuilderLogic(unittest.TestCase):
    def setUp(self):
        # 使用独立的测试缓存文件，避免干扰生产环境或上次测试的残留
        self.test_cache_file = "test_pid_context_verify.json"
        
        # 确保环境干净
        if os.path.exists(self.test_cache_file):
            os.remove(self.test_cache_file)
            
        self.pid_cache = PIDCache(cache_file=self.test_cache_file)
        self.builder = GraphBuilder(pid_cache=self.pid_cache)
        print(f"\n[{self._testMethodName}] 测试开始...")

    def tearDown(self):
        # 清理测试产生的临时文件
        self.pid_cache.clear()
        if os.path.exists(self.test_cache_file):
            try:
                os.remove(self.test_cache_file)
            except OSError:
                pass

    def test_pid_reuse_handling(self):
        """核心测试：PID 复用处理 - 验证同一PID不同时间的进程ID是否唯一"""
        host = "production-server"
        pid = 8888
        
        # 场景 1: 上午 09:00 的进程 (PID 8888 是 Nginx)
        event_early = {
            "event": {"category": "process", "id": "evt_early"},
            "host": {"name": host},
            "process": {
                "pid": pid,
                "executable": "/usr/sbin/nginx",
                "start_time": "2026-01-14T09:00:00Z" # 关键字段：启动时间
            },
            "timestamp": "2026-01-14T09:05:00Z"
        }
        
        # 场景 2: 下午 15:00 的进程 (PID 8888 被复用，变成了 Mining 病毒)
        event_late = {
            "event": {"category": "process", "id": "evt_late"},
            "host": {"name": host},
            "process": {
                "pid": pid,
                "executable": "/tmp/xmrig", # 不同的程序
                "start_time": "2026-01-14T15:00:00Z" # 不同的启动时间
            },
            "timestamp": "2026-01-14T15:05:00Z"
        }

        # 1. 生成第一个进程的 Node ID
        id_early = self.builder.generate_node_id(event_early)
        print(f"   [上午进程] Nginx (PID {pid}) Node ID: {id_early}")
        
        # 模拟 PID 缓存落盘（GraphBuilder 在处理完一批数据后会 flush）
        self.builder.pid_cache.flush()
        
        # 2. 生成第二个进程的 Node ID
        id_late = self.builder.generate_node_id(event_late)
        print(f"   [下午进程] Mining (PID {pid}) Node ID: {id_late}")

        # 断言：虽然 PID 和 Host 相同，但由于 start_time 不同，生成的 Node ID 必须不同
        self.assertNotEqual(id_early, id_late, "严重错误：PID 复用未能生成唯一的节点 ID，会导致溯源图谱混乱！")
        print("   ✅ PID 复用区分验证通过")

    def test_child_process_linkage(self):
        """测试：父子进程关联逻辑 (spawned 边)"""
        # 1. 父进程 Bash 启动
        parent_event = {
            "event": {"category": "process", "id": "evt_p"},
            "host": {"name": "server1"},
            "process": {
                "pid": 2000,
                "executable": "/bin/bash",
                "name": "bash",
                "start_time": "2026-01-14T10:00:00Z"
            },
            "timestamp": "2026-01-14T10:00:01Z"
        }
        
        # 2. 子进程 Curl 启动 (PPID 指向 2000)
        child_event = {
            "event": {"category": "process", "id": "evt_c"},
            "host": {"name": "server1"},
            "process": {
                "pid": 2001,
                "executable": "/usr/bin/curl",
                "name": "curl",
                "start_time": "2026-01-14T10:05:00Z",
                "parent": {
                    "pid": 2000, # 指向父进程
                    "executable": "/bin/bash",
                    "name": "bash"
                }
            },
            "timestamp": "2026-01-14T10:05:01Z"
        }

        # 构建图
        print("   正在构建图谱...")
        result = self.builder.build_from_events([parent_event, child_event])
        
        nodes = result['nodes']
        edges = result['edges']

        print(f"   生成节点数: {len(nodes)} (预期: 2)")
        print(f"   生成边数: {len(edges)} (预期: 1)")

        # 验证节点数量
        self.assertEqual(len(nodes), 2, "节点数量不正确")
        
        # 验证是否包含 'spawned' 类型的边
        spawned_edge = next((e for e in edges if e['relation'] == 'spawned'), None)
        self.assertIsNotNone(spawned_edge, "未找到 'spawned' 边")
        
        # 验证边的方向：source 应该是父进程，target 是子进程
        # 注意：这里我们无法直接断言 ID，因为 ID 是哈希值
        # 但我们可以确认 source 对应的是父进程的节点 ID
        parent_node_id = self.builder.generate_node_id(parent_event)
        self.assertEqual(spawned_edge['source'], parent_node_id, "边的源节点不是父进程")
        
        print(f"   ✅ 找到关系边: {spawned_edge['source']} -> spawned -> {spawned_edge['target']}")

    def test_file_operation_distinctness(self):
        """测试：同一文件的不同操作应生成不同节点 (v5.1 修复验证)"""
        # 场景：先写木马，再删木马。如果在图中合并为一个节点，就无法展示攻击的时间线。
        
        # 事件1：写入文件
        evt_write = {
            "event": {"category": "file", "action": "write", "id": "f_write"},
            "host": {"name": "h1"},
            "file": {"path": "/tmp/backdoor.php"},
            "timestamp": "2026-01-14T12:00:00Z"
        }
        # 事件2：删除同一文件
        evt_delete = {
            "event": {"category": "file", "action": "delete", "id": "f_delete"},
            "host": {"name": "h1"},
            "file": {"path": "/tmp/backdoor.php"},
            "timestamp": "2026-01-14T12:05:00Z"
        }

        id_write = self.builder.generate_node_id(evt_write)
        id_delete = self.builder.generate_node_id(evt_delete)
        
        print(f"   Write ID: {id_write}")
        print(f"   Delete ID: {id_delete}")
        
        self.assertNotEqual(id_write, id_delete, "错误：不同操作(Write/Delete)生成了相同的ID，时序信息丢失！")
        print("   ✅ 文件操作唯一性验证通过")

if __name__ == '__main__':
    unittest.main()
