import sys
import os
import binascii

# 环境准备
sys.path.append(os.getcwd())
from collector.common.es_client import ESClient
from analyzer.attack_analyzer.context_engine import ContextEngine
from analyzer.graph_analyzer.provenance_system import ProvenanceSystem

def decode_hex(data):
    try:
        clean = str(data).replace(" ", "")
        if all(c in '0123456789ABCDEFabcdef' for c in clean) and len(clean) > 10:
            return binascii.unhexlify(clean).decode('utf-8', errors='ignore')
    except: pass
    return data

print("🚀 TraceX 终极全链路溯源验证...")
es = ESClient()
context = ContextEngine(es)
prov = ProvenanceSystem(context)

# 1. 定位攻击种子
resp = es.es.search(index="unified-logs*", body={"query": {"match_all": {}}, "size": 500, "sort": [{"@timestamp": "desc"}]})
hits = resp.get('hits', {}).get('hits', [])
seed = None
for hit in hits:
    cmd = hit['_source'].get('process', {}).get('command_line', "")
    if "wget" in str(cmd) or "chmod" in str(cmd) or "62617368" in str(cmd):
        seed = hit['_source']
        print(f"✅ 找到种子事件: {decode_hex(cmd)[:80]}...")
        break

if not seed:
    print("❌ 未找到攻击日志，请确认是否执行了攻击命令并开启了 Agent")
    exit()

# 2. 执行溯源
print("🕸️  正在构建攻击溯源图谱...")
result = prov.rebuild_attack_path(seed)

# 3. 展示结果
print("\n" + "="*60)
print(f"🛡️  攻击路径签名: {result.get('path_signature')}")
attr = result.get('intelligence', {}).get('attribution', {})
print(f"🕵️  疑似 APT 组织: {attr.get('suspected_group', 'Unclassified')}")
print("="*60)

print("\n📊 溯源链条详情 (节点数: {}):".format(len(result.get('nodes', []))))
# 按时间或逻辑顺序排列节点 (这里简单打印所有进程节点)
for node in result.get('nodes', []):
    label = node.get('label', 'Unknown')
    atlas = node.get('atlas_label', '')
    cmd = node.get('properties', {}).get('command_line', 'N/A')
    
    # 打印格式优化
    prefix = "🔥" if atlas != "PARENT_PROCESS" else "👤"
    print(f"{prefix} [{atlas}] {label}")
    if cmd != 'N/A':
        print(f"   ┗━ 完整指令: {decode_hex(cmd)}")

print("\n🔗 关联边 (Edges): {}".format(len(result.get('edges', []))))
for edge in result.get('edges', []):
    print(f"   {edge.get('relation')} -> {edge.get('target')[:8]}...")

