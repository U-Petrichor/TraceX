# verify_final.py
import sys
import os
import binascii
from datetime import datetime, timedelta

# 环境准备
sys.path.append(os.getcwd())
from collector.common.es_client import ESClient
from analyzer.attack_analyzer.context_engine import ContextEngine
from analyzer.graph_analyzer.provenance_system import ProvenanceSystem

def decode_hex(data):
    """还原 Auditd 的 Hex 编码指令"""
    try:
        clean = str(data).replace(" ", "")
        if all(c in '0123456789ABCDEFabcdef' for c in clean) and len(clean) > 10:
            return binascii.unhexlify(clean).decode('utf-8', errors='ignore')
    except: pass
    return data

print("🚀 TraceX v6.1 深度溯源全链路验证引擎启动...")
es = ESClient()
context = ContextEngine(es)
prov = ProvenanceSystem(context)

# 1. 使用 ContextEngine 自动定位高危种子
print("🔍 正在扫描过去 24 小时内的高危攻击起点...")
now = datetime.utcnow()
start_time = (now - timedelta(days=1)).isoformat() + "Z"
end_time = now.isoformat() + "Z"

# 调用优化后的 get_seed_events 逻辑
seeds = context.get_seed_events((start_time, end_time), min_score=70)

if not seeds:
    print("❌ 未发现置信度 > 70 的攻击种子。请确认 Agent 运行正常且已执行模拟攻击指令。")
    sys.exit(1)

# 选择评分最高的作为溯源起点
seed = sorted(seeds, key=lambda x: x.get('threat', {}).get('confidence', 0), reverse=True)[0]
seed_cmd = decode_hex(seed.get('process', {}).get('command_line', 'N/A'))
print(f"✅ 捕获高危种子: {seed.get('process', {}).get('name')} (Score: {seed.get('threat', {}).get('confidence', 0)*100:.0f})")
print(f"   ┗━ 原始指令: {seed_cmd[:100]}...")

# 2. 执行深度溯源图构建
print("\n🕸️  正在应用 v6.1 算法重建攻击路径 (因果回溯 + 空间模糊关联)...")
result = prov.rebuild_attack_path(seed)

# 3. 展示归因与指纹信息
print("\n" + "═"*65)
intelligence = result.get('intelligence', {})
attr = intelligence.get('attribution', {})
print(f"🕵️  疑似 APT 组织: {attr.get('suspected_group', 'Unclassified')}")
print(f"📈 归因置信度: {attr.get('confidence', 0)*100:.1f}% (算法: 0.7*Recall + 0.3*Jaccard)")
print(f"🧬 攻击链签名: {intelligence.get('chain_hash', 'N/A')[:16]}")
print("" + "═"*65)

# 4. 详细节点链条展示
print("\n📊 溯源路径详情 (共 {} 个节点):".format(len(result.get('nodes', []))))
for node in result.get('nodes', []):
    node_type = node.get('type')
    label = node.get('label', 'Unknown')
    atlas = node.get('atlas_label', 'N/A')
    props = node.get('properties', {})
    
    # 区分展示进程和异常
    if node_type == 'memory_anomaly':
        print(f"🚨 [MEMORY_ANOMALY] {label}")
        print(f"   ┗━ 异常详情: {props.get('details')}")
    else:
        # 获取 TTP 和风险分 (需确保 AtlasMapper 已升级四元组)
        prefix = "🔥" if atlas != "PARENT_PROCESS" else "👤"
        ttp_str = f" [TTP: {node.get('ttp', 'N/A')}]" if node.get('ttp') else ""
        print(f"{prefix} [{atlas}]{ttp_str} {label}")
        
        cmd = props.get('command_line') or props.get('cmd')
        if cmd and cmd != 'N/A':
            print(f"   ┗━ 指令内容: {decode_hex(cmd)}")

# 5. 展示外部基础设施富化结果
external_ti = intelligence.get('external_infrastructure', {})
if external_ti:
    print("\n🌐 发现关联恶意基础设施 (TI Enrichment):")
    for ioc, info in external_ti.items():
        print(f"   🚩 {ioc} -> Risk: {info.get('risk_score')} | Tags: {info.get('tags')}")

# 6. 展示关联边关系
print("\n🔗 关联逻辑 (Edges: {}):".format(len(result.get('edges', []))))
for edge in result.get('edges', []):
    # 突出展示 v6.1 新增的异常边
    rel = edge.get('relation')
    icon = "⚡" if rel == "triggered_anomaly" else "➜"
    print(f"   {edge.get('source')[:8]} {icon} [{rel}] {edge.get('target')[:8]}")

print("\n✅ 验证完成。")
