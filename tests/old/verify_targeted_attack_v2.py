import sys
import os
import binascii
from datetime import datetime, timedelta

# 确保能引用项目模块
sys.path.append(os.getcwd())

from analyzer.attack_analyzer.context_engine import ContextEngine, SafeEventWrapper
from analyzer.graph_analyzer.provenance_system import ProvenanceSystem
from collector.common.es_client import ESClient

print("🔍 TraceX 全链路自动化验证启动...")
es = ESClient()
context = ContextEngine(es)
prov = ProvenanceSystem(context)

def hex_decode(data):
    try:
        clean = str(data).replace(" ", "")
        return binascii.unhexlify(clean).decode('utf-8', errors='ignore')
    except:
        return ""

# 1. 搜索种子：支持 Hex 编码和关键词模糊匹配
print("🎯 正在定位攻击线索 (支持 Hex 解码搜索)...")
# 宽容模式：找过去 1 小时的所有日志
now = datetime.utcnow()
time_range = ((now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), 
              (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))

# 抓取最近 1000 条，然后在内存里做 Hex 解码搜索
resp = es.es.search(index="unified-logs*", 
                    body={"query": {"match_all": {}}, "size": 1000, "sort": [{"@timestamp": "desc"}]})

hits = resp.get('hits', {}).get('hits', [])
target_seed = None

for hit in hits:
    src = hit['_source']
    cmd = str(src.get('process', {}).get('command_line', ""))
    decoded = hex_decode(cmd)
    
    # 检查明文或解码后的内容是否包含攻击特征
    if any(k in cmd or k in decoded for k in ["bash -i", "wget", "backdoor", "malware"]):
        print(f"✅ 找到匹配种子！")
        print(f"   原始数据: {cmd[:50]}...")
        if decoded: print(f"   解码内容: {decoded}")
        
        # 封装为 SafeEventWrapper 并强制加分
        if 'threat' not in src: src['threat'] = {}
        src['threat']['confidence'] = 1.0
        target_seed = SafeEventWrapper(src)
        break

if not target_seed:
    print("❌ 依然没找到攻击日志。请确认你刚才真的执行了 bash -i 命令。")
    exit()

# 2. 构建图谱
print("\n🕸️ 正在调用组员 4 的逻辑构建攻击溯源图谱...")

try:
    print(f"DEBUG: 种子节点 PID={target_seed.process.pid}, PPID={target_seed.process.parent.pid}")
    print(f"DEBUG: 正在 ES 中搜索关联记录...")
    result = prov.rebuild_attack_path(target_seed)

    print("\n" + "="*60)
    print(f"🛡️  攻击路径签名: {result.get('path_signature', 'N/A')}")
    
    intel = result.get('intelligence', {})
    group = "Unknown"
    if isinstance(intel, dict):
        group = intel.get('attribution', {}).get('suspected_group', 'Unknown')
    print(f"🕵️  疑似 APT 组织归因: {group}")
    print("="*60)

    print("\n📊 溯源图节点详情:")
    for node in result.get('nodes', []):
        if hasattr(node, '_data'): node = node._data
        label = node.get('atlas_label', 'Unknown')
        props = node.get('properties', {})
        
        detail = "N/A"
        if 'process' in props: detail = f"CMD: {props['process'].get('command_line')}"
        elif 'file' in props: detail = f"FILE: {props['file'].get('path')}"
        elif 'network' in props: detail = f"NET: {props.get('destination', {}).get('ip')}"
        
        # 对输出的 CMD 也尝试解码展示
        if "CMD:" in detail:
            d_cmd = hex_decode(detail.split("CMD: ")[1])
            if d_cmd: detail += f" (🔓 {d_cmd})"

        print(f" - [{label}] {detail[:100]}")

except Exception as e:
    print(f"❌ 溯源出错: {e}")

