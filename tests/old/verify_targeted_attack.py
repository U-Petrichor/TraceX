from analyzer.attack_analyzer.context_engine import ContextEngine, SafeEventWrapper
from analyzer.graph_analyzer.provenance_system import ProvenanceSystem
from collector.common.es_client import ESClient
import json

print("🔍 初始化分析引擎...")
es = ESClient()
context = ContextEngine(es)
prov = ProvenanceSystem(context)

# =========================================================
# 🎯 核心差异：不再拉取所有日志，而是精确搜索攻击特征
# =========================================================
print("🔍 正在精确搜索攻击痕迹 (bash -i / wget / backdoor)...")

# 构造一个精确的 DSL 查询
target_query = {
    "bool": {
        "should": [
            {"match_phrase": {"process.command_line": "bash -i"}},
            {"match_phrase": {"process.command_line": "backdoor.php"}},
            {"match_phrase": {"process.command_line": "wget"}},
            # 兼容可能的字段差异 (部分 auditd 可能放在 raw.data)
            {"match_phrase": {"raw.data": "bash -i"}} 
        ],
        "minimum_should_match": 1
    }
}

try:
    # 🔧 [修复点] 使用 context.es 而不是 es
    # context.es 是 ContextEngine 初始化时解包出的真正客户端
    resp = context.es.search(
        index="unified-logs*,host-logs*,network-flows*", 
        body={
            "query": target_query, 
            "size": 5, 
            "sort": [{"@timestamp": "desc"}]
        }
    )
except Exception as e:
    print(f"❌ ES 查询失败: {e}")
    # 尝试打印对象结构帮助调试
    # print(dir(es))
    exit()

hits = resp.get('hits', {}).get('hits', [])

if not hits:
    print("\n❌ 未找到特定的攻击日志！")
    print("这说明刚才的攻击命令没有被 Auditd 记录。")
    print("可能原因：Auditd 服务未重启，或者规则未生效。")
    print("建议：重新运行 'python3 collector/host_collector/auditd_agent.py'")
    exit()

print(f"✅ 找到 {len(hits)} 条相关攻击日志！")

# 选取第一条作为种子
source = hits[0].get('_source', {})
seed_event = SafeEventWrapper(source)

# 强制补充评分信息 (确保图谱构建器能处理)
if 'threat' not in source: source['threat'] = {}
source['threat']['confidence'] = 1.0  # 手动确认为高危

# 打印种子信息
cmd = seed_event.process.command_line or seed_event.raw.data or "Unknown"
ts = seed_event['@timestamp']
print(f"🎯 锁定攻击种子: {cmd}")
print(f"🕒 时间戳: {ts}")

# =========================================================
# 🕸️ 开始溯源
# =========================================================
print("\n🔍 [正在构建攻击溯源图谱...]")
try:
    result = prov.rebuild_attack_path(seed_event)

    print("\n" + "="*60)
    print(f"🛡️  攻击路径签名: {result.get('path_signature', 'N/A')}")
    
    intel = result.get('intelligence', {})
    # 兼容字典或对象访问
    if isinstance(intel, dict):
        group = intel.get('attribution', {}).get('suspected_group', 'Unknown')
    else:
        group = "Unknown"
        
    print(f"🕵️  疑似 APT 组织: {group}")
    print("="*60)

    print("\n📊 [溯源图谱节点详情]")
    nodes = result.get('nodes', [])
    if not nodes:
        print("   (图谱只有单节点，未能关联到上下文。可能原因是时间窗口内没有其他相关日志)")
    
    for node in nodes:
        # 处理 SafeDict 或 dict
        if hasattr(node, '_data'): node = node._data
        
        label = node.get('atlas_label', 'Unknown')
        props = node.get('properties', {})
        
        info = "N/A"
        if 'process' in props:
            info = f"CMD: {props['process'].get('command_line')}"
        elif 'file' in props:
            info = f"FILE: {props['file'].get('path')}"
        elif 'network' in props:
            dst = props.get('destination', {})
            info = f"NET: {dst.get('ip')}:{dst.get('port')}"
            
        print(f" - [{label}] {str(info)[:80]}...")

except Exception as e:
    print(f"❌ 溯源分析过程报错: {e}")
    import traceback
    traceback.print_exc()

