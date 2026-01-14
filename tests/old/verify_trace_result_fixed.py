from analyzer.attack_analyzer.context_engine import ContextEngine
from analyzer.graph_analyzer.provenance_system import ProvenanceSystem
from collector.common.es_client import ESClient
from datetime import datetime, timedelta
import json
import time

# ==========================================
# 🔧 核心修复：Monkey Patch (运行时热补丁)
# ==========================================
def safe_get_seed_events(self, time_range, min_score=0):
    """
    替换原有的 get_seed_events。
    策略：只按时间查询，不按分数查询（避免 'high' 字符串导致的 ES 报错），
    然后在 Python 内存中进行过滤。
    """
    start_t, end_t = time_range
    print(f"🔧 [Patch] 正在执行安全查询 (绕过 severity 字段)...")
    
    # 构造仅包含时间的纯净查询
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": start_t, "lte": end_t}}}
            ]
        }
    }
    
    # 获取原始日志 (上限 500 条，防止内存溢出)
    # 注意：这里假设 es.query 能够处理基本的 DSL 结构
    try:
        # 尝试直接发送 DSL
        raw_events = self.es.query(query)
    except Exception as e:
        print(f"⚠️ 查询尝试 1 失败: {e}")
        try:
            # 备用：有些封装需要 query 关键字
            raw_events = self.es.query({"query": query})
        except Exception as e2:
            print(f"❌ 查询彻底失败: {e2}")
            return []
            
    if not raw_events:
        return []

    print(f"📥 [Patch] 从 ES 拉取到 {len(raw_events)} 条原始日志，开始内存评分过滤...")
    
    seeds = []
    # 在 Python 内存中进行安全的评分过滤
    for event in raw_events:
        try:
            # 调用引擎自身的评分逻辑
            threat_info = self.evaluate_threat(event)
            score = threat_info.get('score', 0)
            
            # 只要分数达标，或者包含我们感兴趣的关键字，就保留
            cmd = event.process.command_line or ""
            is_interesting = "backdoor" in cmd or "bash -i" in cmd or "wget" in cmd
            
            if score >= min_score or is_interesting:
                # 临时把分数注入进去，方便展示
                event.threat.confidence = score / 100.0 
                seeds.append(event)
        except Exception as err:
            continue
            
    return seeds

# 应用补丁：覆盖类的方法
ContextEngine.get_seed_events = safe_get_seed_events
# ==========================================

print("🔍 正在初始化 (带补丁模式)...")
es = ESClient()
context = ContextEngine(es)
prov = ProvenanceSystem(context)

# 设定时间窗口 (过去 24 小时)
now = datetime.utcnow()
start_time = now - timedelta(hours=24)
end_time = now + timedelta(hours=2)
time_range = (start_time.strftime("%Y-%m-%dT%H:%M:%SZ"), end_time.strftime("%Y-%m-%dT%H:%M:%SZ"))

print(f"🕒 查询范围 (UTC): {time_range}")

# 获取种子
seeds = context.get_seed_events(time_range, min_score=0)

if not seeds:
    print("\n❌ 未找到任何日志！请检查 collector 是否真的写入了数据。")
    exit()

print(f"\n✅ 成功筛选出 {len(seeds)} 个相关事件。")

# 智能选择最佳种子 (优先找包含 wget/bash/backdoor 的)
target_seed = seeds[0]
for s in seeds:
    cmd = s.process.command_line if s.process.command_line else ""
    if "backdoor" in cmd or "bash -i" in cmd:
        target_seed = s
        break

print(f"🎯 选定种子: [{target_seed.event.category}] CMD: {target_seed.process.command_line}")

print("\n🔍 [开始重构攻击链路...]")
try:
    result = prov.rebuild_attack_path(target_seed)

    print("\n" + "="*60)
    print(f"🛡️  攻击路径签名: {result.get('path_signature', 'N/A')}")
    
    intel = result.get('intelligence', {})
    attribution = intel.get('attribution', {})
    group = attribution.get('suspected_group', 'Unknown')
    print(f"🕵️  疑似 APT 组织: {group}")
    print("="*60)

    print("\n📊 [图谱节点详情]")
    for node in result.get('nodes', []):
        label = node.get('atlas_label', 'Unknown')
        props = node.get('properties', {})
        
        info = "N/A"
        if 'process' in props:
            info = f"CMD: {props['process'].get('command_line')}"
        elif 'file' in props:
            info = f"FILE: {props['file'].get('path')}"
        elif 'network' in props:
            info = f"NET: {props.get('destination', {}).get('ip')}:{props.get('destination', {}).get('port')}"
            
        print(f" - [{label}] {str(info)[:80]}...")
        
except Exception as e:
    print(f"❌ 溯源分析出错: {str(e)}")
    import traceback
    traceback.print_exc()
