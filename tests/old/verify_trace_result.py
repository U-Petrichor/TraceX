from analyzer.attack_analyzer.context_engine import ContextEngine
from analyzer.graph_analyzer.provenance_system import ProvenanceSystem
from collector.common.es_client import ESClient
from datetime import datetime, timedelta
import json
import time

print("🔍 正在初始化...")
es = ESClient()
context = ContextEngine(es)
prov = ProvenanceSystem(context)

# === 策略调整：暴力时间窗口 + 最低分数 ===
# 1. 直接拉取过去 24 小时的数据，避免时区偏差导致漏查
# 2. 同时向后多查 8 小时，防止数据被错误标记为未来时间
now = datetime.utcnow()
start_time = now - timedelta(hours=24) 
end_time = now + timedelta(hours=8)

time_range = (
    start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
)

print(f"🕒 查询范围 (UTC): {time_range}")
print("📉 阈值设置: min_score = 0 (抓取所有日志)")

# 3. 获取种子，分数设为 0 以捕获低危尝试
seeds = context.get_seed_events(time_range, min_score=0)

if not seeds:
    print("\n❌ 依然未找到告警！可能原因：")
    print("1. auditd_agent.py 没有在运行？")
    print("2. 刚才的攻击命令没有产生任何 Process/Network 日志？")
    print("3. ES 服务未启动？")
    # 尝试直接打印一条 raw query 看看 ES 里有没有东西
    try:
        print("\n🔎 [调试] 尝试直接查询 ES 前 5 条数据:")
        raw_res = es.search(index="host-logs-*", query={"match_all": {}}, size=5)
        hits = raw_res.get('hits', {}).get('hits', [])
        print(f"   ES 'host-logs-*' 索引中文档数量: {raw_res.get('hits', {}).get('total', {}).get('value', 0)}")
        if hits:
            print(f"   最新一条日志时间: {hits[0]['_source'].get('@timestamp')}")
    except Exception as e:
        print(f"   ES 连接失败: {str(e)}")
    exit()

print(f"\n✅ 成功捕获 {len(seeds)} 个事件！")

# 4. 寻找跟我们刚才操作相关的事件 (优先找 bash 或 curl)
target_seed = None
for s in seeds:
    cmd = s.process.command_line if s.process.command_line else ""
    # 优先找我们刚才执行的命令
    if "bash -i" in cmd or "wget" in cmd or "backdoor" in cmd:
        target_seed = s
        break

if not target_seed:
    target_seed = seeds[0]
    print("⚠️ 未找到特征明显的攻击命令，使用第一条事件作为种子。")

print(f"🎯 选定种子: [{target_seed.event.category.upper()}] Score={target_seed.threat.confidence*100}")
print(f"   时间: {target_seed.timestamp}")
print(f"   命令: {target_seed.process.command_line}")

print("\n🔍 [开始重构攻击链路...]")
try:
    result = prov.rebuild_attack_path(target_seed)

    print("\n" + "="*50)
    print(f"🛡️  攻击路径签名: {result.get('path_signature', 'N/A')}")
    
    intel = result.get('intelligence', {})
    attribution = intel.get('attribution', {})
    group = attribution.get('suspected_group', 'Unknown')
    print(f"🕵️  疑似 APT 组织: {group}")
    print("="*50)

    print("\n📊 [图谱节点列表]")
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
