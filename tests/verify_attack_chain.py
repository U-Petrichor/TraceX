# 文件名: verify_attack_chain.py
# 存放位置: TraceX 项目根目录

import sys
import json
import time
from datetime import datetime, timedelta
from analyzer.attack_analyzer.context_engine import ContextEngine
from analyzer.graph_analyzer.provenance_system import ProvenanceSystem
from collector.common.es_client import ESClient

def main():
    print("🚀 开始验证 TraceX 溯源分析系统 (真实数据版)...")
    
    # 1. 初始化
    es = ESClient()
    context_engine = ContextEngine(es)
    provenance_system = ProvenanceSystem(context_engine)
    
    # 2. 定义时间窗口 (最近 10 分钟)
    now = datetime.utcnow()
    start_time = (now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    print(f"📅 查询时间窗口: {start_time} ~ {end_time}")

    # 3. 获取种子事件 (从组员3那里拿高分告警)
    # 我们查找刚才产生的特定行为，比如 cat /etc/passwd 或者 curl
    # 为了演示，我们放宽分数限制，确保能抓到刚才的测试数据
    seeds = context_engine.get_seed_events((start_time, end_time), min_score=40)
    
    if not seeds:
        print("❌ 未在最近 10 分钟内发现高危种子事件。")
        print("   请确认：")
        print("   1. Auditd Agent 是否正在运行？")
        print("   2. 是否执行了攻击脚本？")
        print("   3. ES 是否正常写入？")
        return

    print(f"✅ 捕获到 {len(seeds)} 个种子事件。正在分析最新的一个...")
    
    # 选最新的一个种子事件（通常是攻击链的最后一步，如 rm 或 cat /etc/passwd）
    target_seed = seeds[0] 
    print(f"🎯 种子事件: [{target_seed.event.category}] {target_seed.process.command_line or target_seed.file.path}")

    # 4. 执行溯源 (调用组员4核心逻辑)
    analysis_result = provenance_system.rebuild_attack_path(target_seed)

    # 5. 输出报告
    print("\n" + "="*50)
    print("📊 TRACEX 溯源分析报告")
    print("="*50)
    
    # A. 攻击图统计
    print(f"[+] 图谱规模: {len(analysis_result['nodes'])} 节点, {len(analysis_result['edges'])} 边")
    
    # B. 攻击链签名 (这是组员4 AtlasMapper 的功劳)
    print(f"[+] 攻击链签名 (Path Signature):")
    print(f"    👉 {analysis_result['path_signature']}")
    
    # C. 情报与归因 (这是组员4 IntelEnricher 的功劳)
    intel = analysis_result.get('intelligence', {})
    attribution = intel.get('attribution', {})
    
    print(f"[+] APT 归因结果:")
    print(f"    🏴‍☠️  疑似组织: {attribution.get('suspected_group', 'Unknown')}")
    print(f"    ws  置信度:   {attribution.get('similarity_score', 0)}")
    
    # D. 外部基础设施 (IOC)
    infra = intel.get('external_infrastructure', {})
    if infra:
        print(f"[+] 发现恶意基础设施 (IOC):")
        for ip, info in infra.items():
            print(f"    💀 IP: {ip} | 类型: {info.get('type')} | 风险: {info.get('risk')}")
            
    print("="*50)
    print("✅ 验证结束。如果看到了 'suspected_group' 和 'Path Signature'，说明组员4工作正常！")

if __name__ == "__main__":
    main()
