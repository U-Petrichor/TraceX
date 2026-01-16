import json
import sys
import os
from pathlib import Path
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

# 添加项目根目录到 sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from analyzer.graph_analyzer.graph_builder import GraphBuilder
    from analyzer.graph_analyzer.atlas_mapper import AtlasMapper
    from analyzer.graph_analyzer.enrichment import IntelEnricher
    from analyzer.attack_analyzer.attack_tagger import AttackAnalyzer
except ImportError as e:
    print(f"Error importing analyzer modules: {e}")
    print("Please ensure you are running this script from the project root or with PYTHONPATH set.")
    sys.exit(1)

def get_es_client():
    return Elasticsearch(
        hosts=["http://182.92.114.32:9200"],
        request_timeout=30
    )

def fetch_recent_events(minutes=30):
    es = get_es_client()
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}
            ],
            "should": [
                {"term": {"event.category": "process"}},
                {"term": {"event.category": "network"}},
                {"term": {"event.category": "file"}},
                {"term": {"event.category": "authentication"}},
                {"term": {"event.category": "memory"}}
            ],
            "minimum_should_match": 1
        }
    }
    
    print(f"Fetching events from the last {minutes} minutes...")
    resp = es.search(index="unified-logs*", query=query, size=2000, sort=[{"@timestamp": "asc"}])
    events = [hit["_source"] for hit in resp["hits"]["hits"]]
    print(f"Fetched {len(events)} events.")
    return events

def _collect_ttps(events):
    """使用 Sigma 规则检测 TTP"""
    analyzer = AttackAnalyzer()
    analyzer.initialize()
    ttps = []
    matched_rules = []
    
    # 简单的进度条
    total = len(events)
    print(f"Analyzing {total} events for TTPs...")
    
    for i, e in enumerate(events):
        result = analyzer.analyze_event(e)
        for tech in result.get("techniques", []):
            ttp_id = tech.get("technique", {}).get("id")
            if ttp_id:
                ttps.append(ttp_id)
        
        # 记录命中的规则
        matches = result.get("matched_rules", [])
        if matches:
            matched_rules.extend(matches)
            # 将匹配信息回写到事件中，以便后续处理（可选）
            e["matched_rules"] = matches
            
    return list(set(ttps)), list(set(matched_rules))

def generate_report(events):
    # 初始化组件
    builder = GraphBuilder()
    atlas = AtlasMapper()
    enricher = IntelEnricher()
    
    print("Building graph...")
    graph = builder.build_from_events(events)
    nodes = {n['id']: n for n in graph.get('nodes', [])}
    edges = graph.get('edges', [])
    
    print(f"Graph built: {len(nodes)} nodes, {len(edges)} edges.")

    # === ATLAS 签名 ===
    labels = [atlas.get_label(e) for e in events]
    signature = sorted(set([l for l in labels if l != "UNKNOWN"]))
    
    # === TTP 提取 ===
    ttps, matched_rules = _collect_ttps(events)
    print(f"Detected TTPs: {ttps}")
    
    # 如果没有检测到 TTP，尝试手动添加一些（仅用于演示，如果确实是攻击模拟）
    # 在真实环境中应该依赖规则检测
    if not ttps and len(events) > 0:
        print("Warning: No TTPs detected via Sigma rules. Checking for known patterns...")
        # 简单的后备检测逻辑
        for e in events:
            cmd = e.get("process", {}).get("command_line", "") or ""
            if "VirtualAlloc" in str(e):
                ttps.append("T1055") # Process Injection
            if "powershell" in cmd.lower() and "-enc" in cmd.lower():
                ttps.append("T1059.001") # PowerShell
            if "net use" in cmd.lower() or "net.exe" in e.get("process", {}).get("name", "").lower():
                ttps.append("T1078") # Valid Accounts
    
    ttps = list(set(ttps))

    # === 归因 ===
    attribution = enricher.attribute_by_ttps(ttps)
    
    # === APT Profile ===
    suspected = attribution.get("suspected_group")
    profile = {}
    if suspected:
        apt_profile = enricher.get_apt_profile(suspected)
        if apt_profile:
            profile = {
                "name": apt_profile.name,
                "aliases": apt_profile.aliases,
                "ttps": apt_profile.ttps[:20],
                "target_industries": apt_profile.target_industries,
            }
        else:
            # 如果是 TheLastTest，可能不在标准库里，手动构造一个
            profile = {
                "name": suspected,
                "aliases": ["Manual Simulation", "Red Team Operation"],
                "ttps": ttps,
                "target_industries": ["Internal Testing"]
            }

    # === IOC 富化 ===
    ioc = enricher.enrich_entities(graph.get("nodes", []))

    # === 构造 Attack Chain Structure ===
    structure = []
    for e in edges:
        src = nodes.get(e['source'])
        dst = nodes.get(e['target'])
        if src and dst:
            structure.append({
                "source_type": src.get('type', 'unknown'),
                "source": src.get('label', src['id']),
                "relation": e.get('relation', 'related'),
                "target_type": dst.get('type', 'unknown'),
                "target": dst.get('label', dst['id']),
                "timestamp": e.get("timestamp")
            })
            
    # 按时间排序
    structure.sort(key=lambda x: x.get("timestamp", ""))

    # === 最终报告 ===
    report = {
        "simulation": {
            "name": "TheLastTest",
            "mode": "Realtime Verification",
            "event_count": len(events),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "generated_at": datetime.now().isoformat()
        },
        "attack_chain_signature": signature,
        "attack_chain_structure": structure,
        "ttp_attribution": attribution,
        "apt_profile": profile,
        "ioc_enrichment": ioc,
        "sigma_rules": matched_rules,
        "graph_data": graph # 保留原始图数据以备用
    }
    
    return report

def main():
    events = fetch_recent_events(minutes=60) # 扩大到60分钟以防万一
    if not events:
        print("No events found in the last 60 minutes.")
        return

    report = generate_report(events)
    
    output_file = os.path.join(os.path.dirname(__file__), "attack_graph.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        
    print(f"Report generated at: {output_file}")
    print(f"Suspected Group: {report['ttp_attribution'].get('suspected_group')}")
    print(f"Confidence: {report['ttp_attribution'].get('confidence')}")

if __name__ == "__main__":
    main()
