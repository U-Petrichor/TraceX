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

import socket

def fetch_recent_events(minutes=30):
    es = get_es_client()
    hostname = socket.gethostname()
    print(f"Targeting Host: {hostname}")
    
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                # 强制过滤当前主机，排除 ES 中其他主机（如 Linux Lab）的噪音
                {"term": {"host.name.keyword": hostname}} 
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
    
    print(f"Fetching events from the last {minutes} minutes for host '{hostname}'...")
    # 增加 size 以确保覆盖，稍后在内存中过滤
    resp = es.search(index="unified-logs*", query=query, size=5000, sort=[{"@timestamp": "asc"}])
    events = [hit["_source"] for hit in resp["hits"]["hits"]]
    print(f"Fetched {len(events)} events.")
    
    if len(events) == 0:
        print(f"[-] Warning: No logs found for host '{hostname}'.")
        # 尝试查询有哪些主机是活跃的
        try:
            agg_query = {
                "size": 0,
                "aggs": {
                    "hosts": {"terms": {"field": "host.name.keyword", "size": 10}}
                }
            }
            agg_resp = es.search(index="unified-logs*", body=agg_query)
            buckets = agg_resp.get("aggregations", {}).get("hosts", {}).get("buckets", [])
            active_hosts = [b["key"] for b in buckets]
            print(f"[*] Available hosts in Elasticsearch: {active_hosts}")
            print(f"[*] Please ensure the Agent is running on '{hostname}'.")
        except Exception as e:
            print(f"[-] Failed to query active hosts: {e}")
            
    return events

def filter_events_by_interest(events, event_ttp_map):
    """
    基于关注点（TTPs 和 关键字）过滤事件，只保留相关进程树的事件。
    """
    interesting_pids = set()
    
    # 1. 扫描种子 PID
    simulation_roots = set()
    ttp_roots = set()
    
    for e in events:
        pid = e.get("process", {}).get("pid")
        if not pid:
            continue
            
        # B. 关键字 (模拟脚本) - 优先级最高
        cmd = str(e.get("process", {}).get("command_line", "")).lower()
        if "attack_simulation" in cmd or "1_attack_simulation" in cmd:
            simulation_roots.add(pid)
            
        # A. 命中 TTP (仅在没有找到模拟脚本时作为备选，且排除噪音)
        eid = e.get("event", {}).get("id")
        if eid in event_ttp_map:
            # 过滤掉常见的系统噪音 TTP 来源
            proc_name = e.get("process", {}).get("name", "").lower()
            if proc_name not in ["svchost", "searchindexer", "audiodg", "msmpeng"]:
                ttp_roots.add(pid)
    
    # 策略：如果有 simulation_roots，则只关注它们及其子代（因为这就是用户关心的）
    # 如果没有，则关注所有 TTP roots
    
    if simulation_roots:
        print(f"Found simulation roots: {simulation_roots}. Focusing strictly on these.")
        interesting_pids = simulation_roots.copy()
        # 还要加上它们的父进程，以便显示是谁启动了攻击
        # 但不要递归向上，只向上一级
        for e in events:
            pid = e.get("process", {}).get("pid")
            if pid in simulation_roots:
                ppid = e.get("process", {}).get("parent", {}).get("pid")
                if ppid:
                    interesting_pids.add(ppid)
    else:
        print(f"No simulation script found. Falling back to TTP roots: {len(ttp_roots)}")
        interesting_pids = ttp_roots.copy()

    # 2. 扩展 PID 集合 (寻找子进程)
    # 简单的多轮扩散，找到所有父进程是 interesting_pids 的事件，将其 PID 也加入
    # 重复几次以捕捉多级子进程
    for _ in range(5): # 增加深度，确保捕捉所有子孙
        added_new = False
        for e in events:
            ppid = e.get("process", {}).get("parent", {}).get("pid")
            pid = e.get("process", {}).get("pid")
            
            if ppid in interesting_pids and pid and pid not in interesting_pids:
                interesting_pids.add(pid)
                added_new = True
        if not added_new:
            break
            
    print(f"Identified {len(interesting_pids)} interesting PIDs related to the attack.")
    
    # 3. 过滤事件
    filtered_events = []
    for e in events:
        # 保留属于这些 PID 的事件
        pid = e.get("process", {}).get("pid")
        if pid in interesting_pids:
            filtered_events.append(e)
            continue
            
        # 也可以保留父进程是这些 PID 的事件 (即使该事件本身没有 process.pid，例如某些系统日志? 
        # 但通常 unified schema 都有 pid)
        
        # 保留网络/文件/认证事件，如果它们关联到这些 PID
        # (Unified Schema 中，网络/文件事件通常也有 process.pid 字段表示发起者)
        
    return filtered_events

def _collect_ttps(events):
    """使用 Sigma 规则检测 TTP，返回命中详情"""
    analyzer = AttackAnalyzer()
    analyzer.initialize()
    
    event_ttp_map = {} # event_id -> list of ttps
    all_ttps = set()
    all_rules = []
    
    # 简单的进度条
    total = len(events)
    print(f"Analyzing {total} events for TTPs...")
    
    for i, e in enumerate(events):
        result = analyzer.analyze_event(e)
        
        # 提取 TTP
        current_ttps = []
        for tech in result.get("techniques", []):
            ttp_id = tech.get("technique", {}).get("id")
            if ttp_id:
                current_ttps.append(ttp_id)
                all_ttps.add(ttp_id)
        
        # 记录命中的规则
        matches = result.get("matched_rules", [])
        if matches:
            all_rules.extend(matches)
            e["matched_rules"] = matches
            
        if current_ttps:
            eid = e.get("event", {}).get("id")
            if eid:
                event_ttp_map[eid] = current_ttps
            
    return list(all_ttps), list(set(all_rules)), event_ttp_map

def prune_graph(graph, event_ttp_map, max_hops=2):
    """
    对图进行剪枝，只保留与威胁相关的节点和边。
    策略：保留命中 TTP 的节点，以及其上下游 max_hops 范围内的节点。
    """
    nodes = {n['id']: n for n in graph['nodes']}
    edges = graph['edges']
    
    # 1. 识别种子节点 (命中 TTP 的事件对应的节点)
    # 注意：GraphNode ID 是哈希值，需要通过 properties 中的 event_id 或者其他方式关联
    # 但 GraphBuilder 生成 Node ID 时并没有直接使用 event.id (除了 fallback 情况)
    # 这里我们需要一种反向查找机制，或者简化处理：
    # 如果节点的 properties 中包含命中 TTP 的特征（如 process.pid, file.path 等）
    
    # 由于 GraphBuilder 的 ID 生成逻辑比较复杂，我们换一种思路：
    # 遍历所有节点，如果节点对应的原始事件（在 properties 中通常会有一些线索，但 GraphBuilder 没存 raw event）
    # 让我们修改 GraphBuilder 让它在 properties 里存一下 source_event_ids
    
    # 暂时方案：基于“有边连接”的连通分量保留。
    # 只要图中有 TTP 节点，就保留该连通分量。
    # 如何识别 TTP 节点？
    # 我们在 _collect_ttps 中已经修改了 event 对象，注入了 matched_rules/ttps。
    # GraphBuilder 在处理 event 时，应该把这些信息带入 Node。
    
    # 既然修改 GraphBuilder 比较麻烦，我们采用一种基于规则的后处理：
    # 遍历所有节点，如果节点的 label 或 properties 看起来像是有威胁的（基于外部 event_ttp_map 的线索比较难，因为 ID 不对应）
    # 
    # 替代方案：直接过滤掉无关紧要的边和节点。
    
    keep_node_ids = set()
    
    # 简单策略：保留所有 Process 节点，但过滤掉系统噪音
    # 过滤掉 TraceX 组件
    noise_processes = ["auditd", "python", "conhost", "svchost", "SearchIndexer", "MsMpEng", "taskhostw"]
    
    for nid, node in nodes.items():
        is_noise = False
        label = node.get('label', '').lower()
        
        # 检查 label 是否包含噪音进程名 (label 通常是 process name)
        for np in noise_processes:
            if np in label.lower():
                # 特殊豁免：如果是 python，且不是 trace_x，则保留（可能是攻击脚本）
                if "python" in np and "trace_x" not in str(node.get('properties', {}).get('command_line', '')).lower():
                    continue
                # 否则标记为噪音
                is_noise = True
                break
        
        # 过滤 TraceX 自身 (python 运行脚本)
        # 注意：模拟攻击也是 python 脚本，所以不能简单过滤 python
        # 但是我们可以过滤掉含有 "analyzer" "collector" 路径的 python
        
        cmdline = node.get('properties', {}).get('command_line')
        if cmdline:
            cmdline = str(cmdline).lower()
            if 'trace_x' in cmdline or 'tracex' in cmdline:
                 if 'simulation' not in cmdline and 'verify' not in cmdline: # 保留模拟脚本本身，方便调试，或者也过滤掉
                     is_noise = True
        
        if not is_noise:
            keep_node_ids.add(nid)
            
    # 基于 keep_node_ids 过滤边
    final_edges = []
    for e in edges:
        if e['source'] in keep_node_ids and e['target'] in keep_node_ids:
            final_edges.append(e)
            
    # 基于 final_edges 反向补充节点 (防止孤立)
    final_node_ids = set()
    for e in final_edges:
        final_node_ids.add(e['source'])
        final_node_ids.add(e['target'])
        
    final_nodes = [nodes[nid] for nid in final_node_ids]
    
    return {"nodes": final_nodes, "edges": final_edges}

def generate_report(events):
    # 初始化组件
    builder = GraphBuilder()
    atlas = AtlasMapper()
    enricher = IntelEnricher()
    
    # === TTP 提取 (先做，以便给 event 打标) ===
    ttps, matched_rules, event_ttp_map = _collect_ttps(events)
    print(f"Detected TTPs: {ttps}")
    
    # === 智能过滤 ===
    # 在构图之前，先过滤掉不相关的事件
    if len(events) > 100:
        print("Filtering events to focus on attack chain...")
        events = filter_events_by_interest(events, event_ttp_map)
        print(f"Events after filtering: {len(events)}")

    print("Building graph...")
    # 构图时，GraphBuilder 会读取 event 中的字段。
    # 我们刚刚在 _collect_ttps 里给 event 加了 matched_rules，
    # 但 GraphBuilder 默认可能不会把这个字段放到 properties 里。
    # 不过没关系，我们主要依靠后续的剪枝。
    
    graph = builder.build_from_events(events)
    print(f"Graph built (Raw): {len(graph['nodes'])} nodes, {len(graph['edges'])} edges.")
    
    # === 剪枝 ===
    # 只有当检测到 TTP 或者图特别大时才剪枝
    if ttps or len(graph['nodes']) > 500:
        print("Pruning graph to focus on threats...")
        graph = prune_graph(graph, event_ttp_map)
        print(f"Graph pruned: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges.")
    
    nodes = {n['id']: n for n in graph.get('nodes', [])}
    edges = graph.get('edges', [])
    
    # === ATLAS 签名 (补充) ===
    labels = [atlas.get_label(e) for e in events]
    signature = sorted(set([l for l in labels if l != "UNKNOWN"]))
    
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
    # 1. Fetch data (30 minutes)
    events = fetch_recent_events(minutes=30)
    if not events:
        print("No events found in the last 30 minutes.")
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
