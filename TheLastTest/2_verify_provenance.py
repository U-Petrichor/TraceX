import json
import time
import sys
import os
import requests
from datetime import datetime, timedelta

# 添加项目根目录到路径，以便导入 analyzer 模块
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from analyzer.graph_analyzer.graph_builder import GraphBuilder
except ImportError:
    # 尝试相对路径导入
    sys.path.append(os.path.join(os.path.dirname(current_dir), "analyzer"))
    from graph_analyzer.graph_builder import GraphBuilder

ES_HOST = "http://182.92.114.32:9200"

def get_recent_logs(minutes=10):
    """从 ES 获取最近 N 分钟的所有相关日志"""
    index_pattern = f"unified-logs-{datetime.utcnow().strftime('%Y.%m.%d')}"
    url = f"{ES_HOST}/{index_pattern}/_search"
    
    # 查询：过去 N 分钟，且包含 memory 或 iam 类别的日志
    query = {
        "size": 1000,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}
                ],
                "should": [
                    {"term": {"event.category": "memory"}}, # 内存告警
                    {"term": {"event.category": "iam"}},    # 登录日志
                    {"term": {"event.category": "process"}}, # 进程日志
                    {"term": {"event.category": "network"}}  # 网络日志
                ],
                "minimum_should_match": 1
            }
        },
        "sort": [{"@timestamp": {"order": "asc"}}]
    }
    
    try:
        print(f"[*] 正在从 ES 查询最近 {minutes} 分钟的日志...")
        resp = requests.post(url, json=query, headers={"Content-Type": "application/json"}, timeout=10)
        if resp.status_code != 200:
            print(f"[-] 查询失败: {resp.text}")
            return []
        
        hits = resp.json().get("hits", {}).get("hits", [])
        events = [h["_source"] for h in hits]
        print(f"[+] 获取到 {len(events)} 条相关日志。")
        return events
    except Exception as e:
        print(f"[-] 连接 ES 异常: {e}")
        return []

def analyze_and_visualize(events):
    """调用 GraphBuilder 进行关联分析并输出"""
    if not events:
        print("[-] 没有日志，无法分析。")
        return

    print("\n[*] 正在启动 Graph Analyzer 进行多源关联分析...")
    builder = GraphBuilder()
    graph = builder.build_from_events(events)
    
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    
    print(f"[+] 构建完成！包含 {len(nodes)} 个实体节点，{len(edges)} 条关联边。")
    
    # --- 打印 ASCII 溯源图 ---
    print("\n" + "="*30 + " 攻击溯源路径可视化 " + "="*30)
    
    # 1. 寻找起点：通常是包含内存异常的进程
    attacker_nodes = [n for n in nodes if n['type'] == 'process' and any(e['source'] == n['id'] and e['target'] in [m['id'] for m in nodes if m['type']=='memory_anomaly'] for e in edges)]
    
    if not attacker_nodes:
        print("[-] 未发现明显的攻击起点 (无内存异常关联进程)。展示所有节点...")
        attacker_nodes = [n for n in nodes if n['type'] == 'process'][:3]

    for start_node in attacker_nodes:
        print(f"\n[!] 发现受害进程: {start_node['label']} ({start_node['id'][:6]})")
        
        # 往下找内存异常
        mem_anomalies = [n for n in nodes if n['type'] == 'memory_anomaly' and any(e['source'] == start_node['id'] and e['target'] == n['id'] for e in edges)]
        for mem in mem_anomalies:
            print(f"    |--> [内存异常] {mem['label']} (TTP: {mem['ttp']}, Severity: {mem['severity']})")
            
        # 往上找父进程
        parents = [n for n in nodes if any(e['source'] == n['id'] and e['target'] == start_node['id'] for e in edges)]
        for p in parents:
             print(f"    ^-- [父进程] {p['label']}")

        # 往外找横向移动 (Auth/Network)
        # 查找以此进程所在主机为源头的认证行为
        # 由于我们现在的图构建里，Process -> Auth 只有在同一个日志里才连线
        # 但如果是跨日志关联 (Process -> Host -> Auth)，我们需要通过 Host 关联
        host_id = start_node['properties'].get('host')
        
        # 查找同主机的 Auth 节点
        # 注意：这里我们简化逻辑，直接找 Authentication 节点，看 source_ip 是否匹配
        # 更好的方式是遍历图的边
        related_auths = [n for n in nodes if n['type'] == 'authentication']
        
        # 简单的 IP 匹配 (模拟图关联)
        # 在真实的 GraphDB 里这是图查询，这里我们用 Python 模拟
        for auth in related_auths:
            # 如果认证的源 IP 等于 进程所在主机的 IP (或者我们在 win_agent_dc 里填的 Remote-Host IP)
            # 这里做一个模糊匹配展示
            print(f"    |--> [横向移动?] {auth['label']} (User: {auth['properties'].get('user')}, Outcome: {auth['properties'].get('outcome')})")

    print("\n" + "="*80)
    
    # 导出 JSON 供前端使用
    output_file = os.path.join(current_dir, "attack_graph.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2, ensure_ascii=False)
    print(f"[+] 完整图谱数据已保存至: {output_file}")
    print("[+] 您可以将此 JSON 文件导入前端进行渲染。")

if __name__ == "__main__":
    print("TraceX 终极溯源验证工具")
    print("--------------------------------")
    
    # 1. 获取日志
    logs = get_recent_logs(minutes=10)
    
    # 2. 分析
    analyze_and_visualize(logs)