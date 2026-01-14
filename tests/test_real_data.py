# tests/test_real_data.py
"""
真实数据测试脚本 - 测试组员3和组员4的完整功能

使用方法:
    # 在服务器上运行（ES 在 localhost:9200）
    python tests/test_real_data.py
    
    # 指定远程 ES 地址
    python tests/test_real_data.py --es-host http://192.168.1.100:9200
    
    # 指定时间范围
    python tests/test_real_data.py --hours 24
"""
import sys
import os
import argparse
import logging
from datetime import datetime, timedelta

# 设置路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Windows 控制台编码
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from collector.common.es_client import ESClient

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def print_separator(title: str = ""):
    """打印分隔线"""
    if title:
        print(f"\n{'='*70}")
        print(f"  {title}")
        print(f"{'='*70}")
    else:
        print(f"\n{'-'*70}")


def test_es_connection(es_host: str) -> ESClient:
    """测试 ES 连接"""
    print_separator("Step 1: 测试 Elasticsearch 连接")
    
    try:
        es_client = ESClient(hosts=[es_host])
        # 测试连接
        info = es_client.es.info()
        print(f"[OK] ES 连接成功!")
        print(f"     集群名: {info.get('cluster_name', 'N/A')}")
        print(f"     版本: {info.get('version', {}).get('number', 'N/A')}")
        return es_client
    except Exception as e:
        print(f"[FAIL] ES 连接失败: {e}")
        sys.exit(1)


def list_indices(es_client: ESClient):
    """列出所有相关索引"""
    print_separator("Step 2: 列出数据索引")
    
    try:
        indices = es_client.es.cat.indices(index="*logs*,*flows*", format="json")
        
        if not indices:
            print("[WARN] 没有找到任何日志索引!")
            print("       请确保已经运行过 Cowrie/Auditd 采集器")
            return []
        
        print(f"找到 {len(indices)} 个索引:")
        for idx in sorted(indices, key=lambda x: x.get('index', '')):
            name = idx.get('index', '')
            docs = idx.get('docs.count', '0')
            size = idx.get('store.size', '0')
            print(f"  - {name}: {docs} docs, {size}")
        
        return [idx['index'] for idx in indices]
        
    except Exception as e:
        print(f"[FAIL] 列出索引失败: {e}")
        return []


def query_sample_events(es_client: ESClient, hours: int = 24) -> list:
    """查询样本事件"""
    print_separator("Step 3: 查询样本事件")
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    
    print(f"时间范围: {start_time.isoformat()}Z ~ {end_time.isoformat()}Z")
    
    try:
        # 查询所有类型的事件
        events = es_client.query_events(
            start_time=start_time.isoformat() + "Z",
            end_time=end_time.isoformat() + "Z",
            index_prefix="*",  # 查所有索引
            size=100
        )
        
        print(f"\n找到 {len(events)} 条事件")
        
        if events:
            # 统计事件类型
            categories = {}
            datasets = {}
            for e in events:
                cat = e.get('event', {}).get('category', 'unknown')
                ds = e.get('event', {}).get('dataset', 'unknown')
                categories[cat] = categories.get(cat, 0) + 1
                datasets[ds] = datasets.get(ds, 0) + 1
            
            print("\n按事件类型:")
            for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
                print(f"  - {cat}: {count}")
            
            print("\n按数据源:")
            for ds, count in sorted(datasets.items(), key=lambda x: -x[1]):
                print(f"  - {ds}: {count}")
        
        return events
        
    except Exception as e:
        print(f"[FAIL] 查询事件失败: {e}")
        return []


def test_context_engine(es_client: ESClient, events: list):
    """测试组员3: ContextEngine"""
    print_separator("Step 4: 测试组员3 - ContextEngine")
    
    from analyzer.attack_analyzer.context_engine import ContextEngine
    
    context_engine = ContextEngine(es_client)
    
    # 4.1 测试威胁评估
    print("\n4.1 威胁评估 (evaluate_threat):")
    print("-" * 50)
    
    threats = []
    for i, event in enumerate(events[:20]):  # 测试前20条
        result = context_engine.evaluate_threat(event)
        
        if result['score'] >= 50:  # 只显示威胁
            threats.append((event, result))
            
            src_ip = event.get('source', {}).get('ip', 'N/A')
            cmd = event.get('process', {}).get('command_line', '')[:50]
            action = event.get('event', {}).get('action', 'N/A')
            
            print(f"\n  [{i+1}] 分数: {result['score']} | 级别: {result['severity']}")
            print(f"      IP: {src_ip}")
            print(f"      动作: {action}")
            if cmd:
                print(f"      命令: {cmd}...")
            print(f"      原因: {', '.join(result['reasons'][:2])}")
    
    if not threats:
        print("  没有发现高威胁事件 (score >= 50)")
    else:
        print(f"\n  共发现 {len(threats)} 条威胁事件")
    
    # 4.2 测试关联搜索
    print("\n4.2 关联搜索 (find_related_events):")
    print("-" * 50)
    
    if threats:
        seed_event, threat_info = threats[0]  # 用第一个威胁事件作为种子
        
        print(f"  使用种子事件: {seed_event.get('event', {}).get('id', 'N/A')[:16]}...")
        print(f"  种子威胁分数: {threat_info['score']}")
        
        related = context_engine.find_related_events(seed_event, window=120)
        
        print(f"\n  找到 {len(related)} 条关联事件:")
        for i, rel in enumerate(related[:10]):
            rel_cat = rel.get('event', {}).get('category', 'N/A')
            rel_action = rel.get('event', {}).get('action', 'N/A')
            rel_ts = rel.get('@timestamp', '')[:19]
            print(f"    [{i+1}] {rel_ts} | {rel_cat} | {rel_action}")
    else:
        print("  没有威胁事件可用于关联搜索")
    
    # 4.3 测试获取种子事件
    print("\n4.3 获取种子事件 (get_seed_events):")
    print("-" * 50)
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)
    
    seeds = context_engine.get_seed_events(
        time_range=(start_time.isoformat() + "Z", end_time.isoformat() + "Z"),
        min_score=50
    )
    
    print(f"  找到 {len(seeds)} 个种子事件 (score >= 50)")
    for i, seed in enumerate(seeds[:5]):
        score = seed.get('_threat_score', 0)
        reasons = seed.get('_threat_reasons', [])
        src_ip = seed.get('source', {}).get('ip', 'N/A')
        print(f"    [{i+1}] 分数: {score} | IP: {src_ip}")
        if reasons:
            print(f"        原因: {reasons[0]}")
    
    return threats, seeds


def test_graph_analyzer(es_client: ESClient, events: list, seeds: list):
    """测试组员4: GraphAnalyzer"""
    print_separator("Step 5: 测试组员4 - GraphAnalyzer")
    
    from analyzer.graph_analyzer.graph_builder import GraphBuilder
    from analyzer.graph_analyzer.atlas_mapper import AtlasMapper
    from analyzer.graph_analyzer.enrichment import IntelEnricher
    from analyzer.graph_analyzer.pid_cache import PIDCache
    
    # 5.1 测试 ATLAS 标签映射
    print("\n5.1 ATLAS 标签映射 (AtlasMapper):")
    print("-" * 50)
    
    atlas_mapper = AtlasMapper()
    label_stats = {}
    
    for event in events[:50]:
        label = atlas_mapper.get_label(event)
        label_stats[label] = label_stats.get(label, 0) + 1
    
    print("  标签分布:")
    for label, count in sorted(label_stats.items(), key=lambda x: -x[1])[:10]:
        print(f"    - {label}: {count}")
    
    # 5.2 测试图构建
    print("\n5.2 图构建 (GraphBuilder):")
    print("-" * 50)
    
    pid_cache = PIDCache()
    builder = GraphBuilder(pid_cache=pid_cache)
    
    # 使用前50条事件构建图
    graph = builder.build_from_events(events[:50])
    
    print(f"  节点数: {graph['stats']['total_nodes']}")
    print(f"  边数: {graph['stats']['total_edges']}")
    print(f"  处理事件数: {graph['stats']['events_processed']}")
    
    # 统计节点类型
    node_types = {}
    for node in graph['nodes']:
        t = node.get('type', 'unknown')
        node_types[t] = node_types.get(t, 0) + 1
    
    print("\n  节点类型分布:")
    for t, count in sorted(node_types.items(), key=lambda x: -x[1]):
        print(f"    - {t}: {count}")
    
    # 显示一些节点
    print("\n  样本节点:")
    for node in graph['nodes'][:5]:
        print(f"    - [{node['type']}] {node['label'][:40]}")
        if node.get('atlas_label'):
            print(f"      ATLAS: {node['atlas_label']}")
    
    # 5.3 测试 IOC 富化
    print("\n5.3 IOC 富化 (IntelEnricher):")
    print("-" * 50)
    
    enricher = IntelEnricher()
    
    # 统计 MITRE 数据
    mitre_stats = enricher.get_mitre_statistics()
    if mitre_stats.get('loaded'):
        print(f"  MITRE 数据已加载:")
        print(f"    - APT 组织: {mitre_stats.get('total_groups', 0)}")
        print(f"    - 技术数: {mitre_stats.get('total_techniques', 0)}")
    else:
        print(f"  MITRE 数据未加载: {mitre_stats.get('message', '')}")
    
    # 对图节点进行富化
    ti_info = enricher.enrich_entities(graph['nodes'])
    
    print(f"\n  富化了 {len(ti_info)} 个 IOC:")
    for ioc, info in list(ti_info.items())[:5]:
        risk = info.get('risk_score', 0)
        tags = info.get('tags', [])[:3]
        source = info.get('source', 'unknown')
        status = "[!] 恶意" if info.get('is_malicious') else "[ ] 正常"
        print(f"    {status} {ioc}")
        print(f"       风险: {risk}, 标签: {tags}, 来源: {source}")
    
    return graph, enricher


def test_provenance_system(es_client: ESClient, seeds: list):
    """测试组员4: 溯源系统"""
    print_separator("Step 6: 测试溯源系统 (ProvenanceSystem)")
    
    if not seeds:
        print("  没有种子事件，跳过溯源测试")
        return None
    
    from analyzer.attack_analyzer.context_engine import ContextEngine
    from analyzer.graph_analyzer.provenance_system import ProvenanceSystem
    
    context_engine = ContextEngine(es_client)
    provenance = ProvenanceSystem(context_engine)
    
    # 使用第一个种子事件进行溯源
    seed = seeds[0]
    print(f"  使用种子事件: {seed.get('event', {}).get('id', 'N/A')[:16]}...")
    print(f"  种子威胁分数: {seed.get('_threat_score', 0)}")
    
    session_id = seed.get('user', {}).get('session_id') or seed.get('raw', {}).get('session', '')
    if session_id:
        print(f"  会话ID: {session_id}")
    
    # 执行溯源
    print("\n  执行攻击路径重建...")
    result = provenance.rebuild_attack_path(
        seed_event=seed,
        time_window=120,  # 2分钟窗口
        enable_session_isolation=True
    )
    
    stats = result.get('stats', {})
    print(f"\n  溯源结果:")
    print(f"    - 处理事件数: {stats.get('events_processed', 0)}")
    print(f"    - 边数: {stats.get('edges_created', 0)}")
    print(f"    - 节点数: {stats.get('nodes_visited', 0)}")
    print(f"    - 会话ID: {stats.get('session_id', 'N/A')}")
    
    # 显示攻击路径签名
    path_sig = result.get('path_signature', '')
    if path_sig:
        print(f"\n  攻击路径签名:")
        print(f"    {path_sig[:100]}...")
    
    # 显示 APT 归因
    intel = result.get('intelligence', {})
    attribution = intel.get('attribution', {})
    if attribution.get('suspected_group') and attribution['suspected_group'] != 'Unclassified':
        print(f"\n  APT 归因:")
        print(f"    - 疑似组织: {attribution['suspected_group']}")
        print(f"    - 相似度: {attribution.get('similarity_score', 0):.1%}")
        print(f"    - 来源: {attribution.get('source', 'unknown')}")
    else:
        print(f"\n  APT 归因: 未匹配到已知攻击组织")
        if attribution.get('alternative_matches'):
            print(f"    候选组织: {attribution['alternative_matches'][:3]}")
    
    # 显示外部基础设施
    infra = intel.get('external_infrastructure', {})
    malicious = {k: v for k, v in infra.items() if v.get('is_malicious')}
    if malicious:
        print(f"\n  恶意基础设施:")
        for ioc, info in list(malicious.items())[:3]:
            print(f"    - {ioc}: {info.get('tags', [])[:3]}")
    
    # 生成详细报告
    print("\n  生成攻击时间线报告...")
    try:
        report = provenance.format_attack_timeline(result)
        print("\n" + report[:2000])  # 只显示前2000字符
        if len(report) > 2000:
            print("\n  ... (报告已截断，完整报告请查看返回值)")
    except Exception as e:
        print(f"  生成报告失败: {e}")
    
    return result


def main():
    parser = argparse.ArgumentParser(description='TraceX 真实数据测试')
    parser.add_argument('--es-host', default='http://localhost:9200',
                        help='Elasticsearch 地址 (默认: http://localhost:9200)')
    parser.add_argument('--hours', type=int, default=24,
                        help='查询最近多少小时的数据 (默认: 24)')
    args = parser.parse_args()
    
    print_separator("TraceX 组员3+4 真实数据测试")
    print(f"ES 地址: {args.es_host}")
    print(f"时间范围: 最近 {args.hours} 小时")
    
    # Step 1: 连接 ES
    es_client = test_es_connection(args.es_host)
    
    # Step 2: 列出索引
    indices = list_indices(es_client)
    if not indices:
        print("\n[WARN] 没有数据索引，请先运行采集器收集数据")
        return
    
    # Step 3: 查询样本事件
    events = query_sample_events(es_client, args.hours)
    if not events:
        print("\n[WARN] 没有查询到事件数据")
        return
    
    # Step 4: 测试组员3
    threats, seeds = test_context_engine(es_client, events)
    
    # Step 5: 测试组员4 - 图构建和富化
    graph, enricher = test_graph_analyzer(es_client, events, seeds)
    
    # Step 6: 测试组员4 - 溯源系统
    provenance_result = test_provenance_system(es_client, seeds)
    
    # 总结
    print_separator("测试完成")
    print(f"""
总结:
  - 查询事件数: {len(events)}
  - 威胁事件数: {len(threats)}
  - 种子事件数: {len(seeds)}
  - 图节点数: {graph['stats']['total_nodes'] if graph else 0}
  - 图边数: {graph['stats']['total_edges'] if graph else 0}
  - 溯源结果: {'成功' if provenance_result else '跳过'}
    """)


if __name__ == "__main__":
    main()
