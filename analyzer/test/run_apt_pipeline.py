"""
APT 攻击链分析流水线
支持两种模式：
1. direct: 直接使用事件中的 TTP (跳过 Sigma)
2. sigma: 使用 Sigma 规则检测生成 TTP

用法:
  python run_apt_pipeline.py --mode direct                     # 分析所有直接TTP事件
  python run_apt_pipeline.py --mode sigma                      # 分析所有仿真事件(Sigma检测)
  python run_apt_pipeline.py --mode direct --data APT28.jsonl  # 分析指定文件
  python run_apt_pipeline.py --mode sigma --data APT28.jsonl   # 分析指定文件(Sigma)
"""
import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzer.graph_analyzer.graph_builder import GraphBuilder
from analyzer.graph_analyzer.atlas_mapper import AtlasMapper
from analyzer.graph_analyzer.enrichment import IntelEnricher
from analyzer.attack_analyzer.attack_tagger import AttackAnalyzer


def _load_events(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _collect_ttps_from_sigma(events):
    """使用 Sigma 规则检测 TTP"""
    analyzer = AttackAnalyzer()
    analyzer.initialize()
    ttps = []
    matched_rules = []
    for e in events:
        result = analyzer.analyze_event(e)
        for tech in result.get("techniques", []):
            ttp_id = tech.get("technique", {}).get("id")
            if ttp_id:
                ttps.append(ttp_id)
        matched_rules.extend(result.get("matched_rules", []))
    return list(set(ttps)), list(set(matched_rules))


def _collect_ttps_direct(events):
    """直接从事件中提取 TTP"""
    ttps = []
    for e in events:
        ttp_id = e.get("threat", {}).get("technique", {}).get("id")
        if ttp_id:
            ttps.append(ttp_id)
    return list(set(ttps)), []


def _print_chain(graph):
    """打印攻击链条结构"""
    nodes_by_id = {n.get("id"): n for n in graph.get("nodes", [])}
    edges = graph.get("edges", [])
    
    if not edges:
        print("  (无边)")
        return
    
    # 按时间排序
    edges_sorted = sorted(edges, key=lambda x: x.get("timestamp", ""))
    
    for edge in edges_sorted:
        src = nodes_by_id.get(edge.get("source"), {})
        dst = nodes_by_id.get(edge.get("target"), {})
        src_label = src.get("label", "unknown")
        dst_label = dst.get("label", "unknown")
        src_type = src.get("type", "unknown")
        dst_type = dst.get("type", "unknown")
        relation = edge.get("relation", "related")
        print(f"  [{src_type}] {src_label} --{relation}--> [{dst_type}] {dst_label}")


def _analyze_file(file_path: Path, mode: str, builder: GraphBuilder, enricher: IntelEnricher, atlas: AtlasMapper):
    """分析单个事件文件"""
    events = _load_events(file_path)
    
    # === 1. 构图 ===
    graph = builder.build_from_events(events)
    
    # === 2. ATLAS 签名 (仅语义描述，不参与归因) ===
    labels = [atlas.get_label(e) for e in events]
    signature = " -> ".join(sorted(set([l for l in labels if l != "UNKNOWN"])))
    
    # === 3. TTP 提取 ===
    if mode == "sigma":
        ttps, matched_rules = _collect_ttps_from_sigma(events)
    else:
        ttps, matched_rules = _collect_ttps_direct(events)
    
    # === 4. 归因 ===
    attribution = enricher.attribute_by_ttps(ttps)
    
    # === 5. IOC 富化 ===
    ioc = enricher.enrich_entities(graph.get("nodes", []))
    
    # === 6. APT Profile ===
    suspected = attribution.get("suspected_group")
    profile = None
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
            mitre_profile = enricher.get_mitre_apt_info(suspected)
            if mitre_profile:
                profile = mitre_profile
    
    # === 输出 ===
    print("\n" + "=" * 70)
    print(f"APT 模拟: {file_path.stem}")
    print(f"模式: {'Sigma 检测' if mode == 'sigma' else '直接 TTP'}")
    print(f"事件数: {len(events)} | 节点数: {len(graph.get('nodes', []))} | 边数: {len(graph.get('edges', []))}")
    
    print(f"\n【1. 攻击链签名 (ATLAS)】")
    print(f"  {signature if signature else 'UNKNOWN'}")
    
    print(f"\n【2. 攻击链条结构 (节点 -> 边 -> 节点)】")
    _print_chain(graph)
    
    print(f"\n【3. TTP 归因结果】")
    print(json.dumps(attribution, ensure_ascii=False, indent=2))
    
    if mode == "sigma" and matched_rules:
        print(f"\n【Sigma 命中规则】")
        print(json.dumps(sorted(matched_rules), ensure_ascii=False, indent=2))
    
    if profile:
        print(f"\n【4. APT Profile】")
        print(json.dumps(profile, ensure_ascii=False, indent=2))
    
    print(f"\n【5. IOC 富化结果】")
    print(json.dumps(ioc, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description="APT 攻击链分析流水线")
    parser.add_argument("--mode", default="direct", choices=["direct", "sigma"],
                        help="分析模式: direct=直接TTP, sigma=Sigma检测")
    parser.add_argument("--data", default=None, help="指定单个 JSONL 文件名 (如 APT28.jsonl)")
    args = parser.parse_args()
    
    # 确定数据目录
    base_dir = Path(__file__).resolve().parent / "apt_events"
    if args.mode == "sigma":
        data_dir = base_dir / "sigma"
    else:
        data_dir = base_dir / "direct"
    
    if not data_dir.exists():
        print(f"[!] 找不到目录: {data_dir}")
        print(f"    请先运行对应的生成脚本:")
        if args.mode == "sigma":
            print(f"    python analyzer/test/generate_events_for_sigma.py")
        else:
            print(f"    python analyzer/test/generate_events_with_ttp.py")
        return
    
    # 初始化组件
    enricher = IntelEnricher()
    builder = GraphBuilder()
    atlas = AtlasMapper()
    
    # 分析
    if args.data:
        # 指定单个文件
        file_path = data_dir / args.data
        if not file_path.exists():
            print(f"[!] 找不到文件: {file_path}")
            return
        _analyze_file(file_path, args.mode, builder, enricher, atlas)
    else:
        # 分析目录下所有文件
        files = sorted(data_dir.glob("*.jsonl"))
        if not files:
            print(f"[!] 目录为空: {data_dir}")
            return
        for file_path in files:
            _analyze_file(file_path, args.mode, builder, enricher, atlas)


if __name__ == "__main__":
    main()
