import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzer.graph_analyzer.graph_builder import GraphBuilder
from analyzer.graph_analyzer.atlas_mapper import AtlasMapper
from analyzer.graph_analyzer.enrichment import IntelEnricher


def _load_events(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _print_chain(graph):
    nodes_by_id = {n.get("id"): n for n in graph.get("nodes", [])}
    print("\n链条结构 (source -> target):")
    for edge in graph.get("edges", []):
        src = nodes_by_id.get(edge.get("source"), {})
        dst = nodes_by_id.get(edge.get("target"), {})
        src_label = src.get("label", "unknown")
        dst_label = dst.get("label", "unknown")
        src_type = src.get("type", "unknown")
        dst_type = dst.get("type", "unknown")
        relation = edge.get("relation", "related")
        print(f"- [{src_type}] {src_label} --{relation}--> [{dst_type}] {dst_label}")


def _print_result(title, events, graph, attribution, ioc, profile, signature):
    print("\n" + "=" * 60)
    print(f"APT 模拟: {title}")
    print(f"事件数: {len(events)} | 节点数: {len(graph.get('nodes', []))} | 边数: {len(graph.get('edges', []))}")
    print(f"攻击链签名: {signature if signature else 'UNKNOWN'}")
    _print_chain(graph)
    print("\n归因结果:")
    print(json.dumps(attribution, ensure_ascii=False, indent=2))
    if profile:
        print("\nAPTProfile:")
        print(json.dumps(profile, ensure_ascii=False, indent=2))
    print("\nIOC 结果:")
    print(json.dumps(ioc, ensure_ascii=False, indent=2))


def main():
    base_dir = Path(__file__).resolve().parent / "apt_events"
    if not base_dir.exists():
        print(f"[!] 找不到目录: {base_dir}")
        print("    先运行: python tests/test/generate_apt_events.py")
        return

    enricher = IntelEnricher()
    builder = GraphBuilder()

    atlas = AtlasMapper()
    for file_path in sorted(base_dir.glob("*.jsonl")):
        events = _load_events(file_path)
        graph = builder.build_from_events(events)

        labels = [atlas.get_label(e) for e in events]
        signature = " -> ".join(sorted(set([l for l in labels if l != "UNKNOWN"])))

        ttps = []
        for e in events:
            ttp_id = e.get("threat", {}).get("technique", {}).get("id")
            if ttp_id:
                ttps.append(ttp_id)

        attribution = enricher.attribute_by_ttps(list(set(ttps)))
        ioc = enricher.enrich_entities(graph.get("nodes", []))

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

        _print_result(file_path.stem, events, graph, attribution, ioc, profile, signature)


if __name__ == "__main__":
    main()
