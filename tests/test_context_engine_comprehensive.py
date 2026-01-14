import sys
import os
import logging
from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
sys.path.append(os.getcwd())

try:
    from analyzer.attack_analyzer.context_engine import ContextEngine
except ImportError as e:
    print(f"❌ 导入错误: {e}")
    sys.exit(1)

def run_test():
    print("="*60)
    print("🚀 开始测试 Step 1: Context Engine (上下文分析引擎)")
    print("="*60)

    try:
        es_client = Elasticsearch(["http://localhost:9200"])
        if not es_client.ping():
            raise ConnectionError("无法连接到 Elasticsearch (localhost:9200)")
        engine = ContextEngine(es_client)
        print("✅ ContextEngine 初始化成功 | ES 连接状态: 正常")
    except Exception as e:
        print(f"❌ 初始化失败: {e}")
        return

    test_cases = [
        {
            "name": "🛡️ 组员1 - Host Auditd (WebShell 写入)",
            "index": "unified-logs*",
            "query": {
                "bool": {
                    "should": [
                        # 尝试多种方式匹配 PHP 文件
                        {"wildcard": {"file.path": "*php*"}},
                        {"wildcard": {"process.command_line": "*php*"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            # 只要是 Root 操作(80) 或 WebShell(90) 均可，重点是能找到数据
            "expected_score_min": 80, 
            "verify_logic": "evaluate_threat"
        },
        {
            "name": "🧠 组员1 - MemDefense (无文件攻击)",
            "index": "unified-logs*",
            "query": {"term": {"event.category": "memory"}},
            "expected_score_min": 90,
            "verify_logic": "evaluate_threat"
        },
        {
            "name": "📡 组员2 - Zeek Flow (DNS/ICMP 隧道)",
            "index": "network-flows*",
            "query": {"range": {"event.severity": {"gte": 7}}},
            "expected_score_min": 70,
            "verify_logic": "evaluate_threat"
        },
        {
            "name": "🍯 组员2 - Cowrie Honeypot (APT 命令)",
            "index": "honeypot-logs*",
            "query": {"match": {"event.dataset": "cowrie"}},
            "expected_score_min": 50,
            "verify_logic": "evaluate_threat"
        }
    ]

    for case in test_cases:
        print(f"\n[测试场景] {case['name']} ...")
        try:
            # 增加 query 打印，方便调试
            res = es_client.search(index=case['index'], body={"query": case['query'], "size": 1, "sort": [{"@timestamp": "desc"}]})
            hits = res['hits']['hits']
            
            if len(hits) == 0:
                print(f"   ⚠️  跳过: ES 中未找到相关数据 (索引: {case['index']})")
                continue
            
            raw_hit = hits[0]['_source']
            event_id = hits[0]['_id']
            # 注入 ID
            if 'event' not in raw_hit: raw_hit['event'] = {}
            raw_hit['event']['id'] = event_id 
            
            print(f"   ✅ 获取样本成功 (ID: {event_id})")
            
            # 打印关键调试信息
            if "Host" in case['name']:
                print(f"      File Path: {raw_hit.get('file', {}).get('path')}")
                print(f"      Command:   {raw_hit.get('process', {}).get('command_line')}")

            threat_result = engine.evaluate_threat(raw_hit)
            score = threat_result.get('score', 0)
            reasons = threat_result.get('reasons', [])
            
            print(f"   🔍 评分结果: {score} 分 | 级别: {threat_result.get('severity')}")
            print(f"   📝 判黑依据: {reasons}")
            
            if score >= case['expected_score_min']:
                print("   ✅ [PASS] 评分逻辑验证通过")
            else:
                print(f"   ❌ [FAIL] 评分过低 (预期 >= {case['expected_score_min']})")

            # 关联测试
            if "Host" in case['name'] or "Zeek" in case['name'] or "Honeypot" in case['name']:
                print(f"   🔗 正在测试关联搜索 (Find Related)...")
                related = engine.find_related_events(raw_hit, window=60)
                print(f"   🔍 关联事件数量: {len(related)}")

        except Exception as e:
            print(f"   ❌ 运行崩溃: {e}")

if __name__ == "__main__":
    run_test()
