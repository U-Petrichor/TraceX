# /root/attack-tracing-system/test_common.py
from collector.common.schema import UnifiedEvent, EventInfo, SourceInfo
from collector.common.es_client import ESClient
import time

def test_integration():
    # 1. 测试 Schema：创建一个模拟的 SSH 登录失败事件
    print("--- 正在测试 Schema 格式化 ---")
    event_data = UnifiedEvent(
        event=EventInfo(
            category="authentication",
            action="ssh_login",
            outcome="failure",
            severity=7,
            dataset="test-suite"
        ),
        source=SourceInfo(ip="192.168.1.100", port=4433),
        message="Test authentication failure"
    )
    
    # 转换为字典（模拟存入 ES 前的步骤）
    event_dict = event_data.to_dict()
    print(f"格式化成功，生成的 ID: {event_dict['event']['id']}")

    # 2. 测试 ESClient 写入
    print("\n--- 正在测试 ES 写入 ---")
    client = ESClient(hosts=["http://localhost:9200"])
    try:
        event_id = client.write_event(event_dict, index_prefix="test-logs")
        print(f"写入成功！索引 ID: {event_id}")
        
        # 等待 ES 索引刷新
        time.sleep(2)
        
        # 3. 测试查询
        print("\n--- 正在测试数据查询 ---")
        # 查询最近 1 分钟的数据
        results = client.query_events(
            start_time="now-1m", 
            end_time="now", 
            index_prefix="test-logs"
        )
        
        if len(results) > 0:
            print(f"查询成功！找回了 {len(results)} 条测试数据。")
            print(f"校验原始信息: {results[0]['message']}")
        else:
            print("查询失败：未能找到刚刚存入的数据。")
            
    except Exception as e:
        print(f"集成测试出错: {e}")

if __name__ == "__main__":
    test_integration()
