# tests/test_zeek_data.py
import sys
import os
from datetime import datetime, timedelta

# 确保可以加载项目根目录下的模块
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from collector.common.es_client import ESClient
    from collector.common.schema import UnifiedEvent
except ImportError:
    print("错误: 无法加载公共模块，请检查目录结构")
    sys.exit(1)

def run_zeek_data_test():
    print("=== 开始 Zeek 数据标准化测试 ===")
    
    # 1. 初始化客户端
    client = ESClient(hosts=["http://localhost:9200"])
    
    # 2. 确定查询时间范围（查询过去 10 分钟的数据）
    now = datetime.utcnow()
    start_time = (now - timedelta(minutes=10)).isoformat() + "Z"
    end_time = now.isoformat() + "Z"
    
    print(f"[*] 正在从 ES 查询范围: {start_time} 至 {end_time}")

    # 3. 从索引 network-flows-* 中检索数据
    raw_events = client.query_events(
        start_time=start_time,
        end_time=end_time,
        index_prefix="network-flows"
    )
    
    if not raw_events:
        print("[!] 警告: 未在指定时间内找到任何 Zeek 数据，请确保解析脚本正在运行。")
        return

    print(f"[*] 找到 {len(raw_events)} 条原始记录，开始模式校验...")

    success_count = 0
    fail_count = 0

    for i, event_dict in enumerate(raw_events):
        try:
            # 4. 尝试使用 schema.py 中的 from_dict 进行还原
            unified_obj = UnifiedEvent.from_dict(event_dict)
            
            # 5. 关键字段业务校验
            # 检查是否为 Zeek 数据集
            assert unified_obj.event.dataset == "zeek.conn", f"Dataset 不匹配: {unified_obj.event.dataset}"
            # 检查关键网络字段是否存在
            assert unified_obj.source.ip != "", "源 IP 不能为空"
            assert unified_obj.destination.ip != "", "目的 IP 不能为空"
            assert unified_obj.network.protocol in ["tcp", "udp", "icmp", "unknown"], f"未知协议: {unified_obj.network.protocol}"
            
            success_count += 1
        except Exception as e:
            print(f"[FAIL] 记录 #{i} 校验失败: {e}")
            fail_count += 1

    # 6. 输出报告
    print("\n=== 测试报告 ===")
    print(f"通过: {success_count}")
    print(f"失败: {fail_count}")
    
    if fail_count == 0 and success_count > 0:
        print("\n[RESULT] 恭喜！Zeek 数据与公共 Schema 完全兼容。")
    elif success_count == 0:
        print("\n[RESULT] 未能成功验证任何数据。")
    else:
        print("\n[RESULT] 部分数据不符合标准，请检查映射逻辑。")

if __name__ == "__main__":
    run_zeek_data_test()
