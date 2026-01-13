# test_network_collector.py
import pytest
from collector.network_collector.flow_parser_zeek import NetworkFlowParser
from collector.common.schema import UnifiedEvent

def test_parse_zeek_conn():
    # 初始化解析器
    parser = NetworkFlowParser()
    
    # 1. 模拟一条 Zeek 原始日志
    mock_raw_log = {
        "ts": 1704067200.0,
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 44332,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "proto": "udp",
        "service": "dns",
        "orig_bytes": 100,
        "resp_bytes": 200,
        "orig_pkts": 2,
        "resp_pkts": 2
    }

    # 2. 调用解析函数
    result = parser.parse_zeek_conn(mock_raw_log)

    # 3. 验证解析结果
    # 验证是否返回了正确的 Dataclass 对象
    assert isinstance(result, UnifiedEvent)
    # 验证字段映射是否正确
    assert result.event.category == "network"
    assert result.source.ip == "192.168.1.10"
    assert result.destination.ip == "8.8.8.8"
    # 验证流量累加逻辑
    assert result.network.bytes == 300  
    
    # 4. 验证转换为字典后的格式（存入 ES 的最终格式）
    es_dict = result.to_dict()
    assert "@timestamp" in es_dict
    assert es_dict["@timestamp"] == "2024-01-01T00:00:00Z"
    
    print("\n✅ 解析逻辑验证通过！")

if __name__ == "__main__":
    # 如果不想用 pytest 命令，直接运行 python3 也可以触发
    test_parse_zeek_conn()