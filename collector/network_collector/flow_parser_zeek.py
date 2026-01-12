# collector/network_collector/flow_parser.py

import json
from datetime import datetime
from collector.common.es_client import ESClient
from collector.common.schema import (
    UnifiedEvent, EventInfo, SourceInfo, DestinationInfo, 
    NetworkInfo, HostInfo
)

class NetworkFlowParser:
    """网络流量解析器：负责将 Zeek 等日志解析为统一范式并存储"""

    def __init__(self, es_hosts=["http://localhost:9200"]):
        # 初始化公共 ES 客户端
        self.es_client = ESClient(hosts=es_hosts)

    def _format_timestamp(self, ts):
        """处理 Zeek 浮点数时间戳为 ISO 格式"""
        if isinstance(ts, (int, float)):
            return datetime.utcfromtimestamp(ts).isoformat() + "Z"
        return ts

    def parse_zeek_conn(self, raw_data: dict) -> UnifiedEvent:
        """
        解析 Zeek conn.log 数据
        """
        # 1. 构建基础网络信息
        network = NetworkInfo(
            protocol=raw_data.get("proto", ""),
            transport=raw_data.get("proto", ""),
            application=raw_data.get("service", ""),
            bytes=(raw_data.get("orig_bytes", 0) or 0) + (raw_data.get("resp_bytes", 0) or 0),
            packets=(raw_data.get("orig_pkts", 0) or 0) + (raw_data.get("resp_pkts", 0) or 0),
            direction="inbound"  # 默认标记，后续可根据 IP 范围调整
        )

        # 2. 构建事件元信息
        event = EventInfo(
            category="network",
            type="connection",
            action="network_flow",
            outcome="success",
            severity=3,
            dataset="zeek.conn"
        )

        # 3. 映射源和目的
        source = SourceInfo(
            ip=raw_data.get("id.orig_h", ""),
            port=raw_data.get("id.orig_p", 0)
        )
        destination = DestinationInfo(
            ip=raw_data.get("id.resp_h", ""),
            port=raw_data.get("id.resp_p", 0)
        )

        # 4. 封装为 UnifiedEvent 对象
        unified_event = UnifiedEvent(
            timestamp=self._format_timestamp(raw_data.get("ts")),
            event=event,
            source=source,
            destination=destination,
            network=network,
            message=f"Network flow: {source.ip}:{source.port} -> {destination.ip}:{destination.port}",
            raw=raw_data  # 保留原始数据以便溯源
        )

        return unified_event

    def process_log_file(self, file_path: str, log_type: str = "conn"):
        """
        读取日志文件并批量写入 ES
        """
        events_to_write = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    if line.startswith("#"): continue  # 跳过 Zeek 头部注释
                    
                    raw_data = json.loads(line)
                    
                    if log_type == "conn":
                        unified_obj = self.parse_zeek_conn(raw_data)
                        # 转换为字典格式用于写入
                        events_to_write.append(unified_obj.to_dict())

            # 调用公共 ESClient 批量写入接口
            if events_to_write:
                result = self.es_client.write_events_bulk(
                    events_to_write, 
                    index_prefix="network-flows"
                )
                print(f"成功处理 {result['success']} 条记录，失败 {result['failed']} 条。")
                
        except Exception as e:
            print(f"处理日志文件时出错: {e}")

# 使用示例
if __name__ == "__main__":
    parser = NetworkFlowParser()
    # 假设 Zeek 日志已通过 Filebeat 或其他方式同步到本地
    # parser.process_log_file("/var/log/zeek/current/conn.log")