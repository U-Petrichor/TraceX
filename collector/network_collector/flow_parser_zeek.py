# /root/TraceX/collector/network_collector/flow_parser_zeek.py

import json
import os
import sys
import time
from datetime import datetime

# 确保项目根目录在路径中
sys.path.append('/root/TraceX')
try:
    from collector.common.es_client import ESClient
    from collector.common.schema import (
        UnifiedEvent, EventInfo, SourceInfo, DestinationInfo, 
        NetworkInfo
    )
except ImportError:
    print("错误: 无法加载公共模块，请检查目录结构")
    sys.exit(1)

class ZeekParser:
    def __init__(self):
        # 手动测试时连接本地 ES
        self.es_client = ESClient(hosts=["http://localhost:9200"])
        # 指向 docker-compose 中映射的宿主机路径
        self.log_path = "/root/TraceX/data/zeek-logs/current/conn.log"

    def map_to_unified(self, raw_data: dict) -> dict:
        """将 Zeek conn.log 转换为统一格式"""
        
        # 处理时间戳
        ts = raw_data.get("ts")
        iso_ts = datetime.utcfromtimestamp(ts).isoformat() + "Z" if ts else datetime.utcnow().isoformat() + "Z"

        # 构建对象
        event_obj = UnifiedEvent(
            timestamp=iso_ts,
            event=EventInfo(
                category="network",
                type="connection",
                action="network_flow",
                outcome="success",
                severity=3,
                dataset="zeek.conn"
            ),
            source=SourceInfo(
                ip=raw_data.get("id.orig_h", ""),
                port=raw_data.get("id.orig_p", 0)
            ),
            destination=DestinationInfo(
                ip=raw_data.get("id.resp_h", ""),
                port=raw_data.get("id.resp_p", 0)
            ),
            network=NetworkInfo(
                protocol=raw_data.get("proto", ""),
                transport=raw_data.get("proto", ""),
                application=raw_data.get("service", ""),
                bytes=(raw_data.get("orig_bytes", 0) or 0) + (raw_data.get("resp_bytes", 0) or 0),
                packets=(raw_data.get("orig_pkts", 0) or 0) + (raw_data.get("resp_pkts", 0) or 0)
            ),
            message=f"Zeek Flow: {raw_data.get('id.orig_h')} -> {raw_data.get('id.resp_h')}",
            raw=raw_data
        )
        return event_obj.to_dict()

    def start_monitoring(self):
        """实时监听并解析"""
        if not os.path.exists(self.log_path):
            print(f"[*] 等待 Zeek 生成日志文件: {self.log_path}")
            while not os.path.exists(self.log_path):
                time.sleep(1)

        print(f"[*] 开始监控 Zeek 流量数据...")
        with open(self.log_path, "r") as f:
            # 移动到文件末尾，只处理新数据
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                
                try:
                    raw_log = json.loads(line)
                    unified_data = self.map_to_unified(raw_log)
                    
                    # 写入 ES
                    self.es_client.write_event(unified_data, index_prefix="network-flows")
                    print(f"[OK] 已解析流量: {unified_data['source']['ip']} -> {unified_data['destination']['ip']}")
                except Exception as e:
                    print(f"[Error] 解析失败: {e}")

if __name__ == "__main__":
    parser = ZeekParser()
    parser.start_monitoring()