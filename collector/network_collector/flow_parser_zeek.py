# /root/TraceX/collector/network_collector/flow_parser_zeek.py

import json
import os
import sys
import time
from datetime import datetime, timezone

# 确保项目根目录在路径中
sys.path.append('/root/TraceX')

try:
    from collector.common.es_client import ESClient
    from collector.common.schema import (
        UnifiedEvent, EventInfo, SourceInfo, DestinationInfo, NetworkInfo
    )
except ImportError:
    print("错误: 无法加载公共模块，请检查目录结构")
    sys.exit(1)

class ZeekParser:
    def __init__(self):
        # 初始化 ES 客户端与日志路径
        self.es_client = ESClient(hosts=["http://localhost:9200"])
        self.log_path = "/root/TraceX/data/zeek-logs/conn.log"

    def map_to_unified(self, raw_data: dict) -> dict:
        """将 Zeek 原始数据映射到标准 Schema"""
        ts = raw_data.get("ts")
        iso_ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z") if ts else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        event_obj = UnifiedEvent(
            timestamp=iso_ts,
            event=EventInfo(
                category="network", type="connection", action="network_flow",
                outcome="success", severity=3, dataset="zeek.conn"
            ),
            source=SourceInfo(
                ip=raw_data.get("id.orig_h", ""), port=raw_data.get("id.orig_p", 0)
            ),
            destination=DestinationInfo(
                ip=raw_data.get("id.resp_h", ""), port=raw_data.get("id.resp_p", 0)
            ),
            network=NetworkInfo(
                protocol=raw_data.get("proto", "unknown"),
                transport=raw_data.get("proto", "unknown"),
                application=raw_data.get("service", ""),
                bytes=(raw_data.get("orig_bytes") or 0) + (raw_data.get("resp_bytes") or 0),
                packets=(raw_data.get("orig_pkts") or 0) + (raw_data.get("resp_pkts") or 0)
            ),
            message=f"Zeek Flow: {raw_data.get('id.orig_h')} -> {raw_data.get('id.resp_h')}",
            raw=raw_data
        )
        return event_obj.to_dict()

    def start_monitoring(self, read_from_start=True):
        """实时监听并解析日志，支持文件轮转感知"""
        if not os.path.exists(self.log_path):
            print(f"[*] 等待日志生成: {self.log_path}")
            while not os.path.exists(self.log_path):
                time.sleep(1)

        print(f"[*] 发现日志，开始实时监控 (轮转感知模式已开启)...")
        
        f = open(self.log_path, "r")
        # 获取当前打开文件的 Inode 编号
        last_ino = os.fstat(f.fileno()).st_ino

        # 如果不从头读，就跳到末尾
        if not read_from_start:
            f.seek(0, 2)
        
        while True:
            line = f.readline()
            
            # 如果读不到新行，检查文件是否被 Zeek 轮转了
            if not line:
                try:
                    # 检查磁盘上 conn.log 的最新 Inode
                    current_ino = os.stat(self.log_path).st_ino
                    if current_ino != last_ino:
                        print(f"[*] 检测到文件轮转 (Inode {last_ino} -> {current_ino})，重新打开文件...")
                        f.close()
                        f = open(self.log_path, "r")
                        last_ino = current_ino
                        continue # 重新开始读取新文件
                except FileNotFoundError:
                    # 可能正在轮转的瞬间文件不存在
                    pass
                
                time.sleep(0.5) # 短暂等待新数据写入
                continue
            
            line = line.strip()
            if not line.startswith('{'): # 跳过 Zeek 的头部注释行
                continue
            
            try:
                raw_log = json.loads(line)
                unified_data = self.map_to_unified(raw_log)
                
                # 写入 ES
                self.es_client.write_event(unified_data, index_prefix="network-flows")
                # 打印摘要，方便观察
                print(f"[OK] {unified_data['source']['ip']} -> {unified_data['destination']['ip']} ({unified_data['network']['protocol']})")
            except Exception as e:
                print(f"[Error] 解析失败: {e}")

if __name__ == "__main__":
    parser = ZeekParser()
    # 第一次运行建议设为 True，把现有的日志全部刷进 ES
    try:
        parser.start_monitoring(read_from_start=True)
    except KeyboardInterrupt:
        print("\n[*] 监控已手动停止")
        sys.exit(0)
