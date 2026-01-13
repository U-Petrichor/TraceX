# /root/TraceX/collector/network_collector/flow_parser_cowrie.py
import json
import os
import sys
import time
from datetime import datetime

# 导入公共模块
sys.path.append('/root/TraceX')
try:
    from collector.common.es_client import ESClient
    from collector.common.schema import (
        UnifiedEvent, EventInfo, SourceInfo, DestinationInfo, 
        HostInfo, UserInfo, ProcessInfo
    )
except ImportError:
    print("错误: 无法找到公共模块，请确认目录结构。")
    sys.exit(1)

class CowrieParser:
    def __init__(self):
        self.es_client = ESClient()
        self.log_path = "/root/TraceX/infrastructure/range/honeypots/cowrie/var/log/cowrie/cowrie.json"

    def map_to_unified(self, raw_log: dict) -> dict:
        """使用 Dataclass 构建符合规范的事件"""
        event_id = raw_log.get("eventid", "")
        
        # 1. 映射类别与严重程度
        category = "host"
        severity = 3
        outcome = "success"

        if "login" in event_id:
            category = "authentication"
            outcome = "success" if "success" in event_id else "failure"
            severity = 8 if outcome == "success" else 4
        elif "command" in event_id or "session.exec" in event_id:
            category = "process"
            severity = 6
        elif "direct-tcpip" in event_id:
            category = "network"
            severity = 5

        # 2. 构建结构化对象
        event_obj = UnifiedEvent(
            timestamp=raw_log.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            event=EventInfo(
                category=category,
                type="info",
                action=event_id,
                outcome=outcome,
                severity=severity,
                dataset="cowrie"
            ),
            source=SourceInfo(
                ip=raw_log.get("src_ip", ""),
                port=raw_log.get("src_port", 0)
            ),
            destination=DestinationInfo(
                ip=raw_log.get("dst_ip", ""),
                port=raw_log.get("dst_port", 0)
            ),
            host=HostInfo(
                name=raw_log.get("sensor", "cowrie-honeypot")
            ),
            user=UserInfo(
                name=raw_log.get("username", "")
            ),
            process=ProcessInfo(
                command_line=raw_log.get("input", ""),
                name="bash" if raw_log.get("input") else ""
            ),
            message=raw_log.get("message", ""),
            raw=raw_log
        )
        
        # 返回标准的字典格式
        return event_obj.to_dict()

    def start_parsing(self):
        if not os.path.exists(self.log_path):
            print(f"等待日志文件: {self.log_path}")
            while not os.path.exists(self.log_path): time.sleep(1)

        print(f"[*] Cowrie 解析器启动，正在监听: {self.log_path}")
        with open(self.log_path, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    raw_log = json.loads(line)
                    # 过滤掉一些无意义的噪音日志（可选）
                    if raw_log.get("eventid") in ["cowrie.session.connect", "cowrie.session.closed", "cowrie.login.failed", "cowrie.command.input"]:
                        unified_data = self.map_to_unified(raw_log)
                        self.es_client.write_event(unified_data)
                        print(f"已入库: {raw_log.get('eventid')} | 源 IP: {raw_log.get('src_ip')}")
                except Exception as e:
                    print(f"解析失败: {e}")

if __name__ == "__main__":
    parser = CowrieParser()
    parser.start_parsing()