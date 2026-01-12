import json
import os
import sys
import time
import uuid
from datetime import datetime

# 1. 导入公共模块
# 确保项目根目录在路径中，以便加载 collector.common.es_client
sys.path.append('/root/TraceX')
try:
    from collector.common.es_client import ESClient
except ImportError:
    print("错误: 无法找到公共模块 es_client，请确认目录结构正确。")
    sys.exit(1)

class CowrieParser:
    """针对 Cowrie 蜜罐日志的解析器"""

    def __init__(self):
        self.es_client = ESClient()
        # 定义日志路径
        self.log_path = "/root/TraceX/infrastructure/range/honeypots/cowrie/var/log/cowrie/cowrie.json"

    def map_to_unified(self, raw_log: dict) -> dict:
        """将原始日志转换为 UNIFIED_EVENT_SCHEMA 格式"""
        event_id = raw_log.get("eventid", "")
        
        # 定义事件类别映射
        category = "host"
        if "login" in event_id:
            category = "authentication"
        elif "command" in event_id or "session.exec" in event_id:
            category = "process"
        elif "direct-tcpip" in event_id:
            category = "network"

        # 映射严重程度 (1-10)
        severity = 3
        if "login.success" in event_id: severity = 8
        if "command.input" in event_id: severity = 6

        # 构造统一格式字典
        unified_event = {
            "@timestamp": raw_log.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            "event": {
                "id": str(uuid.uuid4()),
                "category": category,
                "type": "info",
                "action": event_id,
                "outcome": "success" if "success" in event_id else "failure",
                "severity": severity,
                "dataset": "cowrie"
            },
            "source": {
                "ip": raw_log.get("src_ip", ""),
                "port": raw_log.get("src_port", 0)
            },
            "destination": {
                "ip": raw_log.get("dst_ip", ""),
                "port": raw_log.get("dst_port", 0)
            },
            "host": {
                "name": raw_log.get("sensor", "cowrie-honeypot")
            },
            "user": {
                "name": raw_log.get("username", "")
            },
            "process": {
                "command_line": raw_log.get("input", ""),
                "name": "ssh_shell" if raw_log.get("input") else ""
            },
            "message": raw_log.get("message", ""),
            "raw": raw_log  # 保留原始日志以便组员 3、4 深度分析
        }
        return unified_event

    def start_parsing(self):
        """实时监听文件并解析入库"""
        if not os.path.exists(self.log_path):
            print(f"等待日志文件生成: {self.log_path}")
            while not os.path.exists(self.log_path):
                time.sleep(1)

        print(f"开始解析蜜罐日志: {self.log_path}")
        with open(self.log_path, "r") as f:
            # 移动到文件末尾，仅处理启动后的新攻击
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                
                try:
                    raw_log = json.loads(line)
                    unified_data = self.map_to_unified(raw_log)
                    
                    # 写入 Elasticsearch
                    doc_id = self.es_client.write_event(unified_data)
                    print(f"[{unified_data['@timestamp']}] 已存入 ES | 类别: {unified_data['event']['category']} | 动作: {unified_data['event']['action']}")
                except Exception as e:
                    print(f"解析行失败: {e}")

if __name__ == "__main__":
    parser = CowrieParser()
    parser.start_parsing()
