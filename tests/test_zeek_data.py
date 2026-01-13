# /root/TraceX/tests/test_zeek_data.py

import sys
import json
from datetime import datetime

# 确保加载公共模块路径
sys.path.append('/root/TraceX')

try:
    from collector.common.es_client import ESClient
    from collector.common.schema import UnifiedEvent
except ImportError:
    print("[-] 错误: 无法加载公共模块 (es_client 或 schema)")
    sys.exit(1)

class TraceXValidator:
    def __init__(self):
        self.es = ESClient(hosts=["http://localhost:9200"])
        self.index_pattern = "network-flows-*"

    def run_compliance_check(self):
        print(f"[*] 启动 TraceX 数据合规性检查 (索引: {self.index_pattern})")
        
        # 1. 检索一条确实包含威胁名称的告警记录
        query_threat = {
            "query": { "wildcard": { "threat.technique.name": "*" } },
            "size": 1
        }
        
        # 2. 检索一条普通网络记录 (threat 字段不存在)
        query_normal = {
            "query": { "bool": { "must_not": { "exists": { "field": "threat" } } } },
            "size": 1
        }

        self._validate_sample(query_threat, "【威胁告警记录】")
        self._validate_sample(query_normal, "【普通流转记录】")

    def _validate_sample(self, query, label):
        print(f"\n--- 正在验证 {label} ---")
        try:
            # 使用 es 客户端进行搜索
            res = self.es.es.search(index=self.index_pattern, body=query)
            hits = res['hits']['hits']
            
            if not hits:
                print(f"[!] 跳过: 未找到符合条件的样本记录。")
                return

            raw_doc = hits[0]['_source']
            
            # 基础结构检查
            core_fields = ['@timestamp', 'event', 'source', 'destination']
            if all(f in raw_doc for f in core_fields):
                print(f"[+] 基础结构验证: 成功 (符合 ECS 规范)")
            
            # 核心步骤：尝试还原为 UnifiedEvent 对象
            try:
                event_obj = UnifiedEvent.from_dict(raw_doc)
                print(f"[+] 对象还原验证: 成功 (UnifiedEvent.from_dict 通刷成功)")
                
                # 安全地检查威胁信息
                if event_obj.threat and event_obj.threat.technique.name:
                    print(f"[+] 威胁建模识别: {event_obj.threat.technique.name}")
                    print(f"[+] 告警严重级别: {event_obj.event.severity}")
                else:
                    print(f"[-] 此记录不含威胁告警信息")

            except Exception as e:
                print(f"[-] 对象还原失败: 错误: {e}")

        except Exception as e:
            print(f"[-] ES 查询出错: {e}")

if __name__ == "__main__":
    validator = TraceXValidator()
    validator.run_compliance_check()
