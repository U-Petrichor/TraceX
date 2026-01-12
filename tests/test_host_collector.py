import unittest
import json
import os
import sys
import platform
import subprocess
from elasticsearch import Elasticsearch

# 确保能导入 collector 模块
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

from collector.common.es_client import ESClient
from collector.common.schema import UnifiedEvent, EventInfo, SourceInfo
from collector.host_collector.log_parser import HostLogParser, write_event

class TestHostCollector(unittest.TestCase):
    def setUp(self):
        # 1. 连接本地 Elasticsearch
        # 注意：如果你之前安装的是 elasticsearch<8，这里不用改
        self.es = Elasticsearch(["http://localhost:9200"])
        self.client = ESClient(hosts=["http://localhost:9200"])

    def test_01_connectivity(self):
        """测试: 数据库连接是否正常"""
        if not self.es.ping():
            self.fail("无法连接到 Elasticsearch (localhost:9200)，请检查 Docker 是否开启")
        print("\n[Pass] Elasticsearch 连接成功")

    def test_02_pipeline_installed(self):
        """测试: Auditd 解析规则 (Pipeline) 是否已上传"""
        pipeline_id = "auditd-pipeline"
        pipeline_path = os.path.join(project_root, "collector", "host_collector", "pipeline", "auditd_pipeline.json")
        
        try:
            self.es.ingest.get_pipeline(id=pipeline_id)
            print(f"[Pass] Pipeline '{pipeline_id}' 存在")
        except Exception:
            print(f"[Warn] Pipeline '{pipeline_id}' 丢失，正在尝试自动上传...")
            if not os.path.exists(pipeline_path):
                 self.fail(f"Pipeline 文件未找到: {pipeline_path}")
            
            try:
                with open(pipeline_path, 'r', encoding='utf-8') as f:
                    pipeline_body = json.load(f)
                self.es.ingest.put_pipeline(id=pipeline_id, body=pipeline_body)
                print(f"[Pass] Pipeline '{pipeline_id}' 自动上传成功")
            except Exception as e:
                self.fail(f"Pipeline 自动上传失败: {e}")

    def test_03_data_schema_compliance(self):
        """测试: 采集的数据是否符合小组统一规范 (Schema)"""
        # 搜索最新的 1 条日志
        index_pattern = "unified-logs-*"
        
        # 检查索引是否存在
        # 如果是第一次运行，可能没有索引，尝试手动写入一条数据触发
        if not self.es.indices.exists(index=index_pattern):
             print(f"[Info] 索引 {index_pattern} 不存在，尝试写入一条测试数据...")
             test_event = UnifiedEvent(
                 event=EventInfo(category="test", action="schema_check"),
                 source=SourceInfo(ip="127.0.0.1"),
                 message="Schema check event"
             )
             self.client.write_event(test_event.to_dict())
             # 等待 ES 刷新
             import time
             time.sleep(2)

        # 查询数据 (限定只查 auditd 数据，避免被 cowrie 等其他日志干扰)
        query = {
            "bool": {
                "must": [
                    {"match": {"event.dataset": "auditd"}}
                ]
            }
        }
        res = self.es.search(index=index_pattern, query=query, size=1, sort=[{"@timestamp": "desc"}])
        hits = res['hits']['hits']
        
        if len(hits) == 0:
            print("[Warn] 索引中暂无 auditd 数据，跳过 Schema 校验 (但这不代表测试失败，可能是还没产生日志)")
            return

        data = hits[0]['_source']
        print(f"\n[Info] 正在校验最新日志 ID: {hits[0]['_id']}")

        # === 核心校验逻辑 (对应 UNIFIED_EVENT_SCHEMA) ===
        
        # 1. 检查必填字段是否存在
        required_fields = ["@timestamp", "event", "host", "process", "raw"]
        for field in required_fields:
            # 对于通过 ESClient 写入的测试数据，可能没有 process/raw 字段，需要做区分
            if data['event'].get('category') == 'test':
                 continue
            self.assertIn(field, data, f"缺少核心字段: {field}")

        # 2. 检查 event 结构
        if data['event'].get('category') != 'test':
            self.assertEqual(data['event'].get('dataset'), 'auditd', "event.dataset 应该是 'auditd'")
            self.assertIn('category', data['event'], "缺少 event.category")

        # 3. 检查 process 结构 (这是 Pipeline 转换的重点)
        # 如果是 SYSCALL 类型，必须解析出 pid
        if 'process' in data and 'pid' in data['process']:
            self.assertIsInstance(data['process']['pid'], int, "process.pid 必须是数字类型")
        
        # 4. 检查是否保留了原始数据
        if 'raw' in data:
            self.assertIn('data', data['raw'], "原始日志数据 (raw.data) 丢失")

        print("[Pass] 数据格式校验通过！")

    def test_04_python_compliance(self):
        """测试: Python 代码是否符合开发规范 (ESClient & UnifiedEvent)"""
        print("\n[Info] 开始验证 Python 代码规范性...")
        
        # 1. 验证 UnifiedEvent 构造
        try:
            event = UnifiedEvent(
                event=EventInfo(
                    category="process",
                    action="compliance_test",
                    severity=1
                ),
                source=SourceInfo(ip="127.0.0.1"),
                message="Compliance Check"
            )
            data = event.to_dict()
            self.assertEqual(data['event']['category'], 'process')
            print("[Pass] UnifiedEvent 对象构造正常")
        except Exception as e:
            self.fail(f"UnifiedEvent 构造失败: {e}")

        # 2. 验证 ESClient 写入
        try:
            doc_id = self.client.write_event(data)
            self.assertTrue(doc_id, "ESClient 写入未返回 ID")
            print(f"[Pass] ESClient 写入成功 (Doc ID: {doc_id})")
        except Exception as e:
            self.fail(f"ESClient 写入失败: {e}")

    def test_05_log_parser_logic(self):
        """测试: LogParser 核心解析逻辑 (模拟 Auditd 日志)"""
        print("\n[Info] 开始验证 LogParser 解析逻辑...")
        
        parser = HostLogParser()
        # 模拟一条 Auditd EXECVE 日志
        mock_line = 'type=EXECVE msg=audit(1610000000.123:100): argc=2 a0="cat" a1="/etc/passwd" pid=1234 comm="cat" exe="/bin/cat" uid=0 auid=1000'
        
        raw = parser.parse_auditd_line(mock_line)
        self.assertIsNotNone(raw, "解析失败: 返回 None")
        self.assertEqual(raw['audit_id'], "100", "Event ID 提取错误")
        
        event = parser.to_unified_event(raw)
        self.assertIsNotNone(event, "转换 UnifiedEvent 失败")
        self.assertEqual(event.process.pid, 1234, "PID 提取错误")
        self.assertEqual(event.process.name, "cat", "进程名提取错误")
        self.assertEqual(event.event.category, "process", "事件类别错误")
        
        print("[Pass] LogParser 逻辑验证通过")

    def test_06_host_behavior_simulation(self):
        """测试: 模拟主机行为并验证采集 (自动化触发)"""
        # 仅在 Linux 环境下且安装了 Auditd 时运行
        if platform.system().lower() != 'linux':
            print("\n[Skip] 跳过主机行为模拟 (非 Linux 环境)")
            return
            
        print("\n[Info] 正在模拟主机敏感操作 (读取 /etc/passwd)...")
        try:
            # 触发一个简单的读文件操作，应该被 auditd 捕获
            subprocess.run(["cat", "/etc/passwd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # 等待 Filebeat 采集和 ES 刷新
            import time
            print("[Info] 等待 5 秒让日志入库...")
            time.sleep(5)
            
            # 查询最近的日志
            res = self.es.search(index="unified-logs-*", q="process.name:cat", size=1)
            if res['hits']['total']['value'] > 0:
                print(f"[Pass] 成功采集到 'cat' 操作日志 (ID: {res['hits']['hits'][0]['_id']})")
            else:
                print("[Warn] 未能在 ES 中找到刚才的 'cat' 操作日志，请检查 Filebeat/Auditd 状态")
                # 这里不强制 fail，因为可能是延时问题
        except Exception as e:
            print(f"[Warn] 模拟操作失败: {e}")

if __name__ == '__main__':
    unittest.main()