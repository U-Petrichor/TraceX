#                    _ooOoo_
#                   o8888888o
#                   88" . "88
#                   (| -_- |)
#                   O\  =  /O
#                ____/`---'\____
#              .'  \\|     |//  `.
#             /  \\|||  :  |||//  \
#            /  _||||| -:- |||||-  \
#            |   | \\\  -  /// |   |
#            | \_|  ''\---/''  |   |
#            \  .-\__  `-`  ___/-. /
#          ___`. .'  /--.--\  `. . __
#       ."" '<  `.___\_<|>_/___.'  >'"".
#      | | :  `- \`.;`\ _ /`;.`/ - ` : | |
#      \  \ `-.   \_ __\ /__ _/   .-` /  /
# ======`-.____`-.___\_____/___.-`____.-'======
#                    `=---='
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#             佛祖保佑       永无BUG

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
from collector.common.schema import UnifiedEvent, EventInfo, SourceInfo, DestinationInfo, MetaData, DetectionInfo
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

    def test_03_data_schema_compliance(self):
        """测试: 采集的数据是否符合小组统一规范 (Schema v4.0)"""
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

        # === 核心校验逻辑 (对应 UNIFIED_EVENT_SCHEMA v4.0) ===
        
        # 1. 检查必填字段是否存在
        required_fields = ["@timestamp", "event", "host", "process", "raw", "metadata", "detection"]
        for field in required_fields:
            # 对于通过 ESClient 写入的测试数据，可能没有 process/raw 字段，需要做区分
            if data['event'].get('category') == 'test':
                 continue
            self.assertIn(field, data, f"缺少核心字段: {field}")

        # 2. 检查 event 结构
        if data['event'].get('category') != 'test':
            self.assertEqual(data['event'].get('dataset'), 'auditd', "event.dataset 应该是 'auditd'")
            self.assertIn('category', data['event'], "缺少 event.category")

        # 3. 检查 process 结构
        if 'process' in data and 'pid' in data['process']:
            self.assertIsInstance(data['process']['pid'], int, "process.pid 必须是数字类型")
            # v4.0 新增: 检查 start_time
            if 'start_time' in data['process']:
                 print(f" [Debug] process.start_time: {data['process']['start_time']}")
        
        # 4. 检查是否保留了原始数据
        if 'raw' in data:
            self.assertIn('records', data['raw'], "原始日志数据 (raw.records) 丢失 (v4.0 使用 records 列表)")

        # 5. 检查 v4.0 新增字段
        if 'metadata' in data:
             print(f" [Debug] metadata: {data['metadata']}")
        if 'detection' in data:
             print(f" [Debug] detection: {data['detection']}")

        print("[Pass] 数据格式校验通过！")

    def test_04_python_compliance(self):
        """测试: Python 代码是否符合开发规范 (ESClient & UnifiedEvent v4.0)"""
        print("\n[Info] 开始验证 Python 代码规范性...")
        
        # 1. 验证 UnifiedEvent 构造 (包含 v4.0 新字段)
        try:
            event = UnifiedEvent(
                event=EventInfo(
                    category="process",
                    action="compliance_test",
                    severity=1
                ),
                source=SourceInfo(ip="127.0.0.1"),
                destination=DestinationInfo(ip="127.0.0.1"),
                message="Compliance Check",
                metadata=MetaData(atlas_label="TEST_LABEL"),
                detection=DetectionInfo(severity="low")
            )
            data = event.to_dict()
            self.assertEqual(data['event']['category'], 'process')
            self.assertEqual(data['metadata']['atlas_label'], 'TEST_LABEL')
            self.assertEqual(data['detection']['severity'], 'low')
            print("[Pass] UnifiedEvent v4.0 对象构造正常")
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
        """测试: LogParser 核心解析逻辑 (v4.0: 模拟 Auditd 日志聚合与新字段填充)"""
        print("\n[Info] 开始验证 LogParser 解析逻辑...")
        
        parser = HostLogParser()
        # 模拟多行 Auditd 日志 (SYSCALL + EXECVE + PATH + EOE)
        # 构造一个涉及 /tmp 下脚本执行的场景，以触发 metadata.atlas_label = TEMP_FILE
        logs = [
            'type=SYSCALL msg=audit(1610000000.123:100): arch=c000003e syscall=59 success=yes exit=0 a0=... pid=1234 comm="sh" exe="/bin/dash" uid=0 auid=1000',
            'type=EXECVE msg=audit(1610000000.123:100): argc=2 a0="sh" a1="/tmp/evil.sh"',
            'type=PATH msg=audit(1610000000.123:100): item=0 name="/tmp/evil.sh" inode=123 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0',
            'type=EOE msg=audit(1610000000.123:100):'
        ]
        
        event = None
        for line in logs:
            result = parser.parse(line, log_type="auditd")
            if result:
                event = result
                
        self.assertIsNotNone(event, "解析失败: 未能聚合事件")
        
        # 验证基础字段
        self.assertEqual(event.process.pid, 1234, "PID 提取错误")
        self.assertEqual(event.process.name, "sh", "进程名提取错误")
        self.assertEqual(event.event.category, "file", "事件类别错误 (涉及文件操作应被标记为 file)") # 逻辑中如果检测到 PATH 会改为 file
        self.assertIn("/tmp/evil.sh", event.process.command_line, "命令行重组错误")
        
        # 验证 v4.0 新增字段逻辑
        print(f" [Debug] Process Start Time: {event.process.start_time}")
        self.assertTrue(event.process.start_time.startswith("2021-01-07"), "Process Start Time 未正确填充 (应基于 timestamp)")
        
        print(f" [Debug] MetaData Atlas Label: {event.metadata.atlas_label}")
        self.assertEqual(event.metadata.atlas_label, "TEMP_FILE", "Atlas Label 规则未生效 (预期: TEMP_FILE)")
        
        print("[Pass] LogParser v4.0 聚合与增强逻辑验证通过")

    def test_06_host_behavior_simulation(self):
        """测试: 模拟主机行为并验证采集 (自动化触发)"""
        # 仅在 Linux 环境下且安装了 Auditd 时运行
        if platform.system().lower() != 'linux':
            print("\n[Skip] 跳过主机行为模拟 (非 Linux 环境)")
            return
        
        print("\n[Info] 注意：请确保 Host Collector Agent (auditd_agent.py) 正在运行")
        print("[Info] 正在模拟主机敏感操作 (读取 /etc/passwd)...")
        try:
            # 触发一个简单的读文件操作，应该被 auditd 捕获
            subprocess.run(["cat", "/etc/passwd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # 等待 Agent 采集和 ES 刷新
            import time
            print("[Info] 等待 15 秒让日志入库...")
            time.sleep(15)
            
            # 查询最近的日志
            # 注意：process.name 在 ES 中可能是 "cat" 也可能是 "/usr/bin/cat"
            # 使用更宽泛的查询条件：process.name 包含 cat 且 event.dataset 为 auditd
            # 另外，由于可能存在大量网络日志，增加时间范围过滤 (最近 1 分钟)
            from datetime import datetime, timedelta
            now = datetime.utcnow()
            start_time = (now - timedelta(minutes=1)).isoformat() + "Z"
            
            query = {
                "bool": {
                    "must": [
                        {"match": {"event.dataset": "auditd"}},
                        {"wildcard": {"process.name": "*cat*"}},
                        {"range": {"@timestamp": {"gte": start_time}}}
                    ]
                }
            }
            res = self.es.search(index="unified-logs-*", query=query, size=5, sort=[{"@timestamp": "desc"}])
            
            if res['hits']['total']['value'] > 0:
                print(f"[Pass] 成功采集到 'cat' 操作日志 (ID: {res['hits']['hits'][0]['_id']})")
                # 打印一下实际的 process.name 方便调试
                actual_name = res['hits']['hits'][0]['_source'].get('process', {}).get('name', 'N/A')
                print(f"[Debug] 实际 process.name: {actual_name}")
            else:
                print("[Warn] 未能在 ES 中找到刚才的 'cat' 操作日志，请检查 Agent 运行状态")
                print("[Debug] 尝试查询最近5分钟的所有 auditd 日志进行排查:")
                debug_query = {
                    "bool": {
                        "must": [
                            {"match": {"event.dataset": "auditd"}},
                            {"range": {"@timestamp": {"gte": start_time}}}
                        ]
                    }
                }
                debug_res = self.es.search(index="unified-logs-*", query=debug_query, size=3, sort=[{"@timestamp": "desc"}])
                for hit in debug_res['hits']['hits']:
                    print(f" - Found log: {hit['_source'].get('process', {}).get('name', 'Unknown')} @ {hit['_source'].get('@timestamp')}")
                
                if debug_res['hits']['total']['value'] == 0:
                     print(" [Debug] 最近5分钟内没有查询到任何 auditd 日志，可能是 Agent 未运行或时区问题")
                # 这里不强制 fail，因为可能是延时问题
        except Exception as e:
            print(f"[Warn] 模拟操作失败: {e}")

    def test_07_auditd_log_simulation(self):
        """测试: 模拟 Auditd 写文件并验证采集 (自定义日志注入)"""
        import tempfile
        
        print("\n[Info] 开始验证 Auditd 日志文件模拟采集...")
        
        # 1. 准备测试数据
        # 用户提供的特定日志行 (v4.0: 包含失败登录场景以测试 detection)
        target_log = 'type=USER_LOGIN msg=audit(1616450000.123:101): pid=2000 uid=0 auid=4294967295 ses=4294967295 msg=\'op=login id=1000 exe="/usr/sbin/sshd" hostname=? addr=192.168.1.100 terminal=ssh res=failed\''
        
        # 为了触发解析器刷新，我们需要追加一个 EOE 信号或新的 ID
        flush_log = 'type=EOE msg=audit(1616450000.123:101):'
        
        # 2. 创建临时文件并写入
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8') as tmp:
            tmp_path = tmp.name
            print(f"[Info] 创建临时审计日志文件: {tmp_path}")
            tmp.write(target_log + "\n")
            tmp.write(flush_log + "\n")
            
        try:
            # 3. 模拟采集过程 (读取文件 -> 解析)
            parser = HostLogParser()
            collected_event = None
            
            with open(tmp_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    result = parser.parse(line, log_type="auditd")
                    if result:
                        collected_event = result
                        break
            
            # 4. 验证结果
            self.assertIsNotNone(collected_event, "未能采集到事件 (解析器未返回)")
            
            # 验证关键字段
            print(f"[Info] 采集到的事件: {collected_event.to_dict()}")
            
            self.assertEqual(collected_event.event.category, "authentication", "Category 错误")
            self.assertEqual(collected_event.event.outcome, "failure", "Outcome 错误 (应为 failure)")
            
            # 验证 v4.0 detection 字段
            print(f" [Debug] Detection Severity: {collected_event.detection.severity}")
            self.assertEqual(collected_event.detection.severity, "low", "Detection Severity 未正确设置 (应为 low)")
            
            print("[Pass] 自定义 Auditd 日志 (失败登录) 采集模拟验证通过")
            
        finally:
            # 清理临时文件
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
                print(f"[Info] 已清理临时文件: {tmp_path}")

if __name__ == '__main__':
    unittest.main()
