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
try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    print("[Warn] elasticsearch module not found. ES tests will be skipped.")

# 确保能导入 collector 模块
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

try:
    from collector.common.es_client import ESClient
except ImportError:
    ESClient = None
from collector.common.schema import UnifiedEvent, EventInfo, SourceInfo, DestinationInfo, MetaData, DetectionInfo
from collector.host_collector.log_parser import HostLogParser, write_event

class TestHostCollector(unittest.TestCase):
    def setUp(self):
        # 1. 连接本地 Elasticsearch
        if ES_AVAILABLE and ESClient:
            self.es = Elasticsearch(["http://localhost:9200"])
            self.client = ESClient(hosts=["http://localhost:9200"])
        else:
            self.es = None
            self.client = None

    def _print_header(self, title):
        print("\n" + "="*60)
        print(f" {title}")
        print("="*60)

    def test_01_connectivity(self):
        """测试: 数据库连接是否正常"""
        self._print_header("Test 01: Elasticsearch Connectivity Check")
        
        if not ES_AVAILABLE:
            print("[Skip] elasticsearch module missing")
            return

        if not self.es.ping():
            self.fail("无法连接到 Elasticsearch (localhost:9200)，请检查 Docker 是否开启")
        
        print("[Pass] Elasticsearch 连接成功")

    def _clean_dict(self, data: dict) -> dict:
        """递归清理空值 (None, '', [], {})"""
        if not isinstance(data, dict):
            return data
            
        clean = {}
        for k, v in data.items():
            if isinstance(v, dict):
                nested = self._clean_dict(v)
                if nested:
                    clean[k] = nested
            elif isinstance(v, list):
                if v:
                    clean[k] = v
            elif v not in [None, ""]:
                clean[k] = v
        return clean

    def test_02_data_schema_compliance(self):
        """测试: 采集的数据是否符合小组统一规范 (Schema v4.0)"""
        self._print_header("Test 02: Data Schema Compliance (v4.0)")
        
        if not ES_AVAILABLE:
            print("[Skip] elasticsearch module missing")
            return

        # 搜索最新的 1 条日志
        index_pattern = "unified-logs-*"
        
        # 检查索引是否存在
        if not self.es.indices.exists(index=index_pattern):
             print(f"[Info] 索引 {index_pattern} 不存在，尝试写入一条测试数据...")
             test_event = UnifiedEvent(
                 event=EventInfo(category="test", action="schema_check"),
                 source=SourceInfo(ip="127.0.0.1"),
                 message="Schema check event"
             )
             self.client.write_event(self._clean_dict(test_event.to_dict()))
             import time
             time.sleep(2)

        # 查询数据
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
            print("[Warn] 索引中暂无 auditd 数据，跳过 Schema 校验")
            return

        data = hits[0]['_source']
        print(f"[Info] 正在校验最新日志 ID: {hits[0]['_id']}")

        # === 核心校验逻辑 ===
        # 注意：清理逻辑会移除空字段，因此这里只检查存在的字段是否合法，或者核心字段是否非空
        required_fields = ["@timestamp", "event"]
        for field in required_fields:
            self.assertIn(field, data, f"缺少核心字段: {field}")

        if data['event'].get('category') != 'test':
            self.assertEqual(data['event'].get('dataset'), 'auditd', "event.dataset 应该是 'auditd'")
            self.assertIn('category', data['event'], "缺少 event.category")

        if 'process' in data and 'pid' in data['process']:
            self.assertIsInstance(data['process']['pid'], int, "process.pid 必须是数字类型")
            if 'start_time' in data['process']:
                 print(f"  > process.start_time: {data['process']['start_time']}")
        
        if 'raw' in data:
            self.assertIn('records', data['raw'], "原始日志数据 (raw.records) 丢失")

        if 'metadata' in data:
             print(f"  > metadata: {data['metadata']}")
        if 'detection' in data:
             print(f"  > detection: {data['detection']}")

        print("[Pass] 数据格式校验通过")

    def test_03_python_compliance(self):
        """测试: Python 代码是否符合开发规范 (ESClient & UnifiedEvent v4.0)"""
        self._print_header("Test 03: Python Code Compliance Check")
        
        # 1. 验证 UnifiedEvent 构造
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
            # 清理空字段后再写入，避免 ES 出现 (empty) 字段
            cleaned_data = self._clean_dict(data)
            doc_id = self.client.write_event(cleaned_data)
            self.assertTrue(doc_id, "ESClient 写入未返回 ID")
            print(f"[Pass] ESClient 写入成功 (Doc ID: {doc_id})")
        except Exception as e:
            self.fail(f"ESClient 写入失败: {e}")
        
        print("[Pass] Python 代码规范性验证通过")

    def test_04_log_parser_logic(self):
        """测试: LogParser 核心解析逻辑"""
        self._print_header("Test 04: LogParser Logic Verification")
        
        parser = HostLogParser()
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
        
        self.assertEqual(event.process.pid, 1234, "PID 提取错误")
        self.assertEqual(event.process.name, "sh", "进程名提取错误")
        self.assertEqual(event.event.category, "file", "事件类别错误")
        self.assertIn("/tmp/evil.sh", event.process.command_line, "命令行重组错误")
        
        print(f"  > Process Start Time: {event.process.start_time}")
        self.assertTrue(event.process.start_time.startswith("2021-01-07"), "Process Start Time 未正确填充")
        
        print(f"  > MetaData Atlas Label: {event.metadata.atlas_label}")
        self.assertEqual(event.metadata.atlas_label, "TEMP_FILE", "Atlas Label 规则未生效")
        
        print("[Pass] LogParser v4.0 聚合与增强逻辑验证通过")

    def test_05_host_behavior_simulation(self):
        """测试: 模拟主机行为并验证采集"""
        self._print_header("Test 05: Host Behavior Simulation")
        
        if not ES_AVAILABLE:
            print("[Skip] elasticsearch module missing")
            return

        if platform.system().lower() != 'linux':
            print("[Skip] 跳过主机行为模拟 (非 Linux 环境)")
            return
        
        print("[Info] 正在模拟主机敏感操作 (读取 /etc/passwd)...")
        try:
            subprocess.run(["cat", "/etc/passwd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            print("[Info] 等待 15 秒让日志入库...")
            import time
            time.sleep(15)
            
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
            else:
                print("[Warn] 未能在 ES 中找到刚才的 'cat' 操作日志，请检查 Agent 运行状态")
                
        except Exception as e:
            print(f"[Warn] 模拟操作失败: {e}")

        print("[Pass] 主机行为模拟验证结束")

    def test_06_auditd_log_simulation(self):
        """测试: 模拟 Auditd 写文件并验证采集"""
        self._print_header("Test 06: Auditd Log File Simulation")
        
        import tempfile
        
        target_log = 'type=USER_LOGIN msg=audit(1616450000.123:101): pid=2000 uid=0 auid=4294967295 ses=4294967295 msg=\'op=login id=1000 exe="/usr/sbin/sshd" hostname=? addr=192.168.1.100 terminal=ssh res=failed\''
        flush_log = 'type=EOE msg=audit(1616450000.123:101):'
        
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8') as tmp:
            tmp_path = tmp.name
            print(f"[Info] 创建临时审计日志文件: {tmp_path}")
            tmp.write(target_log + "\n")
            tmp.write(flush_log + "\n")
            
        try:
            parser = HostLogParser()
            collected_event = None
            
            with open(tmp_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    result = parser.parse(line, log_type="auditd")
                    if result:
                        collected_event = result
                        break
            
            self.assertIsNotNone(collected_event, "未能采集到事件 (解析器未返回)")
            
            print(f"  > Event Category: {collected_event.event.category}")
            self.assertEqual(collected_event.event.category, "authentication", "Category 错误")
            self.assertEqual(collected_event.event.outcome, "failure", "Outcome 错误")
            
            print(f"  > Detection Severity: {collected_event.detection.severity}")
            self.assertEqual(collected_event.detection.severity, "low", "Detection Severity 未正确设置")
            
            # Verify new alignment requirement
            print(f"  > Event Severity: {collected_event.event.severity}")
            self.assertEqual(collected_event.event.severity, 4, "Event Severity 应为 Int 4 (Failure)")
            
            print("[Pass] 自定义 Auditd 日志模拟验证通过")
            
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
                print(f"[Info] 已清理临时文件: {tmp_path}")

    def test_07_severity_rules(self):
        """测试: 验证 Event Severity 评分逻辑 (1/4/8/10)"""
        self._print_header("Test 07: Severity Rules Verification")
        
        parser = HostLogParser()
        
        # Case 1: Root Operation (Success) -> Expect 8
        # uid=0
        log_root = 'type=SYSCALL msg=audit(1616450000.123:201): arch=c000003e syscall=2 success=yes exit=0 a0=... items=1 ppid=1 pid=1000 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="whoami" exe="/usr/bin/whoami" key=(null)'
        flush_root = 'type=EOE msg=audit(1616450000.123:201):'
        
        # Parse logic requires flush or smart buffering. EOE flushes.
        parser.parse(log_root, log_type="auditd")
        event_root = parser.parse(flush_root, log_type="auditd")
        
        if event_root:
            print(f"  > Case 1 (Root Success): Severity={event_root.event.severity}")
            self.assertEqual(event_root.event.severity, 8, "Root 操作应为 High (8)")
        else:
            self.fail("Case 1 Failed to parse")

        # Case 2: Sensitive File Access (Failure) -> Expect 10
        # /etc/passwd
        # Note: log_parser logic prioritizes sensitive file (10) over everything.
        log_sensitive = 'type=SYSCALL msg=audit(1616450000.123:202): arch=c000003e syscall=2 success=no exit=-13 items=1 ppid=1 pid=1000 auid=1000 uid=1000 gid=1000 ... comm="cat" exe="/usr/bin/cat" key=(null)'
        path_sensitive = 'type=PATH msg=audit(1616450000.123:202): item=0 name="/etc/passwd" inode=123 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL'
        flush_sensitive = 'type=EOE msg=audit(1616450000.123:202):'
        
        parser.parse(log_sensitive, log_type="auditd")
        parser.parse(path_sensitive, log_type="auditd")
        event_sensitive = parser.parse(flush_sensitive, log_type="auditd")
        
        if event_sensitive:
            print(f"  > Case 2 (Sensitive File): Severity={event_sensitive.event.severity}")
            self.assertEqual(event_sensitive.event.severity, 10, "触碰敏感文件应为 Critical (10)")
        else:
             self.fail("Case 2 Failed to parse")
             
        print("[Pass] Severity 评分逻辑验证通过")

    def test_08_session_reconstruction(self):
        """测试: 验证会话重建逻辑 (Session IP Caching)"""
        self._print_header("Test 08: Session Reconstruction")
        
        parser = HostLogParser()
        
        # 1. 模拟登录 (USER_LOGIN) - Session 1001 来自 192.168.1.50
        log_login = 'type=USER_LOGIN msg=audit(1616450000.123:301): pid=2000 uid=0 auid=0 ses=1001 msg=\'op=login id=1000 exe="/usr/sbin/sshd" hostname=? addr=192.168.1.50 terminal=ssh res=success\''
        flush_login = 'type=EOE msg=audit(1616450000.123:301):'
        
        parser.parse(log_login, log_type="auditd")
        event_login = parser.parse(flush_login, log_type="auditd")
        
        if event_login:
            print(f"  > Login Event: Session={event_login.user.session_id}, IP={event_login.source.ip}")
            self.assertEqual(event_login.user.session_id, "1001", "Session ID 提取失败")
            self.assertEqual(event_login.source.ip, "192.168.1.50", "Source IP 提取失败")
        else:
            self.fail("Login Event parse failed")

        # 2. 模拟后续命令 (SYSCALL) - Session 1001 执行 'whoami'
        # 注意: 原始日志里没有 addr 字段
        log_cmd = 'type=SYSCALL msg=audit(1616450010.123:302): arch=c000003e syscall=59 success=yes exit=0 a0=... ppid=2000 pid=2001 auid=0 uid=0 ses=1001 comm="whoami" exe="/usr/bin/whoami" key=(null)'
        flush_cmd = 'type=EOE msg=audit(1616450010.123:302):'
        
        parser.parse(log_cmd, log_type="auditd")
        event_cmd = parser.parse(flush_cmd, log_type="auditd")
        
        if event_cmd:
            print(f"  > Command Event: Session={event_cmd.user.session_id}, Enriched IP={event_cmd.source.ip}")
            self.assertEqual(event_cmd.user.session_id, "1001", "Command Session ID 提取失败")
            self.assertEqual(event_cmd.source.ip, "192.168.1.50", "未能从 Session Cache 回填 IP (Context Loss)")
        else:
            self.fail("Command Event parse failed")
            
        print("[Pass] 会话重建与 IP 回填验证通过")

if __name__ == '__main__':
    unittest.main()
