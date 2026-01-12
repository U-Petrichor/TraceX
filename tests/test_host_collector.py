import unittest
import json
from elasticsearch import Elasticsearch

class TestHostCollector(unittest.TestCase):
    def setUp(self):
        # 1. 连接本地 Elasticsearch
        # 注意：如果你之前安装的是 elasticsearch<8，这里不用改
        self.es = Elasticsearch(["http://localhost:9200"])

    def test_01_connectivity(self):
        """测试: 数据库连接是否正常"""
        if not self.es.ping():
            self.fail("无法连接到 Elasticsearch (localhost:9200)，请检查 Docker 是否开启")
        print("\n[Pass] Elasticsearch 连接成功")

    def test_02_pipeline_installed(self):
        """测试: Auditd 解析规则 (Pipeline) 是否已上传"""
        try:
            self.es.ingest.get_pipeline(id="auditd-pipeline")
            print("[Pass] Pipeline 'auditd-pipeline' 存在")
        except Exception as e:
            self.fail(f"Pipeline 丢失！请重新运行 curl 上传 pipeline.json。错误: {e}")

    def test_03_data_schema_compliance(self):
        """测试: 采集的数据是否符合小组统一规范 (Schema)"""
        # 搜索最新的 1 条日志
        index_pattern = "unified-logs-*"
        
        # 检查索引是否存在
        indices = self.es.indices.get_alias(index=index_pattern).keys()
        if not indices:
            self.fail(f"未找到索引 {index_pattern}，请先在终端执行 'cat /etc/passwd' 产生日志！")

        # 查询数据
        res = self.es.search(index=index_pattern, size=1, sort=[{"@timestamp": "desc"}])
        hits = res['hits']['hits']
        
        if len(hits) == 0:
            self.fail("索引存在但没有数据。Filebeat 可能没在运行。")

        data = hits[0]['_source']
        print(f"\n[Info] 正在校验最新日志 ID: {hits[0]['_id']}")

        # === 核心校验逻辑 (对应 UNIFIED_EVENT_SCHEMA) ===
        
        # 1. 检查必填字段是否存在
        required_fields = ["@timestamp", "event", "host", "process", "raw"]
        for field in required_fields:
            self.assertIn(field, data, f"缺少核心字段: {field}")

        # 2. 检查 event 结构
        self.assertEqual(data['event'].get('dataset'), 'auditd', "event.dataset 应该是 'auditd'")
        self.assertIn('category', data['event'], "缺少 event.category")

        # 3. 检查 process 结构 (这是 Pipeline 转换的重点)
        # 如果是 SYSCALL 类型，必须解析出 pid
        if 'pid' in data['process']:
            self.assertIsInstance(data['process']['pid'], int, "process.pid 必须是数字类型")
        
        # 4. 检查是否保留了原始数据
        self.assertIn('data', data['raw'], "原始日志数据 (raw.data) 丢失")

        print("[Pass] 数据格式校验通过！完全符合小组 Schema。")

if __name__ == '__main__':
    unittest.main()