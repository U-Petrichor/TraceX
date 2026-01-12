import sys
import json
from datetime import datetime, timedelta

# 1. 引入公共模块
sys.path.append('/root/TraceX')
try:
    from collector.common.es_client import ESClient
    from collector.common.schema import UnifiedEvent
except ImportError:
    print("错误: 无法加载公共模块，请检查目录结构是否为 /root/TraceX/collector/common/")
    sys.exit(1)

class DataValidator:
    """数据质量自检工具"""

    def __init__(self):
        self.es = ESClient()
        self.stats = {
            "total": 0,
            "valid": 0,
            "invalid": 0,
            "missing_fields": {},
            "type_errors": 0
        }

    def check_quality(self, hours=1):
        """检查过去 X 小时内的数据质量"""
        now = datetime.utcnow()
        start_time = (now - timedelta(hours=hours)).isoformat() + "Z"
        end_time = now.isoformat() + "Z"

        print(f"[*] 开始自检时间段: {start_time} 至 {end_time}")
        
        # 调用公共接口查询数据
        events = self.es.query_events(start_time, end_time, size=500)
        self.stats["total"] = len(events)

        if not events:
            print("[!] 警告: 未在 ES 中发现任何数据，请检查 flow_parser.py 是否正在运行。")
            return

        for doc in events:
            self._validate_document(doc)

        self._print_report()

    def _validate_document(self, doc):
        """根据 UNIFIED_EVENT_SCHEMA 校验文档字段"""
        is_valid = True
        errors = []

        # 1. 核心必填字段校验
        mandatory_fields = ["@timestamp", "event", "source", "host"]
        for field in mandatory_fields:
            if field not in doc:
                is_valid = False
                self.stats["missing_fields"][field] = self.stats["missing_fields"].get(field, 0) + 1
                errors.append(f"缺失必填主字段: {field}")

        # 2. 严重程度逻辑校验 (1-10)
        severity = doc.get("event", {}).get("severity", 0)
        if not (1 <= severity <= 10):
            is_valid = False
            self.stats["type_errors"] += 1
            errors.append(f"Severity 越界: {severity}")

        # 3. 数据来源校验
        if not doc.get("event", {}).get("dataset"):
            is_valid = False
            errors.append("缺失数据来源标识 (dataset)")

        # 4. 关键业务字段校验 (针对蜜罐连接)
        if doc.get("event", {}).get("action") == "cowrie.session.connect":
            if not doc.get("source", {}).get("ip"):
                is_valid = False
                errors.append("连接事件缺失源 IP")

        if is_valid:
            self.stats["valid"] += 1
        else:
            self.stats["invalid"] += 1
            # print(f"[X] 文档 ID {doc.get('event', {}).get('id')} 校验失败: {errors}")

    def _print_report(self):
        """打印质量分析报告"""
        print("\n" + "="*40)
        print("📊 数据质量自检报告")
        print("="*40)
        print(f"总检查条数: {self.stats['total']}")
        print(f"✅ 合格条数: {self.stats['valid']}")
        print(f"❌ 不合格条数: {self.stats['invalid']}")
        
        if self.stats["invalid"] > 0:
            print("\n主要问题统计:")
            for field, count in self.stats["missing_fields"].items():
                print(f"- 缺失字段 '{field}': {count} 次")
            print(f"- 字段类型/逻辑错误: {self.stats['type_errors']} 次")
        
        score = (self.stats["valid"] / self.stats["total"]) * 100 if self.stats["total"] > 0 else 0
        print(f"\n健康分: {score:.1f}/100")
        if score < 90:
            print("[建议] 数据质量较低，请检查 flow_parser.py 的映射逻辑。")
        else:
            print("[优秀] 数据格式完美，组员 3 和 4 可以放心使用。")
        print("="*40)

if __name__ == "__main__":
    validator = DataValidator()
    # 检查过去 24 小时的数据
    validator.check_quality(hours=24)
