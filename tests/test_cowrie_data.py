# /root/TraceX/tests/test_cowrie_data.py
import sys
from datetime import datetime, timedelta

sys.path.append('/root/TraceX')
try:
    from collector.common.es_client import ESClient
    from collector.common.schema import UnifiedEvent
except ImportError:
    print("错误: 无法加载公共模块")
    sys.exit(1)

class DataValidator:
    def __init__(self):
        self.es = ESClient()
        self.stats = {"total": 0, "valid": 0, "invalid": 0, "errors": []}

    def check_quality(self, hours=24):
        now = datetime.utcnow()
        start_time = (now - timedelta(hours=hours)).isoformat() + "Z"
        end_time = now.isoformat() + "Z"

        print(f"[*] 正在从 ES 读取过去 {hours} 小时的数据进行合规性校验...")
        events = self.es.query_events(start_time, end_time, size=1000)
        self.stats["total"] = len(events)

        if not events:
            print("[!] 警告: 未发现数据。")
            return

        for doc in events:
            self._validate_event(doc)

        self._print_report()

    def _validate_event(self, doc):
        """核心校验逻辑"""
        try:
            # 1. 尝试还原为 Dataclass 对象，这会自动处理嵌套结构
            event_obj = UnifiedEvent.from_dict(doc)
            
            is_valid = True
            reasons = []

            # 2. 检查必须具备的业务字段
            if not event_obj.event.dataset:
                is_valid = False
                reasons.append("缺失 event.dataset")
            
            if not event_obj.source.ip:
                is_valid = False
                reasons.append("缺失 source.ip")
            
            if not event_obj.event.category:
                is_valid = False
                reasons.append("缺失 event.category")

            if is_valid:
                self.stats["valid"] += 1
            else:
                self.stats["invalid"] += 1
                self.stats["errors"].append(f"ID {event_obj.event.id}: {', '.join(reasons)}")

        except Exception as e:
            self.stats["invalid"] += 1
            self.stats["errors"].append(f"解析异常: {str(e)}")

    def _print_report(self):
        print("\n" + "="*40)
        print("📊 组员 2 数据合规性报告 (基于最新 Schema)")
        print("="*40)
        print(f"总计条数: {self.stats['total']}")
        print(f"通过校验: {self.stats['valid']}")
        print(f"校验失败: {self.stats['invalid']}")
        
        if self.stats["total"] > 0:
            score = (self.stats["valid"] / self.stats["total"]) * 100
            print(f"数据健康分: {score:.1f}/100")
            
            if score < 100 and self.stats["errors"]:
                print("\n具体错误样例 (前5条):")
                for err in self.stats["errors"][:5]:
                    print(f" - {err}")
        print("="*40)

if __name__ == "__main__":
    validator = DataValidator()
    validator.check_quality(hours=1) # 检查最近 1 小时即可