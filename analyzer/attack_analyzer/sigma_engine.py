# analyzer/attack_analyzer/sigma_engine.py
import os
import fnmatch
from typing import List, Dict, Any, Optional
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation
from collector.common.schema import UnifiedEvent

class SigmaQueryEngine:
    def __init__(self, rule_dirs: List[str]):
        """初始化引擎并加载规则库"""
        # 定义字段映射：Sigma标准 -> 系统内部字段
        self.mapping = {
            "Image": "process.name",
            "CommandLine": "process.command_line",
            "ParentImage": "process.parent.name",
            "dst_ip": "destination.ip",
            "src_ip": "source.ip",
            "User": "user.name"
        }
        
        # 兼容性 Pipeline 初始化：使用 items 接收 ProcessingItem
        self.pipeline = ProcessingPipeline(
            items=[ProcessingItem(transformation=FieldMappingTransformation(self.mapping))]
        )
        self.backend = LuceneBackend(processing_pipeline=self.pipeline)
        self.rule_objects = []
        self._load_rules(rule_dirs)

    def _load_rules(self, rule_dirs: List[str]):
        """从目录加载并解析 YAML 规则，支持 UUID 和 Logsource 校验"""
        for folder in rule_dirs:
            if not os.path.exists(folder):
                continue
                
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.endswith(('.yml', '.yaml')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                # 使用 SigmaCollection.from_yaml 加载单个文件内容
                                collection = SigmaCollection.from_yaml(f.read())
                                self.rule_objects.extend(collection.rules)
                        except Exception as e:
                            print(f"[!] 无法加载规则文件 {file_path}: {e}")

    def get_combined_query(self) -> str:
        """生成发送给 ES 的 Lucene 查询语句"""
        if not self.rule_objects:
            return "*"
        queries = self.backend.convert(SigmaCollection(self.rule_objects))
        return " OR ".join(f"({q})" for q in queries)

    def identify_rule(self, event: UnifiedEvent) -> Optional[Dict[str, Any]]:
        """本地匹配引擎：接收 UnifiedEvent 对象"""
        for rule in self.rule_objects:
            detections = rule.detection.detections
            is_match = True
            
            # 遍历所有检测选择项
            for name, selection in detections.items():
                if name == 'condition': continue
                
                # 兼容性处理：尝试获取所有可能的过滤项属性
                items = getattr(selection, 'detection_items', []) or getattr(selection, 'items', [])
                conds = {}
                for item in items:
                    target_field = self.mapping.get(item.field, item.field)
                    conds[target_field] = item.value
                
                if not self._match_local(event, conds):
                    is_match = False
                    break
            
            if is_match:
                tag_list = [str(t.tag if hasattr(t, 'tag') else t) for t in rule.tags] if rule.tags else []
                level_raw = rule.level.name if hasattr(rule.level, 'name') else str(rule.level or "medium")

                return {
                    "id": str(rule.id),
                    "title": rule.title,
                    "level": level_raw.lower(),
                    "tags": tag_list
                }
        return None

    def _match_local(self, event: UnifiedEvent, conditions: Dict) -> bool:
        for field, expected in conditions.items():
            actual = self._get_val(event, field)
            if actual is None: return False
            
            # 统一转为 list 处理，支持 Sigma 的多值匹配
            actual_str = str(actual).lower()
            expected_list = expected if isinstance(expected, list) else [expected]
            if not any(fnmatch.fnmatch(actual_str, str(v).lower()) for v in expected_list):
                return False
        return True

    def _get_val(self, obj: Any, path: str):
        """递归获取对象属性，例如 'process.parent.name'"""
        for part in path.split('.'):
            if obj is None: return None
            # 兼容对象属性访问 (UnifiedEvent) 和 字典访问 (raw dict)
            if hasattr(obj, part):
                obj = getattr(obj, part)
            elif isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return None
        return obj