# analyzer/attack_analyzer/sigma_engine.py
"""
Sigma 检测引擎核心
作用：执行 Sigma 规则匹配，检测事件是否符合攻击特征
"""
import re
import fnmatch
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from .rule_loader import SigmaRule, RuleLoader
from .field_mapper import FieldMapper, EventNormalizer


@dataclass
class DetectionResult:
    """检测结果"""
    matched: bool
    rule: Optional[SigmaRule] = None
    event: Optional[Dict[str, Any]] = None
    matched_fields: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        if not self.matched:
            return {"matched": False}
        return {
            "matched": True,
            "rule_id": self.rule.id if self.rule else None,
            "rule_title": self.rule.title if self.rule else None,
            "level": self.rule.level if self.rule else None,
            "tactics": self.rule.attack_tactics if self.rule else [],
            "techniques": self.rule.attack_techniques if self.rule else [],
            "matched_fields": self.matched_fields,
            "timestamp": self.timestamp
        }


class SigmaMatchEngine:
    """
    Sigma 规则匹配引擎
    支持 Sigma 规则的各种匹配操作符
    """
    
    # Sigma 修饰符映射
    MODIFIERS = {
        'contains': lambda v, p: p.lower() in str(v).lower() if v else False,
        'startswith': lambda v, p: str(v).lower().startswith(p.lower()) if v else False,
        'endswith': lambda v, p: str(v).lower().endswith(p.lower()) if v else False,
        'base64': lambda v, p: p in str(v),  # 简化处理
        're': lambda v, p: bool(re.search(p, str(v), re.IGNORECASE)) if v else False,
        'cidr': lambda v, p: SigmaMatchEngine._match_cidr(v, p),
        'all': None,  # 特殊处理
    }
    
    @staticmethod
    def _match_cidr(value: str, pattern: str) -> bool:
        """简单 CIDR 匹配（简化实现）"""
        try:
            if '/' not in pattern:
                return value == pattern
            # 简单前缀匹配
            prefix = pattern.split('/')[0].rsplit('.', 1)[0]
            return str(value).startswith(prefix)
        except:
            return False
    
    def match_value(self, event_value: Any, pattern: Any, modifiers: List[str] = None) -> bool:
        """
        匹配单个值
        
        Args:
            event_value: 事件中的字段值
            pattern: 匹配模式
            modifiers: Sigma 修饰符列表 (如 ['contains', 'all'])
        """
        if event_value is None:
            return False
        
        modifiers = modifiers or []
        event_str = str(event_value)
        
        # 处理列表模式（多个可选值）
        if isinstance(pattern, list):
            if 'all' in modifiers:
                # 所有模式都必须匹配
                return all(self.match_value(event_value, p, [m for m in modifiers if m != 'all']) 
                          for p in pattern)
            else:
                # 任意一个模式匹配即可
                return any(self.match_value(event_value, p, modifiers) for p in pattern)
        
        pattern_str = str(pattern)
        
        # 应用修饰符
        for mod in modifiers:
            if mod in self.MODIFIERS and self.MODIFIERS[mod]:
                return self.MODIFIERS[mod](event_str, pattern_str)
        
        # 无修饰符：精确匹配（忽略大小写）
        # 支持通配符 *
        if '*' in pattern_str:
            return fnmatch.fnmatch(event_str.lower(), pattern_str.lower())
        return event_str.lower() == pattern_str.lower()
    
    def match_selection(self, event: Dict[str, Any], selection: Dict[str, Any]) -> Tuple[bool, Dict]:
        """
        匹配单个 selection 块
        
        Args:
            event: 事件数据（已映射的字段）
            selection: Sigma 规则中的 selection 定义
            
        Returns:
            (是否匹配, 匹配的字段详情)
        """
        matched_fields = {}
        
        for field_spec, pattern in selection.items():
            # 解析字段名和修饰符: field|modifier1|modifier2
            parts = field_spec.split('|')
            field_name = parts[0]
            modifiers = parts[1:] if len(parts) > 1 else []
            
            # 获取事件中的值
            event_value = self._get_field_value(event, field_name)
            
            # 执行匹配
            if self.match_value(event_value, pattern, modifiers):
                matched_fields[field_name] = {
                    "event_value": event_value,
                    "pattern": pattern,
                    "modifiers": modifiers
                }
            else:
                return False, {}
        
        return True, matched_fields
    
    def _get_field_value(self, event: Dict[str, Any], field_name: str) -> Any:
        """获取事件字段值，支持点号路径"""
        # 首先尝试直接获取
        if field_name in event:
            return event[field_name]
        
        # 尝试点号路径
        parts = field_name.split('.')
        current = event
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current
    
    def evaluate_condition(self, event: Dict[str, Any], 
                          detection: Dict[str, Any]) -> Tuple[bool, Dict]:
        """
        评估完整的 detection 条件
        
        Args:
            event: 事件数据
            detection: Sigma 规则的 detection 块
            
        Returns:
            (是否匹配, 匹配详情)
        """
        condition = detection.get('condition', '')
        if not condition:
            return False, {}
        
        # 提取所有 selection 块
        selections = {}
        filters = {}
        
        for key, value in detection.items():
            if key == 'condition':
                continue
            if key.startswith('filter'):
                filters[key] = value
            elif key.startswith('selection') or not key.startswith(('filter', 'condition')):
                selections[key] = value
        
        # 评估每个 selection/filter
        selection_results = {}
        all_matched_fields = {}
        
        for name, sel_def in {**selections, **filters}.items():
            if isinstance(sel_def, dict):
                matched, fields = self.match_selection(event, sel_def)
                selection_results[name] = matched
                if matched:
                    all_matched_fields.update(fields)
        
        # 解析并评估条件表达式
        try:
            result = self._evaluate_condition_expr(condition, selection_results)
            return result, all_matched_fields if result else {}
        except Exception as e:
            # 条件解析失败，返回不匹配
            return False, {}
    
    def _evaluate_condition_expr(self, condition: str, results: Dict[str, bool]) -> bool:
        """
        评估条件表达式
        
        支持的语法:
        - selection: 直接引用
        - selection1 and selection2: 与
        - selection1 or selection2: 或
        - not filter: 非
        - 1 of selection*: 任意一个匹配
        - all of selection*: 全部匹配
        """
        condition = condition.strip()
        
        # 处理 "1 of xxx*" 语法
        of_match = re.match(r'(\d+|all)\s+of\s+(\w+)\*', condition)
        if of_match:
            count_str, prefix = of_match.groups()
            matching_keys = [k for k in results.keys() if k.startswith(prefix)]
            matching_results = [results.get(k, False) for k in matching_keys]
            
            if count_str == 'all':
                return all(matching_results) if matching_results else False
            else:
                count = int(count_str)
                return sum(matching_results) >= count
        
        # 处理 "xxx and not 1 of filter*" 语法
        and_not_match = re.match(r'(\w+)\s+and\s+not\s+(\d+|all)\s+of\s+(\w+)\*', condition)
        if and_not_match:
            selection_name, count_str, filter_prefix = and_not_match.groups()
            selection_result = results.get(selection_name, False)
            if not selection_result:
                return False
            
            filter_keys = [k for k in results.keys() if k.startswith(filter_prefix)]
            filter_results = [results.get(k, False) for k in filter_keys]
            
            if count_str == 'all':
                filters_match = all(filter_results) if filter_results else False
            else:
                count = int(count_str)
                filters_match = sum(filter_results) >= count
            
            return selection_result and not filters_match
        
        # 简单替换处理
        expr = condition
        
        # 替换布尔操作符
        expr = re.sub(r'\band\b', ' and ', expr)
        expr = re.sub(r'\bor\b', ' or ', expr)
        expr = re.sub(r'\bnot\b', ' not ', expr)
        
        # 替换变量为布尔值
        for name, value in results.items():
            # 使用单词边界匹配
            expr = re.sub(rf'\b{re.escape(name)}\b', str(value), expr)
        
        # 评估表达式
        try:
            return eval(expr)
        except:
            return False


class SigmaDetector:
    """
    Sigma 检测器
    高级接口，整合规则加载、字段映射和匹配引擎
    """
    
    def __init__(self, rules_dir: str = None):
        """
        初始化检测器
        
        Args:
            rules_dir: 规则目录路径
        """
        self.rule_loader = RuleLoader(rules_dir)
        self.normalizer = EventNormalizer()
        self.match_engine = SigmaMatchEngine()
        self._rules_loaded = False
    
    def load_rules(self) -> int:
        """加载所有规则"""
        count = self.rule_loader.load_all()
        self._rules_loaded = True
        return count
    
    def detect(self, event: Dict[str, Any]) -> List[DetectionResult]:
        """
        检测单个事件
        
        Args:
            event: ECS 格式的事件
            
        Returns:
            检测结果列表（一个事件可能匹配多个规则）
        """
        if not self._rules_loaded:
            self.load_rules()
        
        results = []
        
        # 1. 确定事件的 logsource 类型
        logsource = self.normalizer.get_logsource_type(event)
        
        # 2. 获取匹配的规则
        rules = self.rule_loader.get_rules_for_logsource(
            product=logsource.get('product'),
            category=logsource.get('category'),
            service=logsource.get('service')
        )
        
        # 3. 对每个规则进行匹配
        for rule in rules:
            # 映射事件字段
            mapped_event = self.normalizer.mapper.map_event(event, rule.logsource)
            
            # 执行匹配
            matched, matched_fields = self.match_engine.evaluate_condition(
                mapped_event, rule.detection
            )
            
            if matched:
                results.append(DetectionResult(
                    matched=True,
                    rule=rule,
                    event=event,
                    matched_fields=matched_fields,
                    timestamp=event.get('@timestamp', '')
                ))
        
        return results
    
    def detect_batch(self, events: List[Dict[str, Any]], 
                    progress_callback=None) -> List[DetectionResult]:
        """
        批量检测事件
        
        Args:
            events: 事件列表
            progress_callback: 进度回调函数 (processed, total)
            
        Returns:
            所有检测结果
        """
        all_results = []
        total = len(events)
        
        for i, event in enumerate(events):
            results = self.detect(event)
            all_results.extend(results)
            
            if progress_callback and (i + 1) % 100 == 0:
                progress_callback(i + 1, total)
        
        return all_results
    
    def get_stats(self) -> Dict[str, Any]:
        """获取检测器统计信息"""
        return self.rule_loader.get_stats()
