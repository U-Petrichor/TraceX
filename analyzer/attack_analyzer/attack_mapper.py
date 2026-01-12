# analyzer/attack_analyzer/attack_mapper.py

import fnmatch
from typing import Any, Dict, List, Union
from .attack_rules import ATTACK_RULES

class ATTACKMapper:
    """
    ATT&CK 框架映射引擎
    """
    
    def __init__(self):
        self.rules = ATTACK_RULES
        # 严重程度映射：文字 -> 1-10 整数
        self.severity_mapping = {
            "info": 1,
            "low": 3,
            "medium": 5,
            "high": 8,
            "critical": 10
        }

    def map_to_attack(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        将事件映射到 ATT&CK 框架
        """
        for rule in self.rules:
            if self._match_conditions(event, rule["conditions"]):
                
                # 获取规则里的字符串 severity，转换为整数
                rule_severity_str = rule.get("severity", "medium")
                severity_score = self.severity_mapping.get(str(rule_severity_str).lower(), 5)

                # 构造返回结果
                # 注意：这里返回的结构将被 TimelineCorrelator 合并进 UnifiedEvent
                return {
                    "matched": True,
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    
                    # 对应 schema.py 中的 ThreatInfo 结构
                    "threat": {
                        "framework": "MITRE ATT&CK",
                        "tactic": rule["tactic"],      # rule 中已包含 id 和 name
                        "technique": rule["technique"] # rule 中已包含 id 和 name
                    },
                    
                    # 返回处理好的整数 severity
                    "severity": severity_score, 
                    "threshold_config": rule.get("threshold", None)
                }
        
        return {"matched": False}

    def _match_conditions(self, event: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """递归检查条件"""
        for field_path, expected_value in conditions.items():
            actual_value = self._get_nested_field(event, field_path)
            if actual_value is None:
                return False
            if not self._match_value(actual_value, expected_value):
                return False
        return True

    def _get_nested_field(self, event: Dict, field_path: str) -> Any:
        """
        支持点号访问，例如 "process.name" -> event["process"]["name"]
        完全兼容 schema.py 的嵌套结构
        """
        keys = field_path.split('.')
        current_value = event
        try:
            for key in keys:
                if isinstance(current_value, dict):
                    current_value = current_value.get(key)
                else:
                    return None
            return current_value
        except Exception:
            return None

    def _match_value(self, actual: Any, expected: Any) -> bool:
        """值匹配逻辑 (支持列表、通配符、数值比较)"""
        str_actual = str(actual).lower()

        if isinstance(expected, list):
            for item in expected:
                if self._check_single_value(str_actual, item, actual):
                    return True
            return False
        else:
            return self._check_single_value(str_actual, expected, actual)

    def _check_single_value(self, str_actual: str, expected: Any, raw_actual: Any) -> bool:
        str_expected = str(expected).lower()

        # 数值比较 (>1000)
        if str_expected.startswith((">=", "<=", ">", "<")) and isinstance(raw_actual, (int, float)):
            return self._compare_numeric(raw_actual, str_expected)

        # 通配符匹配
        if "*" in str_expected or "?" in str_expected:
            return fnmatch.fnmatch(str_actual, str_expected)
        
        return str_actual == str_expected

    def _compare_numeric(self, actual_num: Union[int, float], operator_str: str) -> bool:
        try:
            if operator_str.startswith(">="): return actual_num >= float(operator_str[2:])
            elif operator_str.startswith("<="): return actual_num <= float(operator_str[2:])
            elif operator_str.startswith(">"): return actual_num > float(operator_str[1:])
            elif operator_str.startswith("<"): return actual_num < float(operator_str[1:])
        except ValueError:
            return False
        return False