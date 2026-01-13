# attack_mapper.py
import fnmatch
from typing import Any, Dict, List

class ATTACKMapper:
    def __init__(self):
        from .attack_rules import ATTACK_RULES
        self.rules = ATTACK_RULES
        # Sigma Level 映射到 1-10 权重
        self.level_map = {
            "informational": 1, "low": 3, "medium": 5, "high": 8, "critical": 10
        }

    def map_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据 Sigma 逻辑进行映射，并返回标准的映射结果
        """
        result = {
            "matched": False,
            "threat": {},
            "severity": 5,
            "rule_id": None,
            "rule_name": None
        }

        for rule in self.rules:
            if self._match_conditions(event, rule["conditions"]):
                result["matched"] = True
                result["rule_id"] = rule["id"]
                result["rule_name"] = rule["name"]
                result["severity"] = self.level_map.get(rule.get("level"), 5)
                
                # 解析 Sigma Tags 提取 Tactic 和 Technique
                tactic, tech_id = self._parse_sigma_tags(rule.get("tags", []))
                
                result["threat"] = {
                    "framework": "MITRE ATT&CK",
                    "tactic": {"name": tactic},
                    "technique": {"id": tech_id},
                    "id": rule["id"]
                }
                break
        return result

    def _parse_sigma_tags(self, tags: List[str]):
        """从 Sigma 标签数组中提取攻击阶段信息"""
        tactic = "Unknown"
        tech_id = "Unknown"
        for tag in tags:
            tag = tag.lower()
            if tag.startswith("attack.t"):
                tech_id = tag.split(".")[-1].upper() # 提取 T1110
            elif tag.startswith("attack."):
                # 简单的转换逻辑：将 initial_access 变为 Initial Access
                tactic = tag.split(".")[-1].replace("_", " ").title()
        return tactic, tech_id

    def _match_conditions(self, event: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """支持通配符的字段匹配器"""
        for field, expected in conditions.items():
            actual = self._get_nested_value(event, field)
            if actual is None: return False
            
            actual_str = str(actual).lower()
            if isinstance(expected, list):
                if not any(fnmatch.fnmatch(actual_str, str(v).lower()) for v in expected):
                    return False
            else:
                if not fnmatch.fnmatch(actual_str, str(expected).lower()):
                    return False
        return True

    def _get_nested_value(self, data: Dict, path: str) -> Any:
        parts = path.split('.')
        for part in parts:
            if isinstance(data, dict): data = data.get(part)
            else: return None
        return data