# analyzer/attack_analyzer/attack_mapper.py
import fnmatch
from typing import Any, Dict, List

class ATTACKMapper:
    def __init__(self):
        # Sigma Level 映射到 1-10 权重，用于后续风险评分
        self.level_map = {
            "informational": 1, 
            "low": 3, 
            "medium": 5, 
            "high": 8, 
            "critical": 10
        }

    def _parse_sigma_tags(self, tags: List[str]):
        """
        从 Sigma 标签数组中提取 MITRE ATT&CK 战术和技术 ID
        例如: ['attack.persistence', 'attack.t1053'] -> ('Persistence', 'T1053')
        """
        tactic = "Unknown"
        tech_id = "Unknown"
        
        for tag in tags:
            tag = tag.lower()
            if tag.startswith("attack.t"):
                # 提取技术 ID (如 T1110)
                tech_id = tag.split(".")[-1].upper() 
            elif tag.startswith("attack."):
                # 将战术标签转换为易读格式 (如 initial_access -> Initial Access)
                tactic = tag.split(".")[-1].replace("_", " ").title()
                
        return tactic, tech_id