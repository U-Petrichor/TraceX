import uuid
from typing import List, Dict, Any
from datetime import datetime

class AttackPathRebuilder:
    """
    攻击路径重建器
    作用：基于 MITRE ATT&CK 战术阶段，将零散的事件串联成完整的攻击故事。
    """
    
    # 战术 ID 到 阶段名 的映射
    TACTIC_TO_STAGE = {
        "TA0001": "initial_access",      # 初始访问
        "TA0002": "execution",           # 执行
        "TA0003": "persistence",         # 持久化
        "TA0004": "privilege_escalation",# 提权
        "TA0005": "defense_evasion",     # 防御规避
        "TA0006": "credential_access",   # 凭证获取
        "TA0007": "discovery",           # 发现
        "TA0008": "lateral_movement",    # 横向移动
        "TA0009": "collection",          # 收集
        "TA0010": "exfiltration",        # 数据窃取
        "TA0011": "command_and_control", # 命令与控制
        "TA0040": "impact"               # 危害
    }
    
    # 标准攻击链顺序
    ATTACK_STAGES_ORDER = [
        "initial_access", "execution", "persistence", "privilege_escalation", 
        "defense_evasion", "credential_access", "discovery", "lateral_movement", 
        "collection", "command_and_control", "exfiltration", "impact"
    ]

    def rebuild(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        重建攻击路径
        
        Args:
            events: 包含 threat 信息的事件列表
            
        Returns:
            攻击路径对象，包含按顺序排列的 stages
        """
        stages_map = {}
        
        # 1. 遍历事件，按 ATT&CK 战术归类
        for event in events:
            # 获取 threat 信息 (Schema: ThreatInfo)
            threat = event.get("threat", {})
            tactic = threat.get("tactic", {})
            tactic_id = tactic.get("id")
            
            # 如果没有 threat 信息，跳过（说明是普通日志，未被标记为攻击）
            if not tactic_id:
                continue
                
            stage_name = self.TACTIC_TO_STAGE.get(tactic_id, "unknown")
            
            if stage_name not in stages_map:
                stages_map[stage_name] = {
                    "stage": stage_name,
                    "tactic_id": tactic_id,
                    "tactic_name": tactic.get("name"),
                    "events": [],
                    "start_time": event.get("@timestamp"),
                    "end_time": event.get("@timestamp")
                }
            
            # 更新时间范围
            current_stage = stages_map[stage_name]
            event_time = event.get("@timestamp")
            if event_time < current_stage["start_time"]:
                current_stage["start_time"] = event_time
            if event_time > current_stage["end_time"]:
                current_stage["end_time"] = event_time
                
            current_stage["events"].append(event)

        # 2. 按攻击链顺序排序
        ordered_stages = []
        for stage_key in self.ATTACK_STAGES_ORDER:
            if stage_key in stages_map:
                stage_data = stages_map[stage_key]
                # 生成描述
                count = len(stage_data["events"])
                tech_names = list(set([e.get("threat", {}).get("technique", {}).get("name") for e in stage_data["events"]]))
                tech_str = ", ".join([t for t in tech_names if t])
                
                stage_data["description"] = f"检测到 {count} 次 {stage_data['tactic_name']} 行为，涉及技术: {tech_str}"
                ordered_stages.append(stage_data)
        
        # 处理未知阶段 (unknown)
        if "unknown" in stages_map:
            ordered_stages.append(stages_map["unknown"])

        return {
            "attack_id": str(uuid.uuid4()),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "stages": ordered_stages,
            "total_stages": len(ordered_stages),
            "total_events": sum(len(s["events"]) for s in ordered_stages)
        }