# analyzer/attack_analyzer/causality_analyzer.py

from typing import List, Dict, Any
from datetime import datetime

class CausalityAnalyzer:
    """
    因果关系分析引擎
    """

    def __init__(self):
        # ATT&CK 战术逻辑顺序
        self.tactic_order = {
            "Reconnaissance": 1, "Resource Development": 2, "Initial Access": 3,
            "Execution": 4, "Persistence": 5, "Privilege Escalation": 6,
            "Defense Evasion": 7, "Credential Access": 8, "Discovery": 9,
            "Lateral Movement": 10, "Collection": 11, "Command and Control": 12,
            "Exfiltration": 13, "Impact": 14
        }
        
    def analyze_session(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """对攻击会话进行因果分析"""
        events = sorted(session["events"], key=lambda x: x["@timestamp"])
        if not events:
            return session

        links = self._build_causal_links(events)
        
        session["causal_chain"] = links
        session["narrative"] = self._generate_narrative(links, session["attacker_ip"])
        session["impacted_assets"] = list(self._extract_impacted_assets(events))
        session["confidence_score"] = self._calculate_confidence(links)
        
        return session

    def _build_causal_links(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        links = []
        for i in range(len(events)):
            current_event = events[i]
            # 这里的路径 threat.tactic.name 符合 schema 定义
            curr_tactic = current_event.get("threat", {}).get("tactic", {}).get("name")
            
            for j in range(i + 1, len(events)):
                next_event = events[j]
                next_tactic = next_event.get("threat", {}).get("tactic", {}).get("name")
                
                if self._is_causally_related(current_event, next_event, curr_tactic, next_tactic):
                    # 获取 event.id，schema 中定义为 event.event.id
                    src_id = current_event.get("event", {}).get("id", "unknown")
                    tgt_id = next_event.get("event", {}).get("id", "unknown")
                    
                    links.append({
                        "source_event_id": src_id,
                        "target_event_id": tgt_id,
                        "relation_type": f"{curr_tactic} -> {next_tactic}",
                        "time_gap": self._calculate_time_gap(current_event, next_event),
                        "evidence": self._get_link_evidence(current_event, next_event)
                    })
                    break 
        return links

    def _is_causally_related(self, event_a: Dict, event_b: Dict, tactic_a: str, tactic_b: str) -> bool:
        order_a = self.tactic_order.get(tactic_a, 0)
        order_b = self.tactic_order.get(tactic_b, 0)
        
        if order_a >= order_b: # 简化的顺序检查
            return False
            
        shared_entities = self._find_shared_entities(event_a, event_b)
        if not shared_entities:
            return False

        if self._calculate_time_gap(event_a, event_b) > 3600:
            return False

        return True

    def _find_shared_entities(self, event_a: Dict, event_b: Dict) -> List[str]:
        """寻找共享实体，字段路径需符合 schema.py"""
        shared = []
        
        # 1. 目标 IP (DestinationInfo)
        dest_a = event_a.get("destination", {}).get("ip")
        dest_b = event_b.get("destination", {}).get("ip")
        if dest_a and dest_b and dest_a == dest_b:
            shared.append(f"Target IP: {dest_a}")
            
        # 2. 受害主机 (HostInfo)
        host_a = event_a.get("host", {}).get("name")
        host_b = event_b.get("host", {}).get("name")
        if host_a and host_b and host_a == host_b:
            shared.append(f"Host: {host_a}")
            
        # 3. 进程 PID (ProcessInfo)
        pid_a = event_a.get("process", {}).get("pid")
        pid_b = event_b.get("process", {}).get("pid")
        if pid_a and pid_b and pid_a != 0 and pid_a == pid_b:
            shared.append(f"PID: {pid_a}")
            
        return shared

    def _generate_narrative(self, links: List[Dict], attacker_ip: str) -> str:
        if not links:
            return f"检测到来自 {attacker_ip} 的孤立攻击行为。"
        story = [f"攻击者 {attacker_ip} 攻击链条："]
        for link in links:
            story.append(f"  - {link['relation_type']} ({link['time_gap']:.1f}s) [{link['evidence']}]")
        return "\n".join(story)

    def _extract_impacted_assets(self, events: List[Dict]) -> set:
        assets = set()
        for event in events:
            if val := event.get("host", {}).get("name"): assets.add(val)
            if val := event.get("destination", {}).get("ip"): assets.add(val)
        return assets

    def _calculate_time_gap(self, event_a, event_b) -> float:
        try:
            ts_a = datetime.fromisoformat(event_a["@timestamp"].replace("Z", "+00:00"))
            ts_b = datetime.fromisoformat(event_b["@timestamp"].replace("Z", "+00:00"))
            return (ts_b - ts_a).total_seconds()
        except:
            return 0.0

    def _get_link_evidence(self, event_a, event_b) -> str:
        shared = self._find_shared_entities(event_a, event_b)
        return f"Shared: {','.join(shared)}"

    def _calculate_confidence(self, links: List) -> float:
        return min(0.5 + (len(links) * 0.1), 1.0)