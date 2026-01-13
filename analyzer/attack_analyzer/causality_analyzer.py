# analyzer/attack_analyzer/causality_analyzer.py

from typing import List, Dict, Any
from datetime import datetime
from collector.common.schema import UnifiedEvent

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
        
    def analyze_session(self, session: Dict) -> Dict:
        # session["events"] 已经是 List[UnifiedEvent]
        events = sorted(session["events"], key=lambda x: x.timestamp)

        links = self._build_causal_links(events)
        
        session["causal_chain"] = links
        session["narrative"] = self._generate_narrative(links, session["attacker_ip"])
        session["impacted_assets"] = list(self._extract_impacted_assets(events))
        session["confidence_score"] = self._calculate_confidence(links)
        # 将对象转回字典供 ES 存储或前端显示
        session["events"] = [e.to_dict() for e in events]
        
        return session

    def _build_causal_links(self, events: List[UnifiedEvent]) -> List[Dict[str, Any]]:
        links = []
        for i in range(len(events)):
            current_event = events[i]
            curr_tactic = current_event.threat.tactic.name
            
            for j in range(i + 1, len(events)):
                next_event = events[j]
                next_tactic = next_event.threat.tactic.name
                
                if self._is_causally_related(current_event, next_event):
                    src_id = current_event.event.id or "unknown"
                    tgt_id = next_event.event.id or "unknown"
                    
                    links.append({
                        "source_event_id": src_id,
                        "target_event_id": tgt_id,
                        "relation_type": f"{curr_tactic} -> {next_tactic}",
                        "time_gap": self._calculate_time_gap(current_event, next_event),
                        "evidence": self._get_link_evidence(current_event, next_event)
                    })
                    break 
        return links

    def _is_causally_related(self, event_a: UnifiedEvent, event_b: UnifiedEvent) -> bool:
        # 直接访问对象属性
        tactic_a = event_a.threat.tactic.name
        tactic_b = event_b.threat.tactic.name
        
        order_a = self.tactic_order.get(tactic_a, 0)
        order_b = self.tactic_order.get(tactic_b, 0)
        
        if order_a >= order_b: return False
            
        shared = self._find_shared_entities(event_a, event_b)
        if not shared: return False

        # 时间间隔计算
        if self._calculate_time_gap(event_a, event_b) > 3600: return False

        return True

    def _find_shared_entities(self, a: UnifiedEvent, b: UnifiedEvent) -> List[str]:
        shared = []
        # 属性对比：非常直观
        if a.destination.ip and a.destination.ip == b.destination.ip:
            shared.append(f"IP:{a.destination.ip}")
        if a.host.hostname and a.host.hostname == b.host.hostname:
            shared.append(f"Host:{a.host.hostname}")
        if a.process.pid and a.process.pid == b.process.pid:
            shared.append(f"PID:{a.process.pid}")
        return shared

    def _generate_narrative(self, links: List[Dict], attacker_ip: str) -> str:
        if not links:
            return f"检测到来自 {attacker_ip} 的孤立攻击行为。"
        story = [f"攻击者 {attacker_ip} 攻击链条："]
        for link in links:
            story.append(f"  - {link['relation_type']} ({link['time_gap']:.1f}s) [{link['evidence']}]")
        return "\n".join(story)

    def _extract_impacted_assets(self, events: List[UnifiedEvent]) -> set:
        assets = set()
        for event in events:
            if event.host and event.host.hostname: assets.add(event.host.hostname)
            if event.destination and event.destination.ip: assets.add(event.destination.ip)
        return assets

    def _calculate_time_gap(self, a: UnifiedEvent, b: UnifiedEvent) -> float:
        try:
            # 去掉末尾的 Z 并解析
            ts_a = datetime.fromisoformat(a.timestamp.replace("Z", "+00:00"))
            ts_b = datetime.fromisoformat(b.timestamp.replace("Z", "+00:00"))
            return (ts_b - ts_a).total_seconds()
        except: return 0.0

    def _get_link_evidence(self, event_a, event_b) -> str:
        shared = self._find_shared_entities(event_a, event_b)
        return f"Shared: {','.join(shared)}"

    def _calculate_confidence(self, links: List) -> float:
        return min(0.5 + (len(links) * 0.1), 1.0)