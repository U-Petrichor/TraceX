# analyzer/attack_analyzer/timeline_correlator.py
import os
from typing import List, Dict, Any
from collector.common.schema import UnifiedEvent
from .sigma_engine import SigmaQueryEngine 
from .attack_mapper import ATTACKMapper

class TimelineCorrelator:
    def __init__(self, es_client=None):
        # 初始化 ES 客户端，假设已有 ESClient 实现
        self.es = es_client 
        
        # 1. 初始化 Sigma 引擎，加载 rules 目录下的 .yml 规则
        base_path = os.path.dirname(__file__)
        rule_sources = [os.path.join(base_path, "rules")] 
        self.sigma_engine = SigmaQueryEngine(rule_sources)
        
        # 2. 初始化标签映射器
        self.mapper = ATTACKMapper() 
        
        # 用于存储按攻击者 IP 分组的会话
        self.active_sessions = {}

    def correlate_timeline(self, start_time: str, end_time: str) -> List[Dict]:
        # 1. 这里的 filters 必须符合 es_client.py 的定义
        # 如果 es_client 不支持 query_string，我们先拉取一定范围内的全量，再在本地通过 Sigma 过滤
        raw_hits = self.es.query_events(
            start_time=start_time,
            end_time=end_time,
            size=5000 # 适当扩大范围
        )
        
        # 【关键步】立即转换为对象列表
        events = [UnifiedEvent.from_dict(hit) for hit in raw_hits]
        
        # 3. 过滤出命中规则的事件并补全威胁标签
        matched_events = []
        for event in events:
            rule_info = self.sigma_engine.identify_rule(event)
            if rule_info:
                # 注入威胁信息 (对齐 schema.py 结构)
                tactic_name, tech_id = self.mapper._parse_sigma_tags(rule_info["tags"])
                event.threat.framework = "MITRE ATT&CK"
                event.threat.tactic.name = tactic_name
                event.threat.technique.id = tech_id
                event.threat.technique.name = rule_info["title"]
                
                event.event.severity = self.mapper.level_map.get(rule_info["level"], 5)
                event.message = f"Sigma Rule Hit: {rule_info['title']}"
                matched_events.append(event)
        
        return self._process_events(matched_events)

    def _process_events(self, events: List[UnifiedEvent]) -> List[Dict]:
        # 对象化排序
        events.sort(key=lambda x: x.timestamp)
        
        for event in events:
            self._update_session(event)

        return self._finalize_sessions()

    def _update_session(self, event: UnifiedEvent):
        # 优先从对象属性获取 IP
        attacker_ip = event.source.ip or event.user.domain or "unknown"
        
        if attacker_ip not in self.active_sessions:
            self.active_sessions[attacker_ip] = {
                "attacker_ip": attacker_ip,
                "first_seen": event.timestamp,
                "last_seen": event.timestamp,
                "events": [], # 存储 UnifiedEvent 对象
                "risk_score": 0
            }
        
        session = self.active_sessions[attacker_ip]
        session["events"].append(event)
        session["last_seen"] = event.timestamp
        session["risk_score"] += event.event.severity

    def _finalize_sessions(self) -> List[Dict[str, Any]]:
        """转化聚合字典为列表并返回"""
        return list(self.active_sessions.values())