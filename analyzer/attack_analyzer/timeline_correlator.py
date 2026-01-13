# analyzer/attack_analyzer/timeline_correlator.py

import time
from datetime import datetime, timedelta
from collections import deque, defaultdict
from typing import List, Dict, Any

# === 引用项目规范模块 ===
# 引入统一的 ES 客户端
from collector.common.es_client import ESClient
# 引入 Mapper
from .attack_mapper import ATTACKMapper

class TimelineCorrelator:
    """
    时间线关联分析器
    负责从 ES 拉取数据，映射 ATT&CK，并聚合为攻击会话
    """

    def __init__(self, es_client: ESClient = None):
        # 使用传入的 client 或初始化新的标准 client
        self.es = es_client if es_client else ESClient()
        self.mapper = ATTACKMapper()
        
        # 状态存储
        self.threshold_state = defaultdict(deque)
        self.active_sessions = {}
        self.session_timeout = 30 * 60  # 30分钟无新动作则会话结束

    def correlate_timeline(self, start_time: str, end_time: str, time_window: int = 300) -> List[Dict[str, Any]]:
        """
        主入口：拉取日志 -> 映射威胁 -> 关联会话
        """
        # 1. 使用 ESClient 查询标准数据
        # query_events 返回的是符合 UnifiedEvent 结构的字典列表
        raw_events = self.es.query_events(
            start_time=start_time,
            end_time=end_time,
            index_prefix="unified-logs", # 对应 es_client 中的默认值
            size=10000 
        )
        
        if not raw_events:
            return []

        # 2. 调用内部处理逻辑
        return self._process_events(raw_events)

    def _process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        内部逻辑：处理事件列表并生成会话
        """
        # 预先排序，确保时间线正确
        sorted_events = sorted(events, key=lambda x: x.get("@timestamp", ""))
        
        for event in sorted_events:
            # === 步骤 A: ATT&CK 映射 ===
            mapping_result = self.mapper.map_event(event)
            
            if mapping_result["matched"]:
                # === 步骤 B: 按照 Schema 规范回填数据 ===
                
                # 1. 注入威胁信息 (对应 schema.py 中的 ThreatInfo)
                # 确保 event 中有 threat 字段
                if "threat" not in event: event["threat"] = {}
                event["threat"].update(mapping_result["threat"])
                
                # 2. [关键修改] 注入整数 Severity (1-10)
                # 写入 schema.py 定义的标准位置: EventInfo -> severity
                if "event" not in event: event["event"] = {}
                
                int_severity = mapping_result.get("severity", 5)
                event["event"]["severity"] = int_severity # 这里是标准存储位置
                
                # 辅助字段（非 Schema 定义，但用于分析器内部逻辑）
                event["rule_id"] = mapping_result["rule_id"]
                event["rule_name"] = mapping_result["rule_name"]

                # === 步骤 C: 阈值与会话逻辑 ===
                
                # 阈值检测 (例如 SSH 爆破需要 5 次失败才算一次攻击)
                threshold_config = mapping_result.get("threshold_config")
                if threshold_config:
                    if not self._check_sliding_window(event, threshold_config):
                        continue
                
                # 更新会话
                self._update_session(event)

        # === 步骤 D: 格式化输出 ===
        final_sessions = []
        for session in self.active_sessions.values():
            # Set 转 List 以支持 JSON 序列化
            session["stages"] = list(session["stages"])
            session["techniques"] = list(session["techniques"])
            
            # 再次按时间排序事件列表
            session["events"].sort(key=lambda x: x.get("@timestamp", ""))
            
            final_sessions.append(session)

        return final_sessions

    def _check_sliding_window(self, event: Dict[str, Any], config: Dict[str, int]) -> bool:
        """滑动窗口检测（针对 Source IP + Rule ID）"""
        # 从 SourceInfo 获取 IP
        src_ip = event.get("source", {}).get("ip", "unknown")
        rule_id = event.get("rule_id")
        
        key = f"{src_ip}_{rule_id}"
        current_ts = self._parse_timestamp(event.get("@timestamp"))
        window = self.threshold_state[key]
        
        window.append(current_ts)
        
        # 滑动清理过期记录
        time_limit = timedelta(seconds=config["time_window"])
        while window and (current_ts - window[0] > time_limit):
            window.popleft()
            
        if len(window) >= config["count"]:
            # 可以在这里追加备注到 message 字段
            event["message"] = f"{event.get('message', '')} [高频触发: {len(window)}次/{config['time_window']}s]"
            return True
        return False

    def _update_session(self, event: Dict[str, Any]):
        # 从 SourceInfo 获取 IP
        src_ip = event.get("source", {}).get("ip", "unknown")
        timestamp = self._parse_timestamp(event.get("@timestamp"))
        
        if src_ip in self.active_sessions:
            session = self.active_sessions[src_ip]
            last_seen = self._parse_timestamp(session["last_seen"])
            
            # 检查会话超时
            if (timestamp - last_seen).total_seconds() > self.session_timeout:
                self._create_new_session(src_ip, event)
            else:
                session["events"].append(event)
                session["last_seen"] = event["@timestamp"]
                # 记录战术和技术名称
                tactic_name = event.get("threat", {}).get("tactic", {}).get("name", "Unknown")
                tech_name = event.get("threat", {}).get("technique", {}).get("name", "Unknown")
                session["stages"].add(tactic_name)
                session["techniques"].add(tech_name)
                session["score"] += self._calculate_risk_score(event)
        else:
            self._create_new_session(src_ip, event)

    def _create_new_session(self, src_ip: str, event: Dict[str, Any]):
        tactic_name = event.get("threat", {}).get("tactic", {}).get("name", "Unknown")
        tech_name = event.get("threat", {}).get("technique", {}).get("name", "Unknown")
        
        self.active_sessions[src_ip] = {
            "session_id": f"sess_{src_ip}_{int(time.time())}",
            "attacker_ip": src_ip,
            "start_time": event["@timestamp"],
            "last_seen": event["@timestamp"],
            "score": self._calculate_risk_score(event),
            "stages": {tactic_name},
            "techniques": {tech_name},
            "events": [event]
        }

    def _calculate_risk_score(self, event: Dict[str, Any]) -> int:
        """
        计算风险评分
        直接读取符合 schema 规范的 event.severity (int 1-10)
        """
        try:
            # 优先读取标准位置
            severity = event.get("event", {}).get("severity", 5)
            return int(severity) * 10
        except (ValueError, TypeError):
            return 50

    def _parse_timestamp(self, ts_str: str) -> datetime:
        if not ts_str:
            return datetime.utcnow()
        try:
            # 兼容带Z和不带Z的情况
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except:
            return datetime.utcnow()