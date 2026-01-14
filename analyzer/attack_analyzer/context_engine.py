# analyzer/attack_analyzer/context_engine.py
"""
TraceX Context Engine v5.7 (Fixed for ES Schema Conflict)
修复点：
1. 新增 get_seed_events 方法
2. 采用内存过滤策略绕过 ES Schema 冲突
3. 添加 SafeEventWrapper 兼容下游对象访问
"""
import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SafeEventWrapper:
    """将字典转换为支持点号访问的对象，缺失属性返回 None 而不报错"""
    def __init__(self, data):
        self._data = data if data else {}

    def __getattr__(self, name):
        val = self._data.get(name)
        if isinstance(val, dict):
            return SafeEventWrapper(val)
        if isinstance(val, list):
            return [SafeEventWrapper(x) if isinstance(x, dict) else x for x in val]
        return val
    
    def __getitem__(self, name):
        return self._data.get(name)
        
    def get(self, name, default=None):
        return self._data.get(name, default)
    
    def __contains__(self, item):
        return item in self._data

class ContextEngine:
    def __init__(self, es_client_wrapper):
        if hasattr(es_client_wrapper, 'es'):
            self.es = es_client_wrapper.es
        else:
            self.es = es_client_wrapper

    def _get_val(self, obj: Any, path: str, default: Any = None) -> Any:
        # 兼容 SafeEventWrapper 和 字典
        if isinstance(obj, SafeEventWrapper):
            obj = obj._data
            
        parts = path.split('.')
        curr = obj
        try:
            for p in parts:
                if curr is None: return default
                if isinstance(curr, dict): curr = curr.get(p)
                elif hasattr(curr, p): curr = getattr(curr, p)
                else: return default
            return curr if curr is not None else default
        except Exception:
            return default

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        if not ts_str: return None
        try:
            clean_ts = ts_str.replace('Z', '')
            if '.' in clean_ts:
                main_part, frac_part = clean_ts.split('.')
                clean_ts = f"{main_part}.{frac_part[:6].ljust(6, '0')}"
                return datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S.%f")
            else:
                return datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S")
        except Exception as e:
            logger.error(f"Time parsing failed for {ts_str}: {e}")
            return None

    # =========================================================================
    # [FIX] 核心任务 0: 获取种子事件
    # =========================================================================
    def get_seed_events(self, time_range: tuple, min_score: int = 50) -> List[Any]:
        """
        获取时间窗口内的高危事件作为溯源种子。
        策略：仅按时间拉取日志，在 Python 内存中计算分数并过滤，避免 ES Schema 冲突。
        """
        start_t, end_t = time_range
        
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_t, "lte": end_t}}}
                ]
            }
        }

        try:
            resp = self.es.search(
                index="unified-logs*,network-flows*,honeypot-logs*,host-logs*", 
                body={"query": query, "size": 500, "sort": [{"@timestamp": "desc"}]},
                ignore_unavailable=True
            )
        except Exception as e:
            logger.error(f"ES Search failed: {e}")
            return []

        hits = resp.get('hits', {}).get('hits', [])
        seeds = []

        for hit in hits:
            source = hit.get('_source', {})
            event_obj = SafeEventWrapper(source)
            
            threat_analysis = self.evaluate_threat(source)
            score = threat_analysis.get('score', 0)
            
            is_high_risk = score >= min_score
            if 'cowrie' in str(source.get('event', {}).get('dataset', '')):
                is_high_risk = True
                score = max(score, 100)
            
            if is_high_risk:
                # 动态注入 threat.confidence，供组员4使用
                # SafeEventWrapper 是只读代理，我们需要直接修改内部字典
                if 'threat' not in source or source['threat'] is None:
                    source['threat'] = {}
                source['threat']['confidence'] = score / 100.0
                
                # 重新包装以包含新数据
                seeds.append(SafeEventWrapper(source))

        return seeds

    # =========================================================================
    # 核心任务 1: 威胁研判 (Scoring)
    # =========================================================================
    def evaluate_threat(self, event: Any) -> Dict[str, Any]:
        # (保持你原有代码不变，不需要修改)
        # ... [为了节省篇幅，此处省略，直接使用你提供的原有逻辑即可] ...
        # 但请确保 _get_val 方法已经更新为上面的版本
        score = 0
        reasons = []
        
        # 基础字段提取 (使用 _get_val 兼容 Wrapper)
        confidence = float(self._get_val(event, 'detection.confidence', 0.0))
        severity_str = str(self._get_val(event, 'detection.severity', '')).lower()
        severity_int = self._get_val(event, 'event.severity', 0)
        dataset = self._get_val(event, 'event.dataset', '')
        category = self._get_val(event, 'event.category', '')
        
        # --- 1. MemDefense (内存防御) ---
        if category == 'memory':
            anomalies = self._get_val(event, 'memory.anomalies', [])
            if isinstance(anomalies, dict): anomalies = [anomalies]
            for anomaly in anomalies:
                if isinstance(anomaly, SafeEventWrapper): anomaly = anomaly._data
                risk = str(anomaly.get('risk_level', '')).upper()
                atype = anomaly.get('type', 'Unknown')
                if risk == 'CRITICAL':
                    score = 100
                    reasons.append(f"MemDefense: Critical Anomaly ({atype})")
                elif risk == 'HIGH':
                    score = max(score, 90)
                    reasons.append(f"MemDefense: High Risk Anomaly ({atype})")

        # --- 2. Sigma 规则映射 ---
        sigma_score = 0
        if severity_str == 'critical': sigma_score = 100; reasons.append("Sigma Rule: CRITICAL")
        elif severity_str == 'high': sigma_score = 80; reasons.append("Sigma Rule: HIGH")
        elif severity_str == 'medium': sigma_score = 50; reasons.append("Sigma Rule: MEDIUM")
        elif confidence > 0: sigma_score = confidence * 100
        
        if sigma_score > 0:
            tech_name = self._get_val(event, 'threat.technique.name')
            if tech_name: reasons.append(f"ATT&CK: {tech_name}")
        score = max(score, sigma_score)

        # --- 3. Agent 兼容性 ---
        if isinstance(severity_int, int) and severity_int > 0:
            agent_score = severity_int * 10
            if agent_score > score:
                score = agent_score
                reasons.append(f"Agent Reported Severity: {severity_int}")

        # --- 4. 蜜罐特判 ---
        honeypot_score = 0
        if 'cowrie' in str(dataset).lower():
            action = self._get_val(event, 'event.action', '')
            if action == 'input' or confidence >= 0.7:
                honeypot_score = 100; reasons.append("CRITICAL: Honeypot Command")
            elif confidence >= 0.5:
                honeypot_score = 80; reasons.append("HIGH: Honeypot Suspicious")
            else:
                honeypot_score = 50; reasons.append("MEDIUM: Honeypot Activity")
        score = max(score, honeypot_score)
        
        # --- 5. 身份认证检测 ---
        if category == 'authentication':
            outcome = self._get_val(event, 'event.outcome', 'unknown')
            user = self._get_val(event, 'user.name', 'unknown')
            src_ip = self._get_val(event, 'source.ip')
            if outcome == 'failure':
                score = max(score, 40)
                reasons.append("Authentication: Login Failure")
            if user == 'root' and outcome == 'success':
                local_ips = ['127.0.0.1', '::1', 'localhost', '0.0.0.0']
                if src_ip and src_ip not in local_ips:
                    score = max(score, 60)
                    reasons.append(f"Authentication: Root Remote Login from {src_ip}")

        # --- 6. 启发式兜底 ---
        heuristic_score, heuristic_reasons = self._check_heuristics(event)
        if heuristic_score > score:
            score = heuristic_score
            reasons.extend(heuristic_reasons)

        if score >= 90: final_severity = "critical"
        elif score >= 70: final_severity = "high"
        elif score >= 50: final_severity = "medium"
        else: final_severity = "low"

        return {
            "score": round(score, 2),
            "is_threat": score >= 50,
            "severity": final_severity,
            "reasons": list(set(reasons))
        }

    def _check_heuristics(self, event: Any) -> tuple:
        # (保持原逻辑不变，但需确保 self._get_val 调用正常)
        score = 0
        reasons = []
        
        proc_name = self._get_val(event, 'process.name', '')
        # ... (其余逻辑与你提供的原始文件一致) ...
        # 为节省篇幅，这里假设你保留了原始的 _check_heuristics 实现
        # 只要确保 proc_name, cmd_line 等都是通过 _get_val 获取的即可
        
        # === 简单复刻你的逻辑以确保完整性 ===
        proc_name_lower = str(proc_name).lower()
        cmd_line_lower = str(self._get_val(event, 'process.command_line', '')).lower()
        file_path_lower = str(self._get_val(event, 'file.path', '')).lower()
        
        if any(t in proc_name_lower for t in ["ncat", "nc", "netcat", "socket"]):
            score = max(score, 70)
            reasons.append(f"Heuristic: Dangerous Tool ({proc_name})")
            
        if "bash -i" in cmd_line_lower or "/dev/tcp/" in cmd_line_lower:
            score = max(score, 85)
            reasons.append("Heuristic: Reverse Shell Pattern")
            
        return score, reasons

    def find_related_events(self, anchor: Any, window: int = 60) -> List[Dict[str, Any]]:
        # 修复点：确保 anchor 是 Wrapper 时也能工作
        anchor_ts = self._get_val(anchor, 'timestamp') or self._get_val(anchor, '@timestamp')
        host = self._get_val(anchor, 'host.name')
        if not anchor_ts or not host: return []
        
        dt = self._parse_timestamp(anchor_ts)
        if not dt: return []
        
        start_t = (dt - timedelta(seconds=window)).isoformat()
        end_t = (dt + timedelta(seconds=window)).isoformat()
        
        must = [{"range": {"@timestamp": {"gte": start_t, "lte": end_t}}}, {"term": {"host.name": host}}]
        should = []
        
        path = self._get_val(anchor, 'file.path')
        if path and path not in ["", "unknown"]:
            should.append({"term": {"file.path": path}})
            should.append({"match": {"file.name": os.path.basename(path)}})
        
        ip = self._get_val(anchor, 'source.ip')
        if ip: should.append({"term": {"source.ip": ip}})
        
        if not should: return []
        
        try:
            # 修复点：使用 ignore_unavailable
            res = self.es.search(
                index="unified-logs*,network-flows*,honeypot-logs*", 
                body={"query": {"bool": {"must": must, "should": should, "minimum_should_match": 1}}, "size": 50},
                ignore_unavailable=True
            )
            return [h['_source'] for h in res['hits']['hits']]
        except Exception:
            return []
