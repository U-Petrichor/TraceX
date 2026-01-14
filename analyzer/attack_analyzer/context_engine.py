# analyzer/attack_analyzer/context_engine.py
"""
TraceX Context Engine — 合并修复与启发式补全
本文件整合了 SafeEventWrapper、时间解析、get_seed_events 的最小置信度注入，
并补全漏失的启发式识别规则以通过主机采集验证套件。
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
        if isinstance(obj, SafeEventWrapper):
            obj = obj._data
        parts = path.split('.')
        curr = obj
        try:
            for p in parts:
                if curr is None:
                    return default
                if isinstance(curr, dict):
                    curr = curr.get(p)
                elif hasattr(curr, p):
                    curr = getattr(curr, p)
                else:
                    return default
            return curr if curr is not None else default
        except Exception:
            return default

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        if not ts_str:
            return None
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

    def get_seed_events(self, time_range: tuple, min_score: int = 50) -> List[Any]:
        start_t, end_t = time_range
        query = {"bool": {"must": [{"range": {"@timestamp": {"gte": start_t, "lte": end_t}}}]}}
        try:
            resp = self.es.search(
                index="unified-logs*,network-flows*,honeypot-logs*,host-logs*",
                body={"query": query, "size": 500, "sort": [{"@timestamp": "desc"}]},
                ignore_unavailable=True,
            )
            hits = resp.get('hits', {}).get('hits', [])
            seeds = []
            for hit in hits:
                source = hit.get('_source', {})
                threat_analysis = self.evaluate_threat(source)
                score = threat_analysis.get('score', 0)
                if score >= min_score or 'cowrie' in str(source.get('event', {}).get('dataset', '')):
                    if 'threat' not in source or source['threat'] is None:
                        source['threat'] = {}
                    source['threat']['confidence'] = max(score, 50) / 100.0
                    seeds.append(SafeEventWrapper(source))
            return seeds
        except Exception as e:
            logger.error(f"ES Search failed: {e}")
            return []

    def evaluate_threat(self, event: Any) -> Dict[str, Any]:
        """核心威胁评估逻辑：整合内存、身份、Sigma及所有启发式规则"""
        score = 0
        reasons = []

        confidence = float(self._get_val(event, 'detection.confidence', 0.0))
        severity_str = str(self._get_val(event, 'detection.severity', '')).lower()
        severity_int = self._get_val(event, 'event.severity', 0)
        dataset = self._get_val(event, 'event.dataset', '')
        category = self._get_val(event, 'event.category', '')

        # 1. 内存防御 (已通过测试)
        if category == 'memory':
            anomalies = self._get_val(event, 'memory.anomalies', [])
            if isinstance(anomalies, dict):
                anomalies = [anomalies]
            for a in anomalies:
                risk = str(a.get('risk_level', '')).upper()
                atype = a.get('type', 'Unknown')
                if risk == 'CRITICAL':
                    score = 100
                    reasons.append(f"MemDefense: Critical Anomaly ({atype})")
                elif risk == 'HIGH':
                    score = max(score, 90)
                    reasons.append(f"MemDefense: High Risk Anomaly ({atype})")

        # 2. Sigma 规则映射
        sigma_map = {"critical": 100, "high": 80, "medium": 50, "low": 20}
        if severity_str in sigma_map:
            score = max(score, sigma_map[severity_str])
            reasons.append(f"Sigma Rule: {severity_str.upper()}")

        # 3. Agent 兼容性 (已通过测试)
        if isinstance(severity_int, int) and severity_int > 0:
            agent_score = severity_int * 10
            if agent_score > score:
                score = agent_score
                reasons.append(f"Agent Reported Severity: {severity_int}")

        # 4. 身份认证 (已通过测试)
        if category == 'authentication':
            outcome = self._get_val(event, 'event.outcome', 'unknown')
            user = self._get_val(event, 'user.name', 'unknown')
            if outcome == 'failure':
                score = max(score, 40)
                reasons.append("Authentication: Login Failure")
            if user == 'root' and outcome == 'success':
                if self._get_val(event, 'source.ip') not in ['127.0.0.1', '::1', 'localhost']:
                    score = max(score, 60)
                    reasons.append(f"Authentication: Root Remote Login from {self._get_val(event, 'source.ip')}")

        # 5. 补全：启发式规则 (处理失败的 9 个测试场景)
        h_score, h_reasons = self._check_heuristics(event)
        if h_score > score:
            score = h_score
            reasons.extend(h_reasons)

        # 最终等级映射
        final_sev = "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 50 else "low"
        return {"score": round(score, 2), "is_threat": score >= 50, "severity": final_sev, "reasons": list(set(reasons))}

    def _check_heuristics(self, event: Any) -> tuple:
        """补全所有缺失的识别规则"""
        score = 0
        reasons = []

        proc_name = str(self._get_val(event, 'process.name', '')).lower()
        cmd_line = str(self._get_val(event, 'process.command_line', '')).lower()
        file_path = str(self._get_val(event, 'file.path', '')).lower()
        user_name = str(self._get_val(event, 'user.name', '')).lower()
        dataset = str(self._get_val(event, 'event.dataset', '')).lower()

        # A. 反弹 Shell 与 危险工具 (test_01, test_02)
        if "bash -i" in cmd_line or "/dev/tcp/" in cmd_line:
            score = 85
            reasons.append("Heuristic: Reverse Shell Pattern")
        if any(t in proc_name for t in ["ncat", "nc", "socket"]):
            score = max(score, 70)
            reasons.append(f"Heuristic: Dangerous Tool ({proc_name})")

        # B. 可疑下载 (test_03)
        if any(t in proc_name for t in ["wget", "curl"]):
            score = max(score, 60)
            reasons.append(f"Heuristic: Suspicious Tool ({proc_name})")

        # C. 低权用户异常行为 (test_04)
        if user_name == "www-data" and any(t in proc_name for t in ["curl", "wget", "python", "perl", "php"]):
            score = max(score, 75)
            reasons.append("Heuristic: Low-Priv User Web Request")

        # D. WebShell 特征 (test_05, test_06)
        if "/var/www/html" in file_path or "/var/www/html" in cmd_line:
            if any(ext in file_path or ext in cmd_line for ext in [".php", ".jsp", ".asp", ".aspx"]):
                score = max(score, 90)
                reasons.append("Heuristic: WebShell Pattern" if "/var/www/html" in cmd_line else "Heuristic: WebShell Write")

        # E. 敏感文件访问 (test_07)
        if any(sf in file_path or sf in cmd_line for sf in ["/etc/shadow", "/etc/passwd", "/etc/sudoers"]):
            score = max(score, 70)
            reasons.append("Heuristic: Sensitive/Persistence File Access")

        # F. 持久化后门 (test_08, test_09)
        if any(p in file_path for p in ["/etc/cron.d/", "/etc/rc.local", "systemd/system"]):
            score = max(score, 70)
            reasons.append("Heuristic: Persistence Mechanism Modification")

        # G. Windows 特定检测 (test_10, test_11)
        if dataset == "windows":
            if "powershell" in proc_name and ("-enc" in cmd_line or "-encodedcommand" in cmd_line):
                score = max(score, 70)
                reasons.append("Heuristic: PowerShell Encoded Command")
            if "certutil" in proc_name and "-urlcache" in cmd_line:
                score = max(score, 65)
                reasons.append("Heuristic: Certutil Download (LotL)")

        return score, reasons

    def find_related_events(self, anchor: Any, window: int = 30) -> List[Dict[str, Any]]:
        """查找关联事件：集成 v6.1 优化（窗口30s、PID/PPID 因果关联、basename 空间模糊匹配）"""
        anchor_ts = self._get_val(anchor, 'timestamp') or self._get_val(anchor, '@timestamp')
        host = self._get_val(anchor, 'host.name')
        if not anchor_ts or not host:
            return []

        dt = self._parse_timestamp(anchor_ts)
        if not dt:
            return []

        start_t = (dt - timedelta(seconds=window)).isoformat()
        end_t = (dt + timedelta(seconds=window)).isoformat()

        must = [{"range": {"@timestamp": {"gte": start_t, "lte": end_t}}}, {"term": {"host.name": host}}]
        should = []

        pid = self._get_val(anchor, 'process.pid')
        ppid = self._get_val(anchor, 'process.parent.pid')
        if pid:
            should.append({"term": {"process.parent.pid": pid}})
        if ppid:
            should.append({"term": {"process.pid": ppid}})

        path = self._get_val(anchor, 'file.path', '') or ''
        if path and any(p in path for p in ['/tmp/', '/dev/shm/', '/var/www/']):
            basename = os.path.basename(path)
            if len(basename) > 3:
                should.append({"match": {"file.path": basename}})
        else:
            if path and path not in ["", "unknown"]:
                should.append({"term": {"file.path": path}})
                should.append({"match": {"file.name": os.path.basename(path)}})

        ip = self._get_val(anchor, 'source.ip')
        if ip:
            should.append({"term": {"source.ip": ip}})

        if not should:
            return []

        try:
            query = {"bool": {"must": must, "should": should, "minimum_should_match": 1}}
            res = self.es.search(index="unified-logs*,network-flows*,honeypot-logs*", body={"query": query, "size": 100}, ignore_unavailable=True)
            return [h['_source'] for h in res['hits']['hits']]
        except Exception:
            return []
