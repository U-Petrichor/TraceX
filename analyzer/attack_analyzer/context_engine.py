# analyzer/attack_analyzer/context_engine.py
"""
TraceX Context Engine v5.6 (Final & Comprehensive)
================================================================================
组员3 核心模块 - 案发现场勘查与线索收集

修订记录：
- v5.6: [Fix] 兼容组员1整数Severity，新增登录安全检测 (Root/Failure)
- v5.5: [Feature] 新增 Windows (PowerShell/Certutil) 与 持久化检测
- v5.4: [Fix] 补全所有 Linux 主机安全启发式规则
================================================================================
"""
import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ContextEngine:
    def __init__(self, es_client_wrapper):
        if hasattr(es_client_wrapper, 'es'):
            self.es = es_client_wrapper.es
        else:
            self.es = es_client_wrapper

    def _get_val(self, obj: Any, path: str, default: Any = None) -> Any:
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
    # 核心任务 1: 威胁研判 (Scoring)
    # =========================================================================
    
    def evaluate_threat(self, event: Any) -> Dict[str, Any]:
        score = 0
        reasons = []
        
        # 基础字段
        confidence = float(self._get_val(event, 'detection.confidence', 0.0))
        # 兼容 String (Sigma) 和 Int (Group 1 Agent)
        severity_str = str(self._get_val(event, 'detection.severity', '')).lower()
        severity_int = self._get_val(event, 'event.severity', 0)
        
        dataset = self._get_val(event, 'event.dataset', '')
        category = self._get_val(event, 'event.category', '')
        
        # --- 1. MemDefense (内存防御) ---
        if category == 'memory':
            anomalies = self._get_val(event, 'memory.anomalies', [])
            if isinstance(anomalies, dict): anomalies = [anomalies]
            for anomaly in anomalies:
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

        # --- 3. [New] 组员1 兼容性 (Integer Severity) ---
        # Auditd Agent 使用 1-10 的整数评分
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
        
        # --- 5. [New] 身份认证检测 (Authentication) ---
        if category == 'authentication':
            outcome = self._get_val(event, 'event.outcome', 'unknown')
            user = self._get_val(event, 'user.name', 'unknown')
            src_ip = self._get_val(event, 'source.ip')
            
            # 5.1 登录失败 (暴力破解迹象)
            if outcome == 'failure':
                score = max(score, 40) # 单次失败给低分，靠图谱聚合
                reasons.append("Authentication: Login Failure")
                
            # 5.2 Root 远程登录
            if user == 'root' and outcome == 'success':
                # 检查是否为远程 IP
                local_ips = ['127.0.0.1', '::1', 'localhost', '0.0.0.0']
                if src_ip and src_ip not in local_ips:
                    score = max(score, 60)
                    reasons.append(f"Authentication: Root Remote Login from {src_ip}")

        # --- 6. 启发式兜底 (Heuristics) ---
        heuristic_score, heuristic_reasons = self._check_heuristics(event)
        if heuristic_score > score:
            score = heuristic_score
            reasons.extend(heuristic_reasons)

        # 最终定级
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
        """
        全平台启发式规则库 (Linux + Windows + Persistence)
        """
        score = 0
        reasons = []
        
        proc_name = self._get_val(event, 'process.name', '')
        proc_exe = self._get_val(event, 'process.executable', '')
        file_path = self._get_val(event, 'file.path', '')
        file_ext = self._get_val(event, 'file.extension', '')
        action = self._get_val(event, 'event.action', '')
        cmd_line = self._get_val(event, 'process.command_line', '')
        user_name = self._get_val(event, 'user.name', '')

        proc_name_lower = str(proc_name).lower()
        cmd_line_lower = str(cmd_line).lower()
        file_path_lower = str(file_path).lower()

        # === 规则 1: 工具检测 (Tools) ===
        dangerous_tools = ["ncat", "nc", "netcat", "socket", "wireshark", "nmap", "masscan", "metasploit", "mimikatz"]
        if any(t in proc_name_lower for t in dangerous_tools):
            score = max(score, 70)
            reasons.append(f"Heuristic: Dangerous Tool ({proc_name})")
        
        suspicious_tools = ["curl", "wget", "scp", "rsync", "ftp", "python", "perl", "ruby"]
        win_suspicious = ["certutil", "bitsadmin", "powershell", "psexec", "wmic", "schtasks"]
        
        all_suspicious = suspicious_tools + win_suspicious
        
        if any(t in proc_name_lower for t in all_suspicious):
            base_score = 60
            
            # Windows PowerShell 特判
            if "powershell" in proc_name_lower:
                if any(k in cmd_line_lower for k in ["-enc", "-encodedcommand", "-w hidden", "bypass"]):
                    base_score = 70
                    reasons.append("Heuristic: PowerShell Encoded/Hidden Command")
                else:
                    reasons.append(f"Heuristic: Suspicious Tool ({proc_name})")
            
            # Windows Certutil 特判
            elif "certutil" in proc_name_lower:
                if "urlcache" in cmd_line_lower or "split" in cmd_line_lower:
                    base_score = 65
                    reasons.append("Heuristic: Certutil Download Activity")
                else:
                    reasons.append(f"Heuristic: Suspicious Tool ({proc_name})")
            
            else:
                reasons.append(f"Heuristic: Suspicious Tool ({proc_name})")
            
            score = max(score, base_score)

        # === 规则 2: WebShell 行为 ===
        webshell_paths = ["/var/www", "html", "htdocs", "downloads", "tmp", "/tmp/", "c:\\inetpub\\wwwroot"]
        webshell_exts = [".php", ".jsp", ".asp", ".aspx", ".sh"]
        write_actions = ["write", "create", "moved-to", "rename", "unknown", "process_started"]

        if any(p in file_path_lower for p in webshell_paths):
            if any(file_path_lower.endswith(e) for e in webshell_exts) or str(file_ext) in ["php", "jsp", "asp"]:
                if action in write_actions:
                    score = max(score, 90)
                    reasons.append(f"Heuristic: WebShell Write ({file_path})")
        
        if cmd_line:
            has_ws_path = any(p in cmd_line_lower for p in webshell_paths)
            has_ws_ext = any(e in cmd_line_lower for e in webshell_exts)
            if has_ws_path and has_ws_ext:
                score = max(score, 85)
                reasons.append(f"Heuristic: WebShell Pattern in Command")

        # === 规则 3: 敏感文件与持久化 ===
        sensitive_patterns = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", ".ssh/id_rsa", ".ssh/authorized_keys",
            "/etc/cron", "/var/spool/cron", "/etc/rc.local", "/etc/init.d", "/etc/systemd",
            "windows\\system32\\config\\sam", "windows\\system32\\config\\system",
            "currentversion\\run", "startup"
        ]
        
        if any(p in file_path_lower or p in cmd_line_lower for p in sensitive_patterns):
            score = max(score, 70)
            reasons.append("Heuristic: Sensitive/Persistence File Access")
            
        # === 规则 4: 反弹 Shell 特征 ===
        reverse_shell_patterns = [
            "bash -i", "/dev/tcp/", "nc -e", "ncat -e", 
            "exec 5<>/dev/tcp", "socket.socket", "pty.spawn"
        ]
        if any(p in cmd_line_lower for p in reverse_shell_patterns):
            score = max(score, 85)
            reasons.append("Heuristic: Reverse Shell Pattern")

        # === 规则 5: 低权限用户异常 ===
        low_priv_users = ["www-data", "apache", "nginx", "nobody"]
        if user_name in low_priv_users:
            if any(t in proc_name_lower for t in all_suspicious + dangerous_tools):
                score = max(score, 75)
                reasons.append(f"Heuristic: Low-Priv User ({user_name}) Executing Tool")
            if proc_name_lower in ["whoami", "id", "uname"]:
                score = max(score, 70)
                reasons.append(f"Heuristic: Low-Priv User ({user_name}) Recon")

        return score, reasons

    def find_related_events(self, anchor: Any, window: int = 60) -> List[Dict[str, Any]]:
        # (保持原有的关联逻辑)
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
            dir_path = os.path.dirname(path)
            if dir_path and len(dir_path) > 4: 
                should.append({"prefix": {"file.path": dir_path}})
        
        ip = self._get_val(anchor, 'source.ip')
        if ip: should.append({"term": {"source.ip": ip}}); should.append({"term": {"destination.ip": ip}})
        
        pid = self._get_val(anchor, 'process.pid')
        if pid: should.append({"term": {"process.pid": pid}})
        
        sess = self._get_val(anchor, 'cowrie.session')
        if sess: should.append({"term": {"cowrie.session": sess}})
        
        if not should: return []
        
        try:
            res = self.es.search(index="unified-logs*,network-flows*,honeypot-logs*", body={
                "query": {"bool": {"must": must, "should": should, "minimum_should_match": 1}},
                "size": 50
            })
            return [h['_source'] for h in res['hits']['hits'] if h['_id'] != self._get_val(anchor, 'event.id')]
        except Exception:
            return []
