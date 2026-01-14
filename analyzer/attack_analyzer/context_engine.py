# analyzer/attack_analyzer/context_engine.py
"""
TraceX Context Engine v5.3 (Complete)
================================================================================
组员3 核心模块 - 案发现场勘查与线索收集

职责：
1. evaluate_threat() - 威胁研判（定性：要不要报警、报警级别）
2. find_related_events() - 时空关联搜索（定位种子事件周围发生了什么）

修订记录：
- v5.3: [Complete] 补全网络宽容关联、进程关联、会话关联
- v5.2.2: [Fix] 扩大关联窗口至 60s，增强时间戳解析兼容性
- v5.2.1: [Fix] 移除启发式检测的低分门槛，确保 Max 逻辑生效
- v5.2: [对接组员2] 针对 Cowrie 蜜罐添加 Critical 判定规则
================================================================================
"""
import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ContextEngine:
    """
    上下文引擎 (Context Engine)
    
    作为数据层面的"第一经手人"：
    - 不关心整个攻击故事是怎样的
    - 只关心眼前这条日志坏不坏，以及这一瞬间周围发生了什么
    """
    
    def __init__(self, es_client_wrapper):
        """
        :param es_client_wrapper: collector.common.es_client.ESClient 的实例
        """
        if hasattr(es_client_wrapper, 'es'):
            self.es = es_client_wrapper.es
        else:
            self.es = es_client_wrapper

    # =========================================================================
    # 辅助方法
    # =========================================================================
    
    def _get_val(self, obj: Any, path: str, default: Any = None) -> Any:
        """安全获取嵌套字段值"""
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
        """
        解析时间戳，兼容多种格式
        - ISO8601: 2026-01-14T10:00:00.000000Z
        - 毫秒/微秒精度不统一
        """
        if not ts_str:
            return None
        try:
            clean_ts = ts_str.replace('Z', '')
            if '.' in clean_ts:
                main_part, frac_part = clean_ts.split('.')
                # 截断或补齐到 6 位微秒
                clean_ts = f"{main_part}.{frac_part[:6].ljust(6, '0')}"
                return datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S.%f")
            else:
                return datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S")
        except Exception as e:
            logger.error(f"Time parsing failed for {ts_str}: {e}")
            return None

    # =========================================================================
    # 核心任务 1: 威胁研判 (Scoring & Triage)
    # =========================================================================
    
    def evaluate_threat(self, event: Any) -> Dict[str, Any]:
        """
        威胁聚合打分器 (Scorer)
        
        采用 MAX(Sigma, Honeypot, Heuristic) 策略，而不是加和。
        这能防止多个低危告警累加成高危误报。
        
        评分来源：
        1. Sigma 规则映射 - 读取 detection.confidence 和 detection.severity
        2. 蜜罐特判 (Cowrie) - 蜜罐里的行为无条件高危
        3. 启发式兜底 - 抓漏网之鱼
        
        Returns:
            {
                "score": 0-100,
                "is_threat": bool,
                "severity": "low" | "medium" | "high" | "critical",
                "reasons": [str]
            }
        """
        score = 0
        reasons = []
        
        # --- 1. 获取关键字段 ---
        confidence = float(self._get_val(event, 'detection.confidence', 0.0))
        rules = self._get_val(event, 'detection.rules', [])
        if isinstance(rules, str): 
            rules = [rules]
        severity = self._get_val(event, 'detection.severity', '')
        tech_name = self._get_val(event, 'threat.technique.name')
        tech_id = self._get_val(event, 'threat.technique.id')
        dataset = self._get_val(event, 'event.dataset', '')
        
        # --- 2. Sigma 规则映射 ---
        # 如果 Sigma 说这是 Critical，直接给 100 分
        sigma_score = 0
        if severity == 'critical':
            sigma_score = 100
            reasons.append("Sigma Rule: CRITICAL Severity")
        elif severity == 'high':
            sigma_score = 80
            reasons.append("Sigma Rule: HIGH Severity")
        elif severity == 'medium':
            sigma_score = 50
            reasons.append("Sigma Rule: MEDIUM Severity")
        elif confidence > 0:
            # 没有 severity 时，用 confidence 计算
            sigma_score = confidence * 100
            
        if sigma_score > 0:
            if tech_name:
                reasons.append(f"ATT&CK Technique: {tech_name} ({tech_id})")
            if rules:
                reasons.append(f"Rules Matched: {', '.join(rules[:3])}")  # 最多显示3条
        
        score = max(score, sigma_score)
        
        # --- 3. 蜜罐特判 (Cowrie) ---
        # 死死盯着 event.dataset 里的 cowrie 字段
        # 只要是蜜罐里的高置信度行为，无条件判死刑
        honeypot_score = 0
        if 'cowrie' in dataset.lower():
            # 蜜罐中的任何命令执行都是可疑的
            action = self._get_val(event, 'event.action', '')
            if action == 'input' or confidence >= 0.7:
                honeypot_score = 100
                reasons.append("CRITICAL: Honeypot Command Execution")
            elif confidence >= 0.5:
                honeypot_score = 80
                reasons.append("HIGH: Honeypot Suspicious Activity")
            else:
                # 即使低置信度，蜜罐日志也至少是 Medium
                honeypot_score = 50
                reasons.append("MEDIUM: Honeypot Activity Detected")
        
        score = max(score, honeypot_score)
        
        # --- 4. 启发式兜底 (Heuristics) ---
        # 这是为了抓漏网之鱼：Sigma 没覆盖的，靠硬编码规则抓
        heuristic_score, heuristic_reasons = self._check_heuristics(event)
        
        if heuristic_score > score:
            score = heuristic_score
            reasons.extend(heuristic_reasons)

        # --- 5. 计算最终 severity ---
        if score >= 90:
            final_severity = "critical"
        elif score >= 70:
            final_severity = "high"
        elif score >= 50:
            final_severity = "medium"
        else:
            final_severity = "low"

        return {
            "score": round(score, 2),
            "is_threat": score >= 50,
            "severity": final_severity,
            "reasons": list(set(reasons))
        }

    def _check_heuristics(self, event: Any) -> tuple:
        """
        执行启发式规则检查
        
        Returns:
            (score: int, reasons: List[str])
        """
        score = 0
        reasons = []
        
        proc_name = self._get_val(event, 'process.name', '')
        proc_exe = self._get_val(event, 'process.executable', '')
        cmd_line = self._get_val(event, 'process.command_line', '')
        file_path = self._get_val(event, 'file.path', '')
        file_ext = self._get_val(event, 'file.extension', '')
        action = self._get_val(event, 'event.action', '')
        user_name = self._get_val(event, 'user.name', '')

        # === 规则 1: 工具黑名单 ===
        # 进程名是 nc, ncat, wireshark，直接加 60 分
        dangerous_tools = ["ncat", "nc", "netcat", "socket", "wireshark", "nmap", "masscan"]
        suspicious_tools = ["curl", "wget", "scp", "rsync", "ftp"]
        
        if proc_name in dangerous_tools:
            score = max(score, 70)
            reasons.append(f"Heuristic: Dangerous Tool ({proc_name})")
        elif proc_name in suspicious_tools:
            score = max(score, 60)
            reasons.append(f"Heuristic: Suspicious Tool ({proc_name})")
        
        # === 规则 2: WebShell 行为 ===
        # 在 /var/www/html 目录下写入 .php/.jsp 文件，直接加 90 分
        webshell_paths = ["/var/www/html", "/var/www", "htdocs", "wwwroot", "var/lib/cowrie/downloads"]
        webshell_exts = ["php", "jsp", "asp", "aspx", "sh", "py"]
        write_actions = ["write", "create", "moved-to", "rename", "cowrie.session.file_download"]
        
        if any(p in str(file_path) for p in webshell_paths):
            if action in write_actions and str(file_ext).lower() in webshell_exts:
                score = max(score, 90)
                reasons.append(f"Heuristic: WebShell Write ({file_path})")
        
        # === 规则 3: 敏感文件访问 ===
        sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", ".ssh/authorized_keys", ".bash_history"]
        if any(f in str(file_path) or f in str(cmd_line) for f in sensitive_files):
            score = max(score, 70)
            reasons.append("Heuristic: Sensitive File Access")
        
        # === 规则 4: 可疑命令模式 ===
        # 反弹 Shell 特征
        reverse_shell_patterns = [
            "bash -i", "/dev/tcp/", "nc -e", "ncat -e",
            "python -c", "perl -e", "ruby -e",
            "base64 -d", "| bash", "| sh"
        ]
        if any(p in str(cmd_line) for p in reverse_shell_patterns):
            score = max(score, 85)
            reasons.append("Heuristic: Reverse Shell Pattern")
        
        # === 规则 5: 特权用户异常行为 ===
        # www-data 用户执行网络工具
        low_priv_users = ["www-data", "apache", "nginx", "nobody"]
        if user_name in low_priv_users and proc_name in suspicious_tools + dangerous_tools:
            score = max(score, 75)
            reasons.append(f"Heuristic: Low-Priv User ({user_name}) Running Tools")
        
        return score, reasons

    # =========================================================================
    # 核心任务 2: 时空关联搜索 (Context Retrieval)
    # =========================================================================
    
    def find_related_events(self, anchor: Any, window: int = 60) -> List[Dict[str, Any]]:
        """
        关联事件查找 - 这是脏活累活最重的地方
        
        因为原始日志非常乱，负责把"看似无关"但"实际相关"的日志捞回来。
        
        关联维度：
        1. 时间窗口：前后 60 秒
        2. 主机：必须是同一台机器
        3. 文件：精确路径 + 模糊文件名（解决改名问题）
        4. 网络：宽容模式（IP 出现在任意方向）
        5. 进程：PID + 父进程
        6. 会话：session_id（Cowrie）
        
        Args:
            anchor: 种子事件（锚点）
            window: 时间窗口（秒），默认 60 秒
            
        Returns:
            List of related events from ES
        """
        # === Step 1: 解析时间戳，划定搜索范围 ===
        anchor_ts_str = self._get_val(anchor, 'timestamp') or self._get_val(anchor, '@timestamp')
        anchor_host_name = self._get_val(anchor, 'host.name')
        
        if not anchor_ts_str or not anchor_host_name:
            logger.warning("Anchor event missing timestamp or hostname")
            return []
        
        anchor_dt = self._parse_timestamp(anchor_ts_str)
        if not anchor_dt:
            return []
            
        start_t = (anchor_dt - timedelta(seconds=window)).isoformat()
        end_t = (anchor_dt + timedelta(seconds=window)).isoformat()

        # === Step 2: 构建 Must 查询（必须满足） ===
        must_queries = [
            {"range": {"@timestamp": {"gte": start_t, "lte": end_t}}},
            {"term": {"host.name": anchor_host_name}}
        ]
        
        # === Step 3: 构建 Should 查询（满足任一即可） ===
        should_queries = []

        # --- A. 文件关联 (Fuzzy Matching) ---
        # 攻击者常把 shell.php 改名为 a.php
        # 既查精确路径，也查文件名
        file_path = self._get_val(anchor, 'file.path')
        if file_path and file_path not in ["", "unknown"]:
            # Level 1: 精确路径匹配
            should_queries.append({"term": {"file.path": file_path}})
            
            # Level 2: 模糊文件名匹配
            filename = os.path.basename(file_path)
            if filename:
                should_queries.append({"match": {"file.name": filename}})
                
                # Level 3: 同目录下的其他文件
                dir_path = os.path.dirname(file_path)
                if dir_path:
                    should_queries.append({"prefix": {"file.path": dir_path}})

        # --- B. 网络宽容关联 (Permissive Network Link) ---
        # 流量日志有时分不清方向
        # 只要 IP 出现在日志里，不管是 Source 还是 Destination，都捞回来
        src_ip = self._get_val(anchor, 'source.ip')
        dst_ip = self._get_val(anchor, 'destination.ip')
        
        if src_ip:
            # 查找 src_ip 作为 source 或 destination 的记录
            should_queries.append({"term": {"source.ip": src_ip}})
            should_queries.append({"term": {"destination.ip": src_ip}})
            
        if dst_ip and dst_ip != src_ip:
            should_queries.append({"term": {"source.ip": dst_ip}})
            should_queries.append({"term": {"destination.ip": dst_ip}})

        # --- C. 进程关联 ---
        # 按 PID 和父进程关联
        pid = self._get_val(anchor, 'process.pid')
        ppid = self._get_val(anchor, 'process.parent.pid')
        
        if pid and pid > 0:
            should_queries.append({"term": {"process.pid": pid}})
            should_queries.append({"term": {"process.parent.pid": pid}})  # 找子进程
            
        if ppid and ppid > 0:
            should_queries.append({"term": {"process.pid": ppid}})  # 找父进程
            should_queries.append({"term": {"process.parent.pid": ppid}})  # 找兄弟进程

        # --- D. 用户会话关联 (Cowrie Session) ---
        # Cowrie 的 session_id 是攻击者会话的唯一标识
        session_id = self._get_val(anchor, 'cowrie.session') or \
                     self._get_val(anchor, 'labels.session') or \
                     self._get_val(anchor, 'session_id') or \
                     self._get_val(anchor, 'raw.session') or \
                     self._get_val(anchor, 'user.session_id')
                     
        if session_id:
            should_queries.append({"term": {"cowrie.session": session_id}})
            should_queries.append({"term": {"labels.session": session_id}})
            should_queries.append({"term": {"session_id": session_id}})
            should_queries.append({"term": {"raw.session": session_id}})
            should_queries.append({"term": {"user.session_id": session_id}})

        # --- E. 用户关联 ---
        user_name = self._get_val(anchor, 'user.name')
        if user_name and user_name not in ["", "unknown", "root"]:  # root 太泛了
            should_queries.append({"term": {"user.name": user_name}})

        # === Step 4: 执行查询 ===
        if not should_queries:
            logger.warning("No relation criteria found for anchor event")
            return []

        query = {
            "bool": {
                "must": must_queries,
                "should": should_queries,
                "minimum_should_match": 1
            }
        }
        
        try:
            # 查询所有相关索引
            target_indices = "unified-logs*,network-flows*,honeypot-logs*"
            result = self.es.search(
                index=target_indices, 
                body={"query": query, "size": 200, "sort": [{"@timestamp": "asc"}]}
            )
            hits = result.get('hits', {}).get('hits', [])
            
            # 排除锚点事件本身
            anchor_id = self._get_val(anchor, 'event.id')
            related = []
            for hit in hits:
                event = hit['_source']
                if self._get_val(event, 'event.id') != anchor_id:
                    related.append(event)
                    
            logger.info(f"Found {len(related)} related events for anchor {anchor_id}")
            return related
            
        except Exception as e:
            logger.error(f"Context query failed: {str(e)}")
            return []

    # =========================================================================
    # 辅助方法：为组员4提供
    # =========================================================================
    
    def get_seed_events(self, time_range: tuple, min_score: int = 50) -> List[Dict[str, Any]]:
        """
        获取种子事件（高威胁事件）供组员4的图构建器使用
        
        Args:
            time_range: (start_time, end_time) ISO格式
            min_score: 最低威胁分数阈值
            
        Returns:
            高威胁事件列表
        """
        start_time, end_time = time_range
        
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
                    {"range": {"event.severity": {"gte": 7}}}  # severity >= 7 是高危
                ]
            }
        }
        
        try:
            target_indices = "unified-logs*,network-flows*,honeypot-logs*"
            result = self.es.search(
                index=target_indices,
                body={"query": query, "size": 100, "sort": [{"@timestamp": "asc"}]}
            )
            
            seeds = []
            for hit in result.get('hits', {}).get('hits', []):
                event = hit['_source']
                # 再用 evaluate_threat 精确评分
                threat_info = self.evaluate_threat(event)
                if threat_info['score'] >= min_score:
                    event['_threat_score'] = threat_info['score']
                    event['_threat_reasons'] = threat_info['reasons']
                    seeds.append(event)
                    
            return seeds
            
        except Exception as e:
            logger.error(f"Seed event query failed: {str(e)}")
            return []
