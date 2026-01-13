# analyzer/attack_analyzer/context_engine.py
"""
TraceX Context Engine v5.2.2 (Final RC)
修订记录：
- v5.2.2: [Fix] 扩大关联窗口至 60s，增强时间戳解析兼容性，修复 Cowrie 下载动作漏检
- v5.2.1: [Fix] 移除启发式检测的低分门槛，确保 Max 逻辑生效
- v5.2: [对接组员2] 针对 Cowrie 蜜罐添加 Critical 判定规则
"""
import os
import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ContextEngine:
    def __init__(self, es_client_wrapper):
        """
        :param es_client_wrapper: collector.common.es_client.ESClient 的实例
        """
        if hasattr(es_client_wrapper, 'es'):
            self.es = es_client_wrapper.es
        else:
            self.es = es_client_wrapper

    def _get_val(self, obj: Any, path: str, default: Any = None) -> Any:
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

    def evaluate_threat(self, event: Any) -> Dict[str, Any]:
        """
        威胁聚合打分器 (Scorer)
        """
        score = 0
        reasons = []
        
        # --- 1. 获取关键字段 ---
        confidence = float(self._get_val(event, 'detection.confidence', 0.0))
        rules = self._get_val(event, 'detection.rules', [])
        if isinstance(rules, str): rules = [rules]
        tech_name = self._get_val(event, 'threat.technique.name')
        tech_id = self._get_val(event, 'threat.technique.id')
        dataset = self._get_val(event, 'event.dataset', '')

        # --- 2. 计算基础分数 (Score = confidence * 100) ---
        if confidence > 0:
            sigma_score = confidence * 100
            score = max(score, sigma_score)
            
            if tech_name:
                reasons.append(f"ATT&CK Technique: {tech_name} ({tech_id})")
            if rules:
                reasons.append(f"Rules Matched: {', '.join(rules)}")
        
        # --- 3. Cowrie 蜜罐特殊规则 ---
        if 'cowrie' in dataset and confidence >= 1.0:
            score = 100
            reasons.append("Critical Honeypot Alert (High Confidence)")

        # --- 4. 补充启发式 (修正逻辑：始终检查，取最大值) ---
        heuristic_score = self._check_heuristics(event)
        
        if heuristic_score > score:
            score = heuristic_score
            reasons.append("Heuristic Suspicious Behavior (Context Engine)")

        return {
            "score": round(score, 2),
            "is_threat": score >= 50,
            "reasons": list(set(reasons))
        }

    def _check_heuristics(self, event: Any) -> int:
        """
        执行启发式规则检查
        """
        score = 0
        
        proc_name = self._get_val(event, 'process.name', '')
        file_path = self._get_val(event, 'file.path', '')
        file_ext = self._get_val(event, 'file.extension', '')
        action = self._get_val(event, 'event.action', '')

        # 规则 1: 敏感工具
        tools = ["ncat", "nc", "socket", "wireshark", "nmap", "curl", "wget"]
        if proc_name in tools:
            score = 60
            
        # 规则 2: WebShell 写入特征 (Cowrie 路径 + 标准 Web 路径)
        target_paths = ["/var/www/html", "var/lib/cowrie/downloads"]
        
        # [Fix] 兼容 Cowrie 特有的 action ID，防止漏检恶意下载
        valid_actions = ["write", "create", "moved-to", "cowrie.session.file_download"]
        
        if any(p in str(file_path) for p in target_paths) and action in valid_actions:
            if str(file_ext).lower() in ["php", "jsp", "asp", "sh"]:
                score = 90
        
        return score

    def find_related_events(self, anchor: Any, window: int = 60) -> List[Dict[str, Any]]:
        """
        关联事件查找
        [Fix] 默认窗口从 10s 扩大到 60s，以覆盖 APT 手工操作延迟
        """
        anchor_ts_str = self._get_val(anchor, 'timestamp') or self._get_val(anchor, '@timestamp')
        anchor_host_name = self._get_val(anchor, 'host.name')
        
        if not anchor_ts_str or not anchor_host_name:
            logger.warning("Anchor event missing timestamp or hostname")
            return []
        
        try:
            clean_ts = anchor_ts_str.replace('Z', '')
            # [Fix] 增强时间戳解析兼容性，处理 3位、6位或9位小数的情况
            if '.' in clean_ts:
                main_part, frac_part = clean_ts.split('.')
                # 截断或补齐到 6 位微秒，确保 strptime %f 能解析
                clean_ts = f"{main_part}.{frac_part[:6].ljust(6, '0')}"
                anchor_dt = datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S.%f")
            else:
                anchor_dt = datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S")
                
            start_t = (anchor_dt - timedelta(seconds=window)).isoformat()
            end_t = (anchor_dt + timedelta(seconds=window)).isoformat()
        except Exception as e:
            logger.error(f"Time parsing failed for {anchor_ts_str}: {e}")
            return []

        must_queries = [
            {"range": {"@timestamp": {
                "gte": start_t, 
                "lte": end_t
            }}},
            {"term": {"host.name": anchor_host_name}}
        ]
        should_queries = []

        # --- A. 文件关联 ---
        file_path = self._get_val(anchor, 'file.path')
        if file_path and file_path not in ["", "unknown"]:
            should_queries.append({"term": {"file.path": file_path}})
            filename = os.path.basename(file_path)
            if filename:
                should_queries.append({"match": {"file.name": filename}})

        # --- B. 网络关联 ---
        src_ip = self._get_val(anchor, 'source.ip')
        if src_ip:
            should_queries.append({
                "bool": {
                    "must": [
                        {"term": {"source.ip": src_ip}},
                    ]
                }
            })

        if not should_queries:
            return []

        query = {
            "bool": {
                "must": must_queries,
                "should": should_queries,
                "minimum_should_match": 1
            }
        }
        
        try:
            target_indices = "unified-logs*,network-flows*,honeypot-logs*"
            result = self.es.search(
                index=target_indices, 
                body={"query": query, "size": 100}
            )
            hits = result.get('hits', {}).get('hits', [])
            return [hit['_source'] for hit in hits]
        except Exception as e:
            logger.error(f"Context query failed: {str(e)}")
            return []