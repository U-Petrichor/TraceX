# analyzer/attack_analyzer/context_engine.py
"""
TraceX Context Engine v5.1 (Fixed)
版本：v5.1 (Complete Merged & Patched)
适用对象：组员 3
修订记录：
- 修复了 find_related_events 中的时间窗口计算错误 (不再使用 now)
- 适配了 es_client.py 的封装结构
- 统一了属性访问逻辑 (_get_val)
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
        # [Fix] 兼容性修复：适配 ESClient 封装类
        # 如果传入的是封装对象，取出底层的 .es (官方客户端)
        if hasattr(es_client_wrapper, 'es'):
            self.es = es_client_wrapper.es
        else:
            self.es = es_client_wrapper

    def _get_val(self, obj: Any, path: str, default: Any = None) -> Any:
        """
        [Helper] 统一属性访问器，兼容 dict 和 object (UnifiedEvent)
        支持点号路径访问，例如: 'process.name'
        """
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
        威胁聚合打分器 (Scorer) - v5.1 实施细则 3.1
        逻辑：Score = Max(SigmaScore, HeuristicScore)
        """
        score = 0
        reasons = []
        
        # 严重程度映射表 (转为小写处理，增强健壮性)
        severity_map = {"critical": 100, "high": 80, "medium": 50, "low": 20}

        # --- 1. 第一优先级：Sigma 引擎结果 ---
        # 使用统一的 _get_val 获取嵌套属性
        technique_id = self._get_val(event, 'threat.technique.id')
        technique_name = self._get_val(event, 'threat.technique.name', "Unknown")
        
        # 获取 severity，处理大小写问题
        raw_severity = self._get_val(event, 'event.severity') or self._get_val(event, 'detection.severity')
        event_severity = str(raw_severity).lower() if raw_severity else "low"

        if technique_id:
            sigma_score = severity_map.get(event_severity, 0)
            score = max(score, sigma_score)
            reasons.append(f"Sigma Rule Match: {technique_name}")

        # --- 2. 第二优先级：补充启发式规则 ---
        heuristic_score = self._check_heuristics(event)
        if heuristic_score > score:
            score = heuristic_score
            reasons.append("Heuristic Suspicious Behavior")

        return {
            "score": score,
            "is_threat": score >= 50,
            "reasons": reasons
        }

    def _check_heuristics(self, event: Any) -> int:
        """
        执行启发式规则检查 - v5.1 更新
        """
        score = 0
        
        # 获取字段
        proc_name = self._get_val(event, 'process.name', '')
        file_path = self._get_val(event, 'file.path', '')
        file_ext = self._get_val(event, 'file.extension', '')
        action = self._get_val(event, 'event.action', '')

        # [v5.1 规则 1] 敏感工具
        tools = ["ncat", "nc", "socket", "wireshark", "curl", "wget"]
        if proc_name in tools:
            score = 60
            
        # [v5.1 规则 2] 敏感路径写入 (WebShell)
        # 匹配：/var/www/html 下的 php/jsp/asp 文件
        # Action: 包含 "moved-to" 以覆盖 mv 操作
        if "/var/www/html" in str(file_path) and action in ["write", "create", "moved-to"]:
            if str(file_ext).lower() in ["php", "jsp", "asp"]:
                score = 90
        
        return score

    def find_related_events(self, anchor: Any, window: int = 10) -> List[Dict[str, Any]]:
        """
        关联事件查找 - v5.1 实施细则 3.2
        包含：Fuzzy Match (WebShell断链修复) + 宽容网络关联
        """
        anchor_ts_str = self._get_val(anchor, 'timestamp') or self._get_val(anchor, '@timestamp')
        anchor_host_name = self._get_val(anchor, 'host.name')
        
        if not anchor_ts_str or not anchor_host_name:
            logger.warning("Anchor event missing timestamp or hostname")
            return []
        
        # [Fix] 严重 Bug 修复：基于 anchor 时间计算绝对时间窗口
        # 不使用 now，而是使用 anchor_ts +/- window
        try:
            # 简单处理 ISO 格式 (假设带 'Z' 或无时区)
            clean_ts = anchor_ts_str.replace('Z', '')
            # 支持毫秒或秒级 ISO
            if '.' in clean_ts:
                anchor_dt = datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S.%f")
            else:
                anchor_dt = datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S")
                
            start_t = (anchor_dt - timedelta(seconds=window)).isoformat()
            end_t = (anchor_dt + timedelta(seconds=window)).isoformat()
        except Exception as e:
            logger.error(f"Time parsing failed for {anchor_ts_str}: {e}")
            return []

        # 1. 构建查询主体
        must_queries = [
            {"range": {"@timestamp": {
                "gte": start_t, 
                "lte": end_t
            }}},
            {"term": {"host.name": anchor_host_name}}
        ]
        should_queries = []

        # --- A. 对象重心关联 (Artifact Link) - Fuzzy Fix ---
        file_path = self._get_val(anchor, 'file.path')
        if file_path and file_path not in ["", "unknown"]:
            # Level 1: 精确匹配
            should_queries.append({"term": {"file.path": file_path}})
            
            # Level 2: 模糊匹配 (Basename) - v5.1 核心决议
            filename = os.path.basename(file_path)
            if filename:
                should_queries.append({"match": {"file.name": filename}})

        # --- B. 网络宽容关联 (Lenient Association) ---
        transport = self._get_val(anchor, 'network.transport')
        src_ip = self._get_val(anchor, 'source.ip')
        
        if transport and src_ip:
            # v5.1 逻辑：local_ip = anchor.host.ip[0] if anchor.host.ip else "127.0.0.1"
            host_ips = self._get_val(anchor, 'host.ip')
            local_ip = host_ips[0] if (host_ips and isinstance(host_ips, list)) else "127.0.0.1"
            
            # 尝试匹配 Zeek 的 conn.log (方向缺失时，默认匹配源 IP)
            should_queries.append({
                "bool": {
                    "must": [
                        {"term": {"source.ip": local_ip}},
                        # 限制关联数据集，防止自我关联
                        {"term": {"event.dataset": "zeek.connection"}} 
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
            # 执行 ES 查询
            # 注意：此处使用的是 self.es (官方客户端)，拥有 .search 方法
            result = self.es.search(
                index="unified-logs*", 
                body={"query": query, "size": 100}
            )
            hits = result.get('hits', {}).get('hits', [])
            return [hit['_source'] for hit in hits]
        except Exception as e:
            logger.error(f"Context query failed: {str(e)}")
            return []