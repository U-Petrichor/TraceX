# analyzer/graph_analyzer/provenance_system.py
"""
溯源系统 v5.1 (Complete)

功能：
  从种子事件（高危告警）出发，BFS 广度优先搜索重建完整攻击路径。
  
  工作流程：
  1. 接收种子事件（从组员3的 ContextEngine.get_seed_events 获取）
  2. 调用 ContextEngine.find_related_events 查找关联事件
  3. 使用 GraphBuilder 生成节点和边
  4. 使用 AtlasMapper 标记语义标签
  5. 使用 IntelEnricher 进行情报富化和 APT 归因

架构依赖：
  - 组员3: ContextEngine (注入依赖)
  - 组员4: GraphBuilder, AtlasMapper, IntelEnricher (本模块)

修订记录：
  - v5.1: 修复 _find_neighbors 未定义、graph_edges.append(...) 占位符等致命 bug
  - v5.0: 初始版本

使用示例：
    from analyzer.attack_analyzer.context_engine import ContextEngine
    from collector.common.es_client import ESClient
    
    es_client = ESClient()
    context_engine = ContextEngine(es_client)
    
    system = ProvenanceSystem(context_engine)
    result = system.rebuild_attack_path(seed_event)
"""
import logging
from typing import Any, Dict, List, Optional, Set
from collections import deque
from dataclasses import dataclass, field

from .graph_builder import GraphBuilder
from .atlas_mapper import AtlasMapper
from .enrichment import IntelEnricher
from .pid_cache import PIDCache

logger = logging.getLogger(__name__)


@dataclass
class RebuildResult:
    """攻击路径重建结果"""
    edges: List[Dict[str, Any]] = field(default_factory=list)
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    path_signature: str = ""  # ATLAS 标签序列
    path_sequence: List[str] = field(default_factory=list)  # 原始序列
    intelligence: Dict[str, Any] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)


class ProvenanceSystem:
    """
    溯源系统主类
    
    职责：
    1. 从种子事件出发，BFS 遍历关联事件
    2. 构建攻击路径图
    3. 进行情报富化和 APT 归因
    """
    
    def __init__(self, context_engine: Any, max_depth: int = 10, max_events: int = 500):
        """
        初始化溯源系统
        
        Args:
            context_engine: 组员3的 ContextEngine 实例（依赖注入）
            max_depth: BFS 最大深度，防止无限扩展
            max_events: 最大处理事件数，防止爆内存
        """
        # 组员3 依赖
        if context_engine is None:
            raise ValueError("ContextEngine is required")
        self.context_engine = context_engine
        
        # 组员4 组件
        self.pid_cache = PIDCache()
        self.builder = GraphBuilder(pid_cache=self.pid_cache)
        self.atlas_mapper = AtlasMapper()
        self.enricher = IntelEnricher()
        
        # 配置
        self.max_depth = max_depth
        self.max_events = max_events
    
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
    
    # =========================================================================
    # 核心方法：攻击路径重建
    # =========================================================================
    
    def rebuild_attack_path(self, seed_event: Any, 
                            time_window: int = 60,
                            enable_session_isolation: bool = True) -> Dict[str, Any]:
        """
        从种子事件重建攻击路径 (v5.2 支持会话隔离)
        
        使用 BFS 广度优先搜索，从种子事件出发，
        通过 ContextEngine 查找关联事件，逐步扩展攻击图。
        
        Args:
            seed_event: 种子事件（高危告警），UnifiedEvent 或字典
            time_window: 关联搜索的时间窗口（秒）
            enable_session_isolation: 是否启用会话隔离（默认开启）
                - 开启：只追踪同一 session_id 的事件，解决多攻击者并发问题
                - 关闭：追踪时间窗口内所有相关事件
            
        Returns:
            {
                "edges": [...],
                "nodes": [...],
                "path_signature": "LABEL1 -> LABEL2 -> ...",
                "path_sequence": [...],
                "intelligence": {
                    "chain_hash": "...",
                    "attribution": {...},
                    "external_infrastructure": {...}
                },
                "stats": {...}
            }
        """
        logger.info("Starting attack path rebuild...")
        
        # v5.2 新增：提取会话ID用于隔离不同攻击者
        session_id = None
        if enable_session_isolation:
            session_id = self._get_val(seed_event, 'user.session_id') or \
                         self._get_val(seed_event, 'raw.session', '')
            if session_id:
                logger.info(f"Session isolation enabled: {session_id}")
            else:
                logger.debug("No session_id found, session isolation disabled")
        
        # 初始化
        queue = deque([(seed_event, 0)])  # (event, depth)
        visited: Set[str] = set()  # 使用 node_id 去重（v5.1 修复）
        
        graph_edges: List[Dict[str, Any]] = []
        path_sequence: List[str] = []
        unique_nodes_info: List[Dict[str, Any]] = []
        
        events_processed = 0
        
        # === BFS 广度优先搜索 ===
        while queue and events_processed < self.max_events:
            curr_event, depth = queue.popleft()
            
            if depth > self.max_depth:
                logger.warning(f"Max depth {self.max_depth} reached, stopping expansion")
                continue
            
            # v5.1 修复：使用 node_id 而不是 event.id 进行去重
            # 这确保同一个逻辑节点（如同一进程）的不同事件不会被重复处理
            node_id = self.builder.generate_node_id(curr_event)
            
            if node_id in visited:
                continue
            visited.add(node_id)
            events_processed += 1
            
            # 获取 ATLAS 标签
            atlas_label = self.atlas_mapper.get_label(curr_event)
            path_sequence.append(atlas_label)
            
            # 收集 IOC 信息（用于后续情报富化）
            self._collect_iocs(curr_event, unique_nodes_info)
            
            # v5.2 修复：调用组员3的 find_related_events，支持会话隔离
            neighbors = self._find_neighbors(curr_event, time_window, session_id)
            
            logger.debug(f"Node {node_id[:8]}... ({atlas_label}) has {len(neighbors)} neighbors")
            
            # 处理关联事件
            for neighbor in neighbors[:50]:  # 限制每个节点的扩展数量
                neighbor_node_id = self.builder.generate_node_id(neighbor)
                
                if neighbor_node_id in visited:
                    continue
                
                # v5.1 修复：补全连边逻辑（不再是 ...）
                relation = self._infer_relation(curr_event, neighbor)
                neighbor_ts = self._get_val(neighbor, 'timestamp') or \
                              self._get_val(neighbor, '@timestamp', '')
                
                edge = {
                    "source": node_id,
                    "target": neighbor_node_id,
                    "relation": relation,
                    "timestamp": neighbor_ts,
                    "source_label": atlas_label,
                    "target_label": self.atlas_mapper.get_label(neighbor)
                }
                graph_edges.append(edge)
                
                # 加入队列继续扩展
                queue.append((neighbor, depth + 1))
        
        # === 后处理：情报富化与归因 ===
        logger.info(f"BFS complete: {events_processed} events, {len(graph_edges)} edges")
        
        # A. 外部基础设施画像（C2 识别）
        ti_info = self.enricher.enrich_entities(unique_nodes_info)
        
        # B. 攻击链指纹
        chain_fingerprint = self.enricher.generate_fingerprint(path_sequence)
        
        # C. APT 归因
        attribution = self.enricher.attribute_apt(path_sequence)
        
        # 构建节点列表
        nodes = self._build_nodes_from_edges(graph_edges, path_sequence)
        
        # 刷新 PID 缓存
        self.pid_cache.flush()
        
        return {
            "edges": graph_edges,
            "nodes": nodes,
            "path_signature": " -> ".join(path_sequence),
            "path_sequence": path_sequence,
            "intelligence": {
                "chain_hash": chain_fingerprint,
                "attribution": attribution,
                "external_infrastructure": ti_info
            },
            "stats": {
                "events_processed": events_processed,
                "edges_created": len(graph_edges),
                "nodes_visited": len(visited),
                "unique_labels": len(set(path_sequence)),
                "max_depth_reached": events_processed >= self.max_events,
                "session_id": session_id or "N/A"  # v5.2: 追踪的会话ID
            }
        }
    
    def _find_neighbors(self, event: Any, time_window: int = 60, 
                        session_id: str = None) -> List[Dict[str, Any]]:
        """
        查找关联事件 (v5.2 支持会话隔离)
        
        调用组员3的 ContextEngine.find_related_events 方法，
        然后按 session_id 过滤（如果提供）。
        
        Args:
            event: 当前事件
            time_window: 时间窗口（秒）
            session_id: 会话ID（Cowrie），用于隔离不同攻击者
            
        Returns:
            关联事件列表
        """
        try:
            # 调用组员3的关联搜索
            neighbors = self.context_engine.find_related_events(event, window=time_window)
            
            if not neighbors:
                return []
            
            # v5.2 新增：会话隔离（仅保留同一会话的事件）
            if session_id:
                filtered = []
                for n in neighbors:
                    n_session = self._get_val(n, 'user.session_id') or \
                                self._get_val(n, 'raw.session', '')
                    # 只保留同一会话的事件，或者没有会话ID的事件（如文件操作）
                    if not n_session or n_session == session_id:
                        filtered.append(n)
                
                logger.debug(f"Session filter: {len(neighbors)} -> {len(filtered)} events")
                return filtered
            
            return neighbors
            
        except Exception as e:
            logger.error(f"Failed to find neighbors: {e}")
            return []
    
    def _infer_relation(self, source_event: Any, target_event: Any) -> str:
        """
        推断两个事件之间的关系类型
        
        Args:
            source_event: 源事件
            target_event: 目标事件
            
        Returns:
            关系类型字符串
        """
        src_category = self._get_val(source_event, 'event.category', '')
        tgt_category = self._get_val(target_event, 'event.category', '')
        tgt_action = self._get_val(target_event, 'event.action', '')
        
        # 进程 -> 进程 (spawned)
        if src_category == 'process' and tgt_category == 'process':
            src_pid = self._get_val(source_event, 'process.pid', 0)
            tgt_ppid = self._get_val(target_event, 'process.parent.pid', 0)
            if src_pid == tgt_ppid:
                return 'spawned'
            return 'related_process'
        
        # 进程 -> 文件 (accessed/created/deleted)
        if src_category == 'process' and tgt_category == 'file':
            return tgt_action or 'accessed'
        
        # 进程 -> 网络 (initiated)
        if src_category == 'process' and tgt_category == 'network':
            return 'initiated'
        
        # 网络 -> 进程 (triggered)
        if src_category == 'network' and tgt_category == 'process':
            return 'triggered'
        
        # 认证 -> 进程 (led_to)
        if src_category == 'authentication' and tgt_category == 'process':
            return 'led_to'
        
        # 文件 -> 进程 (executed_by)
        if src_category == 'file' and tgt_category == 'process':
            return 'executed_by'
        
        # 默认关系
        return 'related_to'
    
    def _collect_iocs(self, event: Any, ioc_list: List[Dict[str, Any]]) -> None:
        """
        从事件中收集 IOC 信息
        
        用于后续的情报富化。
        """
        # 收集 IP
        src_ip = self._get_val(event, 'source.ip')
        dst_ip = self._get_val(event, 'destination.ip')
        
        if src_ip and src_ip not in ["", "127.0.0.1"]:
            ioc_list.append({
                "type": "ip",
                "ioc": src_ip,
                "properties": {"ip": src_ip, "role": "source"}
            })
        
        if dst_ip and dst_ip not in ["", "127.0.0.1"]:
            ioc_list.append({
                "type": "ip",
                "ioc": dst_ip,
                "properties": {"ip": dst_ip, "role": "destination"}
            })
        
        # 收集文件哈希
        file_md5 = self._get_val(event, 'file.hash.md5')
        file_sha256 = self._get_val(event, 'file.hash.sha256')
        
        if file_md5:
            ioc_list.append({
                "type": "hash",
                "ioc": file_md5,
                "properties": {"hash_type": "md5", "value": file_md5}
            })
        
        if file_sha256:
            ioc_list.append({
                "type": "hash",
                "ioc": file_sha256,
                "properties": {"hash_type": "sha256", "value": file_sha256}
            })
    
    def _build_nodes_from_edges(self, edges: List[Dict], 
                                path_sequence: List[str]) -> List[Dict[str, Any]]:
        """
        从边信息构建节点列表
        """
        nodes = {}
        label_index = 0
        
        for edge in edges:
            src_id = edge["source"]
            tgt_id = edge["target"]
            
            if src_id not in nodes:
                src_label = edge.get("source_label", path_sequence[label_index] if label_index < len(path_sequence) else "UNKNOWN")
                nodes[src_id] = {
                    "id": src_id,
                    "label": src_label,
                    "type": "event"
                }
                label_index += 1
            
            if tgt_id not in nodes:
                tgt_label = edge.get("target_label", "UNKNOWN")
                nodes[tgt_id] = {
                    "id": tgt_id,
                    "label": tgt_label,
                    "type": "event"
                }
        
        return list(nodes.values())
    
    # =========================================================================
    # 批量处理方法
    # =========================================================================
    
    def rebuild_from_seeds(self, seed_events: List[Any], 
                          time_window: int = 60) -> List[Dict[str, Any]]:
        """
        从多个种子事件批量重建攻击路径
        
        每个种子事件产生一条独立的攻击路径。
        
        Args:
            seed_events: 种子事件列表
            time_window: 时间窗口
            
        Returns:
            攻击路径列表
        """
        results = []
        
        for i, seed in enumerate(seed_events):
            logger.info(f"Processing seed event {i+1}/{len(seed_events)}")
            
            try:
                # 重置图构建器状态
                self.builder.reset()
                
                result = self.rebuild_attack_path(seed, time_window)
                result["seed_index"] = i
                result["seed_event_id"] = self._get_val(seed, 'event.id', '')
                results.append(result)
                
            except Exception as e:
                logger.error(f"Failed to rebuild path for seed {i}: {e}")
                results.append({
                    "seed_index": i,
                    "error": str(e)
                })
        
        return results
    
    def get_high_risk_paths(self, results: List[Dict[str, Any]], 
                           min_score: float = 0.6) -> List[Dict[str, Any]]:
        """
        筛选高风险攻击路径
        
        Args:
            results: rebuild_from_seeds 的输出
            min_score: 最低 APT 匹配分数
            
        Returns:
            高风险路径列表
        """
        high_risk = []
        
        for result in results:
            if "error" in result:
                continue
                
            attribution = result.get("intelligence", {}).get("attribution", {})
            score = attribution.get("similarity_score", 0)
            
            if score >= min_score:
                high_risk.append(result)
        
        # 按相似度排序
        high_risk.sort(
            key=lambda x: x.get("intelligence", {}).get("attribution", {}).get("similarity_score", 0),
            reverse=True
        )
        
        return high_risk
    
    # =========================================================================
    # 具体攻击链输出（v5.2 新增）
    # =========================================================================
    
    def build_attack_timeline(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        构建具体的攻击时间线 (v5.2 新增)
        
        将抽象的 Atlas 标签序列转换为具体的攻击步骤，
        包含实际的 IP、进程、命令行、文件路径等详细信息。
        
        Returns:
            {
                "timeline": [
                    {
                        "step": 1,
                        "timestamp": "2026-01-14T14:30:01Z",
                        "action": "SSH 登录",
                        "actor": "59.64.129.102",
                        "target": "honeypot-01",
                        "details": {
                            "user": "root",
                            "outcome": "success"
                        },
                        "atlas_label": "SSH_CONNECTION"
                    },
                    ...
                ],
                "summary": {
                    "attacker_ip": "59.64.129.102",
                    "victim_host": "honeypot-01",
                    "attack_duration": "45 seconds",
                    "key_actions": ["SSH登录", "下载恶意文件", "写入WebShell", "读取敏感文件"]
                }
            }
        """
        edges = result.get("edges", [])
        nodes = result.get("nodes", [])
        
        # 构建节点ID到详细信息的映射
        node_details = {}
        for node in nodes:
            node_id = node.get("id")
            if node_id:
                node_details[node_id] = node
        
        # 按时间戳排序边
        sorted_edges = sorted(edges, key=lambda e: e.get("timestamp", ""))
        
        timeline = []
        attacker_ips = set()
        victim_hosts = set()
        key_actions = []
        
        for i, edge in enumerate(sorted_edges):
            src_id = edge.get("source")
            tgt_id = edge.get("target")
            src_node = node_details.get(src_id, {})
            tgt_node = node_details.get(tgt_id, {})
            
            src_props = src_node.get("properties", {})
            tgt_props = tgt_node.get("properties", {})
            
            # 提取具体信息
            step = {
                "step": i + 1,
                "timestamp": edge.get("timestamp", ""),
                "relation": edge.get("relation", ""),
                "atlas_label": edge.get("target_label", ""),
            }
            
            # 根据关系类型构建详细描述
            relation = edge.get("relation", "")
            
            if relation == "attempted_login" or relation == "authenticated_as":
                # 认证事件
                step["action"] = "登录尝试" if "attempted" in relation else "登录成功"
                step["actor"] = src_props.get("ip") or src_node.get("label", "")
                step["target"] = tgt_props.get("host") or tgt_props.get("user", "")
                step["details"] = {
                    "user": tgt_props.get("user", ""),
                    "outcome": tgt_props.get("outcome", ""),
                    "source_ip": src_props.get("ip", "")
                }
                if src_props.get("ip"):
                    attacker_ips.add(src_props["ip"])
                key_actions.append(step["action"])
                
            elif relation == "spawned":
                # 进程创建
                step["action"] = "创建子进程"
                step["actor"] = src_node.get("label", "") or src_props.get("executable", "")
                step["target"] = tgt_node.get("label", "") or tgt_props.get("executable", "")
                step["details"] = {
                    "parent_pid": src_props.get("pid"),
                    "child_pid": tgt_props.get("pid"),
                    "command_line": tgt_props.get("command_line", ""),
                    "executable": tgt_props.get("executable", "")
                }
                if tgt_props.get("command_line"):
                    key_actions.append(f"执行: {tgt_props['command_line'][:50]}...")
                    
            elif relation in ["created", "write", "accessed", "deleted"]:
                # 文件操作
                action_map = {
                    "created": "创建文件",
                    "write": "写入文件", 
                    "accessed": "访问文件",
                    "deleted": "删除文件"
                }
                step["action"] = action_map.get(relation, "操作文件")
                step["actor"] = src_node.get("label", "") or src_props.get("executable", "")
                step["target"] = tgt_props.get("path", "") or tgt_node.get("label", "")
                step["details"] = {
                    "file_path": tgt_props.get("path", ""),
                    "process": src_props.get("executable", ""),
                    "pid": src_props.get("pid")
                }
                if tgt_props.get("path"):
                    key_actions.append(f"{step['action']}: {tgt_props['path']}")
                    
            elif relation in ["initiated", "connected_to"]:
                # 网络连接
                step["action"] = "发起连接" if relation == "initiated" else "连接到"
                step["actor"] = src_node.get("label", "") or src_props.get("ip", "")
                step["target"] = tgt_node.get("label", "") or tgt_props.get("ip", "")
                step["details"] = {
                    "src_ip": src_props.get("ip", src_props.get("src_ip", "")),
                    "dst_ip": tgt_props.get("ip", tgt_props.get("dst_ip", "")),
                    "dst_port": tgt_props.get("dst_port", ""),
                    "protocol": src_props.get("protocol", tgt_props.get("protocol", ""))
                }
                if tgt_props.get("ip"):
                    key_actions.append(f"连接到: {tgt_props['ip']}")
                    
            else:
                # 通用处理
                step["action"] = relation or "关联"
                step["actor"] = src_node.get("label", "")
                step["target"] = tgt_node.get("label", "")
                step["details"] = {
                    "source_type": src_node.get("type", ""),
                    "target_type": tgt_node.get("type", "")
                }
            
            # 收集主机信息
            for props in [src_props, tgt_props]:
                if props.get("host"):
                    victim_hosts.add(props["host"])
            
            timeline.append(step)
        
        # 计算攻击持续时间
        duration = "未知"
        if timeline and len(timeline) >= 2:
            first_ts = timeline[0].get("timestamp", "")
            last_ts = timeline[-1].get("timestamp", "")
            if first_ts and last_ts:
                try:
                    from datetime import datetime
                    t1 = datetime.fromisoformat(first_ts.replace('Z', ''))
                    t2 = datetime.fromisoformat(last_ts.replace('Z', ''))
                    diff = (t2 - t1).total_seconds()
                    if diff < 60:
                        duration = f"{int(diff)} 秒"
                    elif diff < 3600:
                        duration = f"{int(diff/60)} 分钟"
                    else:
                        duration = f"{diff/3600:.1f} 小时"
                except:
                    pass
        
        return {
            "timeline": timeline,
            "summary": {
                "attacker_ips": list(attacker_ips),
                "victim_hosts": list(victim_hosts),
                "attack_duration": duration,
                "total_steps": len(timeline),
                "key_actions": key_actions[:10]  # 最多10个关键动作
            }
        }
    
    def format_attack_timeline(self, result: Dict[str, Any]) -> str:
        """
        格式化输出攻击时间线（人类可读）
        """
        timeline_data = self.build_attack_timeline(result)
        timeline = timeline_data.get("timeline", [])
        summary = timeline_data.get("summary", {})
        intel = result.get("intelligence", {})
        
        lines = []
        lines.append("═" * 70)
        lines.append("                    🔍 攻击时间线详细报告")
        lines.append("═" * 70)
        
        # 摘要
        lines.append("\n📋 攻击概要:")
        lines.append(f"   攻击者IP: {', '.join(summary.get('attacker_ips', ['未知']))}")
        lines.append(f"   受害主机: {', '.join(summary.get('victim_hosts', ['未知']))}")
        lines.append(f"   攻击持续: {summary.get('attack_duration', '未知')}")
        lines.append(f"   总步骤数: {summary.get('total_steps', 0)}")
        
        # APT 归因
        attribution = intel.get("attribution", {})
        if attribution.get("suspected_group") and attribution.get("suspected_group") != "Unclassified":
            lines.append(f"\n🎯 APT 归因: {attribution['suspected_group']} (相似度: {attribution.get('similarity_score', 0):.0%})")
        
        # C2 信息
        infra = intel.get("external_infrastructure", {})
        malicious = {k: v for k, v in infra.items() if v.get("is_malicious")}
        if malicious:
            lines.append(f"\n🌐 恶意基础设施:")
            for ioc, info in malicious.items():
                lines.append(f"   • {ioc} - {', '.join(info.get('tags', []))} (风险: {info.get('risk_score', 0)})")
        
        # 详细时间线
        lines.append("\n" + "─" * 70)
        lines.append("                         详细攻击步骤")
        lines.append("─" * 70)
        
        for step in timeline:
            ts = step.get("timestamp", "")[:19].replace("T", " ")  # 格式化时间
            action = step.get("action", "")
            actor = step.get("actor", "")
            target = step.get("target", "")
            label = step.get("atlas_label", "")
            details = step.get("details", {})
            
            # 选择图标
            icon = "│"
            if "登录" in action:
                icon = "🔐"
            elif "进程" in action or "执行" in action:
                icon = "⚙️"
            elif "文件" in action:
                icon = "📄"
            elif "连接" in action:
                icon = "🌐"
            elif "敏感" in label or "SENSITIVE" in label:
                icon = "⚠️"
            
            lines.append(f"\n[{ts}] {icon} {action}")
            lines.append(f"   │ {actor} → {target}")
            
            # 显示关键详情
            if details.get("command_line"):
                cmd = details["command_line"]
                if len(cmd) > 60:
                    cmd = cmd[:60] + "..."
                lines.append(f"   │ 命令: {cmd}")
            if details.get("file_path"):
                lines.append(f"   │ 路径: {details['file_path']}")
            if details.get("dst_ip"):
                lines.append(f"   │ 目标: {details['dst_ip']}:{details.get('dst_port', '')}")
            if details.get("source_ip") and details.get("user"):
                lines.append(f"   │ 来源: {details['source_ip']} (用户: {details['user']})")
            
            lines.append(f"   └─ [{label}]")
        
        lines.append("\n" + "═" * 70)
        
        return "\n".join(lines)
    
    # =========================================================================
    # 调试方法
    # =========================================================================
    
    def explain_path(self, result: Dict[str, Any]) -> str:
        """
        生成攻击路径的人类可读解释
        """
        lines = []
        lines.append("=" * 60)
        lines.append("攻击路径分析报告")
        lines.append("=" * 60)
        
        # 基本统计
        stats = result.get("stats", {})
        lines.append(f"\n📊 统计信息:")
        lines.append(f"   处理事件数: {stats.get('events_processed', 0)}")
        lines.append(f"   创建边数: {stats.get('edges_created', 0)}")
        lines.append(f"   唯一标签数: {stats.get('unique_labels', 0)}")
        
        # 攻击路径签名
        lines.append(f"\n🔗 攻击路径签名:")
        lines.append(f"   {result.get('path_signature', 'N/A')}")
        
        # 情报信息
        intel = result.get("intelligence", {})
        
        lines.append(f"\n🎯 APT 归因:")
        attribution = intel.get("attribution", {})
        lines.append(f"   疑似组织: {attribution.get('suspected_group', 'Unknown')}")
        lines.append(f"   相似度: {attribution.get('similarity_score', 0):.1%}")
        
        if attribution.get("matched_profile"):
            profile = attribution["matched_profile"]
            lines.append(f"   关联 TTP: {', '.join(profile.get('ttps', []))}")
        
        # 外部基础设施
        infra = intel.get("external_infrastructure", {})
        if infra:
            lines.append(f"\n🌐 外部基础设施:")
            for ioc, info in infra.items():
                risk = info.get("risk_score", 0)
                tags = ", ".join(info.get("tags", []))
                status = "⚠️ 恶意" if info.get("is_malicious") else "✅ 正常"
                lines.append(f"   {ioc}: {status} (风险={risk}, 标签={tags})")
        
        lines.append("\n" + "=" * 60)
        
        return "\n".join(lines)
