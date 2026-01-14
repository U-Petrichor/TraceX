# analyzer/graph_analyzer/graph_builder.py
"""
图构建器 v5.2 (新增内存异常事件支持)

功能：
  1. 生成唯一的节点 ID
     - Process: host + pid + executable + start_time
     - Network: host + src_ip + dst_port + event_id
     - File: host + path + action + timestamp (修复：加入时序区分)
     - Memory: host + pid + anomaly_type + event_id (v5.2 新增)
  
  2. 构建实体之间的关系（边）
     - spawned: 进程创建子进程
     - accessed/created/deleted: 进程操作文件
     - connected_to: 网络连接
     - triggered_anomaly: 进程触发内存异常 (v5.2 新增)

核心设计：
  - 使用 PIDCache 解决 Linux PID 复用问题
  - 所有 ID 使用 MD5 哈希，确保长度一致
  - 支持增量构建（多次调用 build_from_events）

使用示例：
    builder = GraphBuilder()
    
    # 生成单个事件的节点ID
    node_id = builder.generate_node_id(event)
    
    # 批量构建图
    graph = builder.build_from_events(events)
"""
import hashlib
import logging
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

from .pid_cache import PIDCache
from .atlas_mapper import AtlasMapper

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """图节点"""
    id: str
    type: str  # process, file, network, ip, user
    label: str  # 显示名称
    atlas_label: str = ""  # ATLAS 语义标签
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass 
class GraphEdge:
    """图边"""
    source: str  # 源节点 ID
    target: str  # 目标节点 ID
    relation: str  # 关系类型
    timestamp: str = ""  # 发生时间
    properties: Dict[str, Any] = field(default_factory=dict)


class GraphBuilder:
    """
    实体关系图构建器
    
    职责：
    1. 为每个实体生成唯一 ID
    2. 提取事件中的实体（节点）
    3. 建立实体之间的关系（边）
    """
    
    def __init__(self, pid_cache: Optional[PIDCache] = None):
        """
        初始化图构建器
        
        Args:
            pid_cache: PID 缓存实例，如果不传则创建新实例
        """
        self.pid_cache = pid_cache or PIDCache()
        self.atlas_mapper = AtlasMapper()
        
        # 内部状态
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._visited_events: Set[str] = set()  # 已处理的事件 ID
    
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
    
    def _md5_hash(self, s: str) -> str:
        """生成 MD5 哈希"""
        return hashlib.md5(s.encode('utf-8')).hexdigest()
    
    # =========================================================================
    # 核心方法：节点 ID 生成
    # =========================================================================
    
    def generate_node_id(self, event: Any) -> str:
        """
        生成唯一节点 ID (v5.0 核心逻辑 + v5.1 修复)
        
        设计原则：
        - Process: 同一进程的不同事件应该生成相同 ID
        - File: 同一文件的不同操作应该生成不同 ID（v5.1 修复）
        - Network: 每个网络流都是独立节点
        
        Args:
            event: UnifiedEvent 对象或字典
            
        Returns:
            MD5 哈希的节点 ID
        """
        category = self._get_val(event, 'event.category', '')
        host_name = self._get_val(event, 'host.name', 'unknown')
        
        if category == 'process':
            return self._generate_process_node_id(event, host_name)
        elif category == 'network':
            return self._generate_network_node_id(event, host_name)
        elif category == 'file':
            return self._generate_file_node_id(event, host_name)
        elif category == 'authentication':
            return self._generate_auth_node_id(event, host_name)
        elif category == 'memory':
            # v5.2 新增：内存异常事件
            return self._generate_memory_node_id(event, host_name)
        else:
            # 兜底：使用 event.id
            event_id = self._get_val(event, 'event.id', '')
            if event_id:
                return self._md5_hash(f"{host_name}|{event_id}")
            else:
                # 最后兜底：使用时间戳
                ts = self._get_val(event, 'timestamp') or self._get_val(event, '@timestamp', '')
                return self._md5_hash(f"{host_name}|{category}|{ts}")
    
    def _generate_process_node_id(self, event: Any, host_name: str) -> str:
        """
        生成进程节点 ID
        
        关键：同一进程（相同 PID + 相同启动时间）的不同事件要映射到同一个节点。
        这需要处理 PID 复用问题。
        """
        pid = self._get_val(event, 'process.pid', 0)
        executable = self._get_val(event, 'process.executable', '')
        
        # 1. 优先使用事件自带的 start_time（如 EXECVE 事件）
        start_time = self._get_val(event, 'process.start_time', '')
        
        if start_time:
            # 有 start_time，更新缓存
            self.pid_cache.set_start_time(host_name, pid, start_time)
        else:
            # 2. 查本地缓存
            start_time = self.pid_cache.get_start_time(host_name, pid)
            
            if not start_time:
                # 3. 缓存未命中，使用事件时间戳作为兜底
                start_time = self._get_val(event, 'timestamp') or \
                             self._get_val(event, '@timestamp', '')
                logger.debug(f"PID cache miss for {host_name}:{pid}, using event timestamp")
        
        # 构造唯一字符串
        uniq_str = f"{host_name}|{pid}|{executable}|{start_time}"
        return self._md5_hash(uniq_str)
    
    def _generate_network_node_id(self, event: Any, host_name: str) -> str:
        """
        生成网络节点 ID
        
        每个网络流都是独立的，使用 event.id 确保唯一性。
        """
        src_ip = self._get_val(event, 'source.ip', '')
        dst_port = self._get_val(event, 'destination.port', 0)
        event_id = self._get_val(event, 'event.id', '')
        
        uniq_str = f"{host_name}|{src_ip}|{dst_port}|{event_id}"
        return self._md5_hash(uniq_str)
    
    def _generate_file_node_id(self, event: Any, host_name: str) -> str:
        """
        生成文件节点 ID (v5.1 修复)
        
        关键修复：同一文件的不同操作（创建、读取、删除）应该生成不同 ID，
        否则攻击路径会丢失关键的时序信息。
        
        加入 action 和 timestamp 来区分。
        """
        file_path = self._get_val(event, 'file.path', '')
        action = self._get_val(event, 'event.action', '')
        timestamp = self._get_val(event, 'timestamp') or \
                    self._get_val(event, '@timestamp', '')
        event_id = self._get_val(event, 'event.id', '')
        
        # v5.1 修复：加入 action 和 event_id 确保同一文件的不同操作有不同 ID
        uniq_str = f"{host_name}|{file_path}|{action}|{event_id or timestamp}"
        return self._md5_hash(uniq_str)
    
    def _generate_auth_node_id(self, event: Any, host_name: str) -> str:
        """
        生成认证事件节点 ID
        
        用于 Cowrie 蜜罐的登录事件等。
        """
        src_ip = self._get_val(event, 'source.ip', '')
        user_name = self._get_val(event, 'user.name', '')
        session_id = self._get_val(event, 'raw.session') or \
                     self._get_val(event, 'user.session_id', '')
        event_id = self._get_val(event, 'event.id', '')
        
        uniq_str = f"{host_name}|auth|{src_ip}|{user_name}|{session_id}|{event_id}"
        return self._md5_hash(uniq_str)
    
    def _generate_memory_node_id(self, event: Any, host_name: str) -> str:
        """
        生成内存异常事件节点 ID (v5.2 新增)
        
        每个内存异常检测事件都是独立的，使用 event.id + pid + anomaly_type 确保唯一性。
        """
        pid = self._get_val(event, 'process.pid', 0)
        event_id = self._get_val(event, 'event.id', '')
        
        # 获取主要异常类型（用于ID生成）
        anomalies = self._get_val(event, 'memory.anomalies', [])
        anomaly_type = ''
        if anomalies:
            if isinstance(anomalies, list) and len(anomalies) > 0:
                anomaly_type = anomalies[0].get('type', '') if isinstance(anomalies[0], dict) else ''
            elif isinstance(anomalies, dict):
                anomaly_type = anomalies.get('type', '')
        
        uniq_str = f"{host_name}|memory|{pid}|{anomaly_type}|{event_id}"
        return self._md5_hash(uniq_str)
    
    # =========================================================================
    # 辅助 ID 生成方法（用于图构建时创建额外节点）
    # =========================================================================
    
    def generate_ip_node_id(self, ip: str, role: str = "unknown") -> str:
        """生成 IP 节点 ID"""
        return self._md5_hash(f"ip|{ip}|{role}")
    
    def generate_file_entity_id(self, host: str, file_path: str) -> str:
        """
        生成文件实体 ID（不区分操作类型）
        
        用于：当需要将多个文件操作关联到同一个文件实体时。
        """
        return self._md5_hash(f"file_entity|{host}|{file_path}")
    
    def generate_user_node_id(self, host: str, user_name: str) -> str:
        """生成用户节点 ID"""
        return self._md5_hash(f"user|{host}|{user_name}")
    
    # =========================================================================
    # 图构建方法
    # =========================================================================
    
    def build_from_events(self, events: List[Any]) -> Dict[str, Any]:
        """
        从事件列表构建图
        
        Args:
            events: 事件列表（UnifiedEvent 或字典）
            
        Returns:
            {
                "nodes": [...],
                "edges": [...],
                "stats": {...}
            }
        """
        for event in events:
            self._process_single_event(event)
        
        # 刷新 PID 缓存
        self.pid_cache.flush()
        
        return {
            "nodes": [self._node_to_dict(n) for n in self._nodes.values()],
            "edges": [self._edge_to_dict(e) for e in self._edges],
            "stats": {
                "total_nodes": len(self._nodes),
                "total_edges": len(self._edges),
                "events_processed": len(self._visited_events)
            }
        }
    
    def _node_to_dict(self, node: GraphNode) -> Dict[str, Any]:
        """将 GraphNode 转为字典"""
        return {
            "id": node.id,
            "type": node.type,
            "label": node.label,
            "atlas_label": node.atlas_label,
            "properties": node.properties
        }
    
    def _edge_to_dict(self, edge: GraphEdge) -> Dict[str, Any]:
        """将 GraphEdge 转为字典"""
        return {
            "source": edge.source,
            "target": edge.target,
            "relation": edge.relation,
            "timestamp": edge.timestamp,
            "properties": edge.properties
        }
    
    def _process_single_event(self, event: Any) -> Optional[str]:
        """
        处理单个事件
        
        Returns:
            主节点 ID
        """
        event_id = self._get_val(event, 'event.id', '')
        
        # 避免重复处理
        if event_id and event_id in self._visited_events:
            return None
        if event_id:
            self._visited_events.add(event_id)
        
        # 获取主节点 ID 和基本信息
        node_id = self.generate_node_id(event)
        category = self._get_val(event, 'event.category', 'unknown')
        timestamp = self._get_val(event, 'timestamp') or self._get_val(event, '@timestamp', '')
        atlas_label = self.atlas_mapper.get_label(event)
        
        # 根据类别创建节点和边
        if category == 'process':
            self._extract_process_entities(event, node_id, atlas_label, timestamp)
        elif category == 'network':
            self._extract_network_entities(event, node_id, atlas_label, timestamp)
        elif category == 'file':
            self._extract_file_entities(event, node_id, atlas_label, timestamp)
        elif category == 'authentication':
            self._extract_auth_entities(event, node_id, atlas_label, timestamp)
        elif category == 'memory':
            # v5.2 新增：内存异常事件处理
            self._extract_memory_entities(event, node_id, atlas_label, timestamp)
        else:
            # 通用处理
            self._add_node(node_id, category, 
                          label=self._get_val(event, 'message', 'Unknown Event'),
                          atlas_label=atlas_label,
                          properties={"event_id": event_id})
        
        return node_id
    
    def _extract_process_entities(self, event: Any, node_id: str, 
                                  atlas_label: str, timestamp: str) -> None:
        """提取进程相关实体"""
        proc_name = self._get_val(event, 'process.name', '')
        executable = self._get_val(event, 'process.executable', '')
        pid = self._get_val(event, 'process.pid', 0)
        cmd_line = self._get_val(event, 'process.command_line', '')
        host_name = self._get_val(event, 'host.name', '')
        
        # 创建进程节点
        label = proc_name or executable or f"Process:{pid}"
        self._add_node(node_id, 'process', label=label, atlas_label=atlas_label,
                       properties={
                           "pid": pid,
                           "executable": executable,
                           "command_line": cmd_line,
                           "host": host_name
                       })
        
        # 处理父进程关系
        ppid = self._get_val(event, 'process.parent.pid', 0)
        parent_name = self._get_val(event, 'process.parent.name', '')
        parent_exe = self._get_val(event, 'process.parent.executable', '')
        
        if ppid and ppid > 0:
            # 生成父进程节点 ID
            parent_start = self.pid_cache.get_start_time(host_name, ppid) or timestamp
            parent_uniq = f"{host_name}|{ppid}|{parent_exe}|{parent_start}"
            parent_id = self._md5_hash(parent_uniq)
            
            # 创建父进程节点
            parent_label = parent_name or parent_exe or f"Process:{ppid}"
            self._add_node(parent_id, 'process', label=parent_label, atlas_label="PARENT_PROCESS",
                           properties={"pid": ppid, "executable": parent_exe, "host": host_name})
            
            # 父进程 -> 子进程（spawned）
            self._add_edge(parent_id, node_id, 'spawned', timestamp)
        
        # 如果有文件操作
        file_path = self._get_val(event, 'file.path', '')
        if file_path:
            file_id = self.generate_file_entity_id(host_name, file_path)
            file_name = self._get_val(event, 'file.name', '') or file_path.split('/')[-1]
            
            self._add_node(file_id, 'file', label=file_name, atlas_label="FILE",
                           properties={"path": file_path, "host": host_name})
            
            action = self._get_val(event, 'event.action', 'accessed')
            self._add_edge(node_id, file_id, action, timestamp)
    
    def _extract_network_entities(self, event: Any, node_id: str,
                                  atlas_label: str, timestamp: str) -> None:
        """提取网络相关实体"""
        src_ip = self._get_val(event, 'source.ip', '')
        src_port = self._get_val(event, 'source.port', 0)
        dst_ip = self._get_val(event, 'destination.ip', '')
        dst_port = self._get_val(event, 'destination.port', 0)
        protocol = self._get_val(event, 'network.protocol', '')
        
        # 创建网络流节点
        label = f"{protocol.upper()}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        self._add_node(node_id, 'network', label=label, atlas_label=atlas_label,
                       properties={
                           "src_ip": src_ip, "src_port": src_port,
                           "dst_ip": dst_ip, "dst_port": dst_port,
                           "protocol": protocol
                       })
        
        # 创建 IP 节点并连边
        if src_ip:
            src_id = self.generate_ip_node_id(src_ip, "source")
            self._add_node(src_id, 'ip', label=src_ip, atlas_label="IP_SOURCE",
                           properties={"ip": src_ip, "role": "source"})
            self._add_edge(src_id, node_id, 'initiated', timestamp)
        
        if dst_ip:
            dst_id = self.generate_ip_node_id(dst_ip, "destination")
            self._add_node(dst_id, 'ip', label=dst_ip, atlas_label="IP_DESTINATION",
                           properties={"ip": dst_ip, "role": "destination"})
            self._add_edge(node_id, dst_id, 'connected_to', timestamp)
    
    def _extract_file_entities(self, event: Any, node_id: str,
                               atlas_label: str, timestamp: str) -> None:
        """提取文件相关实体"""
        file_path = self._get_val(event, 'file.path', '')
        file_name = self._get_val(event, 'file.name', '') or (file_path.split('/')[-1] if file_path else '')
        action = self._get_val(event, 'event.action', '')
        host_name = self._get_val(event, 'host.name', '')
        
        # 创建文件操作节点
        label = f"{action}:{file_name}" if action else file_name
        self._add_node(node_id, 'file_operation', label=label, atlas_label=atlas_label,
                       properties={
                           "path": file_path,
                           "action": action,
                           "host": host_name
                       })
        
        # 如果有关联进程
        pid = self._get_val(event, 'process.pid', 0)
        if pid and pid > 0:
            proc_name = self._get_val(event, 'process.name', '')
            proc_exe = self._get_val(event, 'process.executable', '')
            
            # 获取或构造进程节点
            start_time = self.pid_cache.get_start_time(host_name, pid) or timestamp
            proc_uniq = f"{host_name}|{pid}|{proc_exe}|{start_time}"
            proc_id = self._md5_hash(proc_uniq)
            
            proc_label = proc_name or proc_exe or f"Process:{pid}"
            self._add_node(proc_id, 'process', label=proc_label, atlas_label="PROCESS",
                           properties={"pid": pid, "executable": proc_exe})
            
            # 进程 -> 文件操作
            self._add_edge(proc_id, node_id, action or 'accessed', timestamp)
    
    def _extract_auth_entities(self, event: Any, node_id: str,
                               atlas_label: str, timestamp: str) -> None:
        """提取认证相关实体"""
        src_ip = self._get_val(event, 'source.ip', '')
        user_name = self._get_val(event, 'user.name', '')
        outcome = self._get_val(event, 'event.outcome', '')
        action = self._get_val(event, 'event.action', '')
        host_name = self._get_val(event, 'host.name', '')
        
        # 创建认证事件节点
        label = f"Auth:{user_name}@{src_ip}" if user_name else f"Auth:{src_ip}"
        self._add_node(node_id, 'authentication', label=label, atlas_label=atlas_label,
                       properties={
                           "user": user_name,
                           "source_ip": src_ip,
                           "outcome": outcome,
                           "action": action
                       })
        
        # 创建攻击者 IP 节点
        if src_ip:
            ip_id = self.generate_ip_node_id(src_ip, "attacker")
            self._add_node(ip_id, 'ip', label=src_ip, atlas_label="ATTACKER_IP",
                           properties={"ip": src_ip, "role": "attacker"})
            self._add_edge(ip_id, node_id, 'attempted_login', timestamp)
        
        # 创建用户节点
        if user_name:
            user_id = self.generate_user_node_id(host_name, user_name)
            self._add_node(user_id, 'user', label=user_name, atlas_label="USER",
                           properties={"name": user_name, "host": host_name})
            
            relation = 'authenticated_as' if outcome == 'success' else 'failed_login_as'
            self._add_edge(node_id, user_id, relation, timestamp)
    
    def _extract_memory_entities(self, event: Any, node_id: str,
                                 atlas_label: str, timestamp: str) -> None:
        """
        提取内存异常相关实体 (v5.2 新增)
        
        内存异常事件关键字段：
        - memory.anomalies: 异常列表，每个异常包含 type, risk_level, address, perms 等
        - process.pid: 触发异常的进程 PID
        - process.executable: 进程可执行文件路径
        
        关系建模：
        - 进程节点 -> 内存异常节点 (triggered_anomaly)
        """
        pid = self._get_val(event, 'process.pid', 0)
        executable = self._get_val(event, 'process.executable', '')
        host_name = self._get_val(event, 'host.name', '')
        
        # 获取内存异常信息
        anomalies = self._get_val(event, 'memory.anomalies', [])
        if isinstance(anomalies, dict):
            anomalies = [anomalies]  # 兼容单个异常的情况
        
        # 提取主要异常信息用于节点属性
        anomaly_types = []
        risk_levels = []
        anomaly_details = []
        
        for anomaly in anomalies:
            if isinstance(anomaly, dict):
                a_type = anomaly.get('type', 'UNKNOWN')
                risk = anomaly.get('risk_level', '')
                address = anomaly.get('address', '')
                perms = anomaly.get('perms', '')
                details = anomaly.get('details', '')
                
                anomaly_types.append(a_type)
                if risk:
                    risk_levels.append(risk)
                anomaly_details.append({
                    'type': a_type,
                    'risk_level': risk,
                    'address': address,
                    'perms': perms,
                    'details': details
                })
        
        # 确定主要异常类型和风险等级
        primary_type = anomaly_types[0] if anomaly_types else 'MEMORY_ANOMALY'
        primary_risk = risk_levels[0] if risk_levels else 'UNKNOWN'
        
        # 创建内存异常节点
        label = f"MemAnomaly:{primary_type}(PID:{pid})"
        self._add_node(node_id, 'memory_anomaly', label=label, atlas_label=atlas_label,
                       properties={
                           "pid": pid,
                           "executable": executable,
                           "anomaly_types": anomaly_types,
                           "risk_level": primary_risk,
                           "anomaly_count": len(anomalies),
                           "anomalies": anomaly_details,
                           "host": host_name
                       })
        
        # 建立与进程节点的关系
        if pid and pid > 0:
            # 获取或构造进程节点 ID
            start_time = self.pid_cache.get_start_time(host_name, pid) or timestamp
            proc_uniq = f"{host_name}|{pid}|{executable}|{start_time}"
            proc_id = self._md5_hash(proc_uniq)
            
            # 创建进程节点（如果不存在）
            proc_name = self._get_val(event, 'process.name', '')
            proc_label = proc_name or executable or f"Process:{pid}"
            self._add_node(proc_id, 'process', label=proc_label, 
                          atlas_label="SUSPICIOUS_PROCESS",
                          properties={
                              "pid": pid, 
                              "executable": executable, 
                              "host": host_name,
                              "has_memory_anomaly": True
                          })
            
            # 进程 -> 内存异常（triggered_anomaly）
            self._add_edge(proc_id, node_id, 'triggered_anomaly', timestamp,
                          properties={
                              "anomaly_type": primary_type,
                              "risk_level": primary_risk
                          })
    
    def _add_node(self, node_id: str, node_type: str, label: str,
                  atlas_label: str = "", properties: Optional[Dict] = None) -> None:
        """添加节点（去重）"""
        if node_id not in self._nodes:
            self._nodes[node_id] = GraphNode(
                id=node_id,
                type=node_type,
                label=label,
                atlas_label=atlas_label,
                properties=properties or {}
            )
    
    def _add_edge(self, source: str, target: str, relation: str, 
                  timestamp: str = "", properties: Optional[Dict] = None) -> None:
        """添加边"""
        edge = GraphEdge(
            source=source,
            target=target,
            relation=relation,
            timestamp=timestamp,
            properties=properties or {}
        )
        self._edges.append(edge)
    
    def reset(self) -> None:
        """重置图状态"""
        self._nodes.clear()
        self._edges.clear()
        self._visited_events.clear()
    
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """获取节点"""
        return self._nodes.get(node_id)
    
    def get_nodes_by_type(self, node_type: str) -> List[GraphNode]:
        """获取指定类型的所有节点"""
        return [n for n in self._nodes.values() if n.type == node_type]
