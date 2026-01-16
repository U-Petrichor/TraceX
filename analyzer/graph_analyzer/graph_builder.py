# analyzer/graph_analyzer/graph_builder.py
import hashlib
import os
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from .pid_cache import PIDCache
from .atlas_mapper import AtlasMapper

@dataclass
class GraphNode:
    id: str
    type: str
    label: str
    atlas_label: str = ""
    ttp: str = ""
    severity: int = 0
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass 
class GraphEdge:
    source: str; target: str; relation: str; timestamp: str = ""

class GraphBuilder:
    def __init__(self, pid_cache: Optional[PIDCache] = None):
        self.pid_cache = pid_cache or PIDCache()
        self.atlas_mapper = AtlasMapper()
        self.reset()
    
    def reset(self):
        self._nodes = {} # 修复：确保它是字典
        self._edges = []
        self._visited_events = set()
        self._deferred_parent_links = []

    def _md5(self, s: str): return hashlib.md5(s.encode()).hexdigest()

    # =========================================================================
    # [FIX] 补全公有接口：generate_node_id（支持 process/file/其它类型）
    # =========================================================================
    def generate_node_id(self, e: Any) -> str:
        host = self._get_val(e, 'host.name', 'unknown')
        category = self._get_val(e, 'event.category', '')

        if category == 'process':
            pid = self._get_val(e, 'process.pid', 0)
            exe = self._get_val(e, 'process.executable', '')
            ts = self._get_val(e, 'timestamp', '') or self._get_val(e, '@timestamp', '')
            st = self.pid_cache.get_start_time(host, pid) or self._get_val(e, 'process.start_time') or ts
            return self._md5(f"{host}|{pid}|{exe}|{st}")

        if category == 'file':
            path = self._get_val(e, 'file.path', 'unknown')
            ts = self._get_val(e, 'timestamp', '') or self._get_val(e, '@timestamp', '')
            return self._md5(f"{host}|{path}|{ts}")

        if category == 'network':
            src_ip = self._get_val(e, 'source.ip', '')
            src_port = self._get_val(e, 'source.port', '')
            dst_ip = self._get_val(e, 'destination.ip', '')
            dst_port = self._get_val(e, 'destination.port', '')
            proto = self._get_val(e, 'network.protocol', '')
            ts = self._get_val(e, 'timestamp', '') or self._get_val(e, '@timestamp', '')
            return self._md5(f"{host}|{src_ip}|{src_port}|{dst_ip}|{dst_port}|{proto}|{ts}")

        if category == 'authentication':
            user = self._get_val(e, 'user.name', '')
            src_ip = self._get_val(e, 'source.ip', '')
            outcome = self._get_val(e, 'event.outcome', '')
            ts = self._get_val(e, 'timestamp', '') or self._get_val(e, '@timestamp', '')
            return self._md5(f"{host}|{user}|{src_ip}|{outcome}|{ts}")

        return self._md5(str(self._get_val(e, 'event.id', 'unknown')))

    def build_from_events(self, events: List[Any]):
        for e in events:
            self._process_event(e)

        # 处理延迟的父子关系，确保父节点若在事件集中出现不会被占位覆盖
        for link in self._deferred_parent_links:
            host, ppid, pexe, pst, node_id, ts = link

            # 尝试找到已存在的父节点（按 pid+host 匹配）
            parent_node_id = None
            for nid, node in self._nodes.items():
                if node.type == 'process' and node.properties.get('pid') == ppid and node.properties.get('host') == host:
                    parent_node_id = nid
                    break

            # 如果找不到，则按原有逻辑生成一个父节点 id 并创建占位节点
            if not parent_node_id:
                parent_node_id = self._md5(f"{host}|{ppid}|{pexe}|{pst}")
                if parent_node_id not in self._nodes:
                    # [FIX] 父进程 label 也包含 PID
                    parent_label = f"parent (PID:{ppid})"
                    self._nodes[parent_node_id] = GraphNode(id=parent_node_id, type='process', label=parent_label, properties={"pid": ppid, "host": host})

            # 添加 spawned 边（避免重复边）
            if not any(e.source == parent_node_id and e.target == node_id and e.relation == 'spawned' for e in self._edges):
                self._edges.append(GraphEdge(source=parent_node_id, target=node_id, relation='spawned', timestamp=ts))

        return {"nodes": [n.__dict__ for n in self._nodes.values()], "edges": [e.__dict__ for e in self._edges]}

    def _process_event(self, e: Any):
        host = self._get_val(e, 'host.name', 'unknown')
        host_node_id = self._ensure_host_node(e, host)
        pid = self._get_val(e, 'process.pid', 0)
        exe = self._get_val(e, 'process.executable', '')
        ts = self._get_val(e, 'timestamp', '') or self._get_val(e, '@timestamp', '')
        category = self._get_val(e, 'event.category', '')

        # 1. 统一使用公开接口生成 node_id
        node_id = self.generate_node_id(e)

        # 2. [v6.1] 语义信息提取 (AtlasMapper 可能返回 label 或 (label,severity,ttp))
        semantic_info = self.atlas_mapper.get_label(e)
        if isinstance(semantic_info, tuple) and len(semantic_info) >= 3:
            atlas_label, severity, ttp = semantic_info[0], int(semantic_info[1] or 0), semantic_info[2]
        elif isinstance(semantic_info, tuple) and len(semantic_info) == 2:
            atlas_label, severity, ttp = semantic_info[0], int(semantic_info[1] or 0), ""
        else:
            atlas_label, severity, ttp = semantic_info, 0, ""

        # 3. 内存异常节点挂载（强制连边，带风险与 TTP 注入）
        if category == "memory":
            anomaly_id = self._md5(f"anomaly|{ts}|{node_id}")
            if anomaly_id not in self._nodes:
                self._nodes[anomaly_id] = GraphNode(
                    id=anomaly_id,
                    type='memory_anomaly',
                    label='Memory Anomaly',
                    severity=severity or 9,
                    ttp=ttp or 'T1055',
                    properties={'details': self._get_val(e, 'memory.anomalies')}
                )
            self._add_edge(node_id, anomaly_id, 'triggered_anomaly', ts)

        # 4. 进程节点（仅当有进程信息时创建）
        process_node_id = None
        if pid or exe:
            process_node_id = self._ensure_process_node(
                e, host, pid, exe, ts,
                atlas_label if category == "process" else "",
                severity if category == "process" else 0,
                ttp if category == "process" else ""
            )

        # 5. 父进程回溯：延迟处理父子关系以避免占位节点与后续父事件冲突
        ppid = self._get_val(e, 'process.parent.pid', 0)
        if ppid > 0 and process_node_id:
            pst = self.pid_cache.get_start_time(host, ppid) or self._get_val(e, 'process.parent.start_time') or "unknown"
            pexe = self._get_val(e, 'process.parent.executable', '') or self._get_val(e, 'process.parent.path', '')
            # 延迟处理：收集必要信息，稍后在 build_from_events 统一解析
            self._deferred_parent_links.append((host, ppid, pexe, pst, process_node_id, ts))

        # 6. 文件节点与关系
        # [FIX] 只有 file 类别或非 authentication/network 类别且有文件数据时才创建
        if category == "file" or (category not in ("authentication", "network") and self._has_file_data(e)):
            file_node_id = self._ensure_file_node(e, host, ts, atlas_label, severity, ttp)
            if process_node_id and file_node_id:
                relation = self._map_file_relation(self._get_val(e, 'event.action', ''))
                self._add_edge(process_node_id, file_node_id, relation, ts)
            elif host_node_id and file_node_id:
                self._add_edge(host_node_id, file_node_id, 'host_file', ts)

        # 7. 网络节点与关系
        # [FIX] 只有 network 类别或非 authentication/file 类别且有网络数据时才创建
        # authentication 事件的 destination.ip 是认证目标，不应创建 network 节点
        if category == "network" or (category not in ("authentication", "file") and self._has_network_data(e)):
            network_node_id = self._ensure_network_node(e, host, ts, atlas_label, severity, ttp)
            if process_node_id and network_node_id:
                relation = self._map_network_relation(self._get_val(e, 'network.direction', ''))
                self._add_edge(process_node_id, network_node_id, relation, ts)
            elif host_node_id and network_node_id:
                self._add_edge(host_node_id, network_node_id, 'host_network', ts)

        # 8. 认证节点与关系
        # [FIX] 只有 authentication 类别或非 network/file 类别且有认证数据时才创建
        if category == "authentication" or (category not in ("network", "file") and self._has_auth_data(e)):
            auth_node_id = self._ensure_auth_node(e, host, ts, atlas_label, severity, ttp)
            if process_node_id and auth_node_id:
                self._add_edge(process_node_id, auth_node_id, 'auth', ts)
            elif host_node_id and auth_node_id:
                self._add_edge(host_node_id, auth_node_id, 'host_auth', ts)

    def _ensure_process_node(self, e: Any, host: str, pid: int, exe: str, ts: str,
                             atlas_label: str, severity: int, ttp: str) -> Optional[str]:
        if not (pid or exe):
            return None
        st = self.pid_cache.get_start_time(host, pid) or self._get_val(e, 'process.start_time') or ts
        node_id = self._md5(f"{host}|{pid}|{exe}|{st}")
        if node_id not in self._nodes:
            # [FIX] 进程 label 包含 PID，便于区分不同进程实例
            base_name = os.path.basename(exe) if exe else "process"
            label = f"{base_name} (PID:{pid})" if pid else base_name
            self._nodes[node_id] = GraphNode(
                id=node_id,
                type='process',
                label=label,
                atlas_label=atlas_label,
                severity=severity,
                ttp=ttp,
                properties={
                    "pid": pid,
                    "command_line": self._get_val(e, 'process.command_line'),
                    "host": host
                }
            )
        return node_id

    def _ensure_host_node(self, e: Any, host: str) -> Optional[str]:
        if not host or host == "unknown":
            return None
        node_id = self._md5(f"host|{host}")
        if node_id not in self._nodes:
            self._nodes[node_id] = GraphNode(
                id=node_id,
                type='host',
                label=host,
                properties={
                    "host": host,
                    "hostname": self._get_val(e, 'host.hostname'),
                    "ip": self._get_val(e, 'host.ip'),
                    "os": self._get_val(e, 'host.os.name')
                }
            )
        return node_id

    def _ensure_file_node(self, e: Any, host: str, ts: str,
                          atlas_label: str, severity: int, ttp: str) -> Optional[str]:
        path = self._get_val(e, 'file.path', '')
        if not path:
            return None
        # [FIX] 使用文件特定的 ID 生成逻辑，避免与其他节点类型 ID 冲突
        node_id = self._md5(f"file|{host}|{path}")
        if node_id not in self._nodes:
            self._nodes[node_id] = GraphNode(
                id=node_id,
                type='file',
                label=os.path.basename(path) if path else "unknown",
                atlas_label=atlas_label,
                severity=severity,
                ttp=ttp,
                properties={
                    "path": path,
                    "name": self._get_val(e, 'file.name'),
                    "extension": self._get_val(e, 'file.extension'),
                    "size": self._get_val(e, 'file.size', 0),
                    "host": host
                }
            )
        return node_id

    def _ensure_network_node(self, e: Any, host: str, ts: str,
                             atlas_label: str, severity: int, ttp: str) -> Optional[str]:
        src_ip = self._get_val(e, 'source.ip', '')
        dst_ip = self._get_val(e, 'destination.ip', '')
        dst_port = self._get_val(e, 'destination.port', '')
        proto = self._get_val(e, 'network.protocol', '')
        if not (src_ip or dst_ip or proto):
            return None
        # [FIX] 使用网络特定的 ID 生成逻辑，避免与其他节点类型 ID 冲突
        node_id = self._md5(f"network|{host}|{dst_ip}|{dst_port}|{proto}")
        label = self._build_network_label(e)
        if node_id not in self._nodes:
            self._nodes[node_id] = GraphNode(
                id=node_id,
                type='network',
                label=label,
                atlas_label=atlas_label,
                severity=severity,
                ttp=ttp,
                properties={
                    "source_ip": src_ip,
                    "source_port": self._get_val(e, 'source.port'),
                    "destination_ip": dst_ip,
                    "destination_port": dst_port,
                    "protocol": proto,
                    "direction": self._get_val(e, 'network.direction'),
                    "host": host
                }
            )
        return node_id

    def _ensure_auth_node(self, e: Any, host: str, ts: str,
                          atlas_label: str, severity: int, ttp: str) -> Optional[str]:
        user = self._get_val(e, 'user.name', '')
        src_ip = self._get_val(e, 'source.ip', '')
        outcome = self._get_val(e, 'event.outcome', '')
        if not (user or src_ip):
            return None
        # [FIX] 使用认证特定的 ID 生成逻辑，避免与其他节点类型 ID 冲突
        node_id = self._md5(f"auth|{host}|{user}|{src_ip}|{outcome}")
        label = f"{user}@{src_ip}" if user and src_ip else (user or src_ip)
        if node_id not in self._nodes:
            self._nodes[node_id] = GraphNode(
                id=node_id,
                type='authentication',
                label=label or "auth",
                atlas_label=atlas_label,
                severity=severity,
                ttp=ttp,
                properties={
                    "user": user,
                    "source_ip": src_ip,
                    "outcome": outcome,
                    "host": host
                }
            )
        return node_id

    def _build_network_label(self, e: Any) -> str:
        dst_ip = self._get_val(e, 'destination.ip', '')
        dst_port = self._get_val(e, 'destination.port', '')
        proto = self._get_val(e, 'network.protocol', '')
        if dst_ip and dst_port:
            return f"{proto}:{dst_ip}:{dst_port}" if proto else f"{dst_ip}:{dst_port}"
        if dst_ip:
            return f"{proto}:{dst_ip}" if proto else dst_ip
        return proto or "network"

    def _has_file_data(self, e: Any) -> bool:
        return bool(self._get_val(e, 'file.path')) or bool(self._get_val(e, 'file.name'))

    def _has_network_data(self, e: Any) -> bool:
        return bool(self._get_val(e, 'network.protocol') or self._get_val(e, 'source.ip') or self._get_val(e, 'destination.ip'))

    def _has_auth_data(self, e: Any) -> bool:
        action = str(self._get_val(e, 'event.action', '') or '').lower()
        outcome = str(self._get_val(e, 'event.outcome', '') or '').lower()
        user = self._get_val(e, 'user.name', '')
        src_ip = self._get_val(e, 'source.ip', '')
        if action and any(k in action for k in ("login", "logon", "logout", "logoff", "auth")):
            return True
        if outcome in ("success", "failure"):
            return True
        return bool(user or src_ip)

    def _map_file_relation(self, action: Any) -> str:
        act = str(action or "").lower()
        if act in ("read", "open", "access"):
            return "read"
        if act in ("write", "create", "modify", "rename", "moved-to", "truncate"):
            return "write"
        if act in ("delete", "remove", "unlink"):
            return "delete"
        return "file_op"

    def _map_network_relation(self, direction: Any) -> str:
        dir_val = str(direction or "").lower()
        if dir_val in ("outbound", "egress"):
            return "connect_outbound"
        if dir_val in ("inbound", "ingress"):
            return "connect_inbound"
        return "connect"

    def _add_edge(self, source: str, target: str, relation: str, ts: str) -> None:
        if not source or not target:
            return
        if any(e.source == source and e.target == target and e.relation == relation for e in self._edges):
            return
        self._edges.append(GraphEdge(source=source, target=target, relation=relation, timestamp=ts))

    def _get_val(self, obj, path, default=None):
        curr = getattr(obj, '_data', obj)
        for p in path.split('.'):
            if isinstance(curr, dict):
                curr = curr.get(p)
            elif hasattr(curr, p):
                curr = getattr(curr, p)
            else:
                return default
        return curr if curr is not None else default
