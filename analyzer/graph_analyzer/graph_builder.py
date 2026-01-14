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

        return self._md5(str(self._get_val(e, 'event.id', 'unknown')))

    def build_from_events(self, events: List[Any]):
        for e in events: self._process_event(e)
        return {"nodes": [n.__dict__ for n in self._nodes.values()], "edges": [e.__dict__ for e in self._edges]}

    def _process_event(self, e: Any):
        host = self._get_val(e, 'host.name', 'unknown')
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
            self._edges.append(GraphEdge(source=node_id, target=anomaly_id, relation='triggered_anomaly', timestamp=ts))

        # 4. 注册主进程节点（带语义注入）
        if node_id not in self._nodes:
            self._nodes[node_id] = GraphNode(
                id=node_id,
                type='process',
                label=os.path.basename(exe) if exe else f"PID:{pid}",
                atlas_label=atlas_label,
                severity=severity,
                ttp=ttp,
                properties={
                    "pid": pid,
                    "command_line": self._get_val(e, 'process.command_line'),
                    "host": host
                }
            )

        # 5. [FIX] 父进程回溯并对齐 ID 生成逻辑（尝试使用 parent.executable 保持与父事件一致）
        ppid = self._get_val(e, 'process.parent.pid', 0)
        if ppid > 0:
            pst = self.pid_cache.get_start_time(host, ppid) or self._get_val(e, 'process.parent.start_time') or "unknown"
            pexe = self._get_val(e, 'process.parent.executable', '') or self._get_val(e, 'process.parent.path', '')
            parent_id = self._md5(f"{host}|{ppid}|{pexe}|{pst}")
            if parent_id not in self._nodes:
                self._nodes[parent_id] = GraphNode(id=parent_id, type='process', label=f"Parent:{ppid}")
            self._edges.append(GraphEdge(source=parent_id, target=node_id, relation='spawned', timestamp=ts))

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
