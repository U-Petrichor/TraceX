# analyzer/graph_analyzer/graph_builder.py
import hashlib
import os
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from .pid_cache import PIDCache
from .atlas_mapper import AtlasMapper

@dataclass
class GraphNode:
    id: str; type: str; label: str; atlas_label: str = ""; properties: Dict[str, Any] = field(default_factory=dict)

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

    def build_from_events(self, events: List[Any]):
        for e in events: self._process_event(e)
        return {"nodes": [n.__dict__ for n in self._nodes.values()], "edges": [e.__dict__ for e in self._edges]}

    def _process_event(self, e: Any):
        host = self._get_val(e, 'host.name', 'unknown')
        pid = self._get_val(e, 'process.pid', 0)
        exe = self._get_val(e, 'process.executable', '')
        ts = self._get_val(e, 'timestamp', '') or self._get_val(e, '@timestamp', '')
        category = self._get_val(e, 'event.category', '')

        # 1. 唯一 Node ID 生成 (基于 PID 上下文缓存)
        st = self.pid_cache.get_start_time(host, pid)
        if not st:
            # 仅在进程启动事件时设置初始缓存，其余情况使用逻辑兜底
            if category == "process" and self._get_val(e, 'event.action') in ["exec", "process_started"]:
                st = ts
                try:
                    self.pid_cache.set_start_time(host, pid, st)
                except Exception:
                    pass
            else:
                st = "logical_anchor" # v6.1 规格：严禁直接用 ts 以防断链

        node_id = self._md5(f"{host}|{pid}|{exe}|{st}")

        # 2. 内存异常节点挂载（强制连边）
        if category == "memory":
            anomaly_id = self._md5(f"anomaly|{ts}|{node_id}")
            if anomaly_id not in self._nodes:
                self._nodes[anomaly_id] = GraphNode(
                    id=anomaly_id,
                    type='memory_anomaly',
                    label='Memory Anomaly',
                    properties={'details': self._get_val(e, 'memory.anomalies')}
                )
            # 强制建立 triggered_anomaly 边
            self._edges.append(GraphEdge(source=node_id, target=anomaly_id, relation='triggered_anomaly', timestamp=ts))

        # 3. 注册主进程节点
        if node_id not in self._nodes:
            self._nodes[node_id] = GraphNode(
                id=node_id,
                type='process',
                label=os.path.basename(exe) if exe else f"PID:{pid}",
                atlas_label=self.atlas_mapper.get_label(e),
                properties={"pid": pid, "cmd": self._get_val(e, 'process.command_line')}
            )

        # 4. 父进程回溯 (原有功能)
        ppid = self._get_val(e, 'process.parent.pid', 0)
        if ppid > 0:
            pst = self.pid_cache.get_start_time(host, ppid) or "unknown"
            parent_id = self._md5(f"{host}|{ppid}||{pst}")
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
