# analyzer/graph_analyzer/graph_builder.py
import hashlib
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
        ts = self._get_val(e, 'timestamp', '')
        
        # 节点 ID 生成
        st = self.pid_cache.get_start_time(host, pid) or ts
        node_id = self._md5(f"{host}|{pid}|{exe}|{st}")
        
        # [修复] 字典赋值，不再使用错误的 append()
        if node_id not in self._nodes:
            self._nodes[node_id] = GraphNode(
                id=node_id, 
                type='process', 
                label=exe or f"PID:{pid}",
                atlas_label=self.atlas_mapper.get_label(e),
                properties={"pid": pid, "cmd": self._get_val(e, 'process.command_line')}
            )
        
        # 处理父进程关联
        ppid = self._get_val(e, 'process.parent.pid', 0)
        if ppid > 0:
            pst = self.pid_cache.get_start_time(host, ppid) or "unknown"
            parent_id = self._md5(f"{host}|{ppid}||{pst}")
            if parent_id not in self._nodes:
                self._nodes[parent_id] = GraphNode(id=parent_id, type='process', label=f"Parent:{ppid}")
            self._edges.append(GraphEdge(source=parent_id, target=node_id, relation='spawned', timestamp=ts))

    def _get_val(self, obj, path, default=None):
        curr = obj
        for p in path.split('.'):
            if isinstance(curr, dict): curr = curr.get(p)
            elif hasattr(curr, p): curr = getattr(curr, p)
            else: return default
        return curr if curr is not None else default
