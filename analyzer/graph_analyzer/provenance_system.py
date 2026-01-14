# analyzer/graph_analyzer/provenance_system.py
import logging
from typing import Any, Dict, List, Optional, TypedDict
from collections import deque
from .graph_builder import GraphBuilder
from .atlas_mapper import AtlasMapper
from .enrichment import IntelEnricher

class ProvenanceSystem:
    def __init__(self, context_engine, graph_builder=None, atlas_mapper=None, enricher=None):
        self.context_engine = context_engine
        self.graph_builder = graph_builder if graph_builder else GraphBuilder()
        self.atlas_mapper = atlas_mapper if atlas_mapper else AtlasMapper()
        self.enricher = enricher if enricher else IntelEnricher()
        
    def rebuild_attack_path(self, seed_event):
        # 核心逻辑：收集所有逻辑相关的事件，交给 GraphBuilder 统一处理
        # 这样可以利用 GraphBuilder 内部的 PIDCache 自动对齐 ID
        queue = deque([seed_event])
        visited_ids = set()
        all_events = []
        
        # 记录种子 ID 防止死循环
        s_id = seed_event.get('event', {}).get('id')
        if s_id: visited_ids.add(s_id)
        all_events.append(seed_event)

        max_depth = 10 
        current_depth = 0
        
        while queue and current_depth < max_depth:
            level_size = len(queue)
            current_depth += 1
            for _ in range(level_size):
                curr = queue.popleft()
                # 依赖组员 3 的上下文引擎寻找“因果邻居”
                neighbors = self.context_engine.find_related_events(curr)
                for n in neighbors:
                    n_id = n.get('event', {}).get('id')
                    if n_id and n_id not in visited_ids:
                        visited_ids.add(n_id)
                        all_events.append(n)
                        queue.append(n)
        
        # 关键：重置并使用统一的构建逻辑
        self.graph_builder.reset() 
        # GraphBuilder.build_from_events 会根据 host+pid+st 自动计算边
        graph_data = self.graph_builder.build_from_events(all_events)
        
        labels = [self.atlas_mapper.get_label(e) for e in all_events]
        signature = " -> ".join(sorted(set([l for l in labels if l != "UNKNOWN"])))
        
        return {
            "nodes": graph_data.get('nodes', []),
            "edges": graph_data.get('edges', []),
            "path_signature": signature,
            "intelligence": {"attribution": self.enricher.attribute_by_ttps(labels)}
        }
