# analyzer/graph_analyzer/provenance_system.py
"""
溯源系统 v5.3 (Fixed Import Error & TypedDict)

功能：
  从种子事件（高危告警）出发，BFS 广度优先搜索重建完整攻击路径。
  
  工作流程：
  1. 接收种子事件
  2. 查找关联事件 (ContextEngine)
  3. 构建图谱 (GraphBuilder)
  4. 标记标签 (AtlasMapper)
  5. 情报富化 (IntelEnricher)

修订记录：
  - v5.3: 添加 RebuildResult 类型定义，修复 ImportError
  - v5.2: __init__ 支持依赖注入
"""
import logging
from typing import Any, Dict, List, Optional, Set, TypedDict
from collections import deque

# 导入组件
from .graph_builder import GraphBuilder
from .atlas_mapper import AtlasMapper
from .enrichment import IntelEnricher

logger = logging.getLogger(__name__)

# [Fix] 定义返回结果的类型结构，解决 __init__.py 的导入错误
class RebuildResult(TypedDict):
    graph: Dict[str, Any]
    path_signature: str
    stats: Dict[str, Any]
    intelligence: Dict[str, Any]

class ProvenanceSystem:
    """
    攻击溯源主控制器
    负责编排 ContextEngine, GraphBuilder, AtlasMapper 和 IntelEnricher
    """
    
    def __init__(
        self, 
        context_engine: Any,
        graph_builder: Optional[GraphBuilder] = None,
        atlas_mapper: Optional[AtlasMapper] = None,
        enricher: Optional[IntelEnricher] = None
    ):
        """
        初始化溯源系统
        
        Args:
            context_engine: 上下文引擎（必须提供）
            graph_builder: 图构建器（可选，默认新建）
            atlas_mapper: 语义映射器（可选，默认新建）
            enricher: 情报富化器（可选，默认新建）
        """
        self.context_engine = context_engine
        
        # 支持依赖注入，方便测试
        self.graph_builder = graph_builder if graph_builder else GraphBuilder()
        self.atlas_mapper = atlas_mapper if atlas_mapper else AtlasMapper()
        self.enricher = enricher if enricher else IntelEnricher()
        
    def rebuild_attack_path(self, seed_event: Dict[str, Any]) -> RebuildResult:
        """
        重建攻击路径（主入口）
        
        Args:
            seed_event: 种子事件（通常是 IDS/WAF 告警或高危日志）
            
        Returns:
            RebuildResult: 包含图谱、统计信息和情报的字典
        """
        logger.info(f"Starting provenance analysis for seed event: {seed_event.get('event', {}).get('id', 'unknown')}")
        
        # 1. BFS 搜索关联事件
        # ----------------------------------------------------
        queue = deque([seed_event])
        visited_ids = set()
        all_events = [] # 存储所有收集到的事件
        
        # 添加种子事件
        seed_id = self._get_event_id(seed_event)
        if seed_id:
            visited_ids.add(seed_id)
            all_events.append(seed_event)
        
        # BFS 参数
        max_depth = 3
        current_depth = 0
        
        while queue and current_depth < max_depth:
            level_size = len(queue)
            current_depth += 1
            
            for _ in range(level_size):
                current_evt = queue.popleft()
                
                # 调用组员3的接口查找关联事件
                neighbors = self.context_engine.find_related_events(current_evt)
                
                for neighbor in neighbors:
                    n_id = self._get_event_id(neighbor)
                    if n_id and n_id not in visited_ids:
                        visited_ids.add(n_id)
                        all_events.append(neighbor)
                        queue.append(neighbor)
        
        # 2. 构建图谱 & 打标签
        # ----------------------------------------------------
        # GraphBuilder 会处理节点 ID 生成、PID 关联和边构建
        # 注意：我们需要先重置 builder 状态，或者确保它是新的
        self.graph_builder.reset() 
        graph_data = self.graph_builder.build_from_events(all_events)
        
        # 补充 Atlas 语义标签 (虽然 GraphBuilder 内部可能做了，但我们这里显式提取用于签名)
        path_signature_tokens = []
        for evt in all_events:
            label = self.atlas_mapper.get_label(evt)
            # 收集用于生成签名
            if label != "UNKNOWN":
                path_signature_tokens.append(label)

        # 3. 生成路径签名
        # ----------------------------------------------------
        # 简单的去重排序签名，用于聚类
        signature = " -> ".join(sorted(list(set(path_signature_tokens))))
        
        # 4. 情报富化 & APT 归因
        # ----------------------------------------------------
        nodes = graph_data.get('nodes', [])
        
        # 调用 enrichment 进行归因
        attribution_result = self.enricher.attribute_by_ttps(path_signature_tokens)
        
        # 5. 组装最终结果
        # ----------------------------------------------------
        # 确保返回结构符合 RebuildResult 定义
        result: RebuildResult = {
            "graph": graph_data,
            "path_signature": signature,
            "stats": {
                "events_processed": len(all_events),
                "nodes_count": len(nodes),
                "edges_count": len(graph_data.get('edges', [])),
                "depth_reached": current_depth
            },
            "intelligence": {
                "attribution": attribution_result
            }
        }
        
        logger.info(f"Provenance analysis completed. Nodes: {len(nodes)}, Signature: {signature}")
        return result

    def _get_event_id(self, event: Dict) -> Optional[str]:
        """辅助方法：安全获取事件 ID"""
        try:
            return event.get('event', {}).get('id')
        except:
            return None
