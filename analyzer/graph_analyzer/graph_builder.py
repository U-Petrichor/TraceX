from typing import List, Dict, Any
from .entity_extractor import EntityExtractor

class EntityGraphBuilder:
    """
    实体关系图构建器
    作用：建立实体之间的关联（边），形成图结构。
    """
    
    def __init__(self):
        self.extractor = EntityExtractor()
    
    def build(self, events: List[Dict[str, Any]]) -> Dict[str, List]:
        """
        构建图结构
        
        Args:
            events: 事件字典列表
            
        Returns:
            包含 nodes(节点) 和 edges(边) 的字典
        """
        nodes = {} # 使用字典去重
        edges = []
        
        for event in events:
            # 1. 提取所有实体作为节点
            entities = self.extractor.extract(event)
            entity_map = {e["type"]: e for e in entities} # 方便快速查找
            
            # 添加到节点集合
            for entity in entities:
                nodes[entity["id"]] = {
                    "id": entity["id"],
                    "type": entity["type"],
                    "label": entity["value"],
                    "properties": entity
                }
            
            # 2. 构建边 (基于 schema 定义的逻辑关系)
            timestamp = event.get("@timestamp")
            
            # 场景 A: 进程创建子进程 (spawned)
            # 条件: 存在 process 且存在 process.parent
            proc = entity_map.get("process")
            if proc and proc.get("role") != "parent":
                # 在 extract 中我们可能提取了 parent 和 self，需要找到它们
                # 这里为了简化，我们遍历实体列表找父子关系
                parent_entity = None
                child_entity = None
                for e in entities:
                    if e["type"] == "process":
                        if e.get("role") == "parent":
                            parent_entity = e
                        else:
                            child_entity = e
                
                if parent_entity and child_entity:
                    edges.append({
                        "source": parent_entity["id"],
                        "target": child_entity["id"],
                        "relation": "spawned",
                        "timestamp": timestamp
                    })

            # 场景 B: 进程操作文件 (accessed/created/deleted)
            # 条件: 存在 process 和 file
            file_entity = entity_map.get("file")
            proc_entity = next((e for e in entities if e["type"] == "process" and e.get("role") != "parent"), None)
            
            if file_entity and proc_entity:
                action = event.get("event", {}).get("action", "accessed")
                edges.append({
                    "source": proc_entity["id"],
                    "target": file_entity["id"],
                    "relation": action,
                    "timestamp": timestamp
                })
                
            # 场景 C: 网络连接 (connected_to)
            # 条件: Source IP -> Destination IP
            src_ip = next((e for e in entities if e["type"] == "ip" and e.get("role") == "source"), None)
            dst_ip = next((e for e in entities if e["type"] == "ip" and e.get("role") == "destination"), None)
            
            if src_ip and dst_ip:
                edges.append({
                    "source": src_ip["id"],
                    "target": dst_ip["id"],
                    "relation": "connected_to",
                    "timestamp": timestamp
                })
                
            # 场景 D: IP 连接到进程 (Bind/Connect)
            # 如果是 inbound 流量，可能是 外部IP -> 本地进程
            # 这里简化处理：如果有 Source IP 和 进程，且没有 Dest IP，认为是 IP 操作了进程
            if src_ip and proc_entity and not dst_ip:
                 edges.append({
                    "source": src_ip["id"],
                    "target": proc_entity["id"],
                    "relation": "interacted_with",
                    "timestamp": timestamp
                })

        return {
            "nodes": list(nodes.values()),
            "edges": edges
        }