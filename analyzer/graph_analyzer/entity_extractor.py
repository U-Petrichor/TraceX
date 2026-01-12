from typing import List, Dict, Any

class EntityExtractor:
    """
    实体抽取器
    作用：从 UnifiedEvent 格式的日志中提取出独立的实体（如 IP、进程、文件、用户）。
    遵循 collector/common/schema.py 的数据结构。
    """
    
    def extract(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        从单个事件字典中提取所有实体
        
        Args:
            event: 符合 UnifiedEvent.to_dict() 结构的字典
            
        Returns:
            实体列表，每个实体包含 id, type, value 等字段
        """
        entities = []
        
        # 1. 抽取源 IP (Source IP)
        # 对应 schema: SourceInfo.ip
        source_ip = event.get("source", {}).get("ip")
        if source_ip:
            entities.append({
                "id": f"ip:{source_ip}",
                "type": "ip",
                "value": source_ip,
                "role": "source"
            })
        
        # 2. 抽取目的 IP (Destination IP)
        # 对应 schema: DestinationInfo.ip
        dest_ip = event.get("destination", {}).get("ip")
        if dest_ip:
            entities.append({
                "id": f"ip:{dest_ip}",
                "type": "ip",
                "value": dest_ip,
                "role": "destination"
            })
            
        # 3. 抽取进程 (Process)
        # 对应 schema: ProcessInfo
        proc = event.get("process", {})
        proc_name = proc.get("name")
        proc_pid = proc.get("pid")
        
        if proc_name:
            # 当前进程
            entities.append({
                "id": f"process:{proc_name}:{proc_pid}",
                "type": "process",
                "value": proc_name,
                "pid": proc_pid,
                "executable": proc.get("executable", "")
            })
            
            # 父进程 (Parent Process)
            parent = proc.get("parent", {})
            if parent.get("name"):
                entities.append({
                    "id": f"process:{parent.get('name')}:{parent.get('pid')}",
                    "type": "process",
                    "value": parent.get("name"),
                    "pid": parent.get("pid"),
                    "role": "parent"
                })

        # 4. 抽取文件 (File)
        # 对应 schema: FileInfo
        file_path = event.get("file", {}).get("path")
        if file_path:
            entities.append({
                "id": f"file:{file_path}",
                "type": "file",
                "value": file_path
            })
            
        # 5. 抽取用户 (User)
        # 对应 schema: UserInfo
        user_name = event.get("user", {}).get("name")
        if user_name:
            entities.append({
                "id": f"user:{user_name}",
                "type": "user",
                "value": user_name
            })
            
        # 6. 抽取主机 (Host)
        # 对应 schema: HostInfo
        host_name = event.get("host", {}).get("name")
        if host_name:
            entities.append({
                "id": f"host:{host_name}",
                "type": "host",
                "value": host_name
            })
            
        return entities