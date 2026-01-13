# analyzer/attack_analyzer/field_mapper.py
"""
ECS 到 Sigma 字段映射器 (v5.2 Update - Fixed)
修复记录:
- 补全 EventNormalizer 类
- 增强 Auditd 字段映射兜底逻辑
"""
import re
from typing import Dict, Any, Optional

class FieldMapper:
    """
    字段映射器
    """
    
    # Sigma 字段 -> ECS 字段映射
    LINUX_PROCESS_CREATION_MAP = {
        "Image": ["process.executable", "process.name"],
        "CommandLine": ["process.command_line", "raw.input", "raw.data"], # 包含 raw.data
        "User": ["process.user.name", "user.name"],
        "ParentImage": ["process.parent.executable", "process.parent.name"],
        "ParentCommandLine": ["process.parent.command_line"],
        "CurrentDirectory": ["process.working_directory"],
    }
    
    LINUX_AUDITD_MAP = {
        "key": ["event.action", "raw.key"],
        "type": ["raw.type"],
        "syscall": ["raw.syscall"],
        "exe": ["process.executable"],
        "comm": ["process.name"],
        "uid": ["process.user.id", "user.id"],
        "auid": ["user.audit_id"],
    }
    
    ZEEK_CONN_MAP = {
        "id.orig_h": ["source.ip", "raw.id.orig_h"],
        "id.orig_p": ["source.port", "raw.id.orig_p"],
        "id.resp_h": ["destination.ip", "raw.id.resp_h"],
        "id.resp_p": ["destination.port", "raw.id.resp_p"],
        "proto": ["network.transport", "raw.proto"],
        "service": ["network.protocol", "raw.service"],
        "conn_state": ["zeek.conn_state", "raw.conn_state"],
        "orig_bytes": ["source.bytes", "raw.orig_bytes"],
        "resp_bytes": ["destination.bytes", "raw.resp_bytes"],
        "query": ["dns.question.name", "raw.query"],
        "method": ["http.request.method", "raw.method"],
        "uri": ["url.original", "raw.uri"],
        "FileName": ["file.name", "raw.filename"]
    }
    
    COWRIE_MAP = {
        "src_ip": ["source.ip", "raw.src_ip"],
        "src_port": ["source.port", "raw.src_port"],
        "dst_ip": ["destination.ip", "raw.dst_ip"],
        "dst_port": ["destination.port", "raw.dst_port"],
        "username": ["user.name", "raw.username"],
        "password": ["user.password", "raw.password"],
        "input": ["process.command_line", "raw.input"],
        
        # [Critical Fix] 必须优先取 raw.eventid，否则会取到 "success" 导致 Sigma 匹配失败
        "eventid": ["raw.eventid", "event.action"], 
        
        # [Critical Fix] 必须优先取 raw.session (哈希)，否则会取到 UUID 导致图谱断裂
        "session": ["raw.session", "event.id"],
        
        "Image": ["process.name"],
        "TargetFileName": ["file.path", "raw.outfile", "raw.destfile"],
        "CommandLine": ["process.command_line", "raw.input"]
    }
    
    def __init__(self):
        self._compiled_patterns = {}
    
    def map_event(self, event: Dict[str, Any], logsource: Dict[str, str]) -> Dict[str, Any]:
        product = logsource.get('product', '')
        category = logsource.get('category', '')
        dataset = event.get('event', {}).get('dataset', '')
        raw_type = event.get('raw', {}).get('type', '')
        
        if product == 'linux':
            if category == 'process_creation':
                if dataset == 'cowrie':
                     base_map = self._map_with_table(event, self.LINUX_PROCESS_CREATION_MAP)
                     cowrie_map = self._map_with_table(event, self.COWRIE_MAP)
                     base_map.update(cowrie_map)
                     return base_map
                return self._map_auditd_process_creation(event)
            
            elif dataset == 'auditd' or raw_type in ['SYSCALL', 'EXECVE']:
                return self._map_auditd_process_creation(event)
            else:
                return self._map_with_table(event, self.LINUX_AUDITD_MAP)
        
        elif product == 'zeek':
            return self._map_with_table(event, self.ZEEK_CONN_MAP)
        
        elif dataset == 'cowrie':
            return self._map_with_table(event, self.COWRIE_MAP)
        
        return event
    
    def _map_with_table(self, event: Dict[str, Any], mapping_table: Dict[str, list]) -> Dict[str, Any]:
        mapped = {}
        for sigma_field, ecs_paths in mapping_table.items():
            for path in ecs_paths:
                value = self._get_nested_value(event, path)
                if value is not None and value != "": 
                    mapped[sigma_field] = value
                    break
        mapped['_original'] = event
        return mapped
    
    def _map_auditd_process_creation(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        [Fix] 增强版 Auditd 映射：优先解析，失败则回退到通用映射表
        """
        mapped = {}
        proc = event.get('process', {})
        
        # 1. 尝试从 process 字段获取
        proc_exe = self._clean_quoted_string(proc.get('executable', ''))
        proc_name = self._clean_quoted_string(proc.get('name', ''))
        proc_cmdline = proc.get('command_line', '')
        
        mapped['Image'] = proc_exe if proc_exe else proc_name
        mapped['ProcessName'] = proc_name
        mapped['CommandLine'] = proc_cmdline
        mapped['User'] = proc.get('user', {}).get('name', '')
        mapped['ProcessId'] = proc.get('pid')
        mapped['EventTime'] = event.get('@timestamp')
        
        # 2. [Critical Fix] 如果关键字段为空，尝试使用 LINUX_PROCESS_CREATION_MAP 进行兜底
        # 这能确保 raw.data 被映射到 CommandLine
        fallback_needed = False
        if not mapped['CommandLine']:
            fallback_needed = True
            
        if fallback_needed:
            fallback_map = self._map_with_table(event, self.LINUX_PROCESS_CREATION_MAP)
            # 只补充缺失的字段
            for k, v in fallback_map.items():
                if k not in mapped or not mapped[k]:
                    mapped[k] = v
        
        mapped['_original'] = event
        return mapped
    
    def _clean_quoted_string(self, value: str) -> str:
        if isinstance(value, str):
            return value.strip('"\'')
        return str(value) if value else ''
    
    def _get_nested_value(self, data: Dict, path: str) -> Any:
        keys = path.split('.')
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current


class EventNormalizer:
    """
    事件标准化器 (v5.2 Update)
    """
    
    def __init__(self):
        self.mapper = FieldMapper()
    
    def normalize(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """标准化事件"""
        logsource = self.get_logsource_type(event)
        return self.mapper.map_event(event, logsource)
    
    def get_logsource_type(self, event: Dict[str, Any]) -> Dict[str, str]:
        """
        [Optimized] 根据组员2的交付文档，精确映射 logsource 类型
        对接组员 2 索引：network-flows-* (Zeek) 与 honeypot-logs-* (Cowrie)
        """
        dataset = event.get('event', {}).get('dataset', '')
        raw_type = event.get('raw', {}).get('type', '')
        category = event.get('event', {}).get('category', '')
        
        # 1. Cowrie 蜜罐逻辑 (优先级提升，确保蜜罐属性不被 Linux 逻辑覆盖)
        # 组员 2 文档指出 Cowrie 包含登录(authentication)和命令(process)
        if dataset == 'cowrie':
            logsource = {'product': 'cowrie'} # 修改点：保留 product 为 cowrie
            if category == 'process':
                logsource['category'] = 'process_creation'
            elif category == 'authentication':
                logsource['category'] = 'authentication'
            return logsource

        # 2. Zeek 网络流量逻辑
        # 组员 2 文档示例：zeek.dns, zeek.conn, zeek.files
        elif dataset and 'zeek' in dataset:
            parts = dataset.split('.')
            service = parts[1] if len(parts) > 1 else None
            
            # 映射逻辑：根据不同 dataset 映射到 Sigma 对应的 category
            if service == 'conn':
                return {'product': 'zeek', 'category': 'network_connection', 'service': 'conn'}
            elif service == 'dns':
                return {'product': 'zeek', 'category': 'dns', 'service': 'dns'}
            return {'product': 'zeek', 'service': service} if service else {'product': 'zeek'}

        # 3. Auditd / Linux 系统逻辑 (保持不变)
        if dataset == 'auditd' or raw_type in ['SYSCALL', 'EXECVE', 'CWD', 'PATH']:
            if raw_type in ['SYSCALL', 'EXECVE'] or category == 'process':
                return {'product': 'linux', 'category': 'process_creation'}
            elif raw_type == 'SOCKADDR':
                return {'product': 'linux', 'category': 'network_connection'}
            return {'product': 'linux'}
        
        return {'product': 'linux'}