# analyzer/attack_analyzer/field_mapper.py
"""
ECS 到 Sigma 字段映射器
作用：将 Elasticsearch 中的 ECS 格式数据映射到 Sigma 规则所需的字段格式
"""
import re
from typing import Dict, Any, Optional


class FieldMapper:
    """
    字段映射器
    将不同来源的日志数据统一映射到 Sigma 规则可识别的字段
    """
    
    # Sigma 字段 -> ECS 字段映射
    # Linux process_creation
    LINUX_PROCESS_CREATION_MAP = {
        "Image": ["process.executable", "process.name"],
        "CommandLine": ["process.command_line", "raw.data"],  # 需要从 raw.data 提取
        "User": ["process.user.name", "user.name"],
        "ParentImage": ["process.parent.executable", "process.parent.name"],
        "ParentCommandLine": ["process.parent.command_line"],
        "CurrentDirectory": ["process.working_directory"],
    }
    
    # Linux auditd 服务
    LINUX_AUDITD_MAP = {
        "key": ["event.action", "raw.key"],  # auditd 的 key 字段
        "type": ["raw.type"],
        "syscall": ["raw.syscall"],
        "exe": ["process.executable"],
        "comm": ["process.name"],
        "uid": ["process.user.id", "user.id"],
        "auid": ["user.audit_id"],
    }
    
    # Zeek 网络日志
    ZEEK_CONN_MAP = {
        "id.orig_h": ["source.ip"],
        "id.orig_p": ["source.port"],
        "id.resp_h": ["destination.ip"],
        "id.resp_p": ["destination.port"],
        "proto": ["network.transport"],
        "service": ["network.protocol"],
        "conn_state": ["zeek.conn_state"],
        "orig_bytes": ["source.bytes"],
        "resp_bytes": ["destination.bytes"],
    }
    
    # Cowrie 蜜罐日志
    COWRIE_MAP = {
        "src_ip": ["source.ip"],
        "src_port": ["source.port"],
        "dst_ip": ["destination.ip"],
        "dst_port": ["destination.port"],
        "username": ["user.name"],
        "password": ["user.password"],
        "input": ["process.command_line"],
        "eventid": ["event.action"],
        "session": ["event.id"],
    }
    
    def __init__(self):
        self._compiled_patterns = {}
    
    def map_event(self, event: Dict[str, Any], logsource: Dict[str, str]) -> Dict[str, Any]:
        """
        将 ECS 事件映射到 Sigma 字段格式
        
        Args:
            event: 原始 ECS 事件
            logsource: Sigma 规则的 logsource 定义
            
        Returns:
            映射后的事件，包含 Sigma 可识别的字段
        """
        product = logsource.get('product', '')
        category = logsource.get('category', '')
        dataset = event.get('event', {}).get('dataset', '')
        raw_type = event.get('raw', {}).get('type', '')
        
        # 选择合适的映射表
        if product == 'linux':
            # 对于进程创建类别，始终使用进程创建映射
            if category == 'process_creation':
                return self._map_auditd_process_creation(event)
            elif dataset == 'auditd' or raw_type in ['SYSCALL', 'EXECVE']:
                return self._map_auditd_process_creation(event)
            else:
                return self._map_with_table(event, self.LINUX_AUDITD_MAP)
        elif product == 'zeek':
            return self._map_with_table(event, self.ZEEK_CONN_MAP)
        elif dataset == 'cowrie':
            return self._map_with_table(event, self.COWRIE_MAP)
        
        # 默认返回原始事件
        return event
    
    def _map_with_table(self, event: Dict[str, Any], mapping_table: Dict[str, list]) -> Dict[str, Any]:
        """使用映射表转换事件"""
        mapped = {}
        
        for sigma_field, ecs_paths in mapping_table.items():
            for path in ecs_paths:
                value = self._get_nested_value(event, path)
                if value is not None:
                    mapped[sigma_field] = value
                    break
        
        # 保留原始字段以便调试
        mapped['_original'] = event
        return mapped
    
    def _map_auditd_process_creation(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        特殊处理 auditd 进程创建事件
        auditd 的数据结构比较复杂，需要从 raw.data 和 message 中提取信息
        
        Sigma 规则期望的字段:
        - Image: 可执行文件路径 (如 /tmp/malware)
        - CommandLine: 完整命令行
        - User: 用户名
        - ParentImage: 父进程路径
        """
        mapped = {}
        
        # 1. 基本进程信息 - 从 process 字段获取
        proc = event.get('process', {})
        proc_exe = self._clean_quoted_string(proc.get('executable', ''))
        proc_name = self._clean_quoted_string(proc.get('name', ''))
        proc_cmdline = proc.get('command_line', '')
        
        # 2. 从 raw.data 提取更多信息
        raw = event.get('raw', {})
        raw_data = raw.get('data', '')
        raw_type = raw.get('type', '')
        
        if raw_type == 'EXECVE':
            # EXECVE 类型包含完整命令行参数
            cmdline = self._extract_execve_cmdline(raw_data)
            mapped['CommandLine'] = cmdline
            # 命令行的第一个参数通常是程序名
            if cmdline and not proc_exe:
                parts = cmdline.split()
                if parts:
                    proc_name = parts[0]
        elif raw_type == 'SYSCALL':
            # SYSCALL 包含 comm 和 exe
            parsed = self._parse_kv_string(raw_data)
            if 'exe' in parsed:
                proc_exe = self._clean_quoted_string(parsed['exe'])
            if 'comm' in parsed:
                proc_name = self._clean_quoted_string(parsed['comm'])
            if 'key' in parsed:
                mapped['key'] = self._clean_quoted_string(parsed['key'])
            if 'ppid' in parsed:
                try:
                    mapped['ParentProcessId'] = int(parsed['ppid'])
                except:
                    pass
        
        # 3. 设置 Sigma 标准字段
        # Image 是最重要的字段，用于路径匹配
        mapped['Image'] = proc_exe if proc_exe else proc_name
        mapped['ProcessName'] = proc_name
        mapped['CommandLine'] = mapped.get('CommandLine') or proc_cmdline
        mapped['User'] = proc.get('user', {}).get('name', '')
        mapped['ProcessId'] = proc.get('pid')
        
        # 4. 从 message 字段补充 key
        message = event.get('message', '')
        if 'key=' in message and 'key' not in mapped:
            key_match = re.search(r'key="([^"]+)"', message)
            if key_match:
                mapped['key'] = key_match.group(1)
        
        # 5. 事件元数据
        mapped['EventTime'] = event.get('@timestamp')
        mapped['EventId'] = event.get('event', {}).get('id')
        
        # 保留原始数据
        mapped['_original'] = event
        mapped['_raw_type'] = raw_type
        
        return mapped
    
    def _extract_execve_cmdline(self, raw_data: str) -> str:
        """
        从 EXECVE 类型的 raw_data 提取完整命令行
        格式: argc=5 a0="tail" a1="-v" a2="-n" a3="32" a4="/proc/net/dev"
        """
        args = []
        # 匹配 a0, a1, a2... 参数
        pattern = r'a(\d+)=("[^"]*"|[^\s]+)'
        matches = re.findall(pattern, raw_data)
        
        # 按参数索引排序
        sorted_matches = sorted(matches, key=lambda x: int(x[0]))
        
        for _, value in sorted_matches:
            args.append(self._clean_quoted_string(value))
        
        return ' '.join(args)
    
    def _parse_kv_string(self, data: str) -> Dict[str, str]:
        """解析 key=value 格式的字符串"""
        result = {}
        # 匹配 key="value" 或 key=value 格式
        pattern = r'(\w+)=("[^"]*"|[^\s]+)'
        for key, value in re.findall(pattern, data):
            result[key] = value
        return result
    
    def _clean_quoted_string(self, value: str) -> str:
        """清理带引号的字符串"""
        if isinstance(value, str):
            return value.strip('"\'')
        return str(value) if value else ''
    
    def _get_nested_value(self, data: Dict, path: str) -> Any:
        """获取嵌套字典中的值，支持点号路径 (如 'process.name')"""
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
    事件标准化器
    将不同来源的原始日志统一为标准格式，便于后续处理
    """
    
    def __init__(self):
        self.mapper = FieldMapper()
    
    def normalize(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        标准化事件
        
        根据事件来源自动选择合适的映射方式
        """
        dataset = event.get('event', {}).get('dataset', '')
        raw_type = event.get('raw', {}).get('type', '')
        
        # 判断数据来源
        if dataset == 'auditd' or raw_type in ['SYSCALL', 'EXECVE', 'CWD', 'PATH', 'SOCKADDR']:
            logsource = {'product': 'linux', 'category': 'process_creation', 'service': 'auditd'}
        elif dataset and 'zeek' in dataset:
            logsource = {'product': 'zeek', 'category': 'network'}
        elif dataset == 'cowrie':
            logsource = {'product': 'linux', 'category': 'authentication'}
        else:
            # 默认
            logsource = {'product': 'linux'}
        
        return self.mapper.map_event(event, logsource)
    
    def get_logsource_type(self, event: Dict[str, Any]) -> Dict[str, str]:
        """
        推断事件的 logsource 类型
        用于确定应该使用哪些 Sigma 规则
        
        注意：不要返回 service 字段，因为大部分 Sigma 规则不指定 service
        这样可以匹配到更多规则
        """
        dataset = event.get('event', {}).get('dataset', '')
        raw_type = event.get('raw', {}).get('type', '')
        category = event.get('event', {}).get('category', '')
        
        if dataset == 'auditd' or raw_type in ['SYSCALL', 'EXECVE', 'CWD', 'PATH']:
            if raw_type in ['SYSCALL', 'EXECVE'] or category == 'process':
                # 不指定 service，这样可以匹配所有 linux + process_creation 规则
                return {'product': 'linux', 'category': 'process_creation'}
            elif raw_type == 'SOCKADDR':
                return {'product': 'linux', 'category': 'network_connection'}
            else:
                return {'product': 'linux'}
        elif dataset and 'zeek' in dataset:
            return {'product': 'zeek'}
        elif dataset == 'cowrie':
            return {'product': 'linux', 'category': 'authentication'}
        
        return {'product': 'linux'}
