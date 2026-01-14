# analyzer/graph_analyzer/atlas_mapper.py
"""
ATLAS 语义标签映射器 v5.5 (新增内存异常标签支持)

功能：
  将底层事件抽象为高层语义标签。这是 ATLAS 图抽象的核心步骤。

修订记录：
  - v5.5: 新增内存异常事件的语义标签映射（MEMFD_EXEC, CODE_INJECTION 等）
  - v5.4: 调整通用匹配优先级，CmdLine > Executable，确保 'curl | bash' 识别为 'DOWNLOAD_AND_EXECUTE' 而非 'SUSPICIOUS_DOWNLOADER'
  - v5.3: 修复 get_all_labels 同步问题
"""
import re
import logging
from typing import Any, List, Tuple, Optional

logger = logging.getLogger(__name__)


class AtlasMapper:
    """
    ATLAS 语义标签映射器
    
    通过正则规则库将事件映射到预定义的语义标签。
    """
    
    def __init__(self):
        """初始化规则库"""
        # 规则格式：(正则表达式, 标签, 描述)
        # 按优先级排序，越靠前优先级越高
        
        # === 进程/可执行文件规则 ===
        # 采用四元组格式：(pattern, label, severity, ttp)
        self.executable_patterns: List[Tuple[str, str, int, str]] = [
            # 侦察工具
            (r'.*/?(id|whoami|uname|hostname|ifconfig|ip|netstat)$', 'RECON_COMMAND', 3, 'T1082'),
            (r'.*/?(cat|head|tail|less|more|grep|find|locate)$', 'FILE_READER', 3, 'T1005'),
            (r'.*/?(nmap|masscan|zmap)$', 'NETWORK_SCANNER', 5, 'T1595'),

            # 下载/传输工具
            (r'.*/?(curl|wget|fetch)$', 'SUSPICIOUS_DOWNLOADER', 4, 'T1105'),
            (r'.*/?(scp|rsync|ftp|sftp|nc|ncat|netcat)$', 'DATA_TRANSFER_TOOL', 5, 'T1567'),

            # Shell/解释器
            (r'.*/?(bash|sh|zsh|dash|csh|tcsh|ksh)$', 'SHELL_EXECUTION', 2, 'T1059'),
            (r'.*/?(python[23]?|perl|ruby|php|node)$', 'SCRIPT_INTERPRETER', 2, 'T1059'),

            # 权限相关
            (r'.*/?(sudo|su|doas|pkexec)$', 'PRIVILEGE_ESCALATION', 4, 'T1548.001'),
            (r'.*/?(chmod|chown|setfacl)$', 'PERMISSION_CHANGE', 3, 'T1222.002'),

            # 持久化相关
            (r'.*/?(crontab|systemctl|service)$', 'PERSISTENCE_MECHANISM', 5, 'T1543'),

            # 编译/打包
            (r'.*/?(gcc|g\+\+|make|ld)$', 'COMPILATION_TOOL', 4, 'T1027.004'),
            (r'.*/?(tar|gzip|zip|unzip|7z)$', 'ARCHIVE_TOOL', 3, 'T1560'),
        ]
        
        # === 文件路径规则 ===
        self.file_patterns: List[Tuple[str, str, int, str]] = [
            # 临时/内存分区
            (r'^/dev/shm/.*', 'IN_MEMORY_STAGING', 7, 'T1027.004'),
            (r'^/tmp/.*', 'TEMP_FILE_ACCESS', 4, 'T1564'),
            (r'^/var/tmp/.*', 'TEMP_FILE_ACCESS', 4, 'T1564'),
            
            # Web 目录
            (r'.*/var/www/html/.*', 'WEB_ROOT_ACCESS', 6, 'T1505.003'),
            (r'.*/htdocs/.*', 'WEB_ROOT_ACCESS', 6, 'T1505.003'),
            (r'.*/wwwroot/.*', 'WEB_ROOT_ACCESS', 6, 'T1505.003'),
            (r'.*/public_html/.*', 'WEB_ROOT_ACCESS', 6, 'T1505.003'),
            
            # WebShell 文件
            (r'.*\.php$', 'PHP_SCRIPT', 5, 'T1505.003'),
            (r'.*\.jsp$', 'JSP_SCRIPT', 5, 'T1505.003'),
            (r'.*\.asp$', 'ASP_SCRIPT', 5, 'T1505.003'),
            (r'.*\.aspx$', 'ASPX_SCRIPT', 5, 'T1505.003'),
            
            # 敏感文件
            (r'^/etc/passwd$', 'SENSITIVE_FILE', 8, 'T1003.008'),
            (r'^/etc/shadow$', 'SENSITIVE_FILE', 8, 'T1003.008'),
            (r'^/etc/sudoers$', 'SENSITIVE_FILE', 8, 'T1003.008'),
            (r'.*/.ssh/.*', 'SSH_RELATED', 7, 'T1552.004'),
            (r'.*/.bash_history$', 'HISTORY_FILE', 4, 'T1552.003'),
            
            # 日志文件
            (r'^/var/log/.*', 'LOG_FILE_ACCESS', 2, 'T1562.006'),

            # Cowrie 下载目录
            (r'.*/cowrie/downloads/.*', 'COWRIE_DOWNLOAD', 8, 'T1105'),
        ]
        
        # === 命令行规则 ===
        self.cmdline_patterns: List[Tuple[str, str, int, str]] = [
            # 反弹 Shell
            (r'bash\s+-i', 'REVERSE_SHELL', 10, 'T1059.004'),
            (r'/dev/tcp/', 'REVERSE_SHELL', 10, 'T1059.004'),
            (r'nc\s+-e', 'REVERSE_SHELL', 10, 'T1059.004'),
            (r'ncat\s+-e', 'REVERSE_SHELL', 10, 'T1059.004'),

            # 下载执行 (必须在通用管道之前)
            (r'curl.*\|\s*bash', 'DOWNLOAD_AND_EXECUTE', 9, 'T1105'),
            (r'wget.*\|\s*bash', 'DOWNLOAD_AND_EXECUTE', 9, 'T1105'),
            (r'curl.*-o\s+/tmp/', 'DOWNLOAD_TO_TEMP', 8, 'T1105'),
            (r'wget.*-O\s+/tmp/', 'DOWNLOAD_TO_TEMP', 8, 'T1105'),
            
            # Base64 编码执行
            (r'base64\s+-d', 'ENCODED_EXECUTION', 7, 'T1027'),

            # 通用管道 (优先级较低)
            (r'\|\s*bash', 'PIPE_TO_SHELL', 6, 'T1059.004'),
            (r'\|\s*sh', 'PIPE_TO_SHELL', 6, 'T1059.004'),

            # v6.1 新增：破坏性/敏感命令
            (r'rm\s+-rf\s+/', 'DESTRUCTIVE_ACTION', 10, 'T1485'),
            (r'cat\s+/etc/passwd|cat\s+/etc/shadow', 'SENSITIVE_FILE_READ', 8, 'T1003.008')
        ]
        
        # === 网络事件规则 ===
        self.network_patterns: List[Tuple[str, str, str]] = [
            # DNS
            (r'^dns$', 'DNS_QUERY', 'DNS 查询'),
            
            # HTTP
            (r'^http$', 'HTTP_REQUEST', 'HTTP 请求'),
            (r'^https$', 'HTTPS_REQUEST', 'HTTPS 请求'),
            
            # SSH
            (r'^ssh$', 'SSH_CONNECTION', 'SSH 连接'),
            
            # 隧道协议
            (r'^icmp$', 'ICMP_TRAFFIC', 'ICMP 流量'),
        ]
        
        # === v5.5 新增：内存异常类型映射 ===
        # 将内存异常类型映射到语义标签
        self.memory_anomaly_labels: dict = {
            'MEMFD_EXEC': ('FILELESS_ATTACK', 9, 'T1620'),
            'ANON_ELF': ('FILELESS_ATTACK', 9, 'T1620'),
            'RWX_REGION': ('CODE_INJECTION', 8, 'T1055'),
            'STACK_EXEC': ('CODE_INJECTION', 8, 'T1055'),
            'HEAP_EXEC': ('CODE_INJECTION', 8, 'T1055'),
            'PROCESS_HOLLOWING': ('PROCESS_HOLLOWING', 9, 'T1055.012'),
            'REFLECTIVE_LOAD': ('REFLECTIVE_LOADING', 9, 'T1620'),
            'SUSPICIOUS_MEMORY': ('MEMORY_ANOMALY', 5, 'T1055'),
        }
        
        # 编译正则表达式（提高性能）
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """预编译正则表达式"""
        self._exe_compiled = [(re.compile(p, re.IGNORECASE), l, s, t) 
                              for p, l, s, t in self.executable_patterns]
        self._file_compiled = [(re.compile(p, re.IGNORECASE), l, s, t) 
                               for p, l, s, t in self.file_patterns]
        self._cmd_compiled = [(re.compile(p, re.IGNORECASE), l, s, t) 
                              for p, l, s, t in self.cmdline_patterns]
        self._net_compiled = [(re.compile(p, re.IGNORECASE), l, d) 
                              for p, l, d in self.network_patterns]
    
    def _get_val(self, obj: Any, path: str, default: Any = "") -> Any:
        """安全获取嵌套字段值"""
        parts = path.split('.')
        # 支持包装对象（如带 _data 属性的对象）
        curr = getattr(obj, '_data', obj)
        try:
            for p in parts:
                if curr is None:
                    return default
                if isinstance(curr, dict):
                    curr = curr.get(p)
                elif hasattr(curr, p):
                    curr = getattr(curr, p)
                else:
                    return default
            return curr if curr is not None else default
        except Exception:
            return default
    
    def _match_patterns(self, target: str, patterns: list) -> Optional[Tuple[str, str]]:
        """
        在规则列表中查找第一个匹配
        
        Returns:
            (标签, severity, ttp) 或 None
        """
        if not target:
            return None
        for entry in patterns:
            # 支持两种编译后元组：
            # (regex, label, desc) 或 (regex, label, severity, ttp)
            if len(entry) == 3:
                regex, label, desc = entry
                severity = 0
                ttp = ''
            else:
                regex, label, severity, ttp = entry
            if regex.search(target):
                return label, severity, ttp
        return None
    
    def get_label(self, event: Any) -> str:
        """
        为事件生成 ATLAS 语义标签 (返回主标签)
        """
        labels = []
        category = self._get_val(event, 'event.category', '')
        action = self._get_val(event, 'event.action', '')
        
        # === v5.5 新增：内存异常事件优先处理 ===
        if category == 'memory':
            return self._get_memory_label(event)
        
        # 获取各种字段
        file_path = self._get_val(event, 'file.path', '')
        file_ext = self._get_val(event, 'file.extension', '')
        executable = self._get_val(event, 'process.executable', '')
        proc_name = self._get_val(event, 'process.name', '')
        cmd_line = self._get_val(event, 'process.command_line', '')
        protocol = self._get_val(event, 'network.protocol', '')
        direction = self._get_val(event, 'network.direction', '')
        
        # === 特殊高优先级规则 ===
        
        # 敏感文件访问
        sensitive_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
        if any(sf in str(file_path) or sf in str(cmd_line) for sf in sensitive_files):
            return 'SENSITIVE_FILE'
        
        # WebShell 写入
        webshell_paths = ['/var/www', 'htdocs', 'wwwroot', 'public_html']
        webshell_exts = ['php', 'jsp', 'asp', 'aspx']
        if any(wp in str(file_path) for wp in webshell_paths):
            if str(file_ext).lower() in webshell_exts or '.php' in str(file_path):
                if action in ['create', 'write', 'moved-to', 'rename']:
                    return 'PHP_SCRIPT'
                return 'WEB_ROOT_ACCESS'
        
        # 临时文件访问
        if file_path and ('/tmp/' in file_path or '/var/tmp/' in file_path or '/dev/shm/' in file_path):
            return 'TEMP_FILE_ACCESS'
        
        # === 根据事件类别决定匹配优先级 ===
        
        if category == 'network':
            if direction:
                if direction.lower() in ['inbound', 'ingress']:
                    return 'NETWORK_Inbound'
                elif direction.lower() in ['outbound', 'egress']:
                    return 'NETWORK_Outbound'
            if protocol:
                match = self._match_patterns(protocol, self._net_compiled)
                if match:
                    labels.append(match[0])
        
        elif category == 'file':
            if file_path:
                match = self._match_patterns(file_path, self._file_compiled)
                if match:
                    labels.append(match[0])
        
        # === 通用匹配逻辑 ===
        
        # [Fix Priority] 1. 优先检查命令行 (行为特征比工具名称更具体)
        if not labels and cmd_line:
            match = self._match_patterns(cmd_line, self._cmd_compiled)
            if match:
                labels.append(match[0])

        # 2. 检查可执行文件路径
        if not labels and executable:
            match = self._match_patterns(executable, self._exe_compiled)
            if match:
                labels.append(match[0])
        
        # 3. 检查进程名
        if not labels and proc_name:
            match = self._match_patterns(f"/{proc_name}", self._exe_compiled)
            if match:
                labels.append(match[0])
        
        # 4. 检查文件路径
        if not labels and file_path:
            match = self._match_patterns(file_path, self._file_compiled)
            if match:
                labels.append(match[0])
        
        # 5. 检查网络协议
        if not labels and protocol:
            match = self._match_patterns(protocol, self._net_compiled)
            if match:
                labels.append(match[0])
        
        # 6. 网络方向推断
        if direction:
            if direction.lower() in ['inbound', 'ingress']:
                labels.append('NETWORK_Inbound')
            elif direction.lower() in ['outbound', 'egress']:
                labels.append('NETWORK_Outbound')
        elif protocol or category == 'network':
            if proc_name in ['curl', 'wget', 'fetch']:
                labels.append('NETWORK_Outbound')
            elif proc_name in ['nginx', 'apache', 'httpd']:
                labels.append('NETWORK_Inbound')
        
        if not labels:
            category = self._get_val(event, 'event.category', 'UNKNOWN')
            action = self._get_val(event, 'event.action', '')
            if category:
                fallback = category.upper()
                if action:
                    fallback = f"{fallback}_{action.upper()}"
                labels.append(fallback)
            else:
                labels.append('UNKNOWN')
        
        return labels[0] if labels else 'UNKNOWN'
    
    def get_all_labels(self, event: Any) -> List[str]:
        """
        获取事件的所有匹配标签 (包含所有可能的匹配，不短路)
        """
        labels = []
        
        executable = self._get_val(event, 'process.executable')
        file_path = self._get_val(event, 'file.path')
        cmd_line = self._get_val(event, 'process.command_line')
        protocol = self._get_val(event, 'network.protocol')
        proc_name = self._get_val(event, 'process.name')
        direction = self._get_val(event, 'network.direction')
        
        if executable:
            match = self._match_patterns(executable, self._exe_compiled)
            if match: labels.append(match[0])
        
        if file_path:
            match = self._match_patterns(file_path, self._file_compiled)
            if match: labels.append(match[0])
        
        if cmd_line:
            match = self._match_patterns(cmd_line, self._cmd_compiled)
            if match: labels.append(match[0])
        
        if protocol:
            match = self._match_patterns(protocol, self._net_compiled)
            if match: labels.append(match[0])
            
        if direction:
            if direction.lower() in ['inbound', 'ingress']:
                labels.append('NETWORK_Inbound')
            elif direction.lower() in ['outbound', 'egress']:
                labels.append('NETWORK_Outbound')
        else:
            if proc_name in ['curl', 'wget', 'fetch']:
                labels.append('NETWORK_Outbound')
            elif proc_name in ['nginx', 'apache', 'httpd']:
                labels.append('NETWORK_Inbound')
        
        seen = set()
        unique_labels = []
        for label in labels:
            if label not in seen:
                seen.add(label)
                unique_labels.append(label)
        
        return unique_labels if unique_labels else ['UNKNOWN']
    
    def _get_memory_label(self, event: Any) -> str:
        """
        为内存异常事件生成语义标签 (v5.5 新增)
        
        根据异常类型和风险等级映射到对应的语义标签。
        """
        anomalies = self._get_val(event, 'memory.anomalies', [])
        
        # 兼容单个异常的情况
        if isinstance(anomalies, dict):
            anomalies = [anomalies]
        
        if not anomalies:
            return 'MEMORY_ANOMALY'
        
        # 按风险等级排序，优先返回最高风险的标签
        risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_anomalies = sorted(
            anomalies,
            key=lambda x: risk_order.get(str(x.get('risk_level', '')).upper(), 4) if isinstance(x, dict) else 4
        )
        
        # 获取最高风险异常的类型
        for anomaly in sorted_anomalies:
            if isinstance(anomaly, dict):
                anomaly_type = anomaly.get('type', '')
                risk_level = str(anomaly.get('risk_level', '')).upper()
                
                # 尝试从映射表获取标签
                if anomaly_type in self.memory_anomaly_labels:
                    label, _, _ = self.memory_anomaly_labels[anomaly_type]
                    return label
                
                # 根据风险等级返回通用标签
                if risk_level == 'CRITICAL':
                    return 'CRITICAL_MEMORY_ANOMALY'
                elif risk_level == 'HIGH':
                    return 'HIGH_RISK_MEMORY_ANOMALY'
        
        return 'MEMORY_ANOMALY'