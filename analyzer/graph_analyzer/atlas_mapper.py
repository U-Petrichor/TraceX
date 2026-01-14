# analyzer/graph_analyzer/atlas_mapper.py
"""
ATLAS 语义标签映射器 v5.4 (Fixed Priority)

功能：
  将底层事件抽象为高层语义标签。这是 ATLAS 图抽象的核心步骤。

修订记录：
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
        self.executable_patterns: List[Tuple[str, str, str]] = [
            # 侦察工具
            (r'.*/?(id|whoami|uname|hostname|ifconfig|ip|netstat)$', 'RECON_COMMAND', '系统侦察命令'),
            (r'.*/?(cat|head|tail|less|more|grep|find|locate)$', 'FILE_READER', '文件读取命令'),
            (r'.*/?(nmap|masscan|zmap)$', 'NETWORK_SCANNER', '网络扫描器'),
            
            # 下载/传输工具
            (r'.*/?(curl|wget|fetch)$', 'SUSPICIOUS_DOWNLOADER', '可疑下载器'),
            (r'.*/?(scp|rsync|ftp|sftp|nc|ncat|netcat)$', 'DATA_TRANSFER_TOOL', '数据传输工具'),
            
            # Shell/解释器
            (r'.*/?(bash|sh|zsh|dash|csh|tcsh|ksh)$', 'SHELL_EXECUTION', 'Shell 执行'),
            (r'.*/?(python[23]?|perl|ruby|php|node)$', 'SCRIPT_INTERPRETER', '脚本解释器'),
            
            # 权限相关
            (r'.*/?(sudo|su|doas|pkexec)$', 'PRIVILEGE_ESCALATION', '提权工具'),
            (r'.*/?(chmod|chown|setfacl)$', 'PERMISSION_CHANGE', '权限变更'),
            
            # 持久化相关
            (r'.*/?(crontab|systemctl|service)$', 'PERSISTENCE_MECHANISM', '持久化机制'),
            
            # 编译/打包
            (r'.*/?(gcc|g\+\+|make|ld)$', 'COMPILATION_TOOL', '编译工具'),
            (r'.*/?(tar|gzip|zip|unzip|7z)$', 'ARCHIVE_TOOL', '压缩工具'),
        ]
        
        # === 文件路径规则 ===
        self.file_patterns: List[Tuple[str, str, str]] = [
            # 临时文件
            (r'^/tmp/.*', 'TEMP_FILE_ACCESS', '临时文件访问'),
            (r'^/var/tmp/.*', 'TEMP_FILE_ACCESS', '临时文件访问'),
            (r'^/dev/shm/.*', 'TEMP_FILE_ACCESS', '共享内存临时文件'),
            
            # Web 目录
            (r'.*/var/www/html/.*', 'WEB_ROOT_ACCESS', 'Web 根目录访问'),
            (r'.*/htdocs/.*', 'WEB_ROOT_ACCESS', 'Web 根目录访问'),
            (r'.*/wwwroot/.*', 'WEB_ROOT_ACCESS', 'Web 根目录访问'),
            (r'.*/public_html/.*', 'WEB_ROOT_ACCESS', 'Web 根目录访问'),
            
            # WebShell 文件
            (r'.*\.php$', 'PHP_SCRIPT', 'PHP 脚本'),
            (r'.*\.jsp$', 'JSP_SCRIPT', 'JSP 脚本'),
            (r'.*\.asp$', 'ASP_SCRIPT', 'ASP 脚本'),
            (r'.*\.aspx$', 'ASPX_SCRIPT', 'ASPX 脚本'),
            
            # 敏感文件
            (r'^/etc/passwd$', 'SENSITIVE_FILE', '敏感文件（passwd）'),
            (r'^/etc/shadow$', 'SENSITIVE_FILE', '敏感文件（shadow）'),
            (r'^/etc/sudoers$', 'SENSITIVE_FILE', '敏感文件（sudoers）'),
            (r'.*/.ssh/.*', 'SSH_RELATED', 'SSH 相关文件'),
            (r'.*/.bash_history$', 'HISTORY_FILE', '命令历史文件'),
            
            # 日志文件
            (r'^/var/log/.*', 'LOG_FILE_ACCESS', '日志文件访问'),
            
            # Cowrie 下载目录
            (r'.*/cowrie/downloads/.*', 'COWRIE_DOWNLOAD', '蜜罐下载文件'),
        ]
        
        # === 命令行规则 ===
        self.cmdline_patterns: List[Tuple[str, str, str]] = [
            # 反弹 Shell
            (r'bash\s+-i', 'REVERSE_SHELL', '反弹 Shell'),
            (r'/dev/tcp/', 'REVERSE_SHELL', '反弹 Shell'),
            (r'nc\s+-e', 'REVERSE_SHELL', '反弹 Shell'),
            (r'ncat\s+-e', 'REVERSE_SHELL', '反弹 Shell'),
            
            # 下载执行 (必须在通用管道之前)
            (r'curl.*\|\s*bash', 'DOWNLOAD_AND_EXECUTE', '下载并执行'),
            (r'wget.*\|\s*bash', 'DOWNLOAD_AND_EXECUTE', '下载并执行'),
            (r'curl.*-o\s+/tmp/', 'DOWNLOAD_TO_TEMP', '下载到临时目录'),
            (r'wget.*-O\s+/tmp/', 'DOWNLOAD_TO_TEMP', '下载到临时目录'),
            
            # Base64 编码执行
            (r'base64\s+-d', 'ENCODED_EXECUTION', '编码执行'),
            
            # 通用管道 (优先级较低)
            (r'\|\s*bash', 'PIPE_TO_SHELL', '管道到 Shell'),
            (r'\|\s*sh', 'PIPE_TO_SHELL', '管道到 Shell'),
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
        
        # 编译正则表达式（提高性能）
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """预编译正则表达式"""
        self._exe_compiled = [(re.compile(p, re.IGNORECASE), l, d) 
                              for p, l, d in self.executable_patterns]
        self._file_compiled = [(re.compile(p, re.IGNORECASE), l, d) 
                               for p, l, d in self.file_patterns]
        self._cmd_compiled = [(re.compile(p, re.IGNORECASE), l, d) 
                              for p, l, d in self.cmdline_patterns]
        self._net_compiled = [(re.compile(p, re.IGNORECASE), l, d) 
                              for p, l, d in self.network_patterns]
    
    def _get_val(self, obj: Any, path: str, default: Any = "") -> Any:
        """安全获取嵌套字段值"""
        parts = path.split('.')
        curr = obj
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
            (标签, 描述) 或 None
        """
        if not target:
            return None
        for regex, label, desc in patterns:
            if regex.search(target):
                return label, desc
        return None
    
    def get_label(self, event: Any) -> str:
        """
        为事件生成 ATLAS 语义标签 (返回主标签)
        """
        labels = []
        category = self._get_val(event, 'event.category', '')
        action = self._get_val(event, 'event.action', '')
        
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
