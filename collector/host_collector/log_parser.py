import re
import json
import socket
import platform
from datetime import datetime
from collector.common.schema import UnifiedEvent

class HostLogParser:
    """主机日志解析器 - 终极整合版 (保留全功能 + 修复 PPID 溯源)"""
    
    def __init__(self):
        self._audit_buffer = {}
        self._last_audit_id = None
        # v4.1 Session Cache: {session_id: source_ip}
        # 用于将登录时的源 IP 关联到后续的操作事件
        self._session_cache = {}
        self._cache_max_size = 1000

    def parse(self, raw_data, log_type: str = "auditd") -> UnifiedEvent:
        if log_type == "auditd":
            aggregated_data = self.parse_auditd_line(raw_data)
            if aggregated_data:
                return self.to_unified_event(aggregated_data)
            return None
        elif log_type == "windows":
            return self._parse_windows(raw_data)
        else:
            raise ValueError(f"Unsupported log_type: {log_type}")

    def _parse_windows(self, win_log: dict) -> UnifiedEvent:
        """解析 Windows Event Log (保留你原来的逻辑)"""
        event = UnifiedEvent()
        event.raw = win_log
        event.event.dataset = "windows"
        
        event_id = win_log.get("EventID")
        if event_id is None and "System" in win_log:
            event_id = win_log["System"].get("EventID")
            
        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            event_id = 0
            
        event.host.os.family = "windows"
        time_created = win_log.get("TimeCreated")
        if time_created is None and "System" in win_log:
            time_created = win_log["System"].get("TimeCreated")
            if isinstance(time_created, dict):
                time_created = time_created.get("SystemTime")
        if time_created:
            event.timestamp = str(time_created)

        data = win_log.get("EventData", win_log)
        
        if event_id == 4624:
            event.event.category = "iam"
            event.event.action = "login-success"
            event.event.outcome = "success"
            event.event.severity = 1
            # 兼容 PowerShell 解析的扁平字典或嵌套结构
            target_user = data.get("TargetUserName")
            if not target_user and isinstance(data, list): # 处理可能的 List 格式
                 for item in data:
                     if isinstance(item, dict) and item.get("Name") == "TargetUserName":
                         target_user = item.get("#text") or item.get("Value")
            
            event.user.name = target_user or ""
            
            # 尝试提取源 IP
            ip_addr = data.get("IpAddress")
            if not ip_addr and "NetworkInformation" in data: # 某些 XML 结构
                ip_addr = data["NetworkInformation"].get("SourceAddress")
            
            # 过滤掉本地 IP (::1, 127.0.0.1, -)
            if ip_addr and ip_addr not in ["-", "::1", "127.0.0.1"]:
                event.source.ip = ip_addr

        elif event_id == 4768: # Kerberos TGT Request (域登录请求)
            event.event.category = "iam"
            event.event.action = "login-attempt-domain" # 相当于域内的"登录尝试"
            event.event.outcome = "success" # TGT 请求成功通常意味着密码正确
            event.event.severity = 1
            
            # 提取用户名 (TargetUserName)
            event.user.name = data.get("TargetUserName", "")
            
            # 提取源 IP (IpAddress) - 格式通常是 ::ffff:192.168.x.x
            raw_ip = data.get("IpAddress", "")
            if raw_ip:
                # 清洗 IP，去掉 ::ffff: 前缀
                event.source.ip = raw_ip.replace("::ffff:", "")

        elif event_id == 4776: # NTLM Auth (老式域登录)
            event.event.category = "iam"
            event.event.action = "login-attempt-ntlm"
            event.event.outcome = "success"
            event.user.name = data.get("TargetUserName", "")
            event.source.ip = data.get("Workstation", "") # NTLM 记录的是主机名而非 IP，暂时存在 source.ip 里或者 source.host.name

        elif event_id == 4688:
            event.event.category = "process"
            event.event.action = "process_created"
            event.process.executable = data.get("NewProcessName", "")
            if event.process.executable:
                event.process.name = event.process.executable.split("\\")[-1]
            event.process.command_line = data.get("CommandLine", "")
            try:
                # Windows 的 PID 处理
                p_id = data.get("ProcessId", "0")
                event.process.pid = int(p_id, 16) if str(p_id).startswith("0x") else int(p_id)
                pp_id = data.get("ParentProcessId", "0")
                event.process.parent.pid = int(pp_id, 16) if str(pp_id).startswith("0x") else int(pp_id)
            except: pass
        elif event_id == 4663:
            event.event.category = "file"
            event.event.action = "access"
            event.file.path = data.get("ObjectName", "")
            if event.file.path:
                event.file.name = event.file.path.split("\\")[-1]
        # 统一处理 process.start_time
        # Elasticsearch 可能会因为 process.start_time 为空字符串 "" 而报错 mapper_parsing_exception
        # UnifiedEvent 默认可能初始化为 ""，这里要强制修正
        if hasattr(event, "process") and event.process:
             # 如果没有 process 相关的事件（比如纯登录事件），确保这些字段为 None 而不是空字符串
             if not event.process.pid and not event.process.executable:
                 event.process.start_time = None
             elif event.process.start_time == "":
                 event.process.start_time = None

        return event

    def parse_auditd_line(self, line: str) -> dict:
        if not line or not line.strip(): return None
        parsed_line = self._parse_raw_line(line)
        if not parsed_line: return None
        current_id = parsed_line['audit_id']
        flushed_data = None
        if self._last_audit_id and current_id != self._last_audit_id:
            if self._last_audit_id in self._audit_buffer:
                flushed_data = self._audit_buffer.pop(self._last_audit_id)
        self._last_audit_id = current_id
        if current_id not in self._audit_buffer:
            self._audit_buffer[current_id] = {"timestamp": parsed_line['timestamp'], "audit_id": current_id, "records": []}
        self._audit_buffer[current_id]["records"].append(parsed_line['data'])
        if parsed_line['data'].get('type') == 'EOE':
            flushed_data = self._audit_buffer.pop(current_id)
        return flushed_data

    def _parse_raw_line(self, line: str) -> dict:
        timestamp_match = re.search(r'msg=audit\((\d+\.\d+):(\d+)\):', line)
        if not timestamp_match: return None
        kv_pairs = {}
        for token in line.split():
            if "=" in token:
                try:
                    k, v = token.split("=", 1)
                    kv_pairs[k] = v.strip('"\'')
                except: continue
        return {"timestamp": float(timestamp_match.group(1)), "audit_id": timestamp_match.group(2), "data": kv_pairs}

    def to_unified_event(self, raw_data: dict) -> UnifiedEvent:
        records = raw_data.get("records", [])
        syscall_record = next((r for r in records if r.get("type") == "SYSCALL"), {})
        execve_record = next((r for r in records if r.get("type") == "EXECVE"), {})
        cwd_record = next((r for r in records if r.get("type") == "CWD"), {})
        main_record = syscall_record if syscall_record else (records[0] if records else {})
        audit_type = main_record.get("type", "UNKNOWN")
        
        event = UnifiedEvent()
        event.raw = raw_data
        dt = datetime.utcfromtimestamp(raw_data.get("timestamp", 0))
        event.timestamp = dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        
        if audit_type in ["SYSCALL", "EXECVE", "PROCTITLE"] or syscall_record:
            event.event.category = "process"
            event.event.action = "process_started"
            event.process.pid = int(main_record.get("pid", 0))
            
            # === [CORE FIX] 修复 PPID 提取，确保溯源链条不断 ===
            ppid_val = main_record.get("ppid")
            if ppid_val:
                event.process.parent.pid = int(ppid_val)
            
            event.process.name = main_record.get("comm", "unknown")
            event.process.executable = main_record.get("exe", "")
            event.process.start_time = event.timestamp

            if execve_record:
                args = []
                idx = 0
                while f"a{idx}" in execve_record:
                    args.append(execve_record[f"a{idx}"]); idx += 1
                if args: event.process.command_line = " ".join(args)
            if not event.process.command_line:
                 event.process.command_line = main_record.get("proctitle", main_record.get("cmdline", ""))

            if cwd_record: event.process.cwd = cwd_record.get("cwd", "")

            # 用户与 Session 关联
            event.user.id = main_record.get("uid", "")
            event.user.name = main_record.get("auid", "")
            session_id = main_record.get("ses", "")
            if session_id and session_id != "4294967295":
                event.user.session_id = session_id
                if session_id in self._session_cache:
                    event.source.ip = self._session_cache[session_id]

            # 文件路径处理
            path_record = next((r for r in records if r.get("type") == "PATH" and r.get("nametype") == "NORMAL"), None)
            if not path_record: path_record = next((r for r in records if r.get("type") == "PATH"), None)
            if path_record:
                event.file.path = path_record.get("name", "")
                if event.file.path:
                    event.file.name = event.file.path.split("/")[-1]
                    if "/tmp" in event.file.path: event.metadata.atlas_label = "TEMP_FILE"

        elif audit_type in ["USER_LOGIN", "USER_AUTH"]:
            event.event.category = "authentication"
            event.event.action = "login"
            event.source.ip = main_record.get("addr", "localhost")
            session_id = main_record.get("ses", "")
            if session_id and session_id != "4294967295":
                event.user.session_id = session_id
                if event.source.ip and event.source.ip not in ["?", "localhost", "127.0.0.1"]:
                    if len(self._session_cache) > self._cache_max_size: self._session_cache.clear()
                    self._session_cache[session_id] = event.source.ip

        # 威胁等级与主机信息
        if main_record.get("res") == "failed":
            event.event.outcome = "failure"; event.event.severity = 4
        else:
            event.event.outcome = "success"; event.event.severity = 1
        if event.user.id == "0": event.event.severity = max(event.event.severity, 8)

        # 3. 敏感目标判定：触碰敏感文件 -> Critical (10)
        sensitive_patterns = ["/etc/passwd", "/etc/shadow", ".ssh", "/etc/sudoers"]
        target_path = event.file.path or event.process.command_line or ""
        
        for pattern in sensitive_patterns:
            if pattern in target_path:
                event.event.severity = 10
                event.detection.severity = "critical" # 同步更新旧字段
                break
        
        # 填充主机信息
        try:
            event.host.hostname = socket.gethostname()
            event.host.name = event.host.hostname
            event.host.os.family = platform.system().lower()
            event.host.os.name = platform.system()
            event.host.os.version = platform.release()
            event.host.ip = [socket.gethostbyname(event.host.hostname)]
        except:
            pass
        
        event.event.dataset = "auditd"
        return event

def write_event(event: UnifiedEvent, output_file: str = "output.json") -> bool:
    try:
        data = event.to_dict()
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")
        return True
    except: return False
