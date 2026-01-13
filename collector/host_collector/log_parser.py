import re
from datetime import datetime
from collector.common.schema import UnifiedEvent

class HostLogParser:
    """主机日志解析器"""
    
    def __init__(self):
        self._audit_buffer = {}
        self._last_audit_id = None

    def parse(self, raw_data, log_type: str = "auditd") -> UnifiedEvent:
        """
        统一解析入口
        :param raw_data: 原始日志数据 (Auditd为字符串行, Windows为字典)
        :param log_type: 日志类型 ("auditd" 或 "windows")
        :return: UnifiedEvent 对象 或 None (如果正在缓冲)
        """
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
        """
        解析 Windows Event Log (JSON格式)
        支持事件: 4624(登录), 4688(进程创建), 4663(对象访问)
        """
        event = UnifiedEvent()
        event.raw = win_log
        event.event.dataset = "windows"
        
        # 1. 基础字段提取
        # 尝试获取 EventID (支持 top-level 或 System.EventID)
        event_id = win_log.get("EventID")
        if event_id is None and "System" in win_log:
            event_id = win_log["System"].get("EventID")
            
        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            event_id = 0
            
        # event.event.id = str(event_id)  <-- 移除此行以保留自动生成的 UUID
        event.host.os.family = "windows"
        
        # 处理时间戳
        time_created = win_log.get("TimeCreated")
        if time_created is None and "System" in win_log:
            time_created = win_log["System"].get("TimeCreated")
            if isinstance(time_created, dict):
                time_created = time_created.get("SystemTime")
        
        if time_created:
            event.timestamp = str(time_created)

        # 获取 EventData
        data = win_log.get("EventData", win_log)
        
        # 2. 根据 EventID 映射逻辑
        if event_id == 4624:
            # 登录成功
            event.event.category = "authentication"
            event.event.action = "login"
            event.event.outcome = "success"
            event.user.name = data.get("TargetUserName", "")
            event.source.ip = data.get("IpAddress", "")
            
        elif event_id == 4688:
            # 进程创建
            event.event.category = "process"
            event.event.action = "process_created"
            event.event.type = "start"
            
            event.process.executable = data.get("NewProcessName", "")
            # 从完整路径提取文件名
            if event.process.executable:
                event.process.name = event.process.executable.split("\\")[-1]
            else:
                event.process.name = "unknown"
                
            event.process.command_line = data.get("CommandLine", "")
            
            try:
                event.process.pid = int(data.get("ProcessId", 0), 16) if isinstance(data.get("ProcessId"), str) and data.get("ProcessId").startswith("0x") else int(data.get("ProcessId", 0))
                event.process.parent.pid = int(data.get("ParentProcessId", 0), 16) if isinstance(data.get("ParentProcessId"), str) and data.get("ParentProcessId").startswith("0x") else int(data.get("ParentProcessId", 0))
            except ValueError:
                pass

        elif event_id == 4663:
            # 对象访问 (文件等)
            event.event.category = "file"
            event.event.action = "access"
            event.file.path = data.get("ObjectName", "")
            if event.file.path:
                event.file.name = event.file.path.split("\\")[-1]
                
        else:
            event.event.category = "host"
            event.event.action = "unknown_windows_event"

        return event

    def parse_auditd_line(self, line: str) -> dict:
        """
        聚合 Auditd 日志行
        :return: 如果触发刷新，返回完整的事件字典；否则返回 None
        """
        if not line or not line.strip():
            return None
            
        # 1. 解析单行基础信息
        parsed_line = self._parse_raw_line(line)
        if not parsed_line:
            return None
            
        current_id = parsed_line['audit_id']
        flushed_data = None
        
        # 2. 刷新策略: 检测到新 ID 时刷新旧 ID
        if self._last_audit_id and current_id != self._last_audit_id:
            if self._last_audit_id in self._audit_buffer:
                flushed_data = self._audit_buffer.pop(self._last_audit_id)
        
        self._last_audit_id = current_id
        
        # 3. 存入缓冲区
        if current_id not in self._audit_buffer:
            self._audit_buffer[current_id] = {
                "timestamp": parsed_line['timestamp'],
                "audit_id": current_id,
                "records": []
            }
        
        self._audit_buffer[current_id]["records"].append(parsed_line['data'])
        
        # 4. 刷新策略: 检测到 EOE (End of Event)
        # 注意: EOE 记录本身也包含在该事件中
        if parsed_line['data'].get('type') == 'EOE':
            flushed_data = self._audit_buffer.pop(current_id)
            # 如果刚刚因为换ID已经产生了一个 flushed_data，这里可能会覆盖或者丢失
            # 但理论上 EOE 应该是当前 ID 的结尾。
            # 简单起见，如果同时发生 (换ID且当前行是EOE - 不太可能)，优先返回之前的 flush?
            # 实际上 EOE 意味着 current_id 结束了。
            # 如果我们在 step 2 已经 flush 了 old_id，我们现在又 flush current_id (EOE)，
            # 那么我们有两个事件要返回。目前的接口只能返回一个。
            # 这是一个边缘情况。暂且假设 EOE 和 换ID 不会同时导致冲突 (因为 EOE 通常是当前 ID 的最后一行)。
            # 如果 step 2 flush 了 old_id，我们应该优先返回 old_id 的数据。
            # 当前的 EOE 会导致 current_id 也准备好，但我们只能下一次调用返回? 
            # 这里的 buffer 机制在单次调用返回单个结果的限制下，"Flush on new ID" 应该优先。
            pass

        return flushed_data

    def _parse_raw_line(self, line: str) -> dict:
        """
        [Helper] 将原始日志行解析为基础字典
        """
        # 1. 提取 msg=audit(时间戳:ID)
        timestamp_match = re.search(r'msg=audit\((\d+\.\d+):(\d+)\):', line)
        if not timestamp_match:
            return None
            
        ts_epoch = float(timestamp_match.group(1))
        event_id = timestamp_match.group(2)
        
        # 2. 提取 key=value
        kv_pairs = {}
        tokens = line.split()
        for token in tokens:
            if "=" in token:
                try:
                    k, v = token.split("=", 1)
                    kv_pairs[k] = v.strip('"')
                except:
                    continue
        
        return {
            "timestamp": ts_epoch,
            "audit_id": event_id,
            "data": kv_pairs
        }

    def to_unified_event(self, raw_data: dict) -> UnifiedEvent:
        """将聚合后的数据转换为 UnifiedEvent 对象"""
        if not raw_data:
            return None

        records = raw_data.get("records", [])
        if not records:
            # 兼容旧格式 (如果 raw_data 是单行解析结果)
            if "data" in raw_data:
                records = [raw_data["data"]]
            else:
                return None
        
        # 寻找关键记录
        syscall_record = next((r for r in records if r.get("type") == "SYSCALL"), {})
        execve_record = next((r for r in records if r.get("type") == "EXECVE"), {})
        cwd_record = next((r for r in records if r.get("type") == "CWD"), {})
        
        # 寻找主要记录用于通用字段 (优先 SYSCALL，否则取第一个)
        main_record = syscall_record if syscall_record else records[0]
        audit_type = main_record.get("type", "UNKNOWN")
        
        # 创建基础事件对象
        event = UnifiedEvent()
        event.raw = raw_data # 保存完整的聚合数据
        event.message = str(raw_data)
        
        # 设置时间
        dt = datetime.fromtimestamp(raw_data["timestamp"])
        event.timestamp = dt.isoformat() + "Z"
        
        # === 字段映射 ===
        
        # 1. 进程相关 (SYSCALL / EXECVE)
        if audit_type in ["SYSCALL", "EXECVE", "PROCTITLE"] or syscall_record:
            event.event.category = "process"
            event.event.type = "start"
            event.event.action = "process_started"
            
            # 基础进程信息 (优先从 SYSCALL 取)
            event.process.pid = int(main_record.get("pid", 0))
            event.process.name = main_record.get("comm", "unknown")
            event.process.executable = main_record.get("exe", "")
            
            # 命令行重组 (从 EXECVE args)
            if execve_record:
                # 提取所有 a0, a1, a2... 参数
                args = []
                idx = 0
                while f"a{idx}" in execve_record:
                    args.append(execve_record[f"a{idx}"])
                    idx += 1
                if args:
                    event.process.command_line = " ".join(args)
            
            # 如果没有 EXECVE，尝试从 PROCTITLE 或 cmdline 获取
            if not event.process.command_line:
                 event.process.command_line = main_record.get("proctitle", main_record.get("cmdline", ""))

            # CWD
            if cwd_record:
                event.process.cwd = cwd_record.get("cwd", "")

            # 用户信息
            event.user.id = main_record.get("uid", "")
            event.user.name = main_record.get("auid", "")
            
            # 文件路径 (从 PATH 记录)
            # 寻找 nametype=NORMAL 的记录
            path_record = next((r for r in records if r.get("type") == "PATH" and r.get("nametype") == "NORMAL"), None)
            if path_record:
                event.file.path = path_record.get("name", "")
                if event.file.path:
                    event.file.name = event.file.path.split("/")[-1]
                    event.event.category = "file" # 如果有文件操作，也可以标记为 file? 或者是混合
                    # 根据 SYSCALL 类型决定 event.action? 
                    # 比如 syscall=2 (open) -> file access. 但为了简化，暂保持 process_started 或根据 syscall 映射
        
        # 2. 登录事件
        elif audit_type in ["USER_LOGIN", "USER_AUTH"]:
            event.event.category = "authentication"
            event.event.action = "login"
            event.user.id = main_record.get("id", "")
            event.source.ip = main_record.get("addr", "localhost")
            
        else:
            event.event.category = "host"
            event.event.action = audit_type

        event.event.dataset = "auditd"
        
        # 填充主机信息
        import platform
        import socket
        try:
            event.host.hostname = socket.gethostname()
            event.host.name = event.host.hostname
            event.host.os.family = platform.system().lower()
            event.host.os.name = platform.system()
            event.host.os.version = platform.release()
            event.host.ip = [socket.gethostbyname(event.host.hostname)]
        except:
            pass
            
        return event

def write_event(event: UnifiedEvent, output_file: str = "output.json") -> bool:
    """
    实现 write_event() 接口
    将统一事件写入文件 (模拟发送到消息队列或存储)
    """
    import json
    try:
        # 转换为字典 (ES 格式)
        data = event.to_dict()
        
        # 写入文件 (追加模式)
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")
            
        return True
    except Exception as e:
        print(f"[!] write_event failed: {e}")
        return False
