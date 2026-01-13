import re
from datetime import datetime
from collector.common.schema import UnifiedEvent

class HostLogParser:
    """主机日志解析器"""
    
    def parse(self, raw_data, log_type: str = "auditd") -> UnifiedEvent:
        """
        统一解析入口
        :param raw_data: 原始日志数据 (Auditd为字符串行, Windows为字典)
        :param log_type: 日志类型 ("auditd" 或 "windows")
        :return: UnifiedEvent 对象
        """
        if log_type == "auditd":
            parsed = self.parse_auditd_line(raw_data)
            return self.to_unified_event(parsed)
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
            
        # event.event.id = str(event_id)  <-- Removed to preserve UUID
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
        将 Auditd 的原始日志行解析为字典
        例如: type=SYSCALL msg=audit(1610000.123:99): arch=...
        """
        if not line or not line.strip():
            return None
            
        # 简单的键值对解析
        # 1. 提取 msg=audit(时间戳:ID)
        timestamp_match = re.search(r'msg=audit\((\d+\.\d+):(\d+)\):', line)
        if not timestamp_match:
            return None
            
        ts_epoch = float(timestamp_match.group(1))
        event_id = timestamp_match.group(2)
        
        # 2. 提取剩余的 key=value
        # 这是一个简化的正则，处理 key=value 或 key="value"
        kv_pairs = {}
        # 将日志中的 key=value 提取出来
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
        """将解析后的字典转换为 UnifiedEvent 对象"""
        if not raw_data:
            return None

        data = raw_data["data"]
        audit_type = data.get("type", "UNKNOWN")
        
        # 创建基础事件对象
        event = UnifiedEvent()
        event.raw = data
        event.message = str(data)
        
        # 设置时间
        dt = datetime.fromtimestamp(raw_data["timestamp"])
        event.timestamp = dt.isoformat() + "Z"
        
        # === 根据类型填充字段 ===
        
        # 1. 进程执行事件 (EXECVE / SYSCALL)
        if audit_type in ["EXECVE", "SYSCALL", "PROCTITLE"]:
            event.event.category = "process"
            event.event.type = "start"
            event.event.action = "process_started"
            
            # 填充进程信息
            event.process.pid = int(data.get("pid", 0))
            event.process.name = data.get("comm", "unknown") # comm 是命令名
            event.process.executable = data.get("exe", "")
            
            # 尝试获取命令行参数 (PROCTITLE通常包含完整命令)
            event.process.command_line = data.get("proctitle", data.get("cmdline", ""))
            
            # 填充用户信息
            event.user.id = data.get("uid", "")
            event.user.name = data.get("auid", "") # auid 是审计用户ID
            
        # 2. 登录事件
        elif audit_type in ["USER_LOGIN", "USER_AUTH"]:
            event.event.category = "authentication"
            event.event.action = "login"
            event.user.id = data.get("id", "")
            event.source.ip = data.get("addr", "localhost")
            
        else:
            event.event.category = "host"
            event.event.action = audit_type

        event.event.dataset = "auditd"
        
        # 填充主机信息 (尝试获取本机信息)
        import platform
        import socket
        
        try:
            event.host.hostname = socket.gethostname()
            event.host.name = event.host.hostname
            event.host.os.family = platform.system().lower()
            event.host.os.name = platform.system()
            event.host.os.version = platform.release()
            # event.host.ip 通常需要更复杂的网络获取逻辑，这里暂留空或获取本地IP
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
