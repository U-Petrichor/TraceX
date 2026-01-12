import re
from datetime import datetime
from collector.common.schema import UnifiedEvent

class HostLogParser:
    """主机日志解析器"""
    
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