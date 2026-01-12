# collector/host_collector/log_parser.py

from datetime import datetime
import uuid

class HostLogParser:
    """主机日志解析器"""
    
    def parse_auditd_log(self, raw_log: dict) -> dict:
        """
        将 Auditd 日志转换为统一格式
        
        Args:
            raw_log: Auditd 原始日志
            
        Returns:
            符合 UNIFIED_EVENT_SCHEMA 的字典
        """
        return {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event": {
                "id": str(uuid.uuid4()),
                "category": self._map_category(raw_log.get("type")),
                "type": "info",
                "action": raw_log.get("type", "unknown"),
                "outcome": "success" if raw_log.get("success") == "yes" else "failure",
                "severity": 5,
                "dataset": "auditd"
            },
            "source": {
                "ip": raw_log.get("addr", ""),
            },
            "host": {
                "name": raw_log.get("hostname", ""),
            },
            "process": {
                "pid": int(raw_log.get("pid", 0)),
                "name": raw_log.get("comm", ""),
                "executable": raw_log.get("exe", ""),
                "command_line": raw_log.get("proctitle", ""),
                "user": {
                    "name": raw_log.get("auid_user", ""),
                    "id": raw_log.get("auid", "")
                }
            },
            "file": {
                "path": raw_log.get("name", ""),
            },
            "user": {
                "name": raw_log.get("auid_user", ""),
                "id": raw_log.get("auid", "")
            },
            "message": str(raw_log),
            "raw": raw_log
        }
    
    def _map_category(self, audit_type: str) -> str:
        """映射 Auditd 类型到 ECS 类别"""
        mapping = {
            "SYSCALL": "process",
            "EXECVE": "process",
            "PATH": "file",
            "USER_LOGIN": "authentication",
            "USER_AUTH": "authentication",
            "SOCKADDR": "network",
        }
        return mapping.get(audit_type, "host")