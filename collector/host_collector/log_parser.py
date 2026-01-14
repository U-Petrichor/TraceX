import re
from datetime import datetime
from collector.common.schema import UnifiedEvent

class HostLogParser:
    def __init__(self):
        self._audit_buffer = {}
        self._last_audit_id = None
        self._session_cache = {}

    def parse(self, raw_data, log_type: str = "auditd") -> UnifiedEvent:
        if log_type == "auditd":
            aggregated_data = self.parse_auditd_line(raw_data)
            return self.to_unified_event(aggregated_data) if aggregated_data else None
        return None

    def parse_auditd_line(self, line: str) -> dict:
        parsed_line = self._parse_raw_line(line)
        if not parsed_line: return None
        current_id = parsed_line['audit_id']
        flushed_data = None
        if self._last_audit_id and current_id != self._last_audit_id:
            flushed_data = self._audit_buffer.pop(self._last_audit_id, None)
        self._last_audit_id = current_id
        if current_id not in self._audit_buffer:
            self._audit_buffer[current_id] = {"timestamp": parsed_line['timestamp'], "records": []}
        self._audit_buffer[current_id]["records"].append(parsed_line['data'])
        if parsed_line['data'].get('type') == 'EOE' and flushed_data is None:
            flushed_data = self._audit_buffer.pop(current_id, None)
        return flushed_data

    def _parse_raw_line(self, line: str) -> dict:
        m = re.search(r'msg=audit\((\d+\.\d+):(\d+)\):', line)
        if not m: return None
        kv = {t.split("=")[0]: t.split("=")[1].strip('"\'') for t in line.split() if "=" in t}
        return {"timestamp": float(m.group(1)), "audit_id": m.group(2), "data": kv}

    def to_unified_event(self, raw_data: dict) -> UnifiedEvent:
        records = raw_data.get("records", [])
        syscall = next((r for r in records if r.get("type") == "SYSCALL"), {})
        execve = next((r for r in records if r.get("type") == "EXECVE"), {})
        event = UnifiedEvent()
        event.raw = raw_data
        event.timestamp = datetime.utcfromtimestamp(raw_data["timestamp"]).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        
        if syscall:
            event.event.category = "process"
            event.event.action = "process_started"
            event.process.pid = int(syscall.get("pid", 0))
            # [CRITICAL FIX] 提取 PPID
            ppid = syscall.get("ppid")
            if ppid: event.process.parent.pid = int(ppid)
            
            event.process.executable = syscall.get("exe", "")
            event.process.name = syscall.get("comm", "unknown")
            if execve:
                args = [execve[f"a{i}"] for i in range(10) if f"a{i}" in execve]
                event.process.command_line = " ".join(args)
            if not event.process.command_line: event.process.command_line = syscall.get("proctitle", "")
        
        import socket
        event.host.name = socket.gethostname()
        return event
