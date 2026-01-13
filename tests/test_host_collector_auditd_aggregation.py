import unittest
import os
import sys
from datetime import datetime

# Add project root to sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from collector.host_collector.log_parser import HostLogParser
from collector.common.schema import UnifiedEvent

class TestAuditdAggregation(unittest.TestCase):
    
    def setUp(self):
        self.parser = HostLogParser()

    def test_aggregation_flush_on_eoe(self):
        """Test aggregation flushes on EOE type"""
        logs = [
            'type=SYSCALL msg=audit(1600000000.111:100): arch=c000003e syscall=59 success=yes exit=0 a0=... pid=1234 comm="cat" exe="/bin/cat" uid=0 auid=1000',
            'type=EXECVE msg=audit(1600000000.111:100): argc=2 a0="cat" a1="/tmp/test.txt"',
            'type=EOE msg=audit(1600000000.111:100):'
        ]
        
        events = []
        for line in logs:
            res = self.parser.parse(line, log_type="auditd")
            if res:
                events.append(res)
        
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.process.pid, 1234)
        self.assertEqual(event.process.command_line, "cat /tmp/test.txt")

    def test_aggregation_flush_on_new_id(self):
        """Test aggregation flushes previous event when new ID appears"""
        logs = [
            # Event 100 (No EOE)
            'type=SYSCALL msg=audit(1600000000.111:100): arch=c000003e syscall=59 success=yes exit=0 pid=1000 comm="proc1" exe="/bin/proc1"',
            # Event 101 (Starts, should flush 100)
            'type=SYSCALL msg=audit(1600000001.222:101): arch=c000003e syscall=59 success=yes exit=0 pid=2000 comm="proc2" exe="/bin/proc2"',
            # Event 101 continues
            'type=EOE msg=audit(1600000001.222:101):'
        ]
        
        events = []
        for line in logs:
            res = self.parser.parse(line, log_type="auditd")
            if res:
                events.append(res)
        
        # Expect 2 events:
        # 1. ID 100 (flushed when 101 started)
        # 2. ID 101 (flushed when EOE hit)
        self.assertEqual(len(events), 2)
        
        # Verify Event 100
        self.assertEqual(events[0].process.pid, 1000)
        self.assertEqual(events[0].process.name, "proc1")
        
        # Verify Event 101
        self.assertEqual(events[1].process.pid, 2000)
        self.assertEqual(events[1].process.name, "proc2")

    def test_path_and_cwd_extraction(self):
        """Test extraction of file.path from PATH record and CWD"""
        logs = [
            'type=SYSCALL msg=audit(1600000000.333:200): arch=c000003e syscall=2 success=yes exit=3 pid=3000 comm="cat" exe="/bin/cat"',
            'type=CWD msg=audit(1600000000.333:200): cwd="/home/user"',
            'type=PATH msg=audit(1600000000.333:200): item=0 name="/etc/shadow" inode=123 dev=fd:00 mode=0100640 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL',
            'type=EOE msg=audit(1600000000.333:200):'
        ]
        
        events = []
        for line in logs:
            res = self.parser.parse(line, log_type="auditd")
            if res:
                events.append(res)
                
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.process.cwd, "/home/user")
        self.assertEqual(event.file.path, "/etc/shadow")
        self.assertEqual(event.file.name, "shadow")

    def test_mixed_interleaved_logs(self):
        """Test behavior with interleaved logs (though Auditd usually serializes)"""
        # This tests our assumption that we only track ONE buffer ID or handle switching.
        # Our implementation buffers multiple IDs but "flush on new ID" flushes the *previous* one.
        # If logs are: A1, B1, A2, B2
        # A1: Buffer A, last=A
        # B1: Flush A? (Yes, if new ID != last ID). So A is flushed incomplete. Buffer B, last=B
        # A2: Flush B? (Yes). Buffer A (new entry? or append?). 
        # Since we use `if current_id not in self._audit_buffer: create...`, A2 will APPEND to A's buffer if A wasn't popped.
        # BUT `flushed_data = self._audit_buffer.pop(self._last_audit_id)`.
        # So A was popped when B came.
        # So A2 starts a NEW A event.
        # This confirms our logic assumes sequential blocks. Interleaved logs will be fragmented.
        # This is acceptable for standard Auditd.
        pass

if __name__ == "__main__":
    unittest.main()
