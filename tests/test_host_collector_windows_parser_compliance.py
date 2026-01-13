import unittest
import sys
import os
import json

# 确保能导入 collector 模块
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.append(project_root)

from collector.host_collector.log_parser import HostLogParser
from collector.common.schema import UnifiedEvent

class TestWindowsParserCompliance(unittest.TestCase):
    
    def setUp(self):
        self.parser = HostLogParser()
        self.sample_logs = [
            # 4624 登录事件 (扁平结构)
            {
                "EventID": 4624,
                "TimeCreated": "2023-10-27T10:00:00.000000Z",
                "EventData": {
                    "TargetUserName": "Administrator",
                    "IpAddress": "192.168.1.100"
                }
            },
            # 4688 进程创建
            {
                "EventID": 4688,
                "TimeCreated": "2023-10-27T10:05:00.000000Z",
                "EventData": {
                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c whoami",
                    "ProcessId": "0x1234",
                    "ParentProcessId": "0x456"
                }
            },
            # 4663 对象访问
            {
                "EventID": 4663,
                "TimeCreated": "2023-10-27T10:10:00.000000Z",
                "EventData": {
                    "ObjectName": "C:\\Secret\\passwords.txt",
                    "ProcessName": "C:\\Windows\\notepad.exe"
                }
            }
        ]

    def test_parse_windows_login_4624(self):
        """测试 Windows 登录事件 (EventID 4624)"""
        raw = self.sample_logs[0]
        event = self.parser.parse(raw, log_type="windows")
        
        self.assertIsInstance(event, UnifiedEvent)
        self.assertEqual(event.event.category, "authentication")
        self.assertEqual(event.event.action, "login")
        self.assertEqual(event.user.name, "Administrator")
        self.assertEqual(event.source.ip, "192.168.1.100")
        # 验证 raw 中的 EventID，而不是 event.id (UUID)
        self.assertEqual(event.raw['EventID'], 4624)
        self.assertEqual(event.host.os.family, "windows")

    def test_parse_windows_process_4688(self):
        """测试 Windows 进程创建事件 (EventID 4688)"""
        raw = self.sample_logs[1]
        event = self.parser.parse(raw, log_type="windows")
        
        self.assertEqual(event.event.category, "process")
        self.assertEqual(event.process.executable, "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(event.process.name, "cmd.exe")
        self.assertEqual(event.process.command_line, "cmd.exe /c whoami")
        # 验证十六进制 PID 转换
        self.assertEqual(event.process.pid, 4660) # 0x1234
        self.assertEqual(event.process.parent.pid, 1110) # 0x456

    def test_parse_windows_file_4663(self):
        """测试 Windows 文件访问事件 (EventID 4663)"""
        raw = self.sample_logs[2]
        event = self.parser.parse(raw, log_type="windows")
        
        self.assertEqual(event.event.category, "file")
        self.assertEqual(event.file.path, "C:\\Secret\\passwords.txt")
        self.assertEqual(event.file.name, "passwords.txt")

    def test_parse_auditd_compatibility(self):
        """测试 Auditd 解析兼容性 (确保未破坏原有功能)"""
        audit_line = 'type=EXECVE msg=audit(1610000000.123:100): argc=2 a0="cat" a1="/etc/passwd" pid=1234 comm="cat" exe="/bin/cat" uid=0 auid=1000'
        event = self.parser.parse(audit_line, log_type="auditd")
        
        self.assertEqual(event.event.dataset, "auditd")
        self.assertEqual(event.process.pid, 1234)
        self.assertEqual(event.process.name, "cat")

if __name__ == '__main__':
    unittest.main()
