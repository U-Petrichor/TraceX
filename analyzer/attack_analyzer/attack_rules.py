

ATTACK_RULES = [
    # ==========================================
    # 1. Initial Access (初始访问) - TA0001
    # ==========================================
    {
        "id": "IA_001_SSH_BRUTE",
        "name": "SSH 暴力破解",
        "level": "medium",
        "tags": ["attack.initial_access", "attack.t1110"],
        "conditions": {
            "event.category": "authentication",
            "event.outcome": "failure",
            "network.application": "ssh"
        }
    },
    {
        "id": "IA_002_SQL_INJECTION",
        "name": "Web SQL 注入攻击",
        "level": "high",
        "tags": ["attack.initial_access", "attack.t1190"],
        "conditions": {
            "network.protocol": "http",
            "url.query": ["*union select*", "*waitfor delay*", "*1=1*", "*sleep(*", "*information_schema*", "*xp_cmdshell*"]
        }
    },
    {
        "id": "IA_003_CMD_INJECTION",
        "name": "Web 命令注入/RCE",
        "level": "critical",
        "tags": ["attack.initial_access", "attack.t1190"],
        "conditions": {
            "network.protocol": "http",
            "url.path": ["*||*", "*; *", "*| *", "*$(*", "*`*", "*eval(*", "*system(*"]
        }
    },
    {
        "id": "IA_004_WEBSHELL_UPLOAD",
        "name": "WebShell 文件上传尝试",
        "level": "critical",
        "tags": ["attack.initial_access", "attack.t1190"],
        "conditions": {
            "network.protocol": "http",
            "http.method": "POST",
            "url.path": ["*.php", "*.jsp", "*.asp", "*.aspx", "*.jspx"],
            "network.bytes": ">1000"
        }
    },
    {
        "id": "IA_005_HONEYPOT_LOGIN",
        "name": "蜜罐：非法登录尝试",
        "level": "low",
        "tags": ["attack.initial_access", "attack.t1078"],
        "conditions": {
            "event.dataset": ["cowrie"],
            "event.type": "login",
            "event.outcome": ["failure", "success"]
        }
    },
    {
        "id": "IA_006_LOGON_EVENT",
        "name": "用户成功登录会话",
        "level": "informational",
        "tags": ["attack.initial_access", "attack.t1078"],
        "conditions": {
            "event.category": "authentication",
            "event.action": ["logon", "login"],
            "event.outcome": "success"
        }
    },
    # ==========================================
    # 2. Execution (执行) - TA0002
    # ==========================================
    {
        "id": "EX_001_SUSPICIOUS_SHELL",
        "name": "异常 Shell 启动",
        "level": "medium",
        "tags": ["attack.execution", "attack.t1059"],
        "conditions": {
            "event.category": "process",
            "process.name": ["bash", "sh", "dash", "zsh", "powershell.exe", "cmd.exe"],
            "process.parent.name": ["httpd", "nginx", "apache2", "tomcat", "java", "w3wp.exe"]
        }
    },
    {
        "id": "EX_002_REVERSE_SHELL",
        "name": "反弹 Shell 特征",
        "level": "critical",
        "tags": ["attack.execution", "attack.t1059"],
        "conditions": {
            "event.category": "process",
            "process.command_line": ["*bash -i*", "*nc -e*", "*0>&1*", "*dev/tcp/*", "*mkfifo*", "*socat*"]
        }
    },
    {
        "id": "EX_003_ENCODED_CMD",
        "name": "Base64 编码命令执行",
        "level": "medium",
        "tags": ["attack.execution", "attack.t1027"],
        "conditions": {
            "event.category": "process",
            "process.command_line": ["*base64 -d*", "*openssl enc -d*", "*certutil -decode*", "*powershell -enc*"]
        }
    },
    {
        "id": "EX_004_HONEYPOT_CMD",
        "name": "蜜罐：恶意指令执行",
        "level": "medium",
        "tags": ["attack.execution", "attack.t1059"],
        "conditions": {
            "event.dataset": ["cowrie"],
            "event.action": "command"
        }
    },
     {
        "id": "EX_005_DATA_UPLOAD",
        "name": "数据外传 (FTP/Curl)",
        "level": "high",
        "tags": ["attack.exfiltration", "attack.t1048"],
        "conditions": {
            "process.name": ["curl", "wget", "ftp", "nc", "scp"],
            "process.command_line": ["*-T *", "*--upload-file*", "*put *"]
        }
    },
    {
        "id": "EX_006_HONEYPOT_DL",
        "name": "蜜罐：工具下载事件",
        "level": "medium",
        "tags": ["attack.command_and_control", "attack.t1105"],
        "conditions": {
            "event.dataset": ["cowrie"],
            "event.action": ["download", "file_download"]
        }
    },

    {
        "id": "EX_007_MEM_INJECTION",
        "name": "内存注入/反射加载检测",
        "level": "critical",
        "tags": ["attack.execution", "attack.t1055"],
        "conditions": {
            "event.category": "process",
            "event.action": "CreateRemoteThread", # 模拟内核层系统调用捕获
            "process.target.name": ["lsass.exe", "svchost.exe"]
        }
    },
    {
        "id": "EX_008_REFLECTIVE_LOAD",
        "name": "反射性 DLL 加载检测",
        "level": "critical",
        "tags": ["attack.execution", "attack.t1620"],
        "conditions": {
            "event.category": "process",
            "process.thread.start_address": "unknown_module", # 内存中无对应文件
            "process.command_line": ["*ModuleLoad*", "*ThreadCreate*"]
        }
    },
    {
        "id": "EX_009_PROCESS_TREE_ANOMALY",
        "name": "异常父子进程链",
        "level": "high",
        "tags": ["attack.execution", "attack.t1059"],
        "conditions": {
            "event.category": "process",
            "process.parent.name": ["notepad.exe", "calc.exe", "mspaint.exe"], # 办公软件启动了 Shell
            "process.name": ["cmd.exe", "powershell.exe", "bash"]
        }
    },
    {
        "id": "EX_010_MEMFD_EXECUTION",
        "name": "内存文件执行 (无文件攻击特征)",
        "level": "critical",
        "tags": ["attack.execution", "attack.t1620"],
        "conditions": {
            "event.category": "process",
            "process.executable": ["/memfd:*", "/proc/self/fd/*"]
    }
    },
    # ==========================================
    # 3. Persistence (持久化) - TA0003
    # ==========================================
    {
        "id": "PE_001_CRON_MOD",
        "name": "Cron 计划任务篡改",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1053"],
        "conditions": {
            "event.category": "file",
            "file.path": ["/etc/cron*", "/var/spool/cron/*"],
            "event.action": ["write", "change"]
        }
    },
    {
        "id": "PE_002_SSH_AUTH_KEYS",
        "name": "SSH 后门公钥植入",
        "level": "critical",
        "tags": ["attack.persistence", "attack.t1098"],
        "conditions": {
            "event.category": "file",
            "file.name": "authorized_keys",
            "event.action": "write"
        }
    },
    {
        "id": "PE_003_RC_LOCAL",
        "name": "启动项 rc.local 篡改",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1547"],
        "conditions": {
            "file.path": ["/etc/rc.local", "/etc/init.d/*"],
            "event.action": ["write", "change"]
        }
    },
    {
        "id": "PE_004_USER_CREATE",
        "name": "可疑账户创建",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1136"],
        "conditions": {
            "event.category": "process",
            "process.name": "useradd",
            "process.command_line": ["*useradd*", "*adduser*"]
        }
    },
    {
        "id": "PE_005_REG_PERSISTENCE",
        "name": "Windows 注册表持久化篡改",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1547"],
        "conditions": {
            "event.category": "registry",
            "registry.path": ["*\\CurrentVersion\\Run*", "*\\CurrentVersion\\RunOnce*"],
            "event.action": ["added", "modified"]
        }
    },
    {
        "id": "PE_006_SERVICE_CREATION",
        "name": "可疑服务创建",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1543"],
        "conditions": {
            "event.category": "process",
            "process.name": "sc.exe",
            "process.command_line": ["*create*", "*config*"]
        }
    },
    # ==========================================
    # 4. Privilege Escalation (权限提升) - TA0004
    # ==========================================
    {
        "id": "PR_001_POWERSHELL_ABUSE",
        "name": "PowerShell 异常执行",
        "level": "high",
        "tags": ["attack.execution", "attack.t1059.001"],
        "conditions": {
            "process.name": ["powershell.exe", "pwsh.exe"],
            "process.command_line": ["*-enc*", "*-EncodedCommand*", "*IEX*", "*DownloadString*"]
        },
        # 新增：排除合法的运维路径或特定用户，防止误报
        "not_conditions": {
            "user.name": ["system_admin", "it_monitor"],
            "process.executable": ["C:\\Windows\\System32\\Helper\\*"]
        }
    },
    {
        "id": "PR_002_KERNEL_EXPLOIT",
        "name": "内核漏洞利用尝试 (DirtyCow等)",
        "level": "critical",
        "tags": ["attack.privilege_escalation", "attack.t1068"],
        "conditions": {
            "process.command_line": ["*dirty*", "*cow*", "*pwn*", "*exploit*"]
        }
    },
    # ==========================================
    # 5. Defense Evasion (防御规避) - TA0005
    # ==========================================
    {
        "id": "DE_001_LOG_WIPE",
        "name": "日志清除行为",
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1070"],
        "conditions": {
            "process.command_line": ["*rm *.log", "*echo > *.log", "*history -c*", "*unset HISTFILE*"]
        }
    },
    {
        "id": "DE_002_FILE_ATTR",
        "name": "文件锁定 (chattr +i)",
        "level": "medium",
        "tags": ["attack.defense_evasion", "attack.t1222"],
        "conditions": {
            "process.name": "chattr",
            "process.command_line": ["*+i*", "*-i*"]
        }
    },
    {
        "id": "DE_003_TIMESTOMP",
        "name": "时间戳伪造 (touch)",
        "level": "medium",
        "tags": ["attack.defense_evasion", "attack.t1070"],
        "conditions": {
            "process.name": "touch",
            "process.command_line": ["*-r*", "*-t*"]
        }
    },
    
    # ==========================================
    # 6. Credential Access (凭证获取) - TA0006
    # ==========================================
    {
        "id": "CA_001_MIMIKATZ",
        "name": "Mimikatz 工具使用",
        "level": "critical",
        "tags": ["attack.credential_access", "attack.t1003"],
        "conditions": {
            "process.command_line": ["*mimikatz*", "*sekurlsa*", "*logonpasswords*"]
        }
    },
    {
        "id": "CA_002_SHADOW_ACCESS",
        "name": "访问 Shadow 文件",
        "level": "high",
        "tags": ["attack.credential_access", "attack.t1003"],
        "conditions": {
            "event.category": "file",
            "file.path": "/etc/shadow",
            "event.action": "read"
        }
    },

    # ==========================================
    # 7. Discovery (发现/侦查) - TA0007
    # ==========================================
    {
        "id": "DI_001_NET_SCAN",
        "name": "内网扫描 (Nmap/Ping)",
        "level": "low",
        "tags": ["attack.discovery", "attack.t1046"],
        "conditions": {
            "process.name": ["nmap", "masscan", "ping", "fping"],
            "process.command_line": ["*-sS*", "*-sT*", "*-p-*"]
        }
    },
    {
        "id": "DI_002_PROCESS_DISCO",
        "name": "进程/环境侦查",
        "level": "low",
        "tags": ["attack.discovery", "attack.t1057"],
        "conditions": {
            "process.name": ["ps", "top", "htop", "tasklist", "whoami"],
            "process.command_line": ["*aux*", "*-ef*", "*whoami*"]
        }
    },

    # ==========================================
    # 8. Lateral Movement (横向移动) - TA0008
    # ==========================================
    {
        "id": "LM_001_SSH_LATERAL",
        "name": "SSH 横向连接",
        "level": "high",
        "tags": ["attack.lateral_movement", "attack.t1021"],
        "conditions": {
            "process.name": "ssh",
            "process.command_line": ["*ssh *", "*scp *"]
        }
    },
    {
        "id": "LM_002_SMB_EXEC",
        "name": "SMB 远程执行 (Psexec)",
        "level": "high",
        "tags": ["attack.lateral_movement", "attack.t1021"],
        "conditions": {
            "network.protocol": "smb",
            "network.application": ["*psexec*", "*smbexec*"]
        }
    },

    # ==========================================
    # 9. Collection & Exfiltration (收集与窃取)
    # ==========================================
    {
        "id": "CL_001_ARCHIVE",
        "name": "敏感数据打包",
        "level": "medium",
        "tags": ["attack.collection", "attack.t1560"],
        "conditions": {
            "process.name": ["tar", "zip", "rar", "7z"],
            "process.command_line": ["*-c*", "*cvf*", "*zcf*"]
        }
    },
   
    # ==========================================
    # 10. Impact (危害/破坏) - TA0040
    # ==========================================
    {
        "id": "IM_001_DATA_DESTRUCTION",
        "name": "数据删除/破坏",
        "level": "critical",
        "tags": ["attack.impact", "attack.t1485"],
        "conditions": {
            "process.command_line": ["*rm -rf /*", "*rm -rf /boot*", "*mkfs*"]
        }
    },
    {
        "id": "IM_002_RANSOMWARE",
        "name": "勒索加密行为 (批量重命名)",
        "level": "critical",
        "tags": ["attack.impact", "attack.t1486"],
        "conditions": {
            "process.name": ["mv", "rename"],
            "process.command_line": ["*.enc", "*.lock", "*.crypt"]
        }
    },

    # ==========================================
    # 11. Command and Control (C2) - TA0011
    # ==========================================
    {
        "id": "C2_001_DNS_TUNNEL",
        "name": "DNS 隧道通信",
        "level": "high",
        "tags": ["attack.command_and_control", "attack.t1071"],
        "conditions": {
            "network.protocol": "dns",
            "message": "*High Entropy*",
            "network.bytes": ">5000"
        }
    },
    {
        "id": "C2_002_FAST_FLUX",
        "name": "Fast-Flux 域名查询",
        "level": "medium",
        "tags": ["attack.command_and_control", "attack.t1071"],
        "conditions": {
            "network.protocol": "dns",
            "dns.question.name": "*",
            "dns.answers.ip": ">5"  # 同一域名解析到多个 IP
        }
    },
    {
        "id": "C2_003_ICMP_TUNNEL",
        "name": "ICMP 协议隧道检测",
        "level": "high",
        "tags": ["attack.command_and_control", "attack.t1048"],
        "conditions": {
            "network.protocol": "icmp",
            "icmp.type": "8", # Echo Request
            "network.bytes": ">1000" # 异常大的 ICMP 包
        }
    },
    {
        "id": "C2_004_HTTP_COVERT",
        "name": "HTTP 隐蔽信道 (大 Payload 请求)",
        "level": "high",
        "tags": ["attack.command_and_control", "attack.t1071"],
        "conditions": {
            "network.protocol": "http",
            "http.request.body.bytes": ">50000",
            "http.user_agent": "None" # 缺少 UA 特征
        }
    },
    {
    "id": "C2_005_ICMP_TUNNEL",
    "name": "ICMP 隧道通信特征",
    "level": "high",
    "tags": ["attack.command_and_control", "attack.t1071.004"],
    "conditions": {
        "network.protocol": "icmp",
        "network.bytes": ">1000" # ICMP Echo 请求通常很小
    }
    },
]
