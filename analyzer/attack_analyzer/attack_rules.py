# analyzer/attack_analyzer/attack_rules.py

"""
ATT&CK 攻击行为映射规则库 (完整版 - 带危害等级)
"""

ATTACK_RULES = [
    # ==========================================
    # 1. Initial Access (初始访问) - TA0001
    # ==========================================
    {
        "id": "IA_001_SSH_BRUTE",
        "name": "SSH 暴力破解 (高频)",
        "severity": "medium",  # 暴力破解通常是中危，成功了才高危
        "tactic": {"id": "TA0001", "name": "Initial Access"},
        "technique": {"id": "T1110", "name": "Brute Force"},
        "conditions": {
            "event.category": "authentication",
            "event.outcome": "failure",
            "network.application": "ssh"
        },
        "threshold": {"count": 5, "time_window": 60}
    },
    {
        "id": "IA_002_SQL_INJECTION",
        "name": "Web SQL 注入攻击",
        "severity": "high",  # 注入攻击风险较高
        "tactic": {"id": "TA0001", "name": "Initial Access"},
        "technique": {"id": "T1190", "name": "Exploit Public-Facing Application"},
        "conditions": {
            "network.protocol": "http",
            "url.query": ["*union select*", "*waitfor delay*", "*1=1*", "*sleep(*", "*information_schema*", "*xp_cmdshell*"]
        }
    },
    {
        "id": "IA_003_CMD_INJECTION",
        "name": "Web 命令注入/RCE",
        "severity": "critical",  # RCE 是致命的
        "tactic": {"id": "TA0001", "name": "Initial Access"},
        "technique": {"id": "T1190", "name": "Exploit Public-Facing Application"},
        "conditions": {
            "network.protocol": "http",
            "url.path": ["*||*", "*; *", "*| *", "*$(*", "*`*", "*eval(*", "*system(*"]
        }
    },
    {
        "id": "IA_004_WEBSHELL_UPLOAD",
        "name": "WebShell 文件上传尝试",
        "severity": "critical",  # 上传 WebShell 意味着服务器沦陷
        "tactic": {"id": "TA0001", "name": "Initial Access"},
        "technique": {"id": "T1190", "name": "Exploit Public-Facing Application"},
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
        "severity": "low",  # 蜜罐被访问很常见，主要是情报价值
        "tactic": {"id": "TA0001", "name": "Initial Access"},
        "technique": {"id": "T1078", "name": "Valid Accounts"},
        "conditions": {
            "event.dataset": ["cowrie"],
            "event.type": "login",
            "event.outcome": ["failure", "success"]
        }
    },

    # ==========================================
    # 2. Execution (执行) - TA0002
    # ==========================================
    {
        "id": "EX_001_SUSPICIOUS_SHELL",
        "name": "异常 Shell 启动",
        "severity": "medium",
        "tactic": {"id": "TA0002", "name": "Execution"},
        "technique": {"id": "T1059", "name": "Command and Scripting Interpreter"},
        "conditions": {
            "event.category": "process",
            "process.name": ["bash", "sh", "dash", "zsh", "powershell.exe", "cmd.exe"],
            "process.parent.name": ["httpd", "nginx", "apache2", "tomcat", "java", "w3wp.exe"]
        }
    },
    {
        "id": "EX_002_REVERSE_SHELL",
        "name": "反弹 Shell 特征",
        "severity": "critical",  # 反弹 Shell 确凿是攻击
        "tactic": {"id": "TA0002", "name": "Execution"},
        "technique": {"id": "T1059", "name": "Command and Scripting Interpreter"},
        "conditions": {
            "event.category": "process",
            "process.command_line": ["*bash -i*", "*nc -e*", "*0>&1*", "*dev/tcp/*", "*mkfifo*", "*socat*"]
        }
    },
    {
        "id": "EX_003_ENCODED_CMD",
        "name": "Base64 编码命令执行",
        "severity": "medium",
        "tactic": {"id": "TA0002", "name": "Execution"},
        "technique": {"id": "T1027", "name": "Obfuscated Files or Information"},
        "conditions": {
            "event.category": "process",
            "process.command_line": ["*base64 -d*", "*openssl enc -d*", "*certutil -decode*", "*powershell -enc*"]
        }
    },
    {
        "id": "EX_004_HONEYPOT_CMD",
        "name": "蜜罐：恶意指令执行",
        "severity": "medium",
        "tactic": {"id": "TA0002", "name": "Execution"},
        "technique": {"id": "T1059", "name": "Command and Scripting Interpreter"},
        "conditions": {
            "event.dataset": ["cowrie"],
            "event.action": "command"
        }
    },

    # ==========================================
    # 3. Persistence (持久化) - TA0003
    # ==========================================
    {
        "id": "PE_001_CRON_MOD",
        "name": "Cron 计划任务篡改",
        "severity": "high",
        "tactic": {"id": "TA0003", "name": "Persistence"},
        "technique": {"id": "T1053", "name": "Scheduled Task/Job"},
        "conditions": {
            "event.category": "file",
            "file.path": ["/etc/cron*", "/var/spool/cron/*"],
            "event.action": ["write", "change"]
        }
    },
    {
        "id": "PE_002_SSH_AUTH_KEYS",
        "name": "SSH 后门公钥植入",
        "severity": "critical",
        "tactic": {"id": "TA0003", "name": "Persistence"},
        "technique": {"id": "T1098", "name": "Account Manipulation"},
        "conditions": {
            "event.category": "file",
            "file.name": "authorized_keys",
            "event.action": "write"
        }
    },
    {
        "id": "PE_003_RC_LOCAL",
        "name": "启动项 rc.local 篡改",
        "severity": "high",
        "tactic": {"id": "TA0003", "name": "Persistence"},
        "technique": {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
        "conditions": {
            "file.path": ["/etc/rc.local", "/etc/init.d/*"],
            "event.action": ["write", "change"]
        }
    },
    {
        "id": "PE_004_USER_CREATE",
        "name": "可疑账户创建",
        "severity": "high",
        "tactic": {"id": "TA0003", "name": "Persistence"},
        "technique": {"id": "T1136", "name": "Create Account"},
        "conditions": {
            "event.category": "process",
            "process.name": "useradd",
            "process.command_line": ["*useradd*", "*adduser*"]
        }
    },

    # ==========================================
    # 4. Privilege Escalation (权限提升) - TA0004
    # ==========================================
    {
        "id": "PR_001_SUDO_ABUSE",
        "name": "Sudo 滥用/提权",
        "severity": "high",
        "tactic": {"id": "TA0004", "name": "Privilege Escalation"},
        "technique": {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
        "conditions": {
            "process.name": "sudo",
            "process.command_line": ["*sudo su*", "*sudo /bin/bash*", "*sudo -i*"]
        }
    },
    {
        "id": "PR_002_KERNEL_EXPLOIT",
        "name": "内核漏洞利用尝试 (DirtyCow等)",
        "severity": "critical",
        "tactic": {"id": "TA0004", "name": "Privilege Escalation"},
        "technique": {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
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
        "severity": "high",
        "tactic": {"id": "TA0005", "name": "Defense Evasion"},
        "technique": {"id": "T1070", "name": "Indicator Removal on Host"},
        "conditions": {
            "process.command_line": ["*rm *.log", "*echo > *.log", "*history -c*", "*unset HISTFILE*"]
        }
    },
    {
        "id": "DE_002_FILE_ATTR",
        "name": "文件锁定 (chattr +i)",
        "severity": "medium",
        "tactic": {"id": "TA0005", "name": "Defense Evasion"},
        "technique": {"id": "T1222", "name": "File and Directory Permissions Modification"},
        "conditions": {
            "process.name": "chattr",
            "process.command_line": ["*+i*", "*-i*"]
        }
    },
    {
        "id": "DE_003_TIMESTOMP",
        "name": "时间戳伪造 (touch)",
        "severity": "medium",
        "tactic": {"id": "TA0005", "name": "Defense Evasion"},
        "technique": {"id": "T1070", "name": "Indicator Removal on Host"},
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
        "severity": "critical",
        "tactic": {"id": "TA0006", "name": "Credential Access"},
        "technique": {"id": "T1003", "name": "OS Credential Dumping"},
        "conditions": {
            "process.command_line": ["*mimikatz*", "*sekurlsa*", "*logonpasswords*"]
        }
    },
    {
        "id": "CA_002_SHADOW_ACCESS",
        "name": "访问 Shadow 文件",
        "severity": "high",
        "tactic": {"id": "TA0006", "name": "Credential Access"},
        "technique": {"id": "T1003", "name": "OS Credential Dumping"},
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
        "severity": "low",
        "tactic": {"id": "TA0007", "name": "Discovery"},
        "technique": {"id": "T1046", "name": "Network Service Scanning"},
        "conditions": {
            "process.name": ["nmap", "masscan", "ping", "fping"],
            "process.command_line": ["*-sS*", "*-sT*", "*-p-*"]
        }
    },
    {
        "id": "DI_002_PROCESS_DISCO",
        "name": "进程/环境侦查",
        "severity": "low",
        "tactic": {"id": "TA0007", "name": "Discovery"},
        "technique": {"id": "T1057", "name": "Process Discovery"},
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
        "severity": "high",
        "tactic": {"id": "TA0008", "name": "Lateral Movement"},
        "technique": {"id": "T1021", "name": "Remote Services"},
        "conditions": {
            "process.name": "ssh",
            "process.command_line": ["*ssh *", "*scp *"]
        }
    },
    {
        "id": "LM_002_SMB_EXEC",
        "name": "SMB 远程执行 (Psexec)",
        "severity": "high",
        "tactic": {"id": "TA0008", "name": "Lateral Movement"},
        "technique": {"id": "T1021", "name": "Remote Services"},
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
        "severity": "medium",
        "tactic": {"id": "TA0009", "name": "Collection"},
        "technique": {"id": "T1560", "name": "Archive Collected Data"},
        "conditions": {
            "process.name": ["tar", "zip", "rar", "7z"],
            "process.command_line": ["*-c*", "*cvf*", "*zcf*"]
        }
    },
    {
        "id": "EX_001_DATA_UPLOAD",
        "name": "数据外传 (FTP/Curl)",
        "severity": "high",
        "tactic": {"id": "TA0010", "name": "Exfiltration"},
        "technique": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        "conditions": {
            "process.name": ["curl", "wget", "ftp", "nc", "scp"],
            "process.command_line": ["*-T *", "*--upload-file*", "*put *"]
        }
    },
    {
        "id": "EX_002_HONEYPOT_DL",
        "name": "蜜罐：工具下载事件",
        "severity": "medium",
        "tactic": {"id": "TA0011", "name": "Command and Control"},
        "technique": {"id": "T1105", "name": "Ingress Tool Transfer"},
        "conditions": {
            "event.dataset": ["cowrie"],
            "event.action": ["download", "file_download"]
        }
    },

    # ==========================================
    # 10. Impact (危害/破坏) - TA0040
    # ==========================================
    {
        "id": "IM_001_DATA_DESTRUCTION",
        "name": "数据删除/破坏",
        "severity": "critical",
        "tactic": {"id": "TA0040", "name": "Impact"},
        "technique": {"id": "T1485", "name": "Data Destruction"},
        "conditions": {
            "process.command_line": ["*rm -rf /*", "*rm -rf /boot*", "*mkfs*"]
        }
    },
    {
        "id": "IM_002_RANSOMWARE",
        "name": "勒索加密行为 (批量重命名)",
        "severity": "critical",
        "tactic": {"id": "TA0040", "name": "Impact"},
        "technique": {"id": "T1486", "name": "Data Encrypted for Impact"},
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
        "severity": "high",
        "tactic": {"id": "TA0011", "name": "Command and Control"},
        "technique": {"id": "T1071", "name": "Application Layer Protocol"},
        "conditions": {
            "network.protocol": "dns",
            "message": "*High Entropy*",
            "network.bytes": ">5000"
        }
    },
    {
        "id": "C2_002_USER_AGENT",
        "name": "可疑 User-Agent",
        "severity": "medium",
        "tactic": {"id": "TA0011", "name": "Command and Control"},
        "technique": {"id": "T1071", "name": "Application Layer Protocol"},
        "conditions": {
            "network.protocol": "http",
            "http.user_agent": ["*sqlmap*", "*nikto*", "*hydra*", "*python-requests*", "*curl*"]
        }
    }
]