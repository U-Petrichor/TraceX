# TraceX 分析引擎设计白皮书：算法原理与学术思想溯源

**责任模块**: 组员 4 (Analyzer / Graph Analyzer)  
**核心任务**: 攻击链构建、异常检测、威胁归因、情报富化  
**文档版本**: v2.0 (2026-01-15)  
**适用场景**: 毕业设计答辩、技术评审、系统架构讲解

---

## 目录

1. [引言与问题背景](#1-引言与问题背景)
2. [总体架构与处理流水线](#2-总体架构与处理流水线)
3. [学术论文核心思想深度剖析](#3-学术论文核心思想深度剖析)
   - 3.1 [SLEUTH: 基于因果的实时攻击场景重建](#31-sleuth-基于因果的实时攻击场景重建)
   - 3.2 [ATLAS: 基于序列学习的攻击调查](#32-atlas-基于序列学习的攻击调查)
   - 3.3 [NODOZE: 基于惊奇度的告警疲劳缓解](#33-nodoze-基于惊奇度的告警疲劳缓解)
   - 3.4 [SHADEWATCHER: 基于推荐系统的威胁分析](#34-shadewatcher-基于推荐系统的威胁分析)
4. [TraceX 核心模块实现详解](#4-tracex-核心模块实现详解)
   - 4.1 [溯源图构建 (GraphBuilder)](#41-溯源图构建-graphbuilder)
   - 4.2 [语义抽象与标签 (AtlasMapper)](#42-语义抽象与标签-atlasmapper)
   - 4.3 [异常检测策略 (Sigma + FrequencyAnalyzer)](#43-异常检测策略-sigma--frequencyanalyzer)
   - 4.4 [攻击链重建 (ProvenanceSystem)](#44-攻击链重建-provenancesystem)
   - 4.5 [APT 归因 (IntelEnricher)](#45-apt-归因-intelenricher)
   - 4.6 [IOC 情报富化 (三级级联查询)](#46-ioc-情报富化-三级级联查询)
5. [本地 MITRE ATT&CK STIX 知识库](#5-本地-mitre-attck-stix-知识库)
6. [工程决策与技术取舍](#6-工程决策与技术取舍)
7. [与教师任务书的对应关系](#7-与教师任务书的对应关系)
8. [总结与未来展望](#8-总结与未来展望)

---

## 1. 引言与问题背景

### 1.1 高级持续性威胁 (APT) 的溯源挑战

现代网络攻击，尤其是 APT 攻击，具有以下特点：
- **低且慢 (Low and Slow)**: 攻击者会在数周甚至数月内潜伏，逐步渗透。
- **多阶段 (Multi-Stage)**: 一次完整的攻击可能涉及钓鱼、漏洞利用、横向移动、数据窃取等多个阶段。
- **技术多样 (Diverse TTPs)**: 攻击者会混合使用合法工具（Living off the Land）和恶意软件。

传统的安全信息与事件管理 (SIEM) 系统面临的困境：
1.  **数据碎片化**: 主机日志、网络流量、应用日志分散在不同系统中，难以关联。
2.  **告警疲劳 (Alert Fatigue)**: IDS/IPS 产生的海量告警淹没了安全分析师，真正的威胁被噪音掩盖。NODOZE 论文指出，大型企业每天可能收到数百万条告警，而真正的攻击可能只有个位数。
3.  **缺乏上下文 (Lack of Context)**: 单条告警无法说明攻击的全貌，分析师需要手动"拼图"，效率极低。

### 1.2 数据溯源 (Data Provenance) 的兴起

为了解决上述问题，学术界提出了**数据溯源 (Data Provenance)** 的概念。其核心思想是：
> 将操作系统中的所有行为抽象为"**主体 (Subject)** 对 **客体 (Object)** 的 **操作 (Operation)**"，并以 **有向图** 的形式记录下来。

- **主体**: 进程 (Process)、用户 (User)
- **客体**: 文件 (File)、网络连接 (Socket)、注册表项 (Registry)
- **操作**: 读 (Read)、写 (Write)、执行 (Execute)、连接 (Connect)

这样，一条完整的攻击路径就变成了图上的一条**因果链 (Causal Path)**，而非散落在时间线上的孤立日志。

### 1.3 TraceX 的设计目标

TraceX 分析引擎的设计目标是：
1.  **自动化攻击链重建**: 给定一个异常点（如恶意进程），自动追溯其来龙去脉。
2.  **多源数据融合**: 将主机日志、网络流量、蜜罐告警统一到一张图上。
3.  **智能威胁归因**: 基于观测到的 TTP (战术、技术、过程)，推断最可能的攻击者身份。
4.  **情报富化**: 对攻击中涉及的 IP、域名进行威胁情报查询，提供可操作的上下文。

---

## 2. 总体架构与处理流水线

TraceX 分析引擎采用"**图构建 -> 语义抽象 -> 异常定位 -> 上下文回溯 -> 归因与富化**"的五阶段流水线设计。

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           TraceX 分析引擎处理流水线                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                    │
│   │  主机日志    │     │  网络流量    │     │  蜜罐告警    │                    │
│   │  (auditd)    │     │  (Zeek)      │     │  (Cowrie)    │                    │
│   └──────┬───────┘     └──────┬───────┘     └──────┬───────┘                    │
│          │                    │                    │                            │
│          └────────────────────┼────────────────────┘                            │
│                               ▼                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    阶段 1: 数据规范化 (Normalization)                    │   │
│   │                    FieldMapper / EventNormalizer                         │   │
│   │    - 将异构日志转换为统一的 ECS (Elastic Common Schema) 格式             │   │
│   │    - 提取关键实体：host, process.pid, process.ppid, file.path, etc.     │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                               │                                                 │
│                               ▼                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    阶段 2: 溯源图构建 (Graph Building)                   │   │
│   │                    GraphBuilder                                          │   │
│   │    - 为每个事件生成唯一节点 ID: host|pid|exe|start_time                  │   │
│   │    - 构建因果边: spawned (父子进程), read/write (文件), connect (网络)   │   │
│   │    - 【理论来源: SLEUTH - Causality Tracking】                           │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                               │                                                 │
│                               ▼                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    阶段 3: 语义抽象 (Semantic Abstraction)               │   │
│   │                    AtlasMapper                                           │   │
│   │    - 将底层系统调用/命令行映射为高层攻击语义                             │   │
│   │    - 示例: "powershell.exe -enc ..." -> OBFUSCATED_POWERSHELL            │   │
│   │    - 【理论来源: ATLAS - Sequence Learning / Lemmatization】             │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                               │                                                 │
│                               ▼                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    阶段 4: 异常检测 (Anomaly Detection)                  │   │
│   │                    SigmaEngine + FrequencyAnalyzer                       │   │
│   │    【主力方案】Sigma 规则命中 -> 精准定位攻击种子 (Seed Event)           │   │
│   │    【辅助方案】惊奇度评分 -> 发现未知威胁 (路径频率极低 = 异常)          │   │
│   │    - 【理论来源: NODOZE - Surprisal Scoring】                            │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                               │                                                 │
│                               ▼                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    阶段 5: 攻击链重建 (Provenance Reconstruction)        │   │
│   │                    ProvenanceSystem                                      │   │
│   │    - 以异常事件为种子，在溯源图上进行双向遍历 (向上+向下)                │   │
│   │    - 向上回溯: 寻找初始入侵点 (Initial Access)                          │   │
│   │    - 向下追踪: 评估攻击影响 (Impact)                                     │   │
│   │    - 输出: 包含攻击路径的子图 (Attack Chain Subgraph)                    │   │
│   │    - 【理论来源: NODOZE - Contextual Graph / Threat Propagation】        │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                               │                                                 │
│                               ▼                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    阶段 6: 威胁归因 (Threat Attribution)                 │   │
│   │                    IntelEnricher.attribute_by_ttps()                     │   │
│   │    - 提取攻击链中的所有 TTP (Sigma 命中 / 直接标注)                      │   │
│   │    - 与 MITRE ATT&CK STIX 知识库中的 APT 组织 TTP 进行集合相似度匹配     │   │
│   │    - 计算 Jaccard / Recall 得分，输出最可能的攻击者身份                  │   │
│   │    - 【理论来源: SHADEWATCHER - Recommendation System】                  │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                               │                                                 │
│                               ▼                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    阶段 7: IOC 情报富化 (IOC Enrichment)                 │   │
│   │                    IntelEnricher.enrich_entities()                       │   │
│   │    - 从攻击链子图的节点中提取 IP、域名、哈希等 IOC                       │   │
│   │    - 三级级联查询: 本地缓存 -> 外部 API (AbuseIPDB/VirusTotal) -> 启发式 │   │
│   │    - 输出: 丰富的威胁情报上下文 (地理位置、恶意标签、历史记录)           │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                               │                                                 │
│                               ▼                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                           最终输出                                       │   │
│   │    {                                                                     │   │
│   │      "nodes": [...],           // 攻击链涉及的所有节点                   │   │
│   │      "edges": [...],           // 攻击链涉及的所有边 (因果关系)          │   │
│   │      "path_signature": "...",  // ATLAS 语义签名                         │   │
│   │      "anomaly_score": 12.5,    // NODOZE 惊奇度评分                      │   │
│   │      "intelligence": {                                                   │   │
│   │        "attribution_ttp": {    // APT 归因结果                           │   │
│   │          "suspected_group": "APT28",                                     │   │
│   │          "confidence": 0.85,                                             │   │
│   │          "matched_ttps": [...]                                           │   │
│   │        },                                                                │   │
│   │        "external_infrastructure": [...] // IOC 富化结果                  │   │
│   │      }                                                                   │   │
│   │    }                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 架构总览表

| 阶段 | 核心模块 | 关键任务 | 理论来源 | 关键思想 |
| :--- | :--- | :--- | :--- | :--- |
| **1. 图构建** | `GraphBuilder` | 多源日志 → 因果图 | **SLEUTH** | 因果跟踪：基于主体-客体依赖关系构建紧凑图 |
| **2. 语义抽象** | `AtlasMapper` | 底层调用 → 攻击语义 | **ATLAS** | 序列学习：将系统调用视为"单词"，映射为"攻击故事" |
| **3. 异常定位** | `FrequencyAnalyzer` + `SigmaEngine` | 发现攻击种子 | **NODOZE** | 惊奇度：罕见即异常，计算路径统计学惊奇度 |
| **4. 链条重建** | `ProvenanceSystem` | 重建完整攻击路径 | **NODOZE** | 威胁传播：通过图扩散将单点异常扩展为因果上下文 |
| **5. 归因富化** | `IntelEnricher` | 身份推断 & IOC 情报 | **SHADEWATCHER** | 推荐系统：将归因建模为基于 TTP 的推荐问题 |

---

## 3. 学术论文核心思想深度剖析

本节将深入解读 TraceX 所参考的四篇核心论文，阐述其原始设计目标、核心算法、以及 TraceX 如何将其思想进行工程化落地。

### 3.1 SLEUTH: 基于因果的实时攻击场景重建

**论文**: SLEUTH: Real-time Attack Scenario Reconstruction from COTS Audit Data  
**发表会议**: USENIX Security Symposium  
**核心问题**: 如何从商业现货 (COTS) 操作系统的审计日志中，实时重建攻击场景？

#### 3.1.1 SLEUTH 的核心挑战

传统的日志分析方法面临两大挑战：
1.  **日志量巨大**: 一台普通服务器每天可能产生数百万条审计日志。
2.  **依赖爆炸 (Dependency Explosion)**: 一个长期运行的进程（如 Web 服务器）可能与成千上万个文件和网络连接有关联，导致分析时无法聚焦。

#### 3.1.2 SLEUTH 的核心思想：基于标签的因果跟踪 (Tag-based Causality Tracking)

SLEUTH 提出了一种革命性的方法：**为每个主体和客体打上"标签"**。

- **信任度标签 (Trustworthiness Tag)**: 表示一个实体的可信程度。来自外部网络的数据信任度低，本地配置文件信任度高。
- **敏感度标签 (Sensitivity Tag)**: 表示一个实体的敏感程度。用户密码文件敏感度高，临时文件敏感度低。

**标签传播规则**:
- 当一个进程读取一个低信任度的文件时，该进程的信任度也会降低。
- 当一个进程写入一个文件时，文件的信任度会继承进程的信任度。

**攻击检测**:
- 当一个 **低信任度** 的主体尝试访问一个 **高敏感度** 的客体时，系统会发出告警。这正是攻击的典型模式：外部输入 -> 恶意代码 -> 窃取敏感数据。

#### 3.1.3 SLEUTH 的核心算法：因果图压缩

SLEUTH 的另一个贡献是 **因果图压缩**。它只保留与攻击相关的因果链，丢弃无关的后台活动。

**压缩前**: 数千万条日志事件，形成一张巨大的图。
**压缩后**: 仅保留包含"低信任度 -> 高敏感度"路径的子图，通常只有几千个节点。

**原理**: 从告警点（低信任度主体访问高敏感度客体）开始，进行 **反向遍历 (Backward Traversal)**，只保留能够到达告警点的路径。

#### 3.1.4 TraceX 如何应用 SLEUTH

**TraceX 的 `GraphBuilder` 模块直接复刻了 SLEUTH 的因果跟踪思想**:

```python
# analyzer/graph_analyzer/graph_builder.py

def generate_node_id(self, event: dict, category: str) -> str:
    """
    生成唯一节点 ID，解决 PID 复用问题。
    
    SLEUTH 论文指出：PID 会被操作系统复用，因此不能仅用 PID 作为进程标识。
    解决方案：使用 host + pid + start_time 的组合作为唯一 ID。
    
    对于文件/网络节点，使用 host + path 或 host + ip 的组合。
    """
    host = event.get("host", {}).get("name", "unknown")
    
    if category == "process":
        pid = event.get("process", {}).get("pid", 0)
        start_time = event.get("process", {}).get("start", "")
        exe = event.get("process", {}).get("executable", "")
        return f"{host}|{pid}|{exe}|{start_time}"
    elif category == "file":
        path = event.get("file", {}).get("path", "unknown")
        return f"{host}|file|{path}"
    elif category == "network":
        src_ip = event.get("source", {}).get("ip", "")
        dst_ip = event.get("destination", {}).get("ip", "")
        return f"{host}|net|{src_ip}|{dst_ip}"
    # ...
```

**TraceX 的边类型与 SLEUTH 的对应关系**:

| SLEUTH 操作类型 | TraceX 边类型 | 说明 |
| :--- | :--- | :--- |
| `clone/exec` | `spawned` | 父进程创建子进程 |
| `read` | `read` | 进程读取文件 |
| `write/modify` | `write` | 进程写入/修改文件 |
| `connect/accept` | `connect_outbound/inbound` | 网络连接 |
| `delete` | `delete` | 进程删除文件 |

**TraceX 支持的全部节点类型**:

| 节点类型 | 说明 | ID 生成规则 |
| :--- | :--- | :--- |
| `process` | 进程节点 | `host\|pid\|exe\|start_time` |
| `file` | 文件节点 | `host\|file\|path` |
| `network` | 网络连接节点 | `host\|net\|src_ip\|dst_ip` |
| `host` | 主机节点 | `host\|hostname` |
| `authentication` | 认证事件节点 | `host\|auth\|user\|timestamp` |
| `memory_anomaly` | 内存异常节点 | `host\|mem\|pid\|type` |

**TraceX 支持的全部边类型**:

| 边类型 | 说明 | 源节点 -> 目标节点 |
| :--- | :--- | :--- |
| `spawned` | 进程创建 | 父进程 -> 子进程 |
| `read` | 文件读取 | 进程 -> 文件 |
| `write` | 文件写入 | 进程 -> 文件 |
| `delete` | 文件删除 | 进程 -> 文件 |
| `connect_outbound` | 外连网络 | 进程 -> 网络节点 |
| `connect_inbound` | 入站网络 | 网络节点 -> 进程 |
| `triggered_anomaly` | 触发内存异常 | 进程 -> 内存异常节点 |
| `host_file` | 主机-文件关联 | 主机 -> 文件 (无进程时) |
| `host_network` | 主机-网络关联 | 主机 -> 网络 (无进程时) |
| `host_auth` | 主机-认证关联 | 主机 -> 认证节点 |
| `auth` | 认证关系 | 进程 -> 认证节点 |

---

### 3.2 ATLAS: 基于序列学习的攻击调查

**论文**: ATLAS: A Sequence-based Learning Approach for Attack Investigation  
**发表会议**: USENIX Security Symposium  
**核心问题**: 如何将底层的、难以理解的系统调用日志，转化为人类可理解的"攻击故事"？

#### 3.2.1 ATLAS 的核心挑战

溯源图虽然捕获了因果关系，但它仍然是底层的：
- 节点是进程 ID、文件路径。
- 边是 `read`, `write`, `exec` 等系统调用。

安全分析师需要的是 **高层语义**，例如：
- "攻击者通过钓鱼邮件下载了一个恶意脚本"
- "恶意脚本执行了 PowerShell 进行横向移动"
- "攻击者窃取了 SAM 数据库"

#### 3.2.2 ATLAS 的核心思想：将系统日志视为"语言"

ATLAS 的创新之处在于，它将溯源图中的事件序列 **类比为自然语言中的句子**。

- **单词 (Word)**: 单个系统调用或事件，如 `execve("/bin/bash", ...)` 或 `open("/etc/passwd", O_RDONLY)`。
- **句子 (Sentence)**: 一系列相关的事件，如 `[execve(bash) -> open(/etc/passwd) -> write(socket)]`。
- **语义 (Meaning)**: 这个句子的含义是"读取了敏感文件并发送到网络"。

#### 3.2.3 ATLAS 的核心算法：词干提取 (Lemmatization) + LSTM

1.  **词干提取 (Lemmatization)**: 将具体的文件路径、IP 地址等抽象为通用标签。
    - `/etc/passwd` -> `SENSITIVE_FILE`
    - `/tmp/xyz123.sh` -> `TEMP_SCRIPT`
    - `192.168.1.100:4444` -> `C2_CONNECTION`
    
2.  **序列学习 (LSTM)**: 使用长短期记忆网络学习"正常的"事件序列。任何偏离已学习模式的序列都被视为潜在攻击。

3.  **攻击故事生成**: 将识别出的异常路径翻译为人类可读的描述。

#### 3.2.4 TraceX 如何应用 ATLAS

**TraceX 的 `AtlasMapper` 模块实现了 ATLAS 的词干提取思想**:

```python
# analyzer/graph_analyzer/atlas_mapper.py

class AtlasMapper:
    """
    将底层事件映射为 ATLAS 语义标签。
    
    【理论来源】ATLAS 论文的 Lemmatization (词干提取) 思想：
    将具体的文件路径、命令行参数抽象为通用的攻击语义标签，
    使得不同攻击中"相似"的行为能够被归为同一类。
    """
    
    def get_label(self, event: dict) -> str:
        """
        根据事件内容生成 ATLAS 语义标签。
        
        标签层级：
        1. 命令行特征 (最高优先级)
        2. 可执行文件名
        3. 文件路径特征
        4. 网络行为特征
        5. 默认: UNKNOWN
        """
        # 检查命令行 -> 高层语义
        cmdline = self._get_command_line(event)
        if cmdline:
            if "powershell" in cmdline.lower() and "-enc" in cmdline.lower():
                return "OBFUSCATED_POWERSHELL"  # 混淆的 PowerShell 命令
            if "mimikatz" in cmdline.lower():
                return "CREDENTIAL_DUMPING"     # 凭据窃取
            if "whoami" in cmdline.lower() or "net user" in cmdline.lower():
                return "RECONNAISSANCE"          # 侦察活动
            # ...更多规则
        
        # 检查文件路径 -> 敏感文件访问
        file_path = self._get_file_path(event)
        if file_path:
            if any(s in file_path.lower() for s in ["/etc/shadow", "/etc/passwd", "sam", "ntds"]):
                return "SENSITIVE_FILE_ACCESS"
            if any(s in file_path.lower() for s in [".ssh/", "id_rsa"]):
                return "SSH_KEY_ACCESS"
            # ...更多规则
        
        # 检查网络行为
        dst_port = event.get("destination", {}).get("port")
        if dst_port in [4444, 5555, 6666, 8080, 1234]:  # 常见 C2 端口
            return "C2_COMMUNICATION"
        
        return "UNKNOWN"
```

**TraceX 的 ATLAS 标签示例**:

| 事件特征 | ATLAS 标签 | 含义 |
| :--- | :--- | :--- |
| `powershell -enc` | `OBFUSCATED_POWERSHELL` | 混淆的 PowerShell 命令 |
| `mimikatz` | `CREDENTIAL_DUMPING` | 凭据窃取工具 |
| 访问 `/etc/shadow` | `SENSITIVE_FILE_ACCESS` | 访问敏感文件 |
| 连接 `*.ngrok.io` | `C2_COMMUNICATION` | 疑似 C2 通信 |
| 写入 `.bashrc` | `PERSISTENCE` | 持久化机制 |
| `wget http://...` | `DOWNLOAD_PAYLOAD` | 下载载荷 |

**关于 ATLAS 序列学习的工程决策**:

ATLAS 论文的完整实现需要 LSTM 模型来学习"正常"序列。然而，在 TraceX 的实际部署中，我们面临 **冷启动问题**：
- 需要在一个"干净"的环境中运行数周，收集正常行为基线。
- 没有足够的历史数据训练 LSTM 模型。

因此，**TraceX 当前仅采用 ATLAS 的词干提取 (Lemmatization) 部分，用于生成语义标签，但不使用其进行异常检测或归因**。序列学习的异常检测功能由 Sigma 规则和 FrequencyAnalyzer 替代。

---

### 3.3 NODOZE: 基于惊奇度的告警疲劳缓解

**论文**: NODOZE: Combatting Threat Alert Fatigue with Automated Provenance Triage  
**发表会议**: NDSS (Network and Distributed System Security Symposium)  
**核心问题**: 如何从海量的 IDS 告警中，自动筛选出真正重要的威胁？

#### 3.3.1 NODOZE 的核心挑战：告警疲劳 (Alert Fatigue)

现代企业的安全运营中心 (SOC) 面临严重的告警疲劳问题：
- **告警数量**: 大型企业每天可能收到 **数百万条** IDS/IPS 告警。
- **误报率**: 大部分告警是误报 (False Positive)，真正的攻击可能只占 0.01%。
- **后果**: 分析师疲于应对，真正的威胁被忽视。

#### 3.3.2 NODOZE 的核心思想：惊奇度 (Surprisal)

NODOZE 提出了一个简洁而强大的概念：**惊奇度 (Surprisal)**。

> 一个行为越罕见，其惊奇度越高。惊奇度高的行为更可能是攻击。

**惊奇度公式**:
$$S = -\log_2(P(path))$$

其中，$P(path)$ 是该路径在历史数据中出现的概率。

**举例**:
- `Web 服务器 -> 写日志文件`: 每天发生数千次，$P$ 高，惊奇度低 (正常)。
- `Web 服务器 -> 启动 /bin/sh`: 几乎从未发生过，$P$ 极低，惊奇度极高 (异常)。

#### 3.3.3 NODOZE 的核心算法：频率基线 + 网络扩散

1.  **建立基线**: 在一段时间内（如一周），统计每种"主体-操作-客体"三元组的出现频率。
    ```
    (nginx, write, /var/log/access.log) -> 出现 50000 次
    (nginx, exec, /bin/sh) -> 出现 0 次
    ```

2.  **计算惊奇度**: 当检测到新行为时，查询基线获取其频率，计算惊奇度。

3.  **网络扩散 (Network Diffusion)**: 将单点惊奇度沿着溯源图的边传播，生成整个路径的聚合得分。
    - 如果一条路径上有多个高惊奇度的边，其总得分会更高。

4.  **优先级排序**: 将所有路径按得分排序，最高分的路径优先呈现给分析师。

#### 3.3.4 TraceX 如何应用 NODOZE

**TraceX 的 `FrequencyAnalyzer` 模块实现了 NODOZE 的惊奇度计算思想**:

```python
# analyzer/graph_analyzer/frequency_analyzer.py

class FrequencyAnalyzer:
    """
    模拟 NODOZE 论文中的频率分析模块，用于计算路径的"惊奇度" (Surprisal Score)。
    
    【重要说明】
    由于缺乏真实的历史基线数据，本模块采用"模拟基线"的方式进行演示。
    在真实生产环境中，需要部署日志收集系统运行数周来建立基线。
    """
    
    def __init__(self):
        # 模拟的历史基线数据：路径签名 -> 出现频率
        # 真实场景下，这会是一个从大量正常日志中统计出来的数据库
        self.baseline_frequencies = {
            # 高频 (正常) 行为
            "PROCESS_START -> FILE_READ": 10000,
            "PROCESS_START -> NETWORK_CONNECT": 8000,
            "AUTHENTICATION_SUCCESS": 5000,
            "FILE_WRITE -> FILE_READ": 3000,
            
            # 低频 (可疑) 行为
            "POWERSHELL_EXEC -> NETWORK_CONNECT_C2": 5,
            "WEB_SERVER_PROCESS -> SHELL_EXEC": 2,
            "SENSITIVE_FILE_READ -> EXFILTRATION": 1,
            "OBFUSCATED_CMD -> PERSISTENCE": 3,
        }
        self.total_paths = sum(self.baseline_frequencies.values())
    
    def calculate_surprisal_score(self, path_signature: str) -> float:
        """
        计算路径的惊奇度得分。
        
        公式: S = -log2(P(path))
        
        - 高频路径: P 大, S 小 (正常)
        - 低频路径: P 小, S 大 (异常)
        - 从未见过的路径: S 趋近无穷大 (高度可疑)
        """
        count = self.baseline_frequencies.get(path_signature, 1)  # 默认为 1 (极罕见)
        probability = count / self.total_paths
        
        if probability <= 0:
            return float('inf')
        
        return -math.log2(probability)
```

**为什么 TraceX 的频率分析是"模拟"的？**

NODOZE 的惊奇度方法非常优雅，但其落地面临 **冷启动问题**：
1.  **需要大量历史数据**: 必须在一个"干净"的生产环境中运行数周，收集正常行为。
2.  **环境差异**: 不同企业的"正常行为"差异很大，无法直接使用通用基线。
3.  **持续更新**: 基线需要随着业务变化持续更新。

在 TraceX 的当前阶段（靶场验证），我们无法满足上述条件。因此：
- **当前方案**: 使用 **预设的模拟基线** 来演示 NODOZE 的思想，输出惊奇度得分供参考。
- **主力检测**: 依赖 **Sigma 规则** 作为精准的攻击种子发现机制。Sigma 规则相当于引入了"专家先验知识"，不需要历史数据训练。

**TraceX 的双检测策略**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      异常检测策略                                    │
├──────────────────────────────┬──────────────────────────────────────┤
│         Sigma 规则引擎        │         FrequencyAnalyzer           │
│         (主力方案)            │         (辅助/演示)                  │
├──────────────────────────────┼──────────────────────────────────────┤
│ - 精准匹配已知攻击模式        │ - 发现未知异常 (0-day)               │
│ - 无需历史数据                │ - 需要历史基线 (冷启动问题)           │
│ - 可解释性强 (规则明确)       │ - 可能有误报 (需调参)                │
│ - 覆盖 MITRE ATT&CK 大部分 TTP│ - 用模拟基线演示思想                  │
├──────────────────────────────┴──────────────────────────────────────┤
│                        融合输出                                      │
│  - Sigma 命中 -> 作为强信号，直接标记为攻击种子                       │
│  - 惊奇度得分 -> 作为辅助指标，供分析师参考                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

### 3.4 SHADEWATCHER: 基于推荐系统的威胁分析

**论文**: SHADEWATCHER: Recommendation-guided Cyber Threat Analysis using System Audit Records  
**发表会议**: USENIX Security Symposium  
**核心问题**: 如何利用图神经网络 (GNN) 进行威胁检测和归因？

#### 3.4.1 SHADEWATCHER 的核心洞见：安全 ≈ 推荐系统

SHADEWATCHER 提出了一个非常有创意的类比：

> 网络威胁检测与**电商推荐系统**在结构上高度相似。

| 推荐系统 | 威胁检测 |
| :--- | :--- |
| 用户 (User) | 主体 (Process/User) |
| 物品 (Item) | 客体 (File/Socket) |
| 偏好 (Preference) | 正常交互模式 |
| 异常推荐 | 异常交互 = 潜在威胁 |

**推荐系统的核心任务**: 预测用户对物品的"偏好"。如果一个用户与其历史偏好不符的物品产生交互，这就是异常。

**威胁检测的核心任务**: 预测主体对客体的"正常交互"。如果一个进程与其历史行为模式不符的文件/网络产生交互，这就是潜在威胁。

#### 3.4.2 SHADEWATCHER 的核心算法：图神经网络 (GNN) + 高阶连通性

1.  **构建二部图 (Bipartite Graph)**: 主体和客体分别作为两类节点，操作作为边。
2.  **GNN 嵌入**: 使用图神经网络学习每个节点的"嵌入向量"。
3.  **预测交互**: 根据主体和客体的嵌入向量，预测它们之间交互的"合理性得分"。
4.  **异常检测**: 得分低的交互被视为异常。

#### 3.4.3 TraceX 如何应用 SHADEWATCHER

TraceX 没有完整实现 SHADEWATCHER 的 GNN 模型（需要大量训练数据），但**借鉴了其"集合相似度匹配"的归因思想**。

**SHADEWATCHER 的归因逻辑**:
- 如果观测到的攻击行为集合与某个 APT 组织的已知行为高度重叠，则归因于该 APT。

**TraceX 的 `IntelEnricher.attribute_by_ttps()` 实现**:

```python
# analyzer/graph_analyzer/enrichment.py

def attribute_by_ttps(self, observed_ttps: List[str]) -> dict:
    """
    基于 TTP 进行 APT 归因。
    
    【理论来源】SHADEWATCHER 论文的"推荐系统"思想：
    将归因问题转化为"用户-物品"匹配问题。
    
    - 用户 = APT 组织
    - 物品 = TTP (战术、技术、过程)
    - 匹配算法 = 集合相似度 (Jaccard / Recall)
    """
    if not observed_ttps:
        return {"suspected_group": "Unclassified", "confidence": 0.0}
    
    observed_set = set(observed_ttps)
    best_match = None
    best_score = 0.0
    
    # 遍历 MITRE ATT&CK 知识库中的所有 APT 组织
    for apt_name, apt_profile in self.mitre_apt_profiles.items():
        known_ttps = set(apt_profile.get("ttps", []))
        
        if not known_ttps:
            continue
        
        # 计算 Jaccard 相似度
        intersection = observed_set & known_ttps
        union = observed_set | known_ttps
        jaccard = len(intersection) / len(union) if union else 0
        
        # 计算 Recall (覆盖率)
        recall = len(intersection) / len(known_ttps) if known_ttps else 0
        
        # 综合得分 (可调整权重)
        score = 0.6 * jaccard + 0.4 * recall
        
        if score > best_score:
            best_score = score
            best_match = apt_name
    
    return {
        "suspected_group": best_match or "Unclassified",
        "confidence": round(best_score, 3),
        "observed_ttps": list(observed_set),
        "matched_ttps": list(intersection) if best_match else []
    }
```

**Jaccard 相似度与 Recall 的解释**:

- **Jaccard 相似度**: $J = \frac{|A \cap B|}{|A \cup B|}$
  - 衡量两个集合的整体重叠程度。
  - 如果观测到的 TTP 与某 APT 的已知 TTP 完全一致，J = 1。

- **Recall (召回率)**: $R = \frac{|A \cap B|}{|B|}$
  - 衡量观测到的 TTP 覆盖了多少已知 APT 的 TTP。
  - 如果观测到的 TTP 完全覆盖了某 APT 的已知 TTP，R = 1。

**为什么使用 Jaccard + Recall？**

单独使用 Jaccard 可能会偏向 TTP 数量较少的 APT；单独使用 Recall 可能会偏向 TTP 数量较多的 APT。综合使用可以平衡这两种偏差。

---

## 4. TraceX 核心模块实现详解

### 4.1 溯源图构建 (GraphBuilder)

**代码位置**: `analyzer/graph_analyzer/graph_builder.py`

**核心功能**: 将异构的日志事件转换为统一的因果图。

**处理流程**:
```
输入: 事件列表 [event1, event2, ...]
  │
  ▼
对每个事件:
  ├─ 提取事件类别 (process/file/network/auth/memory)
  ├─ 生成唯一节点 ID
  ├─ 创建/更新节点 (带属性)
  └─ 创建边 (基于因果关系)
  │
  ▼
输出: { "nodes": [...], "edges": [...] }
```

**节点 ID 生成策略**:

```python
def generate_node_id(self, event: dict, category: str) -> str:
    """
    【关键设计】解决 PID 复用问题
    
    操作系统会复用 PID，同一个 PID 可能在不同时间代表不同进程。
    因此，节点 ID 必须包含时间戳或启动时间，确保唯一性。
    """
    host = event.get("host", {}).get("name", "unknown")
    
    if category == "process":
        pid = event.get("process", {}).get("pid", 0)
        start_time = event.get("process", {}).get("start", "")
        exe = event.get("process", {}).get("executable", "")
        # 使用 host + pid + exe + start_time 的组合
        return f"{host}|{pid}|{exe}|{start_time}"
    
    elif category == "file":
        path = event.get("file", {}).get("path", "unknown")
        # 文件节点: host + path
        return f"{host}|file|{path}"
    
    elif category == "network":
        src_ip = event.get("source", {}).get("ip", "")
        dst_ip = event.get("destination", {}).get("ip", "")
        # 网络节点: host + src_ip + dst_ip
        return f"{host}|net|{src_ip}|{dst_ip}"
    
    elif category == "authentication":
        user = event.get("user", {}).get("name", "unknown")
        timestamp = event.get("@timestamp", "")
        # 认证节点: host + user + timestamp
        return f"{host}|auth|{user}|{timestamp}"
    
    elif category == "memory":
        pid = event.get("process", {}).get("pid", 0)
        anomaly_type = event.get("memory", {}).get("anomaly_type", "unknown")
        # 内存异常节点: host + pid + anomaly_type
        return f"{host}|mem|{pid}|{anomaly_type}"
```

**边的创建逻辑**:

```python
def _process_event(self, event: dict):
    """处理单个事件，创建节点和边"""
    category = self._get_event_category(event)
    
    if category == "process":
        # 1. 创建进程节点
        node_id = self.generate_node_id(event, "process")
        self._ensure_process_node(event, node_id)
        
        # 2. 检查是否有父进程 -> 创建 spawned 边
        ppid = event.get("process", {}).get("parent", {}).get("pid")
        if ppid:
            parent_id = self._find_or_create_parent_node(event, ppid)
            self._add_edge(parent_id, node_id, "spawned")
    
    elif category == "file":
        # 1. 创建文件节点
        file_id = self.generate_node_id(event, "file")
        self._ensure_file_node(event, file_id)
        
        # 2. 获取操作进程
        process_id = self._get_process_node_id(event)
        
        # 3. 根据操作类型创建边
        action = event.get("event", {}).get("action", "")
        edge_type = self._map_file_relation(action)  # read/write/delete
        
        if process_id:
            self._add_edge(process_id, file_id, edge_type)
        else:
            # 无进程信息时，连接到主机节点
            host_id = self._ensure_host_node(event)
            self._add_edge(host_id, file_id, "host_file")
    
    elif category == "network":
        # 类似逻辑: 创建网络节点，连接到进程或主机
        pass
```

### 4.2 语义抽象与标签 (AtlasMapper)

**代码位置**: `analyzer/graph_analyzer/atlas_mapper.py`

**核心功能**: 将底层事件映射为高层攻击语义标签。

**标签层级**:
1.  **命令行特征** (最高优先级): PowerShell 混淆、Mimikatz 等
2.  **可执行文件名**: 已知恶意工具
3.  **文件路径特征**: 敏感文件访问
4.  **网络行为特征**: C2 通信端口
5.  **默认**: UNKNOWN

**完整标签清单**:

| 标签 | 触发条件 | 对应 ATT&CK | 严重度 |
| :--- | :--- | :--- | :--- |
| `OBFUSCATED_POWERSHELL` | `powershell -enc` | T1059.001 | 高 |
| `CREDENTIAL_DUMPING` | `mimikatz`, `procdump lsass` | T1003 | 高 |
| `RECONNAISSANCE` | `whoami`, `net user`, `systeminfo` | T1087, T1082 | 中 |
| `SENSITIVE_FILE_ACCESS` | 访问 `/etc/shadow`, `SAM` | T1003.002 | 高 |
| `SSH_KEY_ACCESS` | 访问 `.ssh/id_rsa` | T1552.004 | 高 |
| `PERSISTENCE` | 写入 `.bashrc`, 注册表 Run 键 | T1546 | 高 |
| `C2_COMMUNICATION` | 连接 4444/5555/8080 等端口 | T1571 | 高 |
| `DOWNLOAD_PAYLOAD` | `wget`, `curl` 下载可执行文件 | T1105 | 中 |
| `LATERAL_MOVEMENT` | `psexec`, `wmic` 远程执行 | T1021 | 高 |
| `DATA_EXFILTRATION` | 大量数据发送到外部 IP | T1041 | 高 |

### 4.3 异常检测策略 (Sigma + FrequencyAnalyzer)

**代码位置**: 
- `analyzer/attack_analyzer/sigma_engine.py` (Sigma 规则引擎)
- `analyzer/graph_analyzer/frequency_analyzer.py` (惊奇度分析)

**双策略设计**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        异常检测双策略                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────┐       ┌─────────────────────┐              │
│  │     Sigma 规则      │       │   FrequencyAnalyzer  │              │
│  │     (主力方案)       │       │   (辅助演示)         │              │
│  ├─────────────────────┤       ├─────────────────────┤              │
│  │ - 3600+ 条规则      │       │ - NODOZE 惊奇度公式  │              │
│  │ - 覆盖主流 ATT&CK   │       │ - 模拟历史基线       │              │
│  │ - 精准匹配已知攻击   │       │ - 发现未知异常       │              │
│  │ - 无需历史数据      │       │ - 需要真实基线       │              │
│  └─────────┬───────────┘       └─────────┬───────────┘              │
│            │                             │                          │
│            └──────────┬──────────────────┘                          │
│                       ▼                                             │
│            ┌─────────────────────┐                                  │
│            │    融合判断逻辑      │                                  │
│            ├─────────────────────┤                                  │
│            │ IF Sigma 命中:      │                                  │
│            │   -> 强信号，标记种子│                                  │
│            │ ELSE IF 惊奇度 > 阈值:│                                 │
│            │   -> 弱信号，供参考  │                                  │
│            └─────────────────────┘                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Sigma 规则覆盖情况**:

TraceX 集成了 **SigmaHQ 官方规则库**，包含 3600+ 条检测规则，覆盖：
- Windows 进程创建、PowerShell、WMI
- Linux auditd、syslog
- 网络连接、DNS 查询
- Web 服务器日志

**惊奇度计算示例**:

```python
# 示例路径签名
path1 = "PROCESS_START -> FILE_READ"          # 高频，正常
path2 = "WEB_SERVER_PROCESS -> SHELL_EXEC"    # 低频，异常

analyzer = FrequencyAnalyzer()
print(analyzer.calculate_surprisal_score(path1))  # 输出: ~3.0 (低)
print(analyzer.calculate_surprisal_score(path2))  # 输出: ~15.0 (高)
```

### 4.4 攻击链重建 (ProvenanceSystem)

**代码位置**: `analyzer/graph_analyzer/provenance_system.py`

**核心功能**: 以异常事件为种子，在溯源图上进行双向遍历，重建完整攻击路径。

**处理流程**:

```
输入: 种子事件 (Sigma 命中 / 高惊奇度)
  │
  ▼
1. 收集相关事件 (ContextEngine.find_related_events)
   - 基于时间窗口
   - 基于共享实体 (host, pid, ip)
  │
  ▼
2. 构建子图 (GraphBuilder.build_from_events)
   - 创建节点和边
  │
  ▼
3. 提取语义标签 (AtlasMapper.get_label)
   - 为每个事件打标签
   - 生成路径签名 (path_signature)
  │
  ▼
4. 计算惊奇度 (FrequencyAnalyzer.calculate_surprisal_score)
   - 输出 anomaly_score
  │
  ▼
5. 提取 TTP (从 Sigma 命中 / 直接标注)
  │
  ▼
6. APT 归因 (IntelEnricher.attribute_by_ttps)
  │
  ▼
7. IOC 富化 (IntelEnricher.enrich_entities)
  │
  ▼
输出: {
  "nodes": [...],
  "edges": [...],
  "path_signature": "OBFUSCATED_POWERSHELL -> C2_COMMUNICATION -> ...",
  "anomaly_score": 12.5,
  "intelligence": {
    "attribution_ttp": { "suspected_group": "APT28", ... },
    "external_infrastructure": [...]
  }
}
```

**关键代码**:

```python
class ProvenanceSystem:
    def rebuild_attack_path(self, seed_event):
        """
        重建攻击路径。
        
        【理论来源】NODOZE 的 Contextual Graph 思想：
        以告警点为中心，利用溯源图向周围扩散，
        将被因果关系连接的节点纳入，形成完整的"攻击子图"。
        """
        # 1. 收集相关事件
        all_events = self.context_engine.find_related_events(seed_event)
        
        # 2. 构建子图
        graph_data = self.graph_builder.build_from_events(all_events)
        
        # 3. 提取 ATLAS 语义签名
        labels = [self.atlas_mapper.get_label(e) for e in all_events]
        signature = " -> ".join(sorted(set([l for l in labels if l != "UNKNOWN"])))
        
        # 4. 计算惊奇度
        anomaly_score = self.frequency_analyzer.calculate_surprisal_score(signature)
        
        # 5. 提取 TTP
        ttps = []
        for e in all_events:
            ttp_id = e.get("threat", {}).get("technique", {}).get("id")
            if ttp_id:
                ttps.append(ttp_id)
        
        # 6. APT 归因
        attribution = self.enricher.attribute_by_ttps(list(set(ttps)))
        
        # 7. IOC 富化
        ioc_enrichment = self.enricher.enrich_entities(graph_data.get("nodes", []))
        
        return {
            "nodes": graph_data.get('nodes', []),
            "edges": graph_data.get('edges', []),
            "path_signature": signature,
            "anomaly_score": anomaly_score,
            "intelligence": {
                "attribution_ttp": attribution,
                "external_infrastructure": ioc_enrichment
            }
        }
```

### 4.5 APT 归因 (IntelEnricher)

**代码位置**: `analyzer/graph_analyzer/enrichment.py`

**归因数据源**:

TraceX 的 APT 归因依赖于本地克隆的 **MITRE ATT&CK STIX 知识库** (详见第 5 节)。

**归因算法**:

```python
def attribute_by_ttps(self, observed_ttps: List[str]) -> dict:
    """
    基于观测到的 TTP 进行 APT 归因。
    
    算法步骤:
    1. 将观测到的 TTP 转换为集合
    2. 遍历 MITRE 知识库中的所有 APT 组织
    3. 计算观测 TTP 与每个 APT 已知 TTP 的相似度
    4. 返回相似度最高的 APT 作为归因结果
    
    相似度计算:
    - Jaccard: |A ∩ B| / |A ∪ B|
    - Recall:  |A ∩ B| / |B|
    - 综合:    0.6 * Jaccard + 0.4 * Recall
    """
    if not observed_ttps:
        return {"suspected_group": "Unclassified", "confidence": 0.0}
    
    observed_set = set(observed_ttps)
    best_match = None
    best_score = 0.0
    best_intersection = []
    
    for apt_name, profile in self.mitre_apt_profiles.items():
        known_ttps = set(profile.get("ttps", []))
        
        if not known_ttps:
            continue
        
        intersection = observed_set & known_ttps
        union = observed_set | known_ttps
        
        jaccard = len(intersection) / len(union) if union else 0
        recall = len(intersection) / len(known_ttps)
        
        score = 0.6 * jaccard + 0.4 * recall
        
        if score > best_score:
            best_score = score
            best_match = apt_name
            best_intersection = list(intersection)
    
    return {
        "suspected_group": best_match or "Unclassified",
        "confidence": round(best_score, 3),
        "observed_ttps": list(observed_set),
        "matched_ttps": best_intersection,
        "method": "TTP Jaccard + Recall"
    }
```

**归因结果示例**:

```json
{
  "suspected_group": "APT28",
  "confidence": 0.72,
  "observed_ttps": ["T1566.001", "T1059.001", "T1003", "T1021.002", "T1041"],
  "matched_ttps": ["T1566.001", "T1059.001", "T1003", "T1021.002"],
  "method": "TTP Jaccard + Recall"
}
```

### 4.6 IOC 情报富化 (三级级联查询)

**代码位置**: `analyzer/graph_analyzer/enrichment.py`

**核心功能**: 对攻击链中涉及的 IP、域名、文件哈希进行威胁情报查询。

**三级级联策略**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     IOC 情报富化三级级联                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  输入: IOC (IP / Domain / Hash)                                     │
│         │                                                           │
│         ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Level 1: 本地情报缓存 (Local Cache)                         │    │
│  │                                                             │    │
│  │ - 预置的高频威胁情报                                        │    │
│  │ - 内网地址白名单                                            │    │
│  │ - 靶场模拟数据                                              │    │
│  │                                                             │    │
│  │ 优势:                                                       │    │
│  │ - 微秒级响应                                                │    │
│  │ - 无需联网                                                  │    │
│  │ - 隐私保护                                                  │    │
│  │                                                             │    │
│  │ 数据格式:                                                   │    │
│  │ {                                                           │    │
│  │   "source": "local_custom",                                 │    │
│  │   "malicious": true,                                        │    │
│  │   "confidence_score": 95,                                   │    │
│  │   "tags": ["c2", "malware"],                                │    │
│  │   "first_seen": "2024-01-01",                               │    │
│  │   "last_seen": "2026-01-15",                                │    │
│  │   "associated_malware": ["Cobalt Strike"],                  │    │
│  │   "geo": { "country": "Russia", "city": "Moscow" }          │    │
│  │ }                                                           │    │
│  └─────────────────────────────────────────────────────────────┘    │
│         │                                                           │
│         │ 未命中                                                    │
│         ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Level 2: 外部威胁情报 API (External TI)                     │    │
│  │                                                             │    │
│  │ 集成源:                                                     │    │
│  │ - AbuseIPDB (IP 信誉查询)                                   │    │
│  │ - VirusTotal (多引擎扫描)                                   │    │
│  │                                                             │    │
│  │ 触发条件:                                                   │    │
│  │ - 本地未命中                                                │    │
│  │ - 配置允许联网 (api_enabled=True)                           │    │
│  │ - API Key 已配置                                            │    │
│  │                                                             │    │
│  │ 返回数据 (示例 - AbuseIPDB):                                │    │
│  │ {                                                           │    │
│  │   "source": "abuseipdb",                                    │    │
│  │   "malicious": true,                                        │    │
│  │   "confidence_score": 87,                                   │    │
│  │   "total_reports": 156,                                     │    │
│  │   "last_reported": "2026-01-14",                            │    │
│  │   "categories": ["SSH Brute Force", "Web Spam"],            │    │
│  │   "geo": { "country": "China", "isp": "Alibaba Cloud" }     │    │
│  │ }                                                           │    │
│  └─────────────────────────────────────────────────────────────┘    │
│         │                                                           │
│         │ 未命中 / API 不可用                                       │
│         ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Level 3: 启发式兜底 (Heuristic Fallback)                    │    │
│  │                                                             │    │
│  │ 逻辑:                                                       │    │
│  │ - 根据 IP 类型给出基础描述                                  │    │
│  │ - 内网地址 (10.x, 192.168.x) -> "internal_network"          │    │
│  │ - 保留地址 (127.x, 0.0.0.0) -> "reserved_address"           │    │
│  │ - 公网地址 -> "unknown_public_ip"                           │    │
│  │                                                             │    │
│  │ 返回数据:                                                   │    │
│  │ {                                                           │    │
│  │   "source": "heuristic",                                    │    │
│  │   "malicious": false,                                       │    │
│  │   "description": "Internal network address",                │    │
│  │   "recommendation": "Verify if this is expected traffic"    │    │
│  │ }                                                           │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**本地情报缓存示例**:

```python
# analyzer/graph_analyzer/enrichment.py

class IntelEnricher:
    def __init__(self):
        # 本地威胁情报缓存
        self.local_ti_cache = {
            # 已知 C2 服务器
            "45.33.2.1": {
                "source": "local_custom",
                "malicious": True,
                "confidence_score": 95,
                "tags": ["c2", "cobalt_strike"],
                "first_seen": "2024-06-15",
                "last_seen": "2026-01-10",
                "associated_malware": ["Cobalt Strike"],
                "geo": {"country": "Netherlands", "city": "Amsterdam"}
            },
            # 恶意域名
            "evil-domain.com": {
                "source": "local_custom",
                "malicious": True,
                "confidence_score": 90,
                "tags": ["phishing", "malware_distribution"],
                "first_seen": "2025-01-01",
                "geo": {"country": "Russia"}
            },
            # 内网白名单
            "192.168.1.1": {
                "source": "local_whitelist",
                "malicious": False,
                "description": "Internal gateway",
                "tags": ["internal", "infrastructure"]
            },
            # ... 更多条目
        }
```

**为什么需要三级级联？**

1.  **性能**: 本地缓存响应时间 < 1ms，外部 API 响应时间 100ms ~ 1s。
2.  **可用性**: 外部 API 可能因网络问题或配额限制不可用。
3.  **隐私**: 某些敏感环境不允许将 IOC 发送到外部服务。
4.  **成本**: 外部 API 通常有调用配额限制。

---

## 5. 本地 MITRE ATT&CK STIX 知识库

### 5.1 什么是 attack-stix-data？

TraceX 项目根目录下的 `attack-stix-data/` 文件夹是 **MITRE ATT&CK 官方知识库的本地克隆**。

**来源**: https://github.com/mitre-attack/attack-stix-data

**内容**: 以 STIX 2.1 JSON 格式表示的完整 ATT&CK 知识库，包括：
- **APT 组织 (Intrusion Set)**: 140+ 个已知 APT 组织的详细信息
- **攻击技术 (Attack Pattern)**: 700+ 种攻击技术和子技术
- **关系 (Relationship)**: APT 组织与其使用的技术之间的关联

**目录结构**:

```
attack-stix-data/
├── enterprise-attack/           # 企业环境 ATT&CK
│   ├── enterprise-attack.json   # 最新版 (当前使用)
│   ├── enterprise-attack-16.0.json
│   └── ...
├── mobile-attack/               # 移动设备 ATT&CK
├── ics-attack/                  # 工控系统 ATT&CK
├── index.json                   # 版本索引
└── README.md
```

### 5.2 为什么使用本地知识库而非在线 API？

| 方面 | 本地知识库 | 在线 API |
| :--- | :--- | :--- |
| **响应速度** | 微秒级 | 秒级 |
| **离线可用** | ✓ | ✗ |
| **数据完整性** | 完整数据 | 可能有限制 |
| **版本控制** | 可锁定版本 | 实时变化 |
| **隐私** | 不泄露查询内容 | 需发送数据 |

### 5.3 MITRELoader 模块

**代码位置**: `analyzer/graph_analyzer/mitre_loader.py`

**核心功能**: 解析本地 STIX JSON 文件，提供 APT 组织和技术的查询接口。

**数据加载流程**:

```python
class MITRELoader:
    def load(self, version: str = None):
        """
        加载 STIX 数据文件。
        
        文件路径: attack-stix-data/enterprise-attack/enterprise-attack.json
        
        解析内容:
        1. attack-pattern (攻击技术) -> 存入 self._techniques
        2. intrusion-set (APT 组织) -> 存入 self._groups
        3. relationship (关系) -> 建立 APT <-> 技术 的映射
        """
        filepath = os.path.join(
            self.stix_data_path, 
            self.domain, 
            f"{self.domain}.json"
        )
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        objects = data.get('objects', [])
        
        # 第一遍: 加载技术和组织
        for obj in objects:
            if obj.get('type') == 'attack-pattern':
                self._load_technique(obj)
            elif obj.get('type') == 'intrusion-set':
                self._load_group(obj)
        
        # 第二遍: 加载关系
        for obj in objects:
            if obj.get('type') == 'relationship':
                self._load_relationship(obj)
```

**查询接口示例**:

```python
# 创建加载器
loader = MITRELoader()
loader.load()

# 查询 APT28 组织信息
apt28 = loader.get_group_by_name("APT28")
print(apt28.name)       # "APT28"
print(apt28.aliases)    # ["Fancy Bear", "Sofacy", "STRONTIUM", ...]
print(apt28.techniques) # ["T1566", "T1059.001", "T1003", ...]

# 查询使用 T1059.001 (PowerShell) 的 APT 组织
groups = loader.get_groups_using_technique("T1059.001")
for g in groups:
    print(f"{g.name}: {len(g.techniques)} techniques")
```

### 5.4 与 IntelEnricher 的集成

`IntelEnricher` 在初始化时会自动加载 MITRE 知识库：

```python
class IntelEnricher:
    def __init__(self, mitre_stix_path: str = None):
        # 初始化 MITRE 加载器
        self.mitre_loader = MITRELoader(mitre_stix_path)
        self.mitre_loader.load()
        
        # 导出为归因用的字典格式
        self.mitre_apt_profiles = self.mitre_loader.export_apt_profiles_for_enrichment()
        
        # 示例: self.mitre_apt_profiles = {
        #   "APT28": {"name": "APT28", "aliases": [...], "ttps": ["T1566", ...]},
        #   "APT29": {"name": "APT29", "aliases": [...], "ttps": [...]},
        #   ...
        # }
```

---

## 6. 工程决策与技术取舍

### 6.1 为什么选择 Sigma 作为主力检测引擎，而非纯频率分析？

| 考量因素 | Sigma 规则 | 纯频率分析 (NODOZE) |
| :--- | :--- | :--- |
| **冷启动** | 无需历史数据 | 需要数周基线 |
| **准确性** | 精准匹配已知攻击 | 可能有高误报率 |
| **可解释性** | 规则明确，易于理解 | 统计学得分，需解读 |
| **覆盖范围** | 已知攻击 | 可发现未知攻击 |
| **维护成本** | 需更新规则库 | 需维护基线 |

**TraceX 的选择**:
- **主力**: Sigma 规则，利用社区维护的 3600+ 条规则，精准检测已知攻击模式。
- **辅助**: 保留 FrequencyAnalyzer 模块，用模拟基线展示 NODOZE 思想，输出惊奇度供分析师参考。

**未来改进方向**:
- 当系统部署到真实生产环境后，可收集正常行为日志，逐步建立真实基线。
- 届时，频率分析可从"辅助/演示"升级为"主力"之一。

### 6.2 为什么 ATLAS 只用于语义标签，不用于归因？

ATLAS 论文的完整实现包括：
1.  **词干提取 (Lemmatization)**: 将事件映射为语义标签 ✓ (TraceX 已实现)
2.  **序列学习 (LSTM)**: 学习正常序列，发现异常 ✗ (TraceX 未实现)
3.  **攻击故事生成**: 将异常路径翻译为人类可读描述 (部分实现)

**未实现 LSTM 的原因**:
- 需要大量训练数据 (正常行为日志)
- 需要 GPU 资源进行模型训练
- 黑盒模型，可解释性差

**TraceX 的替代方案**:
- 使用 **规则驱动** 的 ATLAS 标签，而非机器学习。
- 归因使用 **基于集合的 TTP 匹配**，可解释性强。

### 6.3 为什么使用本地 MITRE 知识库而非在线查询？

**本地知识库的优势**:
1.  **速度**: 本地查询 < 1ms，远程 API 100ms ~ 1s
2.  **可用性**: 不依赖网络，离线可用
3.  **一致性**: 版本锁定，结果可复现
4.  **隐私**: 不向外部泄露攻击特征

**更新策略**:
- 定期 `git pull` 更新 `attack-stix-data/` 目录
- 或手动下载指定版本的 STIX JSON 文件

---

## 7. 与教师任务书的对应关系

### 任务书要求 vs TraceX 实现

| 任务书要求 | TraceX 实现 | 代码位置 |
| :--- | :--- | :--- |
| 日志的时间序列对齐 | UnifiedEvent 统一时间戳格式 | `collector/common/schema.py` |
| 日志范式解析 | FieldMapper 将异构日志转为 ECS 格式 | `analyzer/attack_analyzer/field_mapper.py` |
| 关键信息提取 (用户、进程、文件) | GraphBuilder 提取实体并建立节点 | `analyzer/graph_analyzer/graph_builder.py` |
| 进程行为链分析 | spawned 边构建父子进程关系树 | `analyzer/graph_analyzer/graph_builder.py` |
| 文件操作监控 | read/write/delete 边记录文件操作 | `analyzer/graph_analyzer/graph_builder.py` |
| 内存行为分析 | memory_anomaly 节点记录异常 | `analyzer/graph_analyzer/graph_builder.py` |
| 网络会话重建 | network 节点 + connect 边 | `analyzer/graph_analyzer/graph_builder.py` |
| 基于 ATT&CK 的攻击链识别 | Sigma 规则命中 + TTP 标注 | `analyzer/attack_analyzer/` |
| 与已知 APT 组织匹配 | IntelEnricher + MITRE STIX | `analyzer/graph_analyzer/enrichment.py` |
| 多源数据时间线关联 | GraphBuilder 基于共享实体关联 | `analyzer/graph_analyzer/graph_builder.py` |
| 实体关系图构建 | GraphBuilder 输出 nodes + edges | `analyzer/graph_analyzer/graph_builder.py` |
| 攻击路径重建 | ProvenanceSystem 双向遍历 | `analyzer/graph_analyzer/provenance_system.py` |
| C2 服务器分析 | IntelEnricher IOC 富化 | `analyzer/graph_analyzer/enrichment.py` |
| 与已知 APT 组织 TTP 匹配 | attribute_by_ttps() | `analyzer/graph_analyzer/enrichment.py` |

---

## 8. 总结与未来展望

### 8.1 TraceX 分析引擎核心能力总结

TraceX 的 `analyzer/graph_analyzer` 模块通过融合多篇顶会论文的思想，实现了：

1.  **自动化攻击链重建**:
    - 基于 SLEUTH 的因果图构建
    - 基于 NODOZE 的上下文回溯
    - 输出完整的攻击路径子图

2.  **多维度异常检测**:
    - Sigma 规则引擎 (精准匹配已知攻击)
    - 频率分析 (发现未知异常，模拟演示)

3.  **智能威胁归因**:
    - 基于 SHADEWATCHER 的推荐系统思想
    - 利用 MITRE ATT&CK STIX 知识库
    - 输出可解释的归因结果

4.  **全面的情报富化**:
    - 三级级联查询 (本地 -> API -> 启发式)
    - 丰富的威胁上下文

### 8.2 未来改进方向

1.  **真实基线建立**:
    - 部署到生产环境后，收集正常行为日志
    - 建立真实的频率基线，使 FrequencyAnalyzer 从"演示"升级为"生产"

2.  **图嵌入与深度学习**:
    - 引入 Graph2Vec 或 GNN 进行图级别的异常检测
    - 实现 PROGRAPHER 论文的思想

3.  **大语言模型集成**:
    - 参考 LogGPT/HuntGPT，利用 LLM 生成人类可读的攻击故事
    - 提供自然语言的归因解释

4.  **实时流处理**:
    - 将批处理改为流处理 (如 Kafka + Flink)
    - 实现真正的实时攻击检测

---

## 附录: 参考论文列表

1.  **SLEUTH**: Real-time Attack Scenario Reconstruction from COTS Audit Data (USENIX Security)
2.  **ATLAS**: A Sequence-based Learning Approach for Attack Investigation (USENIX Security)
3.  **NODOZE**: Combatting Threat Alert Fatigue with Automated Provenance Triage (NDSS)
4.  **SHADEWATCHER**: Recommendation-guided Cyber Threat Analysis (USENIX Security)
5.  **SPADE**: Support for Provenance Auditing in Distributed Environments (Middleware)
6.  **PROVDETECTOR**: Hunting Stealthy Malware via Data Provenance Analysis (NDSS)
7.  **PROGRAPHER**: An Anomaly Detection System based on Provenance Graph Embedding (IEEE S&P)
8.  **LogGPT**: Exploring ChatGPT for Log-Based Anomaly Detection
9.  **HuntGPT**: Integrating ML-Based Anomaly Detection and XAI with LLMs

---

*本文档由 TraceX 项目组员 4 编写，用于阐述 analyzer/graph_analyzer 模块的设计思想与算法溯源。*
