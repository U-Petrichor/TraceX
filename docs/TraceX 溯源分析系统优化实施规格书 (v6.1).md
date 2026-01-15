
### 1. 优化目标

- **解决断链**：引入父进程（PPID）回溯与文件名/Inode 模糊关联，确保攻击链完整性。
    
- **优化归因**：引入 Jaccard + Recall 加权算法，提高在证据不全时的识别准确度。
    
- **语义对齐**：将 ATLAS 标签与 MITRE TTP 深度绑定，作为归因的标准化输入。
    

---

### 2. 模块详细修改指令

#### **模块 A: `analyzer/attack_analyzer/context_engine.py` (关联引擎优化)**

**修改任务**：由“精确匹配”升级为“因果+空间模糊关联”。

- **修改函数**：`find_related_events(self, anchor: UnifiedEvent, window: int = 30)`。
    
- **逻辑规格**：
    
    1. **时间窗扩展**：将默认搜索窗口从 10s 提升至 30s 以应对 ES 写入延迟。
        
    2. **因果回溯 (PPID)**：
        
        - 查询满足 `process.parent.pid == anchor.process.pid` 的事件（寻找子进程）。
            
        - 查询满足 `process.pid == anchor.process.ppid` 的事件（寻找父进程）。
            
    3. **空间模糊关联 (File Staging)**：
        
        - 若 `anchor.file.path` 包含 `/dev/shm/`, `/tmp/`, 或 `/var/www/` 等路径，提取其 `basename`。
            
        - 在同一主机 (`host.name`) 内，搜索 30s 内操作过该 `basename` 的所有进程事件。
            
    4. **网络对齐**：搜索同一时间内，源 IP 为该主机 IP 的所有网络流记录（Zeek 数据）。
        

#### **模块 B: `analyzer/graph_analyzer/graph_builder.py` (图构建逻辑增强)**

**修改任务**：支持异常节点挂载与 PID 复用防误判。

- **修改函数**：`_process_event(self, event)`。
    
- **逻辑规格**：
    
    1. **异常节点挂载**：检测到 `event.category == "memory"` 时，生成 `type: "memory_anomaly"` 节点。
        
    2. **强制连边**：使用 `event.process.pid` + `event.host.name` 生成对应的进程 ID，创建一条关系为 `triggered_anomaly` 的边，连接进程节点与异常节点。
        
    3. **PIDCache 鲁棒性**：生成节点 ID 时，若 `start_time` 缺失，必须调用 `self.pid_cache.get_start_time` 获取，严禁直接使用当前时间戳。
        

#### **模块 C: `analyzer/graph_analyzer/atlas_mapper.py` (语义标签库升级)**

**修改任务**：引入动作描述与 TTP 绑定映射。

- **修改变量**：`self.patterns` 列表。
    
- **逻辑规格**：将规则库扩展为四元组格式：`(正则表达式, 标签名, 风险等级, 关联TTP_ID)`。
    
    - `r".*wget.*|.*curl.*\|.*bash.*"` -> `DOWNLOAD_AND_EXECUTE`, Severity: 9, TTP: `T1105`。
        
    - `r"^/dev/shm/.*"` -> `IN_MEMORY_STAGING`, Severity: 7, TTP: `T1027.004`。
        
    - `r".*nc\s+-e\s+/bin/.*"` -> `REVERSE_SHELL`, Severity: 10, TTP: `T1059.004`。
        

#### **模块 D: `analyzer/graph_analyzer/enrichment.py` (加权归因算法)**

**修改任务**：实现 Recall 优先的相似度评分模型。

- **修改函数**：`attribute_by_ttps(self, detected_ttps: List[str])`。
    
- **逻辑规格**：
    
    1. **输入清洗**：将传入的 `detected_ttps` 去重并过滤空值。
        
    2. **得分计算公式**：
        
        Score=0.3×∣Detected∪Group∣∣Detected∩Group∣​+0.7×∣Group∣∣Detected∩Group∣​
        
        _(注：0.3 为 Jaccard 相似度权重，0.7 为 Recall 召回率权重，以应对攻击者隐藏行为的情况)_。
        
    3. **时序权重 (可选额外分)**：如果检测到的 TTP 中包含 `T1071` (C2) 或 `T1041` (数据外泄)，额外给予 1.1 倍的分数提升。
        

---

### 3. 系统集成与验证流程

1. **环境对齐**：确保 `mem_scanner` 部署在代码预期的 `collector/host_collector/mem_scanner/bin/scanner`。
    
2. **数据注入**：
    
    - 执行内存模拟攻击脚本 `test_host_collector_memory_attack.py`。
        
    - 执行复合指令：`cat /etc/passwd > /dev/shm/.hidden && mv /dev/shm/.hidden /var/www/html/pass.php`。
        
3. **运行验证**：
    
    - 运行 `python3 tools/verify_final.py`。
        
    - **预期指标**：
        
        - **节点数**：应从 2 个增加到 6 个以上（包含 Shell、cat、mv、MemoryAnomaly 节点）。
            
        - **归因结果**：置信度评分应显著超过 0.6，且能识别出模拟的 APT 组织名称。
            

### 4. 关键避坑指南

- **ES 刷新**：ES 索引刷新有延迟，代码中查询前需增加 `refresh` 调用或等待 1-2 秒。
    
- **Host 对齐**：确保 `host.name` 字段在所有日志中一致（使用 `socket.gethostname()`），否则跨源关联会失效。
    

---

**下一步**：只需将此规格书提供给开发人员或 AI，即可在不改变现有架构的前提下完成逻辑注入。