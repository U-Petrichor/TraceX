# APT 攻击链分析测试模块

本模块提供 APT 攻击链的完整验证流程，支持两种分析模式。

---

## 目录结构

```
analyzer/test/
├── README.md                      # 本文档
├── generate_events_with_ttp.py    # 模式1: 生成直接带 TTP 的事件
├── generate_events_for_sigma.py   # 模式2: 生成仿真事件 (需 Sigma 检测)
├── run_apt_pipeline.py            # 统一分析流水线
└── apt_events/
    ├── direct/                    # 直接 TTP 事件数据
    │   ├── APT28.jsonl
    │   ├── APT29.jsonl
    │   ├── FIN7.jsonl
    │   ├── Indrik_Spider.jsonl
    │   └── LuminousMoth.jsonl
    └── sigma/                     # 仿真事件数据 (需 Sigma 检测)
        ├── APT28.jsonl
        ├── APT29.jsonl
        ├── FIN7.jsonl
        ├── Indrik_Spider.jsonl
        └── LuminousMoth.jsonl
```

---

## 两种模式说明

### 模式 1: 直接 TTP (`--mode direct`)

- **事件特点**: 每个事件已包含 `threat.technique.id` 字段
- **用途**: 快速验证归因逻辑、IOC 富化、APT Profile 输出
- **跳过**: Sigma 规则检测
- **适用场景**: 开发调试、演示

### 模式 2: Sigma 检测 (`--mode sigma`)

- **事件特点**: 仿真真实攻击事件，不含 TTP 标签
- **用途**: 验证完整流程（事件 → Sigma 检测 → TTP → 归因）
- **包含**: Sigma 规则匹配、命中规则输出
- **适用场景**: 完整流程验证、Sigma 规则有效性测试

---

## 使用方法

### 1. 生成测试数据

```powershell
# 设置 PYTHONPATH (Windows)
$env:PYTHONPATH="E:\Code\python\TraceX"

# 生成直接 TTP 事件
python .\analyzer\test\generate_events_with_ttp.py

# 生成仿真事件 (需 Sigma 检测)
python .\analyzer\test\generate_events_for_sigma.py
```

### 2. 运行分析流水线

```powershell
# 分析所有直接 TTP 事件
python .\analyzer\test\run_apt_pipeline.py --mode direct

# 分析所有仿真事件 (Sigma 检测)
python .\analyzer\test\run_apt_pipeline.py --mode sigma

# 分析指定 APT 文件
python .\analyzer\test\run_apt_pipeline.py --mode direct --data APT28.jsonl
python .\analyzer\test\run_apt_pipeline.py --mode sigma --data Indrik_Spider.jsonl
```

---

## 分析流程

无论哪种模式，分析流程一致：

```
┌─────────────────────────────────────────────────────────────────┐
│                        事件输入 (JSONL)                          │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                 1. 构图 (GraphBuilder)                           │
│   - 生成节点: process / file / network / authentication / host  │
│   - 生成边: spawned / read / write / connect_outbound / ...     │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                 2. ATLAS 签名 (语义描述)                         │
│   - 给事件打语义标签 (DOWNLOAD_AND_EXECUTE, SENSITIVE_FILE...)  │
│   - 生成攻击链签名 (仅用于可读性，不参与归因)                    │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                 3. TTP 提取                                      │
│   - 模式 direct: 从 threat.technique.id 直接提取                │
│   - 模式 sigma: 使用 Sigma 规则检测生成 TTP                      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                 4. TTP 归因 (IntelEnricher)                      │
│   - 计算 TTP 与 APT 组织的相似度 (Jaccard + Recall)              │
│   - 输出: suspected_group, confidence, matched_ttps             │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                 5. APT Profile 输出                              │
│   - 查询 MITRE STIX 真实数据                                     │
│   - 输出: name, aliases, ttps, target_industries                │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                 6. IOC 富化 (IntelEnricher)                      │
│   - 从图节点提取 IP/域名                                         │
│   - 查询本地库 / 外部 API (AbuseIPDB, VirusTotal)                │
│   - 输出: risk_score, tags, geo, is_malicious                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 输出示例

```
======================================================================
APT 模拟: Indrik_Spider
模式: 直接 TTP
事件数: 10 | 节点数: 15 | 边数: 8

【1. 攻击链签名 (ATLAS)】
  DOWNLOAD_AND_EXECUTE -> MASQUERADE -> SENSITIVE_FILE

【2. 攻击链条结构 (节点 -> 边 -> 节点)】
  [process] powershell.exe --spawned--> [process] net.exe
  [process] net.exe --spawned--> [process] wmic.exe
  [process] powershell.exe --write--> [file] evil.ps1
  [host] PC-1 --host_network--> [network] smb:192.168.1.20:445

【3. TTP 归因结果】
{
  "suspected_group": "Indrik Spider",
  "confidence": 0.791,
  "matched_ttps": ["T1078", "T1047", "T1059.001", ...]
}

【4. APT Profile】
{
  "name": "Indrik Spider",
  "aliases": ["Evil Corp", "Manatee Tempest", "DEV-0243", "UNC2165"],
  "ttps": ["T1489", "T1136.001", ...]
}

【5. IOC 富化结果】
{
  "45.33.2.1": {"type": "ip", "risk_score": 90, "tags": ["C2", "Botnet"], ...}
}
```

---

## 支持的 APT 组织

| 组织名称 | 别名 | 主要 TTP |
|---------|------|----------|
| APT28 | Fancy Bear, Sofacy | T1078, T1110.003, T1036.005, ... |
| APT29 | Cozy Bear, NOBELIUM | T1070.004, T1059.001, T1587.001, ... |
| FIN7 | Carbon Spider, ELBRUS | T1059.001, T1047, T1486, ... |
| Indrik Spider | Evil Corp, UNC2165 | T1078, T1059.001, T1486, T1484.001, ... |
| LuminousMoth | - | T1036.005, T1574.001, T1005, ... |

---

## 常见问题

### Q: Sigma 模式检测不到 TTP？

A: 可能原因：
1. 本地 Sigma 规则库不完整
2. 事件字段与规则不匹配
3. 事件的 `event.dataset` 未正确设置

解决：检查 `analyzer/attack_analyzer/sigma_rules/` 目录下是否有对应规则。

### Q: IOC 富化结果都是 local_custom？

A: 正常。测试数据中的 IP 都在本地库中预设了，不会触发外部 API。  
如需测试外部 API，请使用未在本地库中的公网 IP。

### Q: 归因结果不是预期的 APT？

A: TTP 归因基于相似度计算，如果事件中的 TTP 与多个 APT 组织重叠，可能会归因到其他组织。  
建议：使用直接 TTP 模式 (`--mode direct`) 确保 TTP 精确匹配。

---

## 扩展

### 添加新的 APT 组织

1. 在 `generate_events_with_ttp.py` 的 `APT_TTPS` 字典中添加 TTP 列表
2. 在 `generate_events_for_sigma.py` 中添加对应的攻击链函数
3. 重新生成数据

### 添加新的 IOC

在 `analyzer/graph_analyzer/enrichment.py` 的 `local_ti_cache` 中添加条目。
