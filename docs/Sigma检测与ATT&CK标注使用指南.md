# Sigma 检测与 ATT&CK 标注使用指南

## 一、系统概述

本系统基于 **Sigma 规则** 对 Elasticsearch 中的 ECS 格式日志进行威胁检测，并自动标注 **MITRE ATT&CK** 技术节点（T-node），最终生成攻击链视图。

### 整体架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Elasticsearch                                  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  unified-logs-*  │  network-flows-*  │  其他索引                   │  │
│  │  (auditd 日志)   │  (zeek 流量)      │  (cowrie 蜜罐等)           │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ 查询 ECS 数据
┌─────────────────────────────────────────────────────────────────────────┐
│                        AttackAnalyzer 分析器                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │ RuleLoader  │  │ FieldMapper │  │ SigmaEngine │  │ ATTACKTagger    │ │
│  │ 加载 3600+  │→ │ ECS→Sigma   │→ │ 规则匹配    │→ │ 标注 T-node     │ │
│  │ Sigma 规则  │  │ 字段映射    │  │             │  │                 │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ 输出带标注的事件
┌─────────────────────────────────────────────────────────────────────────┐
│  带 ATT&CK 标注的 ECS 事件                                               │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ { "@timestamp": "...", "process": {...},                          │  │
│  │   "threat": { "tactic": {...}, "technique": {...} },             │  │
│  │   "detection": { "rules": [...], "severity": "..." } }           │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 二、核心模块说明

### 2.1 模块文件结构

```
analyzer/attack_analyzer/
├── __init__.py          # 模块导出
├── rule_loader.py       # Sigma 规则加载器
├── field_mapper.py      # ECS 到 Sigma 字段映射器
├── sigma_engine.py      # Sigma 匹配引擎核心
├── attack_tagger.py     # ATT&CK T-node 标注器
└── rules/               # Sigma 规则库 (3600+ 条规则)
    ├── linux/           # Linux 相关规则
    ├── windows/         # Windows 相关规则
    ├── network/         # 网络相关规则
    └── ...
```

### 2.2 各模块功能

| 模块 | 类 | 功能 |
|------|-----|------|
| `rule_loader.py` | `RuleLoader` | 加载并解析 Sigma YAML 规则文件 |
| `field_mapper.py` | `FieldMapper` | 将 ECS 字段映射为 Sigma 标准字段 |
| `field_mapper.py` | `EventNormalizer` | 自动识别事件类型并选择映射方式 |
| `sigma_engine.py` | `SigmaMatchEngine` | 执行 Sigma 规则匹配逻辑 |
| `sigma_engine.py` | `SigmaDetector` | 高级检测接口 |
| `attack_tagger.py` | `ATTACKTagger` | 将检测结果转为 ATT&CK T-node |
| `attack_tagger.py` | `AttackAnalyzer` | 整合所有功能的主接口 |

---

## 三、完整使用流程

### 3.1 方式一：从 Elasticsearch 提取数据并检测

```python
#!/usr/bin/env python3
"""
完整流程示例：从 ES 提取数据 → Sigma 检测 → ATT&CK 标注
"""
import json
from elasticsearch import Elasticsearch

# 导入攻击分析器
from analyzer.attack_analyzer import AttackAnalyzer

# ========== 步骤 1: 连接 Elasticsearch ==========
es = Elasticsearch(["http://localhost:9200"])

if not es.ping():
    print("无法连接 Elasticsearch")
    exit(1)

print("✓ 已连接 Elasticsearch")

# ========== 步骤 2: 初始化攻击分析器 ==========
analyzer = AttackAnalyzer()
init_result = analyzer.initialize()

print(f"✓ 已加载 {init_result['rules_loaded']} 条 Sigma 规则")

# ========== 步骤 3: 从 ES 查询事件数据 ==========
query = {
    "query": {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": "now-1h"}}}  # 最近1小时
            ],
            "should": [
                {"term": {"event.dataset": "auditd"}},
                {"term": {"event.dataset": "zeek.conn"}},
                {"term": {"event.category": "process"}}
            ],
            "minimum_should_match": 1
        }
    },
    "size": 1000,
    "sort": [{"@timestamp": "desc"}]
}

result = es.search(index="unified-logs-*", body=query)
events = [hit["_source"] for hit in result["hits"]["hits"]]

print(f"✓ 获取到 {len(events)} 条事件")

# ========== 步骤 4: 批量检测分析 ==========
def progress_callback(processed, total, detected):
    print(f"\r  处理进度: {processed}/{total} (检测到 {detected} 个威胁)", end="")

report = analyzer.analyze_batch(events, progress_callback=progress_callback)
print()

# ========== 步骤 5: 输出结果 ==========
print(f"\n========== 检测结果 ==========")
print(f"分析事件数: {report['analyzed_events']}")
print(f"检测到威胁: {report['detected_events']}")
print(f"检测率: {report['detection_rate']}%")

# 攻击摘要
summary = report['attack_summary']
print(f"\n风险等级: {summary['risk_level'].upper()}")
print(f"检测到 {summary['total_techniques']} 种 ATT&CK 技术")

# 攻击链
print(f"\n========== ATT&CK 攻击链 ==========")
chain = analyzer.get_attack_chain()
for stage in chain:
    print(f"\n[{stage['stage']}] {stage['tactic_name']}")
    for tech in stage['techniques']:
        print(f"  └─ {tech['id']}: {tech['name']} ({tech['event_count']} 事件)")

# ========== 步骤 6: 将标注后的事件写回 ES (可选) ==========
tagged_events = []
for det in report['detailed_results']:
    event_id = det['event_id']
    # 找到原始事件
    original = next((e for e in events if e.get('event', {}).get('id') == event_id), None)
    if original:
        tagged = analyzer.export_to_unified_format(original, det)
        tagged_events.append(tagged)

# 写入新索引
for tagged in tagged_events:
    es.index(index="attack-events-2026.01.13", document=tagged)

print(f"\n✓ 已将 {len(tagged_events)} 条标注事件写入 attack-events 索引")
```

### 3.2 方式二：分析单个事件

```python
from analyzer.attack_analyzer import AttackAnalyzer

# 初始化
analyzer = AttackAnalyzer()
analyzer.initialize()

# 单个 ECS 事件
event = {
    "@timestamp": "2026-01-13T12:00:00.000Z",
    "process": {
        "name": "malware",
        "pid": 99999,
        "executable": "/tmp/malware"
    },
    "raw": {
        "type": "SYSCALL",
        "data": "exe=\"/tmp/malware\" key=\"process_exec\""
    },
    "event": {
        "id": "12345",
        "category": "process",
        "dataset": "auditd"
    }
}

# 分析
result = analyzer.analyze_event(event)

if result['detected']:
    print(f"⚠️ 检测到威胁!")
    print(f"匹配规则: {result['matched_rules']}")
    
    for tech in result['techniques']:
        print(f"ATT&CK 技术: {tech['technique']['id']} - {tech['technique']['name']}")
        print(f"ATT&CK 战术: {tech['tactic']['id']} - {tech['tactic']['name']}")
else:
    print("✓ 未检测到威胁")
```

---

## 四、数据格式说明

### 4.1 输入格式 (ECS 事件)

```json
{
    "@timestamp": "2026-01-13T12:40:48.552Z",
    "ecs": { "version": "1.12.0" },
    
    "host": {
        "hostname": "server01",
        "ip": ["172.20.0.4"],
        "os": { "name": "Ubuntu", "family": "linux" }
    },
    
    "process": {
        "pid": 1195434,
        "name": "tail",
        "executable": "/usr/bin/tail",
        "user": { "id": "0", "name": "root" }
    },
    
    "event": {
        "id": "1091378",
        "category": "process",
        "dataset": "auditd"
    },
    
    "raw": {
        "type": "SYSCALL",
        "data": "exe=\"/usr/bin/tail\" key=\"process_exec\"..."
    }
}
```

### 4.2 输出格式 (带 ATT&CK 标注)

```json
{
    "@timestamp": "2026-01-13T12:00:00.000Z",
    
    "host": { "..." },
    "process": { "..." },
    "event": { "..." },
    "raw": { "..." },
    
    "threat": {
        "framework": "MITRE ATT&CK",
        "tactic": {
            "id": "TA0005",
            "name": "Defense Evasion"
        },
        "technique": {
            "id": "T1036",
            "name": "Masquerading"
        }
    },
    
    "detection": {
        "rules": ["Potentially Suspicious Execution From Tmp Folder"],
        "confidence": 0.6,
        "severity": "medium"
    }
}
```

### 4.3 攻击链输出格式

```json
{
    "attack_chain": [
        {
            "stage": "TA0043",
            "tactic_name": "Reconnaissance",
            "techniques": [
                {"id": "T1592.004", "name": "Client Configurations", "event_count": 1}
            ]
        },
        {
            "stage": "TA0002",
            "tactic_name": "Execution",
            "techniques": [
                {"id": "T1059", "name": "Command and Scripting Interpreter", "event_count": 1}
            ]
        }
    ]
}
```

---

## 五、字段映射对照表

### 5.1 ECS → Sigma 字段映射

| ECS 字段 | Sigma 字段 | 说明 |
|----------|-----------|------|
| `process.executable` | `Image` | 可执行文件路径 |
| `process.name` | `ProcessName` | 进程名 |
| `process.command_line` | `CommandLine` | 命令行 |
| `process.pid` | `ProcessId` | 进程 ID |
| `process.user.name` | `User` | 用户名 |
| `source.ip` | `id.orig_h` | 源 IP (Zeek) |
| `destination.ip` | `id.resp_h` | 目标 IP (Zeek) |
| `destination.port` | `id.resp_p` | 目标端口 (Zeek) |

### 5.2 Sigma 匹配修饰符

| 修饰符 | 含义 | 示例 |
|--------|------|------|
| `|startswith` | 以...开头 | `Image|startswith: '/tmp/'` |
| `|endswith` | 以...结尾 | `Image|endswith: '/base64'` |
| `|contains` | 包含 | `CommandLine|contains: '--donate-level'` |
| `|re` | 正则匹配 | `CommandLine|re: '.*evil.*'` |

---

## 六、常见使用场景

### 6.1 实时告警

```python
# 持续监控新事件
while True:
    new_events = fetch_new_events_from_es()
    for event in new_events:
        result = analyzer.analyze_event(event)
        if result['detected']:
            send_alert(result)
    time.sleep(60)
```

### 6.2 批量历史分析

```python
# 分析过去 24 小时的日志
events = query_es_events(time_range="24h")
report = analyzer.analyze_batch(events)
save_report_to_file(report)
```

### 6.3 特定攻击技术搜索

```python
# 只关注特定战术的检测
for node in analyzer.tagger.get_nodes_by_tactic("TA0040"):  # Impact
    print(f"发现 Impact 攻击: {node.technique_id}")
```

---

## 七、运行测试

### 7.1 本地测试（无需 ES）

```bash
cd /path/to/TraceX
python tests/test_local_sigma.py
```

### 7.2 连接 ES 测试

```bash
python tests/test_attack_analyzer.py
```

### 7.3 调试规则匹配

```bash
python tests/debug_sigma.py
```

---

## 八、注意事项

1. **首次加载慢**：3600+ 条规则首次加载需要几秒钟
2. **规则覆盖**：大部分规则是 Windows 规则，Linux 规则约 200+ 条
3. **误报处理**：部分规则可能产生误报，建议根据实际环境调整置信度阈值
4. **性能优化**：批量处理时建议分批查询，避免单次处理过多事件

---

## 九、API 快速参考

```python
from analyzer.attack_analyzer import AttackAnalyzer

# 创建分析器
analyzer = AttackAnalyzer()

# 初始化（加载规则）
analyzer.initialize() -> Dict

# 分析单个事件
analyzer.analyze_event(event: Dict) -> Dict

# 批量分析
analyzer.analyze_batch(events: List[Dict]) -> Dict

# 获取攻击链
analyzer.get_attack_chain() -> List[Dict]

# 导出带标注的事件
analyzer.export_to_unified_format(event, result) -> Dict

# 获取攻击摘要
analyzer.tagger.get_attack_summary() -> Dict
```

---

**文档版本**: 1.0  
**更新日期**: 2026-01-13  
**作者**: TraceX 项目组
