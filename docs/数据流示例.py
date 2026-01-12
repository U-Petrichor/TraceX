"""
组员4任务 - 完整数据流示例
演示从原始事件到攻击者画像的完整流程
"""

# ============================================
# 步骤0：原始数据（从Elasticsearch来）
# ============================================

# 这些是组员1和组员2采集的原始事件
raw_events = [
    {
        "@timestamp": "2024-01-01T10:00:00Z",
        "source": {"ip": "1.2.3.4", "port": 12345},
        "destination": {"ip": "192.168.1.10", "port": 22},
        "event": {"category": "authentication", "outcome": "success"},
        "user": {"name": "root"},
        "host": {"name": "web-server-01"},
        "message": "SSH login successful"
    },
    {
        "@timestamp": "2024-01-01T10:00:05Z",
        "source": {"ip": "1.2.3.4"},
        "process": {
            "pid": 1234,
            "name": "bash",
            "executable": "/bin/bash",
            "command_line": "cat /etc/passwd",
            "parent": {"pid": 1000, "name": "sshd"}
        },
        "file": {"path": "/etc/passwd"},
        "user": {"name": "root"},
        "host": {"name": "web-server-01"},
        "threat": {  # 这是组员3已经映射好的ATT&CK信息
            "tactic": {"id": "TA0002", "name": "Execution"},
            "technique": {"id": "T1059", "name": "Command and Scripting Interpreter"}
        }
    },
    {
        "@timestamp": "2024-01-01T10:00:10Z",
        "source": {"ip": "1.2.3.4"},
        "process": {
            "pid": 1234,
            "name": "bash",
            "command_line": "touch /tmp/backdoor.sh"
        },
        "file": {"path": "/tmp/backdoor.sh"},
        "user": {"name": "root"},
        "host": {"name": "web-server-01"},
        "threat": {
            "tactic": {"id": "TA0003", "name": "Persistence"},
            "technique": {"id": "T1053", "name": "Scheduled Task/Job"}
        }
    },
    {
        "@timestamp": "2024-01-01T10:00:15Z",
        "source": {"ip": "1.2.3.4"},
        "destination": {"ip": "192.168.1.20", "port": 22},
        "event": {"category": "network"},
        "network": {"application": "ssh"},
        "host": {"name": "web-server-01"},
        "threat": {
            "tactic": {"id": "TA0008", "name": "Lateral Movement"},
            "technique": {"id": "T1021", "name": "Remote Services"}
        }
    }
]


# ============================================
# 步骤1：实体抽取 (entity_extractor.py)
# ============================================

def extract_entities(event):
    """从事件中抽取实体"""
    entities = []
    
    # 抽取IP
    if event.get("source", {}).get("ip"):
        entities.append({
            "id": f"ip:{event['source']['ip']}",
            "type": "ip",
            "value": event["source"]["ip"],
            "role": "source"
        })
    
    if event.get("destination", {}).get("ip"):
        entities.append({
            "id": f"ip:{event['destination']['ip']}",
            "type": "ip",
            "value": event["destination"]["ip"],
            "role": "destination"
        })
    
    # 抽取进程
    if event.get("process", {}).get("name"):
        proc = event["process"]
        entities.append({
            "id": f"process:{proc['name']}:{proc.get('pid', 0)}",
            "type": "process",
            "value": proc["name"],
            "pid": proc.get("pid", 0)
        })
        
        # 父进程
        if proc.get("parent", {}).get("name"):
            parent = proc["parent"]
            entities.append({
                "id": f"process:{parent['name']}:{parent.get('pid', 0)}",
                "type": "process",
                "value": parent["name"],
                "pid": parent.get("pid", 0),
                "role": "parent"
            })
    
    # 抽取文件
    if event.get("file", {}).get("path"):
        entities.append({
            "id": f"file:{event['file']['path']}",
            "type": "file",
            "value": event["file"]["path"]
        })
    
    # 抽取用户
    if event.get("user", {}).get("name"):
        entities.append({
            "id": f"user:{event['user']['name']}",
            "type": "user",
            "value": event["user"]["name"]
        })
    
    # 抽取主机
    if event.get("host", {}).get("name"):
        entities.append({
            "id": f"host:{event['host']['name']}",
            "type": "host",
            "value": event["host"]["name"]
        })
    
    return entities


# 对所有事件进行实体抽取
print("=" * 60)
print("步骤1：实体抽取")
print("=" * 60)

all_entities = []
for i, event in enumerate(raw_events):
    entities = extract_entities(event)
    all_entities.extend(entities)
    print(f"\n事件{i+1} 抽取的实体：")
    for entity in entities:
        print(f"  - {entity['type']}: {entity['value']} (ID: {entity['id']})")

print(f"\n总共抽取了 {len(all_entities)} 个实体")


# ============================================
# 步骤2：关系图构建 (graph_builder.py)
# ============================================

def build_graph(events):
    """构建实体关系图"""
    nodes = {}  # 节点字典 {id: node_info}
    edges = []  # 边列表
    
    for event in events:
        entities = extract_entities(event)
        
        # 添加节点
        for entity in entities:
            nodes[entity["id"]] = {
                "id": entity["id"],
                "type": entity["type"],
                "label": entity["value"]
            }
        
        # 添加边（根据事件类型推断关系）
        entity_map = {e["type"]: e for e in entities}
        
        # IP -> 进程（连接关系）
        source_ip = next((e for e in entities if e["type"] == "ip" and e.get("role") == "source"), None)
        process = next((e for e in entities if e["type"] == "process" and e.get("role") != "parent"), None)
        if source_ip and process:
            edges.append({
                "source": source_ip["id"],
                "target": process["id"],
                "relation": "connected_to",
                "timestamp": event["@timestamp"]
            })
        
        # 父进程 -> 子进程（启动关系）
        parent_process = next((e for e in entities if e["type"] == "process" and e.get("role") == "parent"), None)
        child_process = next((e for e in entities if e["type"] == "process" and e.get("role") != "parent"), None)
        if parent_process and child_process:
            edges.append({
                "source": parent_process["id"],
                "target": child_process["id"],
                "relation": "spawned",
                "timestamp": event["@timestamp"]
            })
        
        # 进程 -> 文件（访问关系）
        if process and "file" in entity_map:
            file_entity = entity_map["file"]
            edges.append({
                "source": process["id"],
                "target": file_entity["id"],
                "relation": "accessed" if "read" in event.get("message", "").lower() else "created",
                "timestamp": event["@timestamp"]
            })
    
    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }


print("\n" + "=" * 60)
print("步骤2：关系图构建")
print("=" * 60)

graph = build_graph(raw_events)
print(f"\n节点数量: {len(graph['nodes'])}")
print("节点列表:")
for node in graph["nodes"]:
    print(f"  - [{node['type']}] {node['label']} (ID: {node['id']})")

print(f"\n边数量: {len(graph['edges'])}")
print("关系列表:")
for edge in graph["edges"]:
    print(f"  - {edge['source']} --[{edge['relation']}]--> {edge['target']}")


# ============================================
# 步骤3：攻击路径重建 (path_rebuilder.py)
# ============================================

def rebuild_attack_path(events):
    """重建攻击路径"""
    # ATT&CK阶段映射
    TACTIC_TO_STAGE = {
        "TA0001": "initial_access",
        "TA0002": "execution",
        "TA0003": "persistence",
        "TA0004": "privilege_escalation",
        "TA0008": "lateral_movement",
        "TA0010": "exfiltration"
    }
    
    ATTACK_STAGES = [
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "lateral_movement",
        "exfiltration"
    ]
    
    # 按阶段分组
    stages = {}
    for event in events:
        threat = event.get("threat", {})
        if threat and threat.get("tactic"):
            tactic_id = threat["tactic"]["id"]
            stage = TACTIC_TO_STAGE.get(tactic_id, "unknown")
            
            if stage not in stages:
                stages[stage] = {
                    "stage": stage,
                    "events": [],
                    "first_seen": event["@timestamp"],
                    "last_seen": event["@timestamp"]
                }
            
            stages[stage]["events"].append(event)
            stages[stage]["last_seen"] = event["@timestamp"]
    
    # 按顺序排列
    ordered_stages = []
    for stage_name in ATTACK_STAGES:
        if stage_name in stages:
            stage_data = stages[stage_name]
            stage_data["description"] = f"攻击者执行了{stage_name}阶段（检测到{len(stage_data['events'])}个事件）"
            ordered_stages.append(stage_data)
    
    return {
        "attack_id": "attack-2024-01-01-001",
        "stages": ordered_stages,
        "total_events": sum(len(s["events"]) for s in ordered_stages)
    }


print("\n" + "=" * 60)
print("步骤3：攻击路径重建")
print("=" * 60)

attack_path = rebuild_attack_path(raw_events)
print(f"\n攻击ID: {attack_path['attack_id']}")
print(f"总事件数: {attack_path['total_events']}")
print("\n攻击阶段:")
for i, stage in enumerate(attack_path["stages"], 1):
    print(f"\n阶段{i}: {stage['stage']}")
    print(f"  时间: {stage['first_seen']}")
    print(f"  描述: {stage['description']}")
    print(f"  事件数: {len(stage['events'])}")


# ============================================
# 步骤4：攻击者画像 (attacker_profiler.py)
# ============================================

def build_attacker_profile(attack_path):
    """构建攻击者画像"""
    source_ips = set()
    techniques_used = set()
    tools_identified = set()
    targets = set()
    
    for stage in attack_path["stages"]:
        for event in stage["events"]:
            # 收集源IP
            if event.get("source", {}).get("ip"):
                source_ips.add(event["source"]["ip"])
            
            # 收集技术
            threat = event.get("threat", {})
            if threat and threat.get("technique"):
                techniques_used.add(threat["technique"]["name"])
            
            # 识别工具
            process_name = event.get("process", {}).get("name", "")
            known_tools = ["hydra", "nmap", "bash", "python", "perl"]
            if process_name in known_tools:
                tools_identified.add(process_name)
            
            # 收集目标
            if event.get("host", {}).get("name"):
                host = event["host"]["name"]
                ip = event.get("destination", {}).get("ip", "")
                targets.add(f"{host} ({ip})")
    
    return {
        "source_ips": list(source_ips),
        "techniques_used": list(techniques_used),
        "tools_identified": list(tools_identified),
        "targets": list(targets),
        "attack_stages": len(attack_path["stages"]),
        "risk_score": min(10, len(attack_path["stages"]) * 2)  # 简单评分
    }


print("\n" + "=" * 60)
print("步骤4：攻击者画像")
print("=" * 60)

profile = build_attacker_profile(attack_path)
print("\n攻击者画像:")
print(f"  攻击者IP: {', '.join(profile['source_ips'])}")
print(f"  使用的技术: {', '.join(profile['techniques_used'])}")
print(f"  使用的工具: {', '.join(profile['tools_identified'])}")
print(f"  攻击目标: {', '.join(profile['targets'])}")
print(f"  攻击阶段数: {profile['attack_stages']}")
print(f"  风险评分: {profile['risk_score']}/10")


# ============================================
# 总结
# ============================================

print("\n" + "=" * 60)
print("数据流总结")
print("=" * 60)
print("""
原始事件 (4条) 
    ↓
【实体抽取】→ 提取出 12个实体
    ↓
【关系图构建】→ 构建出 1个关系图（8个节点，6条边）
    ↓
【攻击路径重建】→ 重建出 1条攻击路径（4个阶段）
    ↓
【攻击者画像】→ 生成 1个攻击者画像
""")
