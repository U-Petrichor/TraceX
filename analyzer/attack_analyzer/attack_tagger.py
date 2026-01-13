# analyzer/attack_analyzer/attack_tagger.py
"""
ATT&CK T-node 标注器
作用：将 Sigma 检测结果转换为 ATT&CK 框架标注，生成威胁情报节点
"""
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from .sigma_engine import DetectionResult, SigmaDetector


@dataclass
class TechniqueNode:
    """ATT&CK 技术节点 (T-node)"""
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    confidence: float  # 置信度 0-1
    severity: str      # low, medium, high, critical
    
    # 关联的事件
    event_ids: List[str] = field(default_factory=list)
    timestamps: List[str] = field(default_factory=list)
    
    # 规则信息
    matched_rules: List[str] = field(default_factory=list)
    
    # 上下文信息
    source_ips: List[str] = field(default_factory=list)
    dest_ips: List[str] = field(default_factory=list)
    processes: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": {
                "id": self.technique_id,
                "name": self.technique_name
            },
            "tactic": {
                "id": self.tactic_id,
                "name": self.tactic_name
            },
            "confidence": self.confidence,
            "severity": self.severity,
            "event_count": len(self.event_ids),
            "time_range": {
                "first": min(self.timestamps) if self.timestamps else None,
                "last": max(self.timestamps) if self.timestamps else None
            },
            "context": {
                "source_ips": list(set(self.source_ips)),
                "dest_ips": list(set(self.dest_ips)),
                "processes": list(set(self.processes)),
                "users": list(set(self.users)),
                "hosts": list(set(self.hosts))
            },
            "matched_rules": self.matched_rules
        }


class ATTACKTagger:
    """
    ATT&CK 标注器
    将检测结果标注为 ATT&CK 技术节点
    """
    
    # ATT&CK 战术映射
    TACTIC_MAP = {
        "initial-access": ("TA0001", "Initial Access"),
        "execution": ("TA0002", "Execution"),
        "persistence": ("TA0003", "Persistence"),
        "privilege-escalation": ("TA0004", "Privilege Escalation"),
        "defense-evasion": ("TA0005", "Defense Evasion"),
        "credential-access": ("TA0006", "Credential Access"),
        "discovery": ("TA0007", "Discovery"),
        "lateral-movement": ("TA0008", "Lateral Movement"),
        "collection": ("TA0009", "Collection"),
        "exfiltration": ("TA0010", "Exfiltration"),
        "command-and-control": ("TA0011", "Command and Control"),
        "impact": ("TA0040", "Impact"),
        "reconnaissance": ("TA0043", "Reconnaissance"),
        "resource-development": ("TA0042", "Resource Development"),
    }
    
    # 技术 ID 到名称映射（常见技术）
    TECHNIQUE_MAP = {
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "PowerShell",
        "T1059.004": "Unix Shell",
        "T1027": "Obfuscated Files or Information",
        "T1036": "Masquerading",
        "T1021": "Remote Services",
        "T1021.002": "SMB/Windows Admin Shares",
        "T1021.004": "SSH",
        "T1071": "Application Layer Protocol",
        "T1071.001": "Web Protocols",
        "T1071.004": "DNS",
        "T1095": "Non-Application Layer Protocol",
        "T1132": "Data Encoding",
        "T1496": "Resource Hijacking",
        "T1082": "System Information Discovery",
        "T1087": "Account Discovery",
        "T1083": "File and Directory Discovery",
        "T1018": "Remote System Discovery",
        "T1049": "System Network Connections Discovery",
        "T1016": "System Network Configuration Discovery",
        "T1053": "Scheduled Task/Job",
        "T1053.003": "Cron",
        "T1110": "Brute Force",
        "T1110.001": "Password Guessing",
        "T1110.003": "Password Spraying",
        "T1078": "Valid Accounts",
        "T1098": "Account Manipulation",
        "T1222": "File and Directory Permissions Modification",
        "T1070": "Indicator Removal",
        "T1070.004": "File Deletion",
        "T1562": "Impair Defenses",
        "T1562.001": "Disable or Modify Tools",
        "T1140": "Deobfuscate/Decode Files or Information",
        "T1190": "Exploit Public-Facing Application",
        "T1203": "Exploitation for Client Execution",
        "T1105": "Ingress Tool Transfer",
        "T1046": "Network Service Discovery",
        "T1572": "Protocol Tunneling",
    }
    
    # 严重级别映射
    LEVEL_MAP = {
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
        "informational": "low"
    }
    
    # 置信度映射
    CONFIDENCE_MAP = {
        "low": 0.3,
        "medium": 0.6,
        "high": 0.85,
        "critical": 0.95
    }
    
    def __init__(self):
        self._technique_nodes: Dict[str, TechniqueNode] = {}
    
    def tag_detection(self, detection: DetectionResult) -> List[TechniqueNode]:
        """
        标注单个检测结果
        
        Args:
            detection: Sigma 检测结果
            
        Returns:
            生成的技术节点列表
        """
        if not detection.matched or not detection.rule:
            return []
        
        nodes = []
        rule = detection.rule
        event = detection.event
        
        # 提取上下文信息
        context = self._extract_context(event)
        
        # 为每个技术-战术组合创建节点
        for technique in rule.attack_techniques:
            for tactic_name in rule.attack_tactics:
                tactic_id, tactic_display = self.TACTIC_MAP.get(
                    tactic_name, ("", tactic_name)
                )
                
                # 获取技术名称
                tech_name = self.TECHNIQUE_MAP.get(
                    technique, 
                    f"Unknown Technique ({technique})"
                )
                
                # 创建或更新节点
                node_key = f"{technique}:{tactic_id}"
                
                if node_key not in self._technique_nodes:
                    self._technique_nodes[node_key] = TechniqueNode(
                        technique_id=technique,
                        technique_name=tech_name,
                        tactic_id=tactic_id,
                        tactic_name=tactic_display,
                        confidence=self.CONFIDENCE_MAP.get(rule.level, 0.5),
                        severity=self.LEVEL_MAP.get(rule.level, "medium")
                    )
                
                node = self._technique_nodes[node_key]
                
                # 更新节点信息
                event_id = event.get('event', {}).get('id', str(uuid.uuid4()))
                if event_id not in node.event_ids:
                    node.event_ids.append(event_id)
                
                if detection.timestamp:
                    node.timestamps.append(detection.timestamp)
                
                if rule.title not in node.matched_rules:
                    node.matched_rules.append(rule.title)
                
                # 添加上下文
                node.source_ips.extend(context.get('source_ips', []))
                node.dest_ips.extend(context.get('dest_ips', []))
                node.processes.extend(context.get('processes', []))
                node.users.extend(context.get('users', []))
                node.hosts.extend(context.get('hosts', []))
                
                # 更新置信度（多次匹配提高置信度）
                event_count = len(node.event_ids)
                if event_count > 1:
                    node.confidence = min(0.99, node.confidence + 0.05 * (event_count - 1))
                
                nodes.append(node)
        
        return nodes
    
    def _extract_context(self, event: Dict[str, Any]) -> Dict[str, List]:
        """从事件中提取上下文信息"""
        context = {
            'source_ips': [],
            'dest_ips': [],
            'processes': [],
            'users': [],
            'hosts': []
        }
        
        # Source IP
        src_ip = event.get('source', {}).get('ip')
        if src_ip:
            context['source_ips'].append(src_ip)
        
        # Destination IP
        dst_ip = event.get('destination', {}).get('ip')
        if dst_ip:
            context['dest_ips'].append(dst_ip)
        
        # Process
        proc_name = event.get('process', {}).get('name')
        proc_exe = event.get('process', {}).get('executable')
        if proc_name:
            context['processes'].append(proc_name.strip('"'))
        if proc_exe and proc_exe != proc_name:
            context['processes'].append(proc_exe.strip('"'))
        
        # User
        user = event.get('user', {}).get('name')
        proc_user = event.get('process', {}).get('user', {}).get('name')
        if user:
            context['users'].append(user)
        if proc_user and proc_user != user:
            context['users'].append(proc_user)
        
        # Host
        host = event.get('host', {}).get('name')
        hostname = event.get('host', {}).get('hostname')
        if host:
            context['hosts'].append(host)
        if hostname and hostname != host:
            context['hosts'].append(hostname)
        
        return context
    
    def get_all_nodes(self) -> List[TechniqueNode]:
        """获取所有技术节点"""
        return list(self._technique_nodes.values())
    
    def get_nodes_by_tactic(self, tactic_id: str) -> List[TechniqueNode]:
        """按战术获取节点"""
        return [n for n in self._technique_nodes.values() if n.tactic_id == tactic_id]
    
    def get_attack_summary(self) -> Dict[str, Any]:
        """获取攻击摘要"""
        nodes = list(self._technique_nodes.values())
        
        if not nodes:
            return {"total_techniques": 0, "tactics": [], "summary": "未检测到攻击"}
        
        # 按战术分组
        tactics_found = {}
        for node in nodes:
            if node.tactic_id not in tactics_found:
                tactics_found[node.tactic_id] = {
                    "tactic_id": node.tactic_id,
                    "tactic_name": node.tactic_name,
                    "techniques": []
                }
            tactics_found[node.tactic_id]["techniques"].append({
                "id": node.technique_id,
                "name": node.technique_name,
                "event_count": len(node.event_ids),
                "confidence": node.confidence,
                "severity": node.severity
            })
        
        # 计算风险等级
        max_severity = max(n.severity for n in nodes)
        max_confidence = max(n.confidence for n in nodes)
        
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        risk_score = severity_order.get(max_severity, 2) * max_confidence
        
        if risk_score >= 3.5:
            risk_level = "critical"
        elif risk_score >= 2.5:
            risk_level = "high"
        elif risk_score >= 1.5:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "total_techniques": len(nodes),
            "total_events": sum(len(n.event_ids) for n in nodes),
            "risk_level": risk_level,
            "risk_score": round(risk_score, 2),
            "tactics": list(tactics_found.values()),
            "time_range": {
                "first": min((min(n.timestamps) for n in nodes if n.timestamps), default=None),
                "last": max((max(n.timestamps) for n in nodes if n.timestamps), default=None)
            }
        }
    
    def clear(self):
        """清除所有节点"""
        self._technique_nodes = {}


class AttackAnalyzer:
    """
    攻击分析器
    整合 Sigma 检测和 ATT&CK 标注的高级接口
    """
    
    def __init__(self, rules_dir: str = None):
        """
        初始化分析器
        
        Args:
            rules_dir: Sigma 规则目录
        """
        self.detector = SigmaDetector(rules_dir)
        self.tagger = ATTACKTagger()
        self._initialized = False
    
    def initialize(self) -> Dict[str, Any]:
        """初始化分析器，加载规则"""
        rule_count = self.detector.load_rules()
        self._initialized = True
        return {
            "status": "initialized",
            "rules_loaded": rule_count,
            "rule_stats": self.detector.get_stats()
        }
    
    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析单个事件
        
        Returns:
            分析结果，包含检测和标注信息
        """
        if not self._initialized:
            self.initialize()
        
        # 检测
        detections = self.detector.detect(event)
        
        # 标注
        nodes = []
        for detection in detections:
            tagged_nodes = self.tagger.tag_detection(detection)
            nodes.extend(tagged_nodes)
        
        if not detections:
            return {
                "event_id": event.get('event', {}).get('id'),
                "timestamp": event.get('@timestamp'),
                "detected": False,
                "techniques": []
            }
        
        return {
            "event_id": event.get('event', {}).get('id'),
            "timestamp": event.get('@timestamp'),
            "detected": True,
            "detection_count": len(detections),
            "techniques": [n.to_dict() for n in nodes],
            "matched_rules": [d.rule.title for d in detections if d.rule]
        }
    
    def analyze_batch(self, events: List[Dict[str, Any]], 
                     progress_callback=None) -> Dict[str, Any]:
        """
        批量分析事件
        
        Args:
            events: 事件列表
            progress_callback: 进度回调 (processed, total, detected)
            
        Returns:
            完整分析报告
        """
        if not self._initialized:
            self.initialize()
        
        total = len(events)
        detected_count = 0
        results = []
        
        for i, event in enumerate(events):
            result = self.analyze_event(event)
            if result['detected']:
                detected_count += 1
                results.append(result)
            
            if progress_callback and (i + 1) % 100 == 0:
                progress_callback(i + 1, total, detected_count)
        
        return {
            "analyzed_events": total,
            "detected_events": detected_count,
            "detection_rate": round(detected_count / total * 100, 2) if total > 0 else 0,
            "attack_summary": self.tagger.get_attack_summary(),
            "technique_nodes": [n.to_dict() for n in self.tagger.get_all_nodes()],
            "detailed_results": results
        }
    
    def get_attack_chain(self) -> List[Dict[str, Any]]:
        """
        获取攻击链（按战术阶段排序的技术节点）
        """
        # 战术顺序
        tactic_order = [
            "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004",
            "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", 
            "TA0011", "TA0010", "TA0040"
        ]
        
        nodes = self.tagger.get_all_nodes()
        
        # 按战术分组并排序
        chain = []
        for tactic_id in tactic_order:
            tactic_nodes = [n for n in nodes if n.tactic_id == tactic_id]
            if tactic_nodes:
                chain.append({
                    "stage": tactic_id,
                    "tactic_name": tactic_nodes[0].tactic_name,
                    "techniques": [
                        {
                            "id": n.technique_id,
                            "name": n.technique_name,
                            "event_count": len(n.event_ids),
                            "confidence": n.confidence
                        }
                        for n in tactic_nodes
                    ]
                })
        
        return chain
    
    def export_to_unified_format(self, event: Dict[str, Any], 
                                 analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        将分析结果导出为统一格式（与 collector/common/schema.py 兼容）
        用于写回 Elasticsearch
        """
        # 构建 threat 信息
        if not analysis_result.get('detected'):
            return event  # 未检测到威胁，返回原事件
        
        techniques = analysis_result.get('techniques', [])
        if not techniques:
            return event
        
        # 取第一个技术作为主要威胁（可以扩展为多威胁）
        primary = techniques[0]
        
        # 更新事件的 threat 字段
        event_copy = event.copy()
        event_copy['threat'] = {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": primary['tactic']['id'],
                "name": primary['tactic']['name']
            },
            "technique": {
                "id": primary['technique']['id'],
                "name": primary['technique']['name']
            }
        }
        
        # 添加检测元数据
        event_copy['detection'] = {
            "rules": analysis_result.get('matched_rules', []),
            "confidence": primary.get('confidence', 0.5),
            "severity": primary.get('severity', 'medium')
        }
        
        return event_copy
