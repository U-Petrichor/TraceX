# analyzer/attack_analyzer/rule_loader.py
"""
Sigma 规则加载器
作用：扫描并加载 Sigma 规则文件，解析为可用的规则对象
"""
import os
import yaml
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SigmaRule:
    """Sigma 规则对象"""
    id: str
    title: str
    status: str
    description: str
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    level: str
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    # ATT&CK 相关信息（从 tags 解析）
    attack_tactics: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    
    # 原始文件路径
    file_path: str = ""
    
    def __post_init__(self):
        """解析 tags 中的 ATT&CK 信息"""
        for tag in self.tags:
            if tag.startswith("attack."):
                value = tag.replace("attack.", "")
                # 战术: 如 attack.defense-evasion
                if not value.startswith("t") and not value.startswith("T"):
                    self.attack_tactics.append(value)
                # 技术: 如 attack.t1027
                elif value.lower().startswith("t") and any(c.isdigit() for c in value):
                    self.attack_techniques.append(value.upper())


class RuleLoader:
    """
    Sigma 规则加载器
    支持按 logsource (product, category, service) 过滤规则
    """
    
    # ATT&CK 战术名到 ID 的映射
    TACTIC_NAME_TO_ID = {
        "initial-access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege-escalation": "TA0004",
        "defense-evasion": "TA0005",
        "credential-access": "TA0006",
        "discovery": "TA0007",
        "lateral-movement": "TA0008",
        "collection": "TA0009",
        "exfiltration": "TA0010",
        "command-and-control": "TA0011",
        "impact": "TA0040",
        "reconnaissance": "TA0043",
        "resource-development": "TA0042",
    }
    
    def __init__(self, rules_dir: str = None):
        """
        初始化规则加载器
        
        Args:
            rules_dir: 规则目录路径，默认为 analyzer/attack_analyzer/rules
        """
        if rules_dir is None:
            # 默认规则目录
            current_dir = Path(__file__).parent
            rules_dir = current_dir / "rules"
        self.rules_dir = Path(rules_dir)
        self.rules: List[SigmaRule] = []
        self._rules_by_logsource: Dict[str, List[SigmaRule]] = {}
        
    def load_all(self) -> int:
        """
        加载所有规则
        
        Returns:
            加载的规则数量
        """
        self.rules = []
        self._rules_by_logsource = {}
        
        if not self.rules_dir.exists():
            raise FileNotFoundError(f"规则目录不存在: {self.rules_dir}")
        
        # 递归扫描所有 .yml 文件
        for yml_file in self.rules_dir.rglob("*.yml"):
            try:
                rule = self._load_rule_file(yml_file)
                if rule:
                    self.rules.append(rule)
                    # 按 logsource 索引
                    key = self._make_logsource_key(rule.logsource)
                    if key not in self._rules_by_logsource:
                        self._rules_by_logsource[key] = []
                    self._rules_by_logsource[key].append(rule)
            except Exception as e:
                # 跳过解析失败的文件（可能是非标准格式）
                continue
                
        return len(self.rules)
    
    def _load_rule_file(self, file_path: Path) -> Optional[SigmaRule]:
        """加载单个规则文件"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        # 验证必要字段
        if not data or 'detection' not in data or 'logsource' not in data:
            return None
        
        return SigmaRule(
            id=data.get('id', ''),
            title=data.get('title', ''),
            status=data.get('status', 'unknown'),
            description=data.get('description', ''),
            logsource=data.get('logsource', {}),
            detection=data.get('detection', {}),
            level=data.get('level', 'medium'),
            tags=data.get('tags', []),
            references=data.get('references', []),
            file_path=str(file_path)
        )
    
    def _make_logsource_key(self, logsource: Dict[str, str]) -> str:
        """生成 logsource 索引键"""
        product = logsource.get('product', '*')
        category = logsource.get('category', '*')
        service = logsource.get('service', '*')
        return f"{product}:{category}:{service}"
    
    def get_rules_for_logsource(self, 
                                product: str = None, 
                                category: str = None,
                                service: str = None) -> List[SigmaRule]:
        """
        获取匹配指定 logsource 的规则
        
        匹配逻辑（宽松匹配）：
        - 如果查询指定了条件，规则必须匹配或规则未定义该字段
        - 这样可以匹配到更多规则
        
        例如：查询 {product: linux, category: process_creation}
        可以匹配规则 {product: linux, category: process_creation} 
        也可以匹配规则 {product: linux, category: process_creation, service: auditd}
        
        Args:
            product: 产品名 (如 linux, windows, zeek)
            category: 类别 (如 process_creation, network_connection)
            service: 服务名 (如 auditd, syslog) - 通常不指定，以匹配更多规则
            
        Returns:
            匹配的规则列表
        """
        matched_rules = []
        
        for rule in self.rules:
            ls = rule.logsource
            
            # product 必须匹配（如果指定了）
            if product:
                rule_product = ls.get('product')
                if rule_product and rule_product != product:
                    continue
            
            # category 必须匹配（如果指定了）
            if category:
                rule_category = ls.get('category')
                if rule_category and rule_category != category:
                    continue
            
            # service 是可选的，只有当两边都指定时才检查
            if service:
                rule_service = ls.get('service')
                # 如果规则指定了 service，必须匹配；如果规则没指定，则通过
                if rule_service and rule_service != service:
                    continue
            
            matched_rules.append(rule)
            
        return matched_rules
    
    def get_linux_rules(self) -> List[SigmaRule]:
        """获取所有 Linux 相关规则"""
        return self.get_rules_for_logsource(product='linux')
    
    def get_zeek_rules(self) -> List[SigmaRule]:
        """获取所有 Zeek 网络规则"""
        return self.get_rules_for_logsource(product='zeek')
    
    def get_process_creation_rules(self, product: str = 'linux') -> List[SigmaRule]:
        """获取进程创建相关规则"""
        return self.get_rules_for_logsource(product=product, category='process_creation')
    
    def get_auditd_rules(self) -> List[SigmaRule]:
        """获取 auditd 服务相关规则"""
        return self.get_rules_for_logsource(product='linux', service='auditd')
    
    def get_stats(self) -> Dict[str, Any]:
        """获取规则统计信息"""
        stats = {
            "total_rules": len(self.rules),
            "by_product": {},
            "by_category": {},
            "by_level": {},
            "by_tactic": {}
        }
        
        for rule in self.rules:
            # 按产品统计
            product = rule.logsource.get('product', 'unknown')
            stats["by_product"][product] = stats["by_product"].get(product, 0) + 1
            
            # 按类别统计
            category = rule.logsource.get('category', 'unknown')
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            
            # 按级别统计
            stats["by_level"][rule.level] = stats["by_level"].get(rule.level, 0) + 1
            
            # 按战术统计
            for tactic in rule.attack_tactics:
                stats["by_tactic"][tactic] = stats["by_tactic"].get(tactic, 0) + 1
                
        return stats
