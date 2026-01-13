# analyzer/attack_analyzer/__init__.py
"""
攻击分析模块

提供基于 Sigma 规则的攻击检测和 ATT&CK 标注能力

主要组件:
- RuleLoader: Sigma 规则加载器
- FieldMapper: ECS 到 Sigma 字段映射器  
- SigmaDetector: Sigma 检测引擎
- ATTACKTagger: ATT&CK T-node 标注器
- AttackAnalyzer: 高级分析接口

使用示例:
    from analyzer.attack_analyzer import AttackAnalyzer
    
    # 创建分析器
    analyzer = AttackAnalyzer()
    analyzer.initialize()
    
    # 分析单个事件
    result = analyzer.analyze_event(event)
    
    # 批量分析
    report = analyzer.analyze_batch(events)
    
    # 获取攻击链
    chain = analyzer.get_attack_chain()
"""

from .rule_loader import RuleLoader, SigmaRule
from .field_mapper import FieldMapper, EventNormalizer
from .sigma_engine import SigmaDetector, SigmaMatchEngine, DetectionResult
from .attack_tagger import ATTACKTagger, AttackAnalyzer, TechniqueNode

__all__ = [
    # 规则加载
    'RuleLoader',
    'SigmaRule',
    
    # 字段映射
    'FieldMapper',
    'EventNormalizer',
    
    # 检测引擎
    'SigmaDetector',
    'SigmaMatchEngine',
    'DetectionResult',
    
    # ATT&CK 标注
    'ATTACKTagger',
    'AttackAnalyzer',
    'TechniqueNode',
]
