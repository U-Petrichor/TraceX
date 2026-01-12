# analyzer/attack_analyzer/__init__.py

"""
Attack Analyzer Package
包含 ATT&CK 映射、时间线关联、因果分析等核心模块
"""

# 从各个子文件中导出核心类和变量
# 这样外部调用时可以直接: from analyzer.attack_analyzer import ATTACKMapper
from .attack_rules import ATTACK_RULES
from .attack_mapper import ATTACKMapper
from .timeline_correlator import TimelineCorrelator
from .causality_analyzer import CausalityAnalyzer

# 定义该包对外暴露的列表
__all__ = [
    "ATTACK_RULES",
    "ATTACKMapper",
    "TimelineCorrelator",
    "CausalityAnalyzer"
]