# analyzer/graph_analyzer/mitre_loader.py
"""
MITRE ATT&CK STIX 数据加载器

从本地克隆的 attack-stix-data 仓库加载真实的 MITRE ATT&CK 数据：
- APT 组织 (intrusion-set)
- 攻击技术 (attack-pattern)
- 使用关系 (relationship)

使用方法：
    loader = MITRELoader("E:/Code/python/attack-stix-data")
    
    # 获取所有 APT 组织
    apt_groups = loader.get_all_apt_groups()
    
    # 获取某个 APT 组织使用的技术
    techniques = loader.get_techniques_by_group("APT28")
    
    # 获取某个技术被哪些 APT 组织使用
    groups = loader.get_groups_using_technique("T1059.001")
"""
import json
import os
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class MITRETechnique:
    """MITRE ATT&CK 技术"""
    stix_id: str           # STIX ID (attack-pattern--xxx)
    attack_id: str         # ATT&CK ID (T1059.001)
    name: str              # 技术名称
    description: str = ""  # 描述
    platforms: List[str] = field(default_factory=list)  # 适用平台
    tactics: List[str] = field(default_factory=list)    # 所属战术阶段
    is_subtechnique: bool = False  # 是否为子技术


@dataclass
class MITREGroup:
    """MITRE ATT&CK APT 组织"""
    stix_id: str           # STIX ID (intrusion-set--xxx)
    attack_id: str         # ATT&CK ID (G0001)
    name: str              # 组织名称
    aliases: List[str] = field(default_factory=list)     # 别名
    description: str = ""  # 描述
    techniques: List[str] = field(default_factory=list)  # 使用的技术 ATT&CK ID 列表


class MITRELoader:
    """
    MITRE ATT&CK STIX 数据加载器
    
    从本地 attack-stix-data 仓库加载数据
    """
    
    def __init__(self, stix_data_path: str = None, domain: str = "enterprise-attack"):
        """
        初始化加载器
        
        Args:
            stix_data_path: attack-stix-data 仓库路径
                           默认尝试: "E:/Code/python/attack-stix-data"
            domain: ATT&CK 域，可选: enterprise-attack, mobile-attack, ics-attack
        """
        # 默认路径（使用相对路径，方便部署）
        if stix_data_path is None:
            # 计算相对于当前文件的路径: analyzer/graph_analyzer/ -> attack-stix-data/
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(current_dir))
            default_path = os.path.join(project_root, "attack-stix-data")
            
            if os.path.exists(default_path):
                stix_data_path = default_path
        
        self.stix_data_path = stix_data_path
        self.domain = domain
        
        # 数据缓存
        self._techniques: Dict[str, MITRETechnique] = {}  # stix_id -> technique
        self._groups: Dict[str, MITREGroup] = {}          # stix_id -> group
        self._attack_id_to_stix: Dict[str, str] = {}      # attack_id -> stix_id
        self._name_to_stix: Dict[str, str] = {}           # name/alias -> stix_id
        self._group_techniques: Dict[str, Set[str]] = {}  # group_stix_id -> set of technique_stix_ids
        self._technique_groups: Dict[str, Set[str]] = {}  # technique_stix_id -> set of group_stix_ids
        
        self._loaded = False
    
    def _ensure_loaded(self):
        """确保数据已加载"""
        if not self._loaded:
            self.load()
    
    def load(self, version: str = None) -> bool:
        """
        加载 STIX 数据
        
        Args:
            version: 指定版本号 (如 "18.0")，默认加载最新版
            
        Returns:
            是否加载成功
        """
        if self.stix_data_path is None:
            logger.error("MITRE STIX 数据路径未配置")
            return False
        
        # 构建文件路径
        if version:
            filename = f"{self.domain}-{version}.json"
        else:
            filename = f"{self.domain}.json"  # 最新版
        
        filepath = os.path.join(self.stix_data_path, self.domain, filename)
        
        if not os.path.exists(filepath):
            logger.error(f"STIX 数据文件不存在: {filepath}")
            return False
        
        logger.info(f"正在加载 MITRE ATT&CK 数据: {filepath}")
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            objects = data.get('objects', [])
            
            # 第一遍：加载技术和组织
            for obj in objects:
                obj_type = obj.get('type')
                
                if obj_type == 'attack-pattern':
                    self._load_technique(obj)
                elif obj_type == 'intrusion-set':
                    self._load_group(obj)
            
            # 第二遍：加载关系
            for obj in objects:
                if obj.get('type') == 'relationship':
                    self._load_relationship(obj)
            
            # 将技术列表更新到组织对象
            for group_stix_id, technique_stix_ids in self._group_techniques.items():
                if group_stix_id in self._groups:
                    self._groups[group_stix_id].techniques = [
                        self._techniques[t].attack_id 
                        for t in technique_stix_ids 
                        if t in self._techniques
                    ]
            
            self._loaded = True
            logger.info(f"加载完成: {len(self._groups)} 个 APT 组织, {len(self._techniques)} 个技术")
            return True
            
        except Exception as e:
            logger.error(f"加载 STIX 数据失败: {e}")
            return False
    
    def _load_technique(self, obj: dict):
        """加载技术对象"""
        stix_id = obj.get('id', '')
        
        # 跳过已废弃/撤销的
        if obj.get('x_mitre_deprecated', False) or obj.get('revoked', False):
            return
        
        # 提取 ATT&CK ID
        attack_id = ""
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                attack_id = ref.get('external_id', '')
                break
        
        if not attack_id:
            return
        
        # 提取战术阶段
        tactics = []
        for phase in obj.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') in ['mitre-attack', 'mitre-mobile-attack', 'mitre-ics-attack']:
                tactics.append(phase.get('phase_name', ''))
        
        technique = MITRETechnique(
            stix_id=stix_id,
            attack_id=attack_id,
            name=obj.get('name', ''),
            description=obj.get('description', '')[:500],  # 截断描述
            platforms=obj.get('x_mitre_platforms', []),
            tactics=tactics,
            is_subtechnique=obj.get('x_mitre_is_subtechnique', False)
        )
        
        self._techniques[stix_id] = technique
        self._attack_id_to_stix[attack_id] = stix_id
        self._name_to_stix[technique.name.lower()] = stix_id
    
    def _load_group(self, obj: dict):
        """加载 APT 组织对象"""
        stix_id = obj.get('id', '')
        
        # 跳过已废弃/撤销的
        if obj.get('x_mitre_deprecated', False) or obj.get('revoked', False):
            return
        
        # 提取 ATT&CK ID
        attack_id = ""
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                attack_id = ref.get('external_id', '')
                break
        
        group = MITREGroup(
            stix_id=stix_id,
            attack_id=attack_id,
            name=obj.get('name', ''),
            aliases=obj.get('aliases', []),
            description=obj.get('description', '')[:500]
        )
        
        self._groups[stix_id] = group
        self._attack_id_to_stix[attack_id] = stix_id
        self._name_to_stix[group.name.lower()] = stix_id
        
        # 建立别名索引
        for alias in group.aliases:
            self._name_to_stix[alias.lower()] = stix_id
    
    def _load_relationship(self, obj: dict):
        """加载关系对象"""
        rel_type = obj.get('relationship_type', '')
        source_ref = obj.get('source_ref', '')
        target_ref = obj.get('target_ref', '')
        
        # 跳过已废弃/撤销的关系
        if obj.get('x_mitre_deprecated', False) or obj.get('revoked', False):
            return
        
        # 只处理 "uses" 关系 (APT 组织使用技术)
        if rel_type != 'uses':
            return
        
        # APT 组织 -> 技术
        if 'intrusion-set' in source_ref and 'attack-pattern' in target_ref:
            if source_ref not in self._group_techniques:
                self._group_techniques[source_ref] = set()
            self._group_techniques[source_ref].add(target_ref)
            
            if target_ref not in self._technique_groups:
                self._technique_groups[target_ref] = set()
            self._technique_groups[target_ref].add(source_ref)
    
    # =========================================================================
    # 公开查询接口
    # =========================================================================
    
    def get_all_apt_groups(self) -> List[MITREGroup]:
        """获取所有 APT 组织"""
        self._ensure_loaded()
        return list(self._groups.values())
    
    def get_group_by_name(self, name: str) -> Optional[MITREGroup]:
        """
        根据名称或别名获取 APT 组织
        
        Args:
            name: 组织名称或别名 (如 "APT28", "Fancy Bear", "G0007")
        """
        self._ensure_loaded()
        
        # 先尝试直接查找名称/别名
        stix_id = self._name_to_stix.get(name.lower())
        if stix_id and stix_id in self._groups:
            return self._groups[stix_id]
        
        # 尝试作为 ATT&CK ID 查找
        stix_id = self._attack_id_to_stix.get(name.upper())
        if stix_id and stix_id in self._groups:
            return self._groups[stix_id]
        
        return None
    
    def get_techniques_by_group(self, group_name: str) -> List[MITRETechnique]:
        """
        获取某个 APT 组织使用的所有技术
        
        Args:
            group_name: 组织名称或别名
            
        Returns:
            技术列表
        """
        self._ensure_loaded()
        
        group = self.get_group_by_name(group_name)
        if not group:
            return []
        
        technique_stix_ids = self._group_techniques.get(group.stix_id, set())
        return [self._techniques[t] for t in technique_stix_ids if t in self._techniques]
    
    def get_groups_using_technique(self, technique_id: str) -> List[MITREGroup]:
        """
        获取使用某个技术的所有 APT 组织
        
        Args:
            technique_id: 技术 ATT&CK ID (如 "T1059.001")
            
        Returns:
            APT 组织列表
        """
        self._ensure_loaded()
        
        # 获取技术的 STIX ID
        stix_id = self._attack_id_to_stix.get(technique_id)
        if not stix_id:
            # 尝试按名称查找
            stix_id = self._name_to_stix.get(technique_id.lower())
        
        if not stix_id:
            return []
        
        group_stix_ids = self._technique_groups.get(stix_id, set())
        return [self._groups[g] for g in group_stix_ids if g in self._groups]
    
    def get_technique_by_id(self, technique_id: str) -> Optional[MITRETechnique]:
        """
        根据 ATT&CK ID 获取技术
        
        Args:
            technique_id: 如 "T1059.001"
        """
        self._ensure_loaded()
        
        stix_id = self._attack_id_to_stix.get(technique_id)
        if stix_id:
            return self._techniques.get(stix_id)
        return None
    
    def get_all_techniques(self) -> List[MITRETechnique]:
        """获取所有技术"""
        self._ensure_loaded()
        return list(self._techniques.values())
    
    def get_techniques_by_tactic(self, tactic: str) -> List[MITRETechnique]:
        """
        获取某个战术阶段的所有技术
        
        Args:
            tactic: 战术名称 (如 "initial-access", "execution", "persistence" 等)
        """
        self._ensure_loaded()
        
        return [t for t in self._techniques.values() if tactic in t.tactics]
    
    def search_groups(self, keyword: str) -> List[MITREGroup]:
        """
        搜索 APT 组织
        
        Args:
            keyword: 关键词 (在名称、别名、描述中搜索)
        """
        self._ensure_loaded()
        
        keyword = keyword.lower()
        results = []
        
        for group in self._groups.values():
            if keyword in group.name.lower():
                results.append(group)
            elif any(keyword in alias.lower() for alias in group.aliases):
                results.append(group)
            elif keyword in group.description.lower():
                results.append(group)
        
        return results
    
    # =========================================================================
    # 导出为 enrichment.py 兼容格式
    # =========================================================================
    
    def export_apt_profiles_for_enrichment(self) -> Dict[str, dict]:
        """
        导出为 enrichment.py 的 APTProfile 兼容格式
        
        Returns:
            {
                "APT28": {
                    "name": "APT28",
                    "aliases": ["Fancy Bear", "Sofacy", ...],
                    "ttps": ["T1566", "T1059", ...],
                    "target_industries": []  # STIX 数据中通常没有这个
                },
                ...
            }
        """
        self._ensure_loaded()
        
        profiles = {}
        
        for group in self._groups.values():
            profiles[group.name] = {
                "name": group.name,
                "aliases": group.aliases,
                "ttps": group.techniques,  # 技术 ATT&CK ID 列表
                "target_industries": [],    # STIX 数据中没有这个字段
                "attack_id": group.attack_id,
                "description": group.description
            }
        
        return profiles
    
    def get_statistics(self) -> dict:
        """获取数据统计"""
        self._ensure_loaded()
        
        return {
            "total_groups": len(self._groups),
            "total_techniques": len(self._techniques),
            "total_relationships": sum(len(v) for v in self._group_techniques.values()),
            "groups_with_techniques": len([g for g in self._groups.values() if g.techniques]),
            "subtechniques": len([t for t in self._techniques.values() if t.is_subtechnique])
        }


# 便捷函数
def create_loader(stix_path: str = None) -> MITRELoader:
    """创建并加载 MITRE 数据"""
    loader = MITRELoader(stix_path)
    loader.load()
    return loader


# 测试代码
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # 创建加载器
    loader = MITRELoader("E:/Code/python/attack-stix-data")
    loader.load()
    
    # 打印统计
    stats = loader.get_statistics()
    print(f"\n=== MITRE ATT&CK 数据统计 ===")
    print(f"APT 组织总数: {stats['total_groups']}")
    print(f"技术总数: {stats['total_techniques']}")
    print(f"子技术数: {stats['subtechniques']}")
    print(f"APT-技术关系数: {stats['total_relationships']}")
    
    # 查询示例
    print(f"\n=== 查询 APT28 ===")
    apt28 = loader.get_group_by_name("APT28")
    if apt28:
        print(f"名称: {apt28.name}")
        print(f"别名: {apt28.aliases}")
        print(f"使用技术数: {len(apt28.techniques)}")
        print(f"使用技术 (前10): {apt28.techniques[:10]}")
    
    # 查询使用某技术的组织
    print(f"\n=== 使用 T1059.001 (PowerShell) 的 APT 组织 ===")
    groups = loader.get_groups_using_technique("T1059.001")
    print(f"共 {len(groups)} 个组织使用此技术")
    for g in groups[:5]:
        print(f"  - {g.name} ({g.attack_id})")
