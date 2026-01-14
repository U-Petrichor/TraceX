# analyzer/graph_analyzer/enrichment.py
"""
情报富化与 APT 归因组件 v5.3

功能：
  1. C2 基础设施画像 - 识别已知恶意 IP/域名
  2. APT 攻击归因 - 基于攻击序列相似度匹配
  3. 攻击链指纹 - 生成可用于聚类的哈希
  4. 真实 MITRE ATT&CK 数据 - 从本地 STIX 数据加载

v5.3 更新：集成真实 MITRE ATT&CK 数据
  - 支持从本地 attack-stix-data 仓库加载 187 个真实 APT 组织
  - 支持查询 APT 组织使用的技术 (TTP)
  - 基于真实 TTP 进行攻击归因

v5.2 更新：分层查询架构
  - 第一层：本地自定义数据（用于演示，直接匹配）
  - 第二层：真实 MITRE ATT&CK 数据
  - 第三层：外部 API（VirusTotal、AbuseIPDB）

使用示例：
    # 方式1：使用真实 MITRE 数据
    enricher = IntelEnricher(mitre_stix_path="E:/Code/python/attack-stix-data")
    
    # 方式2：仅使用本地模拟数据
    enricher = IntelEnricher(mitre_stix_path=None)
    
    # 富化 IOC（先查本地，再查外部 API）
    ti_info = enricher.enrich_entities(graph_nodes)
    
    # APT 归因（先查本地剧本，再查真实 MITRE 数据）
    attribution = enricher.attribute_apt(["T1059", "T1105", "T1005"])
    
    # 查询 APT 组织使用的技术
    techniques = enricher.get_apt_techniques("APT28")
"""
import hashlib
import difflib
import logging
import os
import json
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 导入 MITRE 加载器
try:
    from .mitre_loader import MITRELoader, MITREGroup, MITRETechnique
    HAS_MITRE_LOADER = True
except ImportError:
    HAS_MITRE_LOADER = False
    logger.warning("mitre_loader 未找到，MITRE ATT&CK 真实数据不可用")

# 可选依赖：外部 API 客户端
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    logger.warning("requests 未安装，外部 API 查询不可用")


@dataclass
class ThreatIntelEntry:
    """威胁情报条目"""
    ioc: str               # 指标值 (IP, Domain, Hash)
    ioc_type: str          # 指标类型 (ip, domain, hash)
    risk_score: int        # 风险分数 0-100
    tags: List[str] = field(default_factory=list)  # 标签 (CobaltStrike, APT28, etc.)
    geo: str = ""          # 地理位置
    first_seen: str = ""   # 首次发现时间
    last_seen: str = ""    # 最近发现时间
    source: str = "local"  # 情报来源


@dataclass
class APTProfile:
    """APT 组织画像"""
    name: str              # 组织名称
    aliases: List[str] = field(default_factory=list)  # 别名
    attack_sequence: List[str] = field(default_factory=list)  # 典型攻击序列
    target_industries: List[str] = field(default_factory=list)  # 目标行业
    ttps: List[str] = field(default_factory=list)  # 常用 TTP (T1xxx)


class IntelEnricher:
    """
    情报富化器 v5.2
    
    分层查询架构：
    1. 先查本地自定义数据（演示用，立即返回）
    2. 查不到再查外部 API（生产用）
    
    职责：
    1. 对图中的 IOC（IP、域名、哈希）进行情报查询
    2. 基于攻击序列匹配已知 APT 组织
    """
    
    # 默认 API Key（已内置，可直接使用）
    DEFAULT_ABUSEIPDB_KEY = "3646bfb062c47ad8b3604aa09c0b405335d25672dfc1797dced5adb98702504e8a4f2b854d89f1fd"
    
    def __init__(self,
                 enable_external_api: bool = True,  # 默认开启外部 API
                 virustotal_api_key: str = None,
                 abuseipdb_api_key: str = None,
                 mitre_stix_path: str = None):  # 默认自动检测
        """
        初始化情报库

        Args:
            enable_external_api: 是否启用外部 API 查询（默认开启）
            virustotal_api_key: VirusTotal API 密钥
            abuseipdb_api_key: AbuseIPDB API 密钥（已内置默认值）
            mitre_stix_path: MITRE ATT&CK STIX 数据路径
                            默认: "E:/Code/python/attack-stix-data"
                            设为 None 禁用 MITRE 数据
        
        使用示例:
            # 使用真实 MITRE 数据（推荐）
            enricher = IntelEnricher()
            
            # 或者自定义 MITRE 数据路径
            enricher = IntelEnricher(mitre_stix_path="/path/to/attack-stix-data")
            
            # 禁用 MITRE 数据（仅用本地模拟）
            enricher = IntelEnricher(mitre_stix_path=None)
        """
        # === 配置 ===
        self.enable_external_api = enable_external_api
        self.vt_api_key = virustotal_api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
        # AbuseIPDB：优先用传入的 → 环境变量 → 内置默认值
        self.abuseipdb_api_key = (
            abuseipdb_api_key or 
            os.environ.get("ABUSEIPDB_API_KEY", "") or 
            self.DEFAULT_ABUSEIPDB_KEY
        )
        
        # === 第一层：本地自定义威胁情报库（演示用，优先查询）===
        # 你可以在这里添加你模拟攻击用到的 IP/域名
        self.local_ti_cache: Dict[str, ThreatIntelEntry] = {
            # ========== 你的模拟攻击环境 ==========
            # 内网 IP (低风险)
            "192.168.1.5": ThreatIntelEntry(
                ioc="192.168.1.5", ioc_type="ip", risk_score=0,
                tags=["internal", "lab"], geo="Internal Network", source="local_custom"
            ),
            "172.26.155.27": ThreatIntelEntry(
                ioc="172.26.155.27", ioc_type="ip", risk_score=0,
                tags=["internal", "lab"], geo="Internal Network", source="local_custom"
            ),
            
            # 模拟 C2 服务器 (高风险) - 你攻击脚本用的
            "evil.com": ThreatIntelEntry(
                ioc="evil.com", ioc_type="domain", risk_score=100,
                tags=["C2", "CobaltStrike", "Malware", "模拟攻击"], 
                geo="Lab Environment", source="local_custom"
            ),
            "45.33.2.1": ThreatIntelEntry(
                ioc="45.33.2.1", ioc_type="ip", risk_score=90,
                tags=["C2", "Botnet", "模拟攻击"], geo="Lab", source="local_custom"
            ),
            "1.2.3.4": ThreatIntelEntry(
                ioc="1.2.3.4", ioc_type="ip", risk_score=85,
                tags=["C2", "Backdoor", "模拟攻击"], geo="Lab", source="local_custom"
            ),
            
            # 模拟攻击者 IP
            "59.64.129.102": ThreatIntelEntry(
                ioc="59.64.129.102", ioc_type="ip", risk_score=80,
                tags=["Attacker", "BruteForce", "SSH", "模拟攻击"], 
                geo="Simulated Attacker", source="local_custom"
            ),
            
            # ========== 在这里添加更多你的模拟 IOC ==========
            # "your.c2.server": ThreatIntelEntry(...),
        }
        
        # === 第二层：外部 API 查询缓存（避免重复查询）===
        self._external_cache: Dict[str, ThreatIntelEntry] = {}
        
        # === 第一层：本地自定义 APT 剧本（演示用，优先匹配）===
        # 你可以在这里添加你模拟攻击对应的剧本
        self.local_apt_db: Dict[str, APTProfile] = {
            # ========== 你的模拟攻击剧本 ==========
            "APT-Simulated-Group5": APTProfile(
                name="APT-Simulated-Group5",
                aliases=["SimGroup5", "TestAPT", "组员5模拟攻击"],
                attack_sequence=[
                    "NETWORK_Inbound",       # 1. 网络探测/入侵
                    "TEMP_FILE_ACCESS",      # 2. 写入临时文件
                    "WEB_ROOT_ACCESS",       # 3. 访问 Web 目录
                    "PHP_SCRIPT",            # 4. WebShell 执行
                    "SUSPICIOUS_DOWNLOADER", # 5. 下载恶意文件
                    "SENSITIVE_FILE"         # 6. 读取敏感文件
                ],
                target_industries=["Education", "Research", "Lab"],
                ttps=["T1190", "T1505.003", "T1059.004", "T1005"]
            ),
            
            "APT-WebShell-Demo": APTProfile(
                name="APT-WebShell-Demo",
                aliases=["WebShell演示攻击"],
                attack_sequence=[
                    "HTTP_REQUEST",
                    "WEB_ROOT_ACCESS",
                    "PHP_SCRIPT",
                    "SHELL_EXECUTION",
                    "RECON_COMMAND"
                ],
                target_industries=["Demo"],
                ttps=["T1505.003", "T1059.004"]
            ),
            
            "APT-SSH-BruteForce-Demo": APTProfile(
                name="APT-SSH-BruteForce-Demo",
                aliases=["SSH暴力破解演示"],
                attack_sequence=[
                    "SSH_CONNECTION",
                    "SHELL_EXECUTION",
                    "SUSPICIOUS_DOWNLOADER",
                    "TEMP_FILE_ACCESS",
                    "SENSITIVE_FILE"
                ],
                target_industries=["Demo"],
                ttps=["T1110", "T1059.004", "T1105"]
            ),
            
            # ========== 在这里添加更多你的模拟剧本 ==========
        }
        
        # === 第二层：MITRE ATT&CK 真实 APT 剧本（查不到本地时使用）===
        self.mitre_apt_db: Dict[str, APTProfile] = {
            # 真实 APT 组织（简化版，完整版应从 MITRE 加载）
            "APT28": APTProfile(
                name="APT28",
                aliases=["Fancy Bear", "Sofacy", "Pawn Storm"],
                attack_sequence=[
                    "SPEARPHISHING",
                    "MALICIOUS_DOCUMENT",
                    "SHELL_EXECUTION",
                    "CREDENTIAL_DUMP",
                    "LATERAL_MOVEMENT",
                    "DATA_EXFILTRATION"
                ],
                target_industries=["Government", "Military", "Defense"],
                ttps=["T1566", "T1204", "T1059", "T1003", "T1021", "T1048"]
            ),
            "APT29": APTProfile(
                name="APT29",
                aliases=["Cozy Bear", "The Dukes"],
                attack_sequence=[
                    "SPEARPHISHING",
                    "SUPPLY_CHAIN",
                    "SHELL_EXECUTION",
                    "PERSISTENCE_MECHANISM",
                    "CLOUD_ACCESS"
                ],
                target_industries=["Government", "Think Tanks"],
                ttps=["T1566", "T1195", "T1059", "T1547", "T1078"]
            ),
        }
        
        # === 匹配阈值 ===
        self.attribution_threshold = 0.6  # 相似度超过 60% 才归因
        self.local_priority_threshold = 0.5  # 本地匹配超过 50% 就直接用，不查外部
        
        # === 第三层：真实 MITRE ATT&CK 数据 ===
        self.mitre_loader: Optional['MITRELoader'] = None
        self._mitre_apt_profiles: Dict[str, APTProfile] = {}  # 从 MITRE 加载的 APT 画像
        
        # 自动检测 MITRE 数据路径（相对路径，方便部署）
        if mitre_stix_path is None:
            # 计算相对于当前文件的路径: analyzer/graph_analyzer/ -> attack-stix-data/
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(current_dir))  # 回到项目根目录
            mitre_stix_path = os.path.join(project_root, "attack-stix-data")
        
        if mitre_stix_path and HAS_MITRE_LOADER and os.path.exists(mitre_stix_path):
            self._init_mitre_data(mitre_stix_path)
    
    def _init_mitre_data(self, stix_path: str):
        """
        初始化真实 MITRE ATT&CK 数据
        """
        try:
            self.mitre_loader = MITRELoader(stix_path)
            if self.mitre_loader.load():
                # 将 MITRE 数据转换为 APTProfile 格式
                self._load_mitre_apt_profiles()
                stats = self.mitre_loader.get_statistics()
                logger.info(f"已加载真实 MITRE ATT&CK 数据: "
                           f"{stats['total_groups']} 个 APT 组织, "
                           f"{stats['total_techniques']} 个技术")
            else:
                logger.warning("MITRE 数据加载失败，将仅使用本地模拟数据")
                self.mitre_loader = None
        except Exception as e:
            logger.error(f"初始化 MITRE 数据失败: {e}")
            self.mitre_loader = None
    
    def _load_mitre_apt_profiles(self):
        """
        将 MITRE 数据转换为 APTProfile 格式
        """
        if not self.mitre_loader:
            return
        
        for group in self.mitre_loader.get_all_apt_groups():
            # 获取该组织使用的技术
            techniques = self.mitre_loader.get_techniques_by_group(group.name)
            
            # 将技术 ID 转换为 ATLAS 风格的标签序列
            # 这里使用技术的战术阶段作为攻击序列
            attack_sequence = []
            ttps = []
            
            for tech in techniques:
                ttps.append(tech.attack_id)
                # 将战术阶段映射为 ATLAS 标签
                for tactic in tech.tactics:
                    atlas_label = self._tactic_to_atlas_label(tactic)
                    if atlas_label and atlas_label not in attack_sequence:
                        attack_sequence.append(atlas_label)
            
            profile = APTProfile(
                name=group.name,
                aliases=group.aliases,
                attack_sequence=attack_sequence,
                target_industries=[],  # STIX 数据中没有这个
                ttps=ttps[:50]  # 限制数量
            )
            
            self._mitre_apt_profiles[group.name] = profile
            
            # 也用别名建立索引
            for alias in group.aliases:
                if alias != group.name:
                    self._mitre_apt_profiles[alias] = profile
    
    def _tactic_to_atlas_label(self, tactic: str) -> str:
        """
        将 MITRE 战术阶段映射为 ATLAS 标签
        """
        mapping = {
            "initial-access": "NETWORK_Inbound",
            "execution": "SHELL_EXECUTION",
            "persistence": "PERSISTENCE_MECHANISM",
            "privilege-escalation": "PRIVILEGE_ESCALATION",
            "defense-evasion": "DEFENSE_EVASION",
            "credential-access": "CREDENTIAL_ACCESS",
            "discovery": "RECON_COMMAND",
            "lateral-movement": "LATERAL_MOVEMENT",
            "collection": "FILE_READER",
            "command-and-control": "C2_COMMUNICATION",
            "exfiltration": "DATA_EXFILTRATION",
            "impact": "DESTRUCTIVE_ACTION",
            "reconnaissance": "RECON_COMMAND",
            "resource-development": "RESOURCE_DEVELOPMENT",
        }
        return mapping.get(tactic, "")
    
    # =========================================================================
    # 核心方法 1: IOC 情报富化
    # =========================================================================
    
    def enrich_entities(self, graph_nodes: List[Dict[str, Any]]) -> Dict[str, Dict]:
        """
        对图节点中的 IOC 进行情报富化
        
        Args:
            graph_nodes: 图节点列表，每个节点应包含 properties 字段
            
        Returns:
            {
                "ioc_value": {
                    "type": "ip" | "domain",
                    "risk_score": 0-100,
                    "tags": [...],
                    "geo": "...",
                    ...
                },
                ...
            }
        """
        enrichment_data = {}
        
        for node in graph_nodes:
            # 提取可能的 IOC
            iocs = self._extract_iocs_from_node(node)
            
            for ioc in iocs:
                if ioc in enrichment_data:
                    continue  # 已查询过
                    
                intel = self._query_threat_intel(ioc)
                if intel:
                    enrichment_data[ioc] = {
                        "type": intel.ioc_type,
                        "risk_score": intel.risk_score,
                        "tags": intel.tags,
                        "geo": intel.geo,
                        "source": intel.source,
                        "is_malicious": intel.risk_score >= 70
                    }
        
        logger.info(f"Enriched {len(enrichment_data)} IOCs")
        return enrichment_data
    
    def _extract_iocs_from_node(self, node: Dict[str, Any]) -> List[str]:
        """从节点中提取 IOC"""
        iocs = []
        props = node.get("properties", {})
        
        # IP 地址
        for key in ["ip", "src_ip", "dst_ip", "source_ip"]:
            ip = props.get(key)
            if ip and ip not in ["", "127.0.0.1", "0.0.0.0"]:
                iocs.append(ip)
        
        # 直接从 label 提取（IP 节点）
        if node.get("type") == "ip":
            label = node.get("label", "")
            if label:
                iocs.append(label)
        
        # TODO: 域名提取（从 message 或 raw 字段）
        
        return list(set(iocs))  # 去重
    
    def _query_threat_intel(self, ioc: str) -> Optional[ThreatIntelEntry]:
        """
        分层查询威胁情报
        
        查询顺序：
        1. 先查本地自定义（你的模拟数据）→ 命中直接返回
        2. 再查外部缓存（之前查过的）→ 命中直接返回
        3. 最后查外部 API（VirusTotal）→ 缓存后返回
        """
        # === 第一层：本地自定义（优先，演示用）===
        if ioc in self.local_ti_cache:
            logger.debug(f"IOC {ioc} 命中本地自定义情报库")
            return self.local_ti_cache[ioc]
        
        # === 第二层：外部缓存（避免重复查询）===
        if ioc in self._external_cache:
            logger.debug(f"IOC {ioc} 命中外部查询缓存")
            return self._external_cache[ioc]
        
        # === 第三层：外部 API 查询 ===
        if self.enable_external_api and HAS_REQUESTS:
            # 优先用 AbuseIPDB（免费额度高，专门查IP）
            result = self._query_abuseipdb(ioc)
            if result:
                self._external_cache[ioc] = result
                return result
            
            # AbuseIPDB 查不到再用 VirusTotal
            result = self._query_virustotal(ioc)
            if result:
                self._external_cache[ioc] = result
                return result
        
        # 查不到
        logger.debug(f"IOC {ioc} 未找到情报")
        return None
    
    def _query_abuseipdb(self, ioc: str) -> Optional[ThreatIntelEntry]:
        """
        查询 AbuseIPDB API（推荐，免费额度高）

        注册地址: https://www.abuseipdb.com/register
        免费额度: 1000次/天
        """
        # 优先用初始化时传入的 Key，其次用环境变量
        api_key = self.abuseipdb_api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        if not api_key:
            logger.debug("AbuseIPDB API Key 未配置")
            return None
        
        # AbuseIPDB 只支持 IP，不支持域名
        import re
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            return None
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ioc,
                "maxAgeInDays": 90
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                
                # AbuseIPDB 返回的 abuseConfidenceScore 是 0-100
                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                country = data.get("countryCode", "Unknown")
                isp = data.get("isp", "")
                domain = data.get("domain", "")
                
                tags = []
                if abuse_score >= 80:
                    tags.append("High Risk")
                if abuse_score >= 50:
                    tags.append("Malicious")
                if total_reports > 10:
                    tags.append("Frequently Reported")
                if isp:
                    tags.append(f"ISP:{isp[:20]}")
                
                return ThreatIntelEntry(
                    ioc=ioc,
                    ioc_type="ip",
                    risk_score=abuse_score,
                    tags=tags,
                    geo=country,
                    source="AbuseIPDB"
                )
            else:
                logger.warning(f"AbuseIPDB 查询失败: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"AbuseIPDB 查询异常: {e}")
            return None
    
    def _query_virustotal(self, ioc: str) -> Optional[ThreatIntelEntry]:
        """
        查询 VirusTotal API
        
        需要设置 VIRUSTOTAL_API_KEY 环境变量或在初始化时传入
        """
        if not self.vt_api_key:
            logger.warning("VirusTotal API Key 未配置")
            return None
        
        try:
            # 判断是 IP 还是域名
            import re
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc))
            
            if is_ip:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            else:
                url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
            
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                
                # 解析 VirusTotal 返回
                stats = data.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                total_count = sum(stats.values()) if stats else 1
                
                # 计算风险分数
                risk_score = min(100, int(malicious_count / max(total_count, 1) * 100 * 2))
                
                tags = []
                if malicious_count > 5:
                    tags.append("Malicious")
                if malicious_count > 10:
                    tags.append("High Risk")
                
                return ThreatIntelEntry(
                    ioc=ioc,
                    ioc_type="ip" if is_ip else "domain",
                    risk_score=risk_score,
                    tags=tags,
                    geo=data.get("country", "Unknown"),
                    source="VirusTotal"
                )
            else:
                logger.warning(f"VirusTotal 查询失败: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"VirusTotal 查询异常: {e}")
            return None
    
    def add_local_threat_intel(self, ioc: str, intel: ThreatIntelEntry) -> None:
        """添加本地威胁情报条目（用于添加你的模拟 IOC）"""
        self.local_ti_cache[ioc] = intel
        logger.info(f"添加本地 IOC: {ioc}")
    
    def add_threat_intel(self, ioc: str, intel: ThreatIntelEntry) -> None:
        """添加威胁情报条目（兼容旧接口）"""
        self.add_local_threat_intel(ioc, intel)
    
    # =========================================================================
    # 核心方法 2: 攻击链指纹生成
    # =========================================================================
    
    def generate_fingerprint(self, path_sequence: List[str]) -> str:
        """
        生成攻击链指纹
        
        将攻击路径序列哈希为唯一标识，用于：
        1. 攻击聚类（相同指纹 = 相同攻击模式）
        2. 快速比对
        3. 历史追溯
        
        Args:
            path_sequence: ATLAS 标签序列 ["TEMP_FILE_ACCESS", "WEB_ROOT_ACCESS", ...]
            
        Returns:
            SHA-256 哈希字符串
        """
        # 标准化：排序后拼接（消除顺序差异的影响）
        # 注意：如果顺序重要，可以改为直接拼接
        seq_str = "->".join(path_sequence)
        fingerprint = hashlib.sha256(seq_str.encode('utf-8')).hexdigest()
        
        logger.debug(f"Generated fingerprint for {len(path_sequence)} steps: {fingerprint[:16]}...")
        return fingerprint
    
    def generate_order_aware_fingerprint(self, path_sequence: List[str]) -> str:
        """
        生成顺序敏感的攻击链指纹
        
        与 generate_fingerprint 不同，保留操作顺序信息。
        """
        # 直接按顺序拼接
        seq_str = "->".join(path_sequence)
        return hashlib.sha256(seq_str.encode('utf-8')).hexdigest()
    
    # =========================================================================
    # 核心方法 3: APT 归因
    # =========================================================================
    
    def attribute_apt(self, path_sequence: List[str]) -> Dict[str, Any]:
        """
        分层 APT 归因 (v5.3 增强版)
        
        查询顺序：
        1. 先匹配本地自定义剧本（你的模拟攻击）→ 匹配度 > 50% 直接返回
        2. 基于 TTP ID 匹配真实 MITRE APT 组织（新增！）
        3. 基于 ATLAS 标签序列匹配 MITRE APT 剧本
        
        支持两种输入格式：
        - ATLAS 标签序列: ["SHELL_EXECUTION", "SUSPICIOUS_DOWNLOADER", ...]
        - TTP ID 序列: ["T1059", "T1105", "T1005", ...]  ← 新增！
        
        Args:
            path_sequence: ATLAS 标签序列 或 TTP ID 序列
            
        Returns:
            {
                "suspected_group": "APT-xxx" | "Unclassified",
                "similarity_score": 0.0-1.0,
                "matched_profile": { ... } | None,
                "source": "local_custom" | "mitre_ttp" | "mitre_atlas",
                "alternative_matches": [...]
            }
        """
        if not path_sequence:
            return {
                "suspected_group": "Unclassified",
                "similarity_score": 0.0,
                "matched_profile": None,
                "source": None,
                "alternative_matches": []
            }
        
        # 判断输入是 TTP ID 还是 ATLAS 标签
        is_ttp_sequence = all(
            str(item).startswith("T") and any(c.isdigit() for c in str(item))
            for item in path_sequence[:3] if item  # 检查前几个
        )
        
        # === 第一层：本地自定义剧本（优先，方便演示）===
        local_matches = self._match_against_db(path_sequence, self.local_apt_db)
        
        if local_matches:
            best_local = local_matches[0]
            if best_local["score"] >= self.local_priority_threshold:
                logger.info(f"APT 归因命中本地剧本: {best_local['group']} (相似度={best_local['score']:.2f})")
                return self._build_attribution_result(best_local, local_matches[1:4], source="local_custom")
        
        # === 第二层：基于 TTP ID 匹配真实 MITRE APT（新增！）===
        if is_ttp_sequence and self.mitre_loader:
            ttp_matches = self._match_by_ttp_overlap(path_sequence)
            if ttp_matches:
                best_ttp = ttp_matches[0]
                if best_ttp["score"] >= self.attribution_threshold:
                    logger.info(f"APT 归因命中 MITRE TTP: {best_ttp['group']} "
                               f"(TTP重叠率={best_ttp['score']:.2f})")
                    return self._build_attribution_result(best_ttp, ttp_matches[1:4], source="mitre_ttp")
        
        # === 第三层：基于 ATLAS 标签序列匹配 ===
        # 3.1 内置的 MITRE 简化剧本
        mitre_matches = self._match_against_db(path_sequence, self.mitre_apt_db)
        
        # 3.2 从真实 MITRE 数据生成的剧本
        if self._mitre_apt_profiles:
            real_mitre_matches = self._match_against_db(path_sequence, self._mitre_apt_profiles)
            mitre_matches.extend(real_mitre_matches)
        
        # 合并所有匹配结果
        all_matches = local_matches + mitre_matches
        all_matches.sort(key=lambda x: x["score"], reverse=True)
        
        # 去重（同一个组织可能在多个库中）
        seen = set()
        unique_matches = []
        for m in all_matches:
            if m["group"] not in seen:
                seen.add(m["group"])
                unique_matches.append(m)
        
        if unique_matches:
            best_match = unique_matches[0]
            if best_match["score"] >= self.attribution_threshold:
                # 判断来源
                if best_match["group"] in self.local_apt_db:
                    source = "local_custom"
                elif best_match["group"] in self._mitre_apt_profiles:
                    source = "mitre_real"
                else:
                    source = "mitre_builtin"
                    
                logger.info(f"APT 归因: {best_match['group']} (相似度={best_match['score']:.2f}, 来源={source})")
                return self._build_attribution_result(best_match, unique_matches[1:4], source=source)
        
        # 都没匹配上
        logger.info("APT 归因: 未匹配到已知攻击组织")
        return {
            "suspected_group": "Unclassified",
            "similarity_score": unique_matches[0]["score"] if unique_matches else 0.0,
            "matched_profile": None,
            "source": None,
            "alternative_matches": [
                {"group": m["group"], "score": m["score"]} 
                for m in unique_matches[:3] if m["score"] >= 0.3
            ]
        }
    
    def _match_by_ttp_overlap(self, observed_ttps: List[str]) -> List[Dict]:
        """
        基于 TTP 重叠率匹配 APT 组织（使用真实 MITRE 数据）
        
        算法：计算观测到的 TTP 与 APT 组织已知 TTP 的 Jaccard 相似度
        
        Args:
            observed_ttps: 观测到的 TTP ID 列表 (如 ["T1059", "T1105"])
            
        Returns:
            匹配结果列表，按相似度降序排列
        """
        if not self.mitre_loader:
            return []
        
        observed_set = set(observed_ttps)
        matches = []
        
        for group in self.mitre_loader.get_all_apt_groups():
            if not group.techniques:
                continue
            
            group_ttps = set(group.techniques)
            
            # Jaccard 相似度 = 交集 / 并集
            intersection = observed_set & group_ttps
            union = observed_set | group_ttps
            
            if union:
                jaccard = len(intersection) / len(union)
            else:
                jaccard = 0.0
            
            # 也计算召回率（观测 TTP 中有多少在该组织 TTP 中）
            if observed_set:
                recall = len(intersection) / len(observed_set)
            else:
                recall = 0.0

            # 综合得分（偏重召回率，因为我们观测的 TTP 可能只是攻击的一部分）
            score = 0.3 * jaccard + 0.7 * recall

            # 关键技术权重提升（针对 C2 / Exfil / 网络通道等重要 TTP）
            # 对交集包含关键 TTP 的组织适度提升分数（上限 1.0）
            if any(t in intersection for t in ("T1071", "T1041", "T1567")):
                score = min(score * 1.1, 1.0)

            if score > 0.1:  # 过滤太低的
                # 构建一个伪 APTProfile 用于结果
                profile = APTProfile(
                    name=group.name,
                    aliases=group.aliases,
                    attack_sequence=[],  # TTP 匹配不需要这个
                    target_industries=[],
                    ttps=list(intersection)[:20]  # 匹配上的 TTP
                )
                
                matches.append({
                    "group": group.name,
                    "score": round(score, 3),
                    "profile": profile,
                    "matched_ttps": list(intersection),
                    "jaccard": round(jaccard, 3),
                    "recall": round(recall, 3)
                })
        
        # 按得分降序排列
        matches.sort(key=lambda x: x["score"], reverse=True)
        return matches
    
    def _match_against_db(self, path_sequence: List[str], 
                          apt_db: Dict[str, APTProfile]) -> List[Dict]:
        """
        对指定的 APT 数据库进行匹配
        """
        matches = []
        
        for apt_name, profile in apt_db.items():
            matcher = difflib.SequenceMatcher(
                None, 
                path_sequence, 
                profile.attack_sequence
            )
            score = matcher.ratio()
            
            matches.append({
                "group": apt_name,
                "score": round(score, 3),
                "profile": profile
            })
        
        matches.sort(key=lambda x: x["score"], reverse=True)
        return matches
    
    def _build_attribution_result(self, best_match: Dict, 
                                  alternatives: List[Dict],
                                  source: str) -> Dict[str, Any]:
        """
        构建归因结果
        """
        return {
            "suspected_group": best_match["group"],
            "similarity_score": best_match["score"],
            "matched_profile": {
                "name": best_match["profile"].name,
                "aliases": best_match["profile"].aliases,
                "ttps": best_match["profile"].ttps,
                "target_industries": best_match["profile"].target_industries
            },
            "source": source,  # 标识来源：local_custom 或 mitre_attack
            "alternative_matches": [
                {"group": m["group"], "score": m["score"]} 
                for m in alternatives if m["score"] >= 0.3
            ]
        }
    
    def explain_attribution(self, path_sequence: List[str], apt_name: str) -> Dict[str, Any]:
        """
        解释归因结果
        
        详细说明为什么匹配到某个 APT 组织。
        """
        if apt_name not in self.apt_db:
            return {"error": f"Unknown APT: {apt_name}"}
        
        profile = self.apt_db[apt_name]
        
        # 找出匹配和不匹配的步骤
        matcher = difflib.SequenceMatcher(None, path_sequence, profile.attack_sequence)
        
        matching_blocks = matcher.get_matching_blocks()
        matched_steps = []
        for block in matching_blocks:
            if block.size > 0:
                for i in range(block.size):
                    matched_steps.append({
                        "observed": path_sequence[block.a + i],
                        "expected": profile.attack_sequence[block.b + i],
                        "position": block.a + i
                    })
        
        # 找出缺失的步骤
        observed_set = set(path_sequence)
        expected_set = set(profile.attack_sequence)
        missing = expected_set - observed_set
        extra = observed_set - expected_set
        
        return {
            "apt_name": apt_name,
            "total_similarity": matcher.ratio(),
            "matched_steps": matched_steps,
            "missing_steps": list(missing),
            "extra_steps": list(extra),
            "recommendation": "High confidence match" if matcher.ratio() >= 0.7 else 
                             "Possible match, needs manual review"
        }
    
    # =========================================================================
    # 辅助方法
    # =========================================================================
    
    def get_apt_profiles(self) -> List[str]:
        """获取所有 APT 组织名称"""
        return list(self.apt_db.keys())
    
    def get_apt_profile(self, name: str) -> Optional[APTProfile]:
        """获取指定 APT 组织的画像"""
        return self.apt_db.get(name)

    @property
    def apt_db(self) -> Dict[str, APTProfile]:
        """合并视图：返回所有可用的 APT 剧本集合（本地 + 内置 MITRE 简化 + 真实 MITRE 加载）

        这个属性用于兼容历史接口（如 `self.apt_db` 的直接访问）。
        """
        db: Dict[str, APTProfile] = {}
        # 本地自定义优先
        if hasattr(self, 'local_apt_db') and isinstance(self.local_apt_db, dict):
            db.update(self.local_apt_db)
        # 内置的简化 MITRE 剧本
        if hasattr(self, 'mitre_apt_db') and isinstance(self.mitre_apt_db, dict):
            db.update(self.mitre_apt_db)
        # 从真实 MITRE 加载的画像（覆盖同名条目）
        if hasattr(self, '_mitre_apt_profiles') and isinstance(self._mitre_apt_profiles, dict):
            db.update(self._mitre_apt_profiles)
        return db
    
    def add_local_apt_profile(self, profile: APTProfile) -> None:
        """
        添加本地 APT 剧本（用于添加你的模拟攻击剧本）
        
        示例：
            enricher.add_local_apt_profile(APTProfile(
                name="我的模拟攻击",
                aliases=["Demo Attack"],
                attack_sequence=["SSH_CONNECTION", "SHELL_EXECUTION", ...],
                ttps=["T1110", "T1059"]
            ))
        """
        self.local_apt_db[profile.name] = profile
        logger.info(f"添加本地 APT 剧本: {profile.name}")
    
    def add_apt_profile(self, profile: APTProfile) -> None:
        """添加 APT 组织画像（兼容旧接口，添加到本地库）"""
        self.add_local_apt_profile(profile)
    
    # =========================================================================
    # 便捷方法：快速添加模拟数据
    # =========================================================================
    
    def add_simulated_c2(self, ip_or_domain: str, tags: List[str] = None) -> None:
        """
        快速添加模拟 C2 服务器
        
        示例：
            enricher.add_simulated_c2("my-evil-server.com", ["C2", "Cobalt"])
            enricher.add_simulated_c2("10.0.0.100", ["C2", "Backdoor"])
        """
        import re
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_or_domain))
        
        self.local_ti_cache[ip_or_domain] = ThreatIntelEntry(
            ioc=ip_or_domain,
            ioc_type="ip" if is_ip else "domain",
            risk_score=100,
            tags=tags or ["C2", "模拟攻击"],
            geo="Lab Environment",
            source="local_custom"
        )
        logger.info(f"添加模拟 C2: {ip_or_domain}")
    
    def add_simulated_attacker_ip(self, ip: str) -> None:
        """
        快速添加模拟攻击者 IP
        
        示例：
            enricher.add_simulated_attacker_ip("192.168.100.50")
        """
        self.local_ti_cache[ip] = ThreatIntelEntry(
            ioc=ip,
            ioc_type="ip",
            risk_score=80,
            tags=["Attacker", "模拟攻击"],
            geo="Lab Attacker",
            source="local_custom"
        )
        logger.info(f"添加模拟攻击者 IP: {ip}")
    
    def create_attack_profile(self, 
                             name: str, 
                             attack_sequence: List[str],
                             ttps: List[str] = None) -> None:
        """
        快速创建攻击剧本
        
        示例：
            enricher.create_attack_profile(
                name="我的WebShell攻击",
                attack_sequence=["HTTP_REQUEST", "PHP_SCRIPT", "SHELL_EXECUTION", "SENSITIVE_FILE"],
                ttps=["T1505.003", "T1059"]
            )
        """
        profile = APTProfile(
            name=name,
            aliases=[f"{name}_alias"],
            attack_sequence=attack_sequence,
            target_industries=["Demo", "Lab"],
            ttps=ttps or []
        )
        self.local_apt_db[name] = profile
        logger.info(f"创建攻击剧本: {name} (序列长度: {len(attack_sequence)})")
    
    # =========================================================================
    # MITRE ATT&CK 真实数据查询接口（新增！）
    # =========================================================================
    
    def get_mitre_apt_info(self, name: str) -> Optional[Dict[str, Any]]:
        """
        获取 MITRE APT 组织详细信息
        
        Args:
            name: 组织名称或别名 (如 "APT28", "Fancy Bear", "G0007")
            
        Returns:
            {
                "name": "APT28",
                "attack_id": "G0007",
                "aliases": ["Fancy Bear", "Sofacy", ...],
                "description": "...",
                "techniques": ["T1059.001", "T1566", ...],
                "technique_count": 85
            }
        """
        if not self.mitre_loader:
            logger.warning("MITRE 数据未加载")
            return None
        
        group = self.mitre_loader.get_group_by_name(name)
        if not group:
            return None
        
        return {
            "name": group.name,
            "attack_id": group.attack_id,
            "aliases": group.aliases,
            "description": group.description,
            "techniques": group.techniques,
            "technique_count": len(group.techniques)
        }
    
    def get_apt_techniques(self, apt_name: str) -> List[Dict[str, Any]]:
        """
        获取 APT 组织使用的所有技术（详细信息）
        
        Args:
            apt_name: APT 组织名称或别名
            
        Returns:
            [
                {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactics": ["execution"],
                    "platforms": ["Windows"]
                },
                ...
            ]
        """
        if not self.mitre_loader:
            return []
        
        techniques = self.mitre_loader.get_techniques_by_group(apt_name)
        return [
            {
                "id": tech.attack_id,
                "name": tech.name,
                "tactics": tech.tactics,
                "platforms": tech.platforms,
                "is_subtechnique": tech.is_subtechnique
            }
            for tech in techniques
        ]
    
    def get_groups_using_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """
        获取使用某个技术的所有 APT 组织
        
        Args:
            technique_id: 技术 ID (如 "T1059.001")
            
        Returns:
            [
                {"name": "APT28", "attack_id": "G0007", "aliases": [...]},
                ...
            ]
        """
        if not self.mitre_loader:
            return []
        
        groups = self.mitre_loader.get_groups_using_technique(technique_id)
        return [
            {
                "name": g.name,
                "attack_id": g.attack_id,
                "aliases": g.aliases
            }
            for g in groups
        ]
    
    def search_apt_groups(self, keyword: str) -> List[Dict[str, Any]]:
        """
        搜索 APT 组织
        
        Args:
            keyword: 关键词（在名称、别名、描述中搜索）
            
        Returns:
            匹配的组织列表
        """
        if not self.mitre_loader:
            return []
        
        groups = self.mitre_loader.search_groups(keyword)
        return [
            {
                "name": g.name,
                "attack_id": g.attack_id,
                "aliases": g.aliases,
                "technique_count": len(g.techniques)
            }
            for g in groups
        ]
    
    def get_mitre_statistics(self) -> Dict[str, Any]:
        """
        获取 MITRE 数据统计
        
        Returns:
            {
                "total_groups": 187,
                "total_techniques": 835,
                "loaded": True
            }
        """
        if not self.mitre_loader:
            return {
                "loaded": False,
                "message": "MITRE 数据未加载，请检查 mitre_stix_path 配置"
            }
        
        stats = self.mitre_loader.get_statistics()
        stats["loaded"] = True
        return stats
    
    def attribute_by_ttps(self, ttps: List[str], top_n: int = 5) -> Dict[str, Any]:
        """
        基于 TTP 列表进行 APT 归因（简化接口）
        
        这是推荐的归因方式！直接传入观测到的 TTP ID 列表。
        
        Args:
            ttps: TTP ID 列表 (如 ["T1059", "T1105", "T1005"])
            top_n: 返回前 N 个匹配结果
            
        Returns:
            {
                "suspected_group": "APT28",
                "confidence": 0.75,
                "matched_ttps": ["T1059", "T1105"],
                "top_matches": [
                    {"group": "APT28", "score": 0.75, "matched_ttps": [...]},
                    {"group": "APT29", "score": 0.62, "matched_ttps": [...]},
                ]
            }
            
        示例：
            result = enricher.attribute_by_ttps(["T1059.001", "T1105", "T1005"])
            print(f"疑似 APT 组织: {result['suspected_group']}")
        """
        if not ttps:
            return {
                "suspected_group": "Unclassified",
                "confidence": 0.0,
                "matched_ttps": [],
                "top_matches": []
            }
        
        # 使用 TTP 重叠匹配
        matches = self._match_by_ttp_overlap(ttps)
        
        if not matches:
            return {
                "suspected_group": "Unclassified",
                "confidence": 0.0,
                "matched_ttps": [],
                "top_matches": []
            }
        
        best = matches[0]
        return {
            "suspected_group": best["group"] if best["score"] >= 0.3 else "Unclassified",
            "confidence": best["score"],
            "matched_ttps": best.get("matched_ttps", []),
            "jaccard_similarity": best.get("jaccard", 0),
            "recall": best.get("recall", 0),
            "top_matches": [
                {
                    "group": m["group"],
                    "score": m["score"],
                    "matched_ttps": m.get("matched_ttps", [])[:10]
                }
                for m in matches[:top_n]
            ]
        }


# =========================================================================
# 补充：AtlasMapper（内存/行为标签映射辅助类）
# =========================================================================
class AtlasMapper:
    def __init__(self):
        # 预定义内存异常映射到 ATLAS 风格标签
        self.memory_anomaly_labels = {
            'MEMFD_EXEC': 'FILELESS_ATTACK',
            'ANON_ELF': 'FILELESS_ATTACK',
            'RWX_REGION': 'CODE_INJECTION',
            'STACK_EXEC': 'CODE_INJECTION',
            'PROCESS_HOLLOWING': 'PROCESS_HOLLOWING'
        }

    def get_label(self, event: Dict[str, Any]) -> str:
        """结合事件类型、路径、命令行生成简化的 ATLAS 标签

        逻辑：
        - 优先识别内存异常（映射到文件无痕/代码注入等）
        - 再基于命令行简单规则识别下载并执行行为
        - 返回事件类别的大写形式或 'UNKNOWN'
        """
        category = (event.get('event') or {}).get('category', '')

        # 1. 优先处理内存异常
        if category == 'memory':
            anomalies = (event.get('memory') or {}).get('anomalies', [])
            for a in anomalies if isinstance(anomalies, list) else [anomalies]:
                if not isinstance(a, dict):
                    continue
                a_type = a.get('type')
                if a_type in self.memory_anomaly_labels:
                    return self.memory_anomaly_labels[a_type]

        # 2. 命令行与路径匹配（简化规则）
        cmd = (event.get('process') or {}).get('command_line', '') or ''
        if isinstance(cmd, str) and 'curl' in cmd and '|' in cmd and 'bash' in cmd:
            return 'DOWNLOAD_AND_EXECUTE'

        # 3. 返回类别大写或 UNKNOWN
        if category:
            return category.upper()
        return 'UNKNOWN'
