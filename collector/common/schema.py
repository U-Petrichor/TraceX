# collector/common/schema.py
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid

@dataclass
class GeoLocation:
    lat: float = 0.0
    lon: float = 0.0

@dataclass
class GeoInfo:
    country_name: str = ""
    city_name: str = ""
    location: GeoLocation = field(default_factory=GeoLocation)

@dataclass
class SourceInfo:
    ip: str = ""
    port: int = 0
    mac: str = ""
    geo: GeoInfo = field(default_factory=GeoInfo)

@dataclass
class DestinationInfo:
    ip: str = ""
    port: int = 0
    mac: str = ""

@dataclass
class HostOS:
    family: str = ""
    name: str = ""
    version: str = ""

@dataclass
class HostInfo:
    name: str = ""
    hostname: str = ""
    ip: List[str] = field(default_factory=list)
    os: HostOS = field(default_factory=HostOS)

@dataclass
class ProcessParent:
    pid: int = 0
    name: str = ""
    executable: str = ""

@dataclass
class ProcessUser:
    name: str = ""
    id: str = ""

@dataclass
class ProcessInfo:
    pid: int = 0
    name: str = ""
    executable: str = ""
    command_line: str = ""
    parent: ProcessParent = field(default_factory=ProcessParent)
    user: ProcessUser = field(default_factory=ProcessUser)
    start_time: str = "" 

@dataclass
class FileHash:
    md5: str = ""
    sha256: str = ""

@dataclass
class FileInfo:
    path: str = ""
    name: str = ""
    extension: str = ""
    size: int = 0
    hash: FileHash = field(default_factory=FileHash)

@dataclass
class NetworkInfo:
    protocol: str = ""
    transport: str = ""
    application: str = ""
    bytes: int = 0
    packets: int = 0
    direction: str = ""

@dataclass
class UserInfo:
    name: str = ""
    id: str = ""
    domain: str = ""
    session_id: str = "" 

@dataclass
class TacticInfo:
    id: str = ""
    name: str = ""

@dataclass
class TechniqueInfo:
    id: str = ""
    name: str = ""

@dataclass
class ThreatInfo:
    framework: str = "MITRE ATT&CK"
    tactic: TacticInfo = field(default_factory=TacticInfo)
    technique: TechniqueInfo = field(default_factory=TechniqueInfo)

@dataclass
class MetaData:
    """用于图计算和溯源分析的元数据"""
    atlas_label: str = ""     # ATLAS 抽象标签 (如 TEMP_FILE, WEBSHELL)
    path_signature: str = ""  # 路径签名，用于 NODOZE 频率分析

@dataclass
class DetectionInfo:
    """存储 Sigma/IDS 具体检测结果"""
    rules: List[str] = field(default_factory=list)
    confidence: float = 0.0                        # 置信度 0.0 - 1.0
    severity: str = ""                             # low, medium, high, critical


@dataclass
class MemoryAnomaly:
    """v4.1 新增: 内存异常详情"""
    type: str = ""          # MEMFD_EXEC, RWX_REGION, ANON_ELF, etc.
    address: str = ""       # 内存起始地址 (如 7f...)
    size: int = 0           # 区域大小
    perms: str = ""         # 权限字符串 (如 rwxp)
    path: str = ""          # 映射路径 (如 /memfd:...)
    is_elf: bool = False    # 是否包含 ELF 头
    risk_level: str = ""    # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float = 0.0 # 置信度
    details: str = ""       # 详细描述

@dataclass
class MemoryInfo:
    """v4.1 新增: 内存监控信息"""
    anomalies: List[MemoryAnomaly] = field(default_factory=list)

@dataclass
class EventInfo:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: str = ""  # process, network, file, authentication, memory, host
    type: str = ""      # start, end, info
    action: str = ""    # 具体动作
    outcome: str = ""   # success, failure, unknown
    severity: int = 5   # 1-10
    dataset: str = ""   # auditd, zeek, cowrie, etc.

@dataclass
class UnifiedEvent:
    """统一事件格式 v4.0"""
    # 注意：本项目统一采用北京时间 (UTC+8)，但在数据层仍存储为 ISO8601 UTC 格式以便于 ES 索引
    # 业务层应显式传入北京时间转换后的 UTC 时间
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    event: EventInfo = field(default_factory=EventInfo)
    source: SourceInfo = field(default_factory=SourceInfo)
    destination: DestinationInfo = field(default_factory=DestinationInfo)
    host: HostInfo = field(default_factory=HostInfo)
    process: ProcessInfo = field(default_factory=ProcessInfo)
    file: FileInfo = field(default_factory=FileInfo)
    network: NetworkInfo = field(default_factory=NetworkInfo)
    user: UserInfo = field(default_factory=UserInfo)
    threat: ThreatInfo = field(default_factory=ThreatInfo)
    message: str = ""
    raw: Dict = field(default_factory=dict)
    
    metadata: MetaData = field(default_factory=MetaData)
    detection: DetectionInfo = field(default_factory=DetectionInfo)
    
    memory: MemoryInfo = field(default_factory=MemoryInfo)
    
    def to_dict(self) -> dict:
        """转换为字典（用于存入 ES）"""
        data = asdict(self)
        data["@timestamp"] = data.pop("timestamp")
        return data
    
    def get_start_time_ms(self) -> str:
        """
        辅助方法: 获取用于生成唯一 ID 的时间基准
        优先使用 process.start_time，否则降级使用 @timestamp
        """
        if self.process.start_time:
            return self.process.start_time
        return self.timestamp

    @classmethod
    def from_dict(cls, data: dict) -> "UnifiedEvent":
        """从字典递归创建对象"""
        if not data:
            return cls()
            
        # 1. 处理时间戳名字差异
        if "@timestamp" in data:
            data["timestamp"] = data.pop("@timestamp")
            
        # 2. 递归转换嵌套的 Dataclass
        
        # Helper function for safe conversion
        def safe_convert(field_name, target_cls, parent_data):
            if isinstance(parent_data.get(field_name), dict):
                sub_data = parent_data[field_name]
                
                if field_name == "source":
                     if isinstance(sub_data.get("geo"), dict):
                        geo_data = sub_data["geo"]
                        if isinstance(geo_data.get("location"), dict):
                            geo_data["location"] = GeoLocation(**geo_data["location"])
                        sub_data["geo"] = GeoInfo(**geo_data)

                elif field_name == "host":
                    if isinstance(sub_data.get("os"), dict):
                        sub_data["os"] = HostOS(**sub_data["os"])
                
                elif field_name == "process":
                    if isinstance(sub_data.get("parent"), dict):
                        sub_data["parent"] = ProcessParent(**sub_data["parent"])
                    if isinstance(sub_data.get("user"), dict):
                        sub_data["user"] = ProcessUser(**sub_data["user"])

                elif field_name == "file":
                    if isinstance(sub_data.get("hash"), dict):
                        sub_data["hash"] = FileHash(**sub_data["hash"])
                
                elif field_name == "threat":
                    if isinstance(sub_data.get("tactic"), dict):
                        sub_data["tactic"] = TacticInfo(**sub_data["tactic"])
                    if isinstance(sub_data.get("technique"), dict):
                        sub_data["technique"] = TechniqueInfo(**sub_data["technique"])

                elif field_name == "memory":
                    if isinstance(sub_data.get("anomalies"), list):
                        anomalies_list = sub_data["anomalies"]
                        converted_anomalies = []
                        for item in anomalies_list:
                            if isinstance(item, dict):
                                valid_item_keys = {k: v for k, v in item.items() if k in MemoryAnomaly.__dataclass_fields__}
                                converted_anomalies.append(MemoryAnomaly(**valid_item_keys))
                            else:
                                converted_anomalies.append(item)
                        sub_data["anomalies"] = converted_anomalies
                
                # 直接转换
                try:
                    valid_sub_keys = {k: v for k, v in sub_data.items() if k in target_cls.__dataclass_fields__}
                    parent_data[field_name] = target_cls(**valid_sub_keys)
                except Exception:
                    parent_data[field_name] = target_cls()

        # 执行转换
        safe_convert("event", EventInfo, data)
        safe_convert("source", SourceInfo, data)
        safe_convert("destination", DestinationInfo, data)
        safe_convert("host", HostInfo, data)
        safe_convert("process", ProcessInfo, data)
        safe_convert("file", FileInfo, data)
        safe_convert("network", NetworkInfo, data)
        safe_convert("user", UserInfo, data)
        safe_convert("threat", ThreatInfo, data)
        safe_convert("metadata", MetaData, data)
        safe_convert("detection", DetectionInfo, data)
        safe_convert("memory", MemoryInfo, data)

        # 3. 创建主对象
        valid_keys = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid_keys)