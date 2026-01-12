# collector/common/schema.py
"""统一数据格式定义"""
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict
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
class EventInfo:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: str = ""  # process, network, file, authentication, host
    type: str = ""      # start, end, info
    action: str = ""    # 具体动作
    outcome: str = ""   # success, failure, unknown
    severity: int = 5   # 1-10
    dataset: str = ""   # auditd, zeek, cowrie, etc.

@dataclass
class UnifiedEvent:
    """统一事件格式"""
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
    
    def to_dict(self) -> dict:
        """转换为字典（用于存入 ES）"""
        data = asdict(self)
        data["@timestamp"] = data.pop("timestamp")
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "UnifiedEvent":
        """从字典创建"""
        if "@timestamp" in data:
            data["timestamp"] = data.pop("@timestamp")
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
