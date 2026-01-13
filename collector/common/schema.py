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
        
        # 递归清理空字符串，避免 ES 类型映射错误 (如 IP 字段不允许空字符串)
        def clean_data(d):
            if isinstance(d, dict):
                return {k: clean_data(v) for k, v in d.items() if v != ""}
            return d
            
        return clean_data(data)

    @classmethod
    def from_dict(cls, data: dict) -> "UnifiedEvent":
        """从字典递归创建对象 (升级版)"""
        if not data:
            return cls()
            
        # 1. 处理时间戳名字差异
        if "@timestamp" in data:
            data["timestamp"] = data.pop("@timestamp")
            
        # 2. 递归转换嵌套的 Dataclass
        
        # --- EventInfo ---
        if isinstance(data.get("event"), dict):
            data["event"] = EventInfo(**data["event"])
            
        # --- SourceInfo (包含 GeoInfo) ---
        if isinstance(data.get("source"), dict):
            src_data = data["source"]
            # 处理 source.geo
            if isinstance(src_data.get("geo"), dict):
                geo_data = src_data["geo"]
                # 处理 source.geo.location
                if isinstance(geo_data.get("location"), dict):
                    geo_data["location"] = GeoLocation(**geo_data["location"])
                src_data["geo"] = GeoInfo(**geo_data)
            data["source"] = SourceInfo(**src_data)

        # --- DestinationInfo ---
        if isinstance(data.get("destination"), dict):
            data["destination"] = DestinationInfo(**data["destination"])
            
        # --- HostInfo (包含 HostOS) ---
        if isinstance(data.get("host"), dict):
            host_data = data["host"]
            if isinstance(host_data.get("os"), dict):
                host_data["os"] = HostOS(**host_data["os"])
            data["host"] = HostInfo(**host_data)
            
        # --- ProcessInfo (包含 Parent 和 User) ---
        if isinstance(data.get("process"), dict):
            proc_data = data["process"]
            if isinstance(proc_data.get("parent"), dict):
                proc_data["parent"] = ProcessParent(**proc_data["parent"])
            if isinstance(proc_data.get("user"), dict):
                proc_data["user"] = ProcessUser(**proc_data["user"])
            data["process"] = ProcessInfo(**proc_data)
            
        # --- FileInfo (包含 Hash) ---
        if isinstance(data.get("file"), dict):
            file_data = data["file"]
            if isinstance(file_data.get("hash"), dict):
                file_data["hash"] = FileHash(**file_data["hash"])
            data["file"] = FileInfo(**file_data)
            
        # --- NetworkInfo ---
        if isinstance(data.get("network"), dict):
            data["network"] = NetworkInfo(**data["network"])
            
        # --- UserInfo ---
        if isinstance(data.get("user"), dict):
            data["user"] = UserInfo(**data["user"])
            
        # --- ThreatInfo (包含 Tactic 和 Technique) ---
        if isinstance(data.get("threat"), dict):
            threat_data = data["threat"]
            if isinstance(threat_data.get("tactic"), dict):
                threat_data["tactic"] = TacticInfo(**threat_data["tactic"])
            if isinstance(threat_data.get("technique"), dict):
                threat_data["technique"] = TechniqueInfo(**threat_data["technique"])
            data["threat"] = ThreatInfo(**threat_data)

        # 3. 创建主对象
        # 过滤掉不在 dataclass 定义中的多余字段，防止报错
        valid_keys = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid_keys)