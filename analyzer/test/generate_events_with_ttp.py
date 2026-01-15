"""
模式 1: 直接生成带 TTP 标签的事件
TTP 直接写入 threat.technique.id，跳过 Sigma 检测
用于快速验证归因逻辑
"""
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collector.common.schema import UnifiedEvent


# ========== APT 组织 TTP 清单 (MITRE STIX 真实数据) ==========
APT_TTPS = {
    "APT28": ["T1584.008", "T1078", "T1598", "T1030", "T1110.003", "T1036.005", "T1596", "T1037.001", "T1546.015", "T1021.002"],
    "APT29": ["T1070.004", "T1037.004", "T1199", "T1078", "T1047", "T1059.001", "T1568", "T1090.002", "T1070.006", "T1587.001"],
    "FIN7": ["T1078", "T1027.016", "T1047", "T1059.001", "T1572", "T1021.001", "T1674", "T1569.002", "T1102.002", "T1486"],
    "Indrik_Spider": ["T1078", "T1047", "T1059.001", "T1021.001", "T1587.001", "T1486", "T1036.005", "T1552.001", "T1018", "T1484.001"],
    "LuminousMoth": ["T1030", "T1587.001", "T1036.005", "T1574.001", "T1005", "T1553.002", "T1560", "T1112", "T1083", "T1091"],
}

# IOC 来源 (会在 IOC 富化时命中本地库)
IOC_SOURCES = [
    ("59.64.129.102", "45.33.2.1"),
    ("203.0.113.99", "198.51.100.23"),
    ("10.0.0.50", "192.168.1.20"),
]

CATEGORY_ROTATION = ["authentication", "process", "process", "network", "file", "file", "process", "network", "process", "file"]


def _build_event(base_time, offset_s, category, ttp_id, host="PC-1", src_ip=None, dst_ip=None):
    event = UnifiedEvent()
    event.timestamp = (base_time + timedelta(seconds=offset_s)).isoformat() + "Z"
    event.event.category = category
    event.event.dataset = "windows"
    event.host.name = host

    if category == "authentication":
        event.event.action = "login"
        event.event.outcome = "success"
        event.user.name = "admin"
        if src_ip:
            event.source.ip = src_ip
        if dst_ip:
            event.destination.ip = dst_ip
    elif category == "process":
        event.process.pid = 4000 + offset_s
        event.process.parent.pid = 3000
        event.process.name = "powershell.exe"
        event.process.executable = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        event.process.command_line = f"powershell -enc {ttp_id[-4:]}"
        event.process.start_time = event.timestamp
    elif category == "network":
        if src_ip:
            event.source.ip = src_ip
            event.source.port = 51500 + offset_s
        if dst_ip:
            event.destination.ip = dst_ip
            event.destination.port = 443
        event.network.protocol = "https"
        event.network.direction = "outbound"
    elif category == "file":
        event.event.action = "write"
        event.file.path = f"C:\\Users\\Public\\Documents\\{ttp_id}.txt"
        event.file.name = f"{ttp_id}.txt"
        event.file.extension = "txt"

    # 直接写入 TTP
    event.threat.technique.id = ttp_id
    event.threat.technique.name = ""
    return event.to_dict()


def generate_all(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    base_time = datetime.utcnow()

    for apt_name, ttps in APT_TTPS.items():
        events = []
        for i, ttp in enumerate(ttps):
            category = CATEGORY_ROTATION[i % len(CATEGORY_ROTATION)]
            src_ip, dst_ip = IOC_SOURCES[i % len(IOC_SOURCES)]
            events.append(_build_event(base_time, i + 1, category, ttp, src_ip=src_ip, dst_ip=dst_ip))

        file_path = output_dir / f"{apt_name}.jsonl"
        with file_path.open("w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"[直接TTP] 生成 {len(events)} 事件 -> {file_path}")


if __name__ == "__main__":
    generate_all(Path(__file__).resolve().parent / "apt_events" / "direct")
