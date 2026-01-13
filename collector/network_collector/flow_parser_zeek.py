import json
import os
import sys
import time
import threading
import math
import socket
from collections import Counter
from datetime import datetime, timezone

# 确保项目根目录在路径中
sys.path.append('/root/TraceX')

try:
    from collector.common.es_client import ESClient
    from collector.common.schema import (
        UnifiedEvent, EventInfo, SourceInfo, DestinationInfo, NetworkInfo, 
        ThreatInfo, TacticInfo, TechniqueInfo, FileInfo, FileHash,
        # v4.0 新增引入
        DetectionInfo, HostInfo, MetaData
    )
except ImportError:
    print("错误: 无法加载 TraceX 公共模块，请检查目录结构是否正确")
    sys.exit(1)

class ZeekParser:
    def __init__(self):
        self.es_client = ESClient(hosts=["http://localhost:9200"])
        self.log_dir = "/root/TraceX/data/zeek-logs"
        self.hostname = socket.gethostname() # 获取当前传感器主机名，用于图关联
        
        self.log_configs = {
            "conn.log": self.handle_conn,
            "dns.log": self.handle_dns,
            "http.log": self.handle_http,
            "ssl.log": self.handle_ssl,
            "files.log": self.handle_files
        }
        
        self.batch_size = 50       
        self.flush_interval = 2    

    def calculate_entropy(self, text):
        """计算字符串的香农熵"""
        if not text: return 0
        counter = Counter(text)
        length = len(text)
        return round(-sum((count/length) * math.log2(count/length) for count in counter.values()), 2)

    def _create_base_event(self, raw_data, category, dataset):
        """标准化基础事件创建 (适配 Schema v4.0)"""
        ts = raw_data.get("ts")
        # 转换为 UTC ISO8601 字符串
        iso_ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z") if ts else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        event_obj = UnifiedEvent(
            timestamp=iso_ts,
            event=EventInfo(category=category, dataset=dataset, severity=3, action="network_flow"),
            source=SourceInfo(ip=raw_data.get("id.orig_h", ""), port=raw_data.get("id.orig_p", 0)),
            destination=DestinationInfo(ip=raw_data.get("id.resp_h", ""), port=raw_data.get("id.resp_p", 0)),
            # [v5.1 关键] 必须填充 host.name，否则 GraphBuilder 生成的 ID 会冲突
            host=HostInfo(name=self.hostname, ip=[raw_data.get("id.orig_h", "")]),
            # [v4.0] 初始化新增字段
            metadata=MetaData(), 
            detection=DetectionInfo(),
            raw=raw_data
        )
        return event_obj

    # --- 协议处理器 ---

    def handle_dns(self, raw_data):
        """DNS 隧道检测"""
        event_obj = self._create_base_event(raw_data, "network", "zeek.dns")
        query = raw_data.get("query", "")
        event_obj.network = NetworkInfo(protocol="dns", transport="udp")
        
        reasons = []
        if len(query) > 70: reasons.append(f"Length({len(query)})")
        sub_depth = len(query.split('.'))
        if sub_depth > 7: reasons.append(f"Depth({sub_depth})")
        
        entropy = self.calculate_entropy(query)
        if entropy > 5.0: reasons.append(f"Entropy({entropy})")

        if reasons:
            # MITRE ATT&CK 映射
            event_obj.threat = ThreatInfo(
                technique=TechniqueInfo(id="T1071.004", name="DNS Tunneling")
            )
            # Schema v4.0 DetectionInfo 填充
            event_obj.detection = DetectionInfo(
                rules=[f"DNS Anomaly: {r}" for r in reasons],
                confidence=0.9,
                severity="high"
            )
            event_obj.event.severity = 7
            event_obj.message = f"DNS隧道检测 [{', '.join(reasons)}]: {query}"
        else:
            event_obj.message = f"DNS Query: {query}"
        return event_obj.to_dict()

    def handle_conn(self, raw_data):
        """ICMP 隧道检测"""
        event_obj = self._create_base_event(raw_data, "network", "zeek.conn")
        proto = raw_data.get("proto", "unknown")
        event_obj.network = NetworkInfo(
            protocol=proto, 
            bytes=raw_data.get("orig_bytes", 0),
            packets=raw_data.get("orig_pkts", 0)
        )
        
        if proto == "icmp" and (raw_data.get("orig_bytes") or 0) > 800:
            event_obj.threat = ThreatInfo(
                technique=TechniqueInfo(id="T1071.004", name="ICMP Tunneling")
            )
            event_obj.detection = DetectionInfo(
                rules=["Large ICMP Payload"],
                confidence=0.8,
                severity="high"
            )
            event_obj.event.severity = 7
            event_obj.message = "疑似 ICMP 隧道告警"
        else:
            event_obj.message = f"Conn: {proto} flow"
        return event_obj.to_dict()

    def handle_ssl(self, raw_data):
        """弱加密检测"""
        event_obj = self._create_base_event(raw_data, "network", "zeek.ssl")
        version = raw_data.get("version", "unknown")
        event_obj.network = NetworkInfo(protocol="ssl", application=version)
        
        if version in ["SSLv2", "SSLv3", "TLSv10"]:
            event_obj.threat = ThreatInfo(
                technique=TechniqueInfo(id="T1573", name="Insecure TLS Version")
            )
            event_obj.detection = DetectionInfo(
                rules=[f"Deprecated Protocol: {version}"],
                confidence=1.0,
                severity="medium"
            )
            event_obj.event.severity = 7
            event_obj.message = f"弱加密协议检测: {version}"
        else:
            event_obj.message = f"SSL/TLS Handshake: {version}"
        return event_obj.to_dict()

    def handle_http(self, raw_data):
        """HTTP 会话重建"""
        event_obj = self._create_base_event(raw_data, "network", "zeek.http")
        method = raw_data.get("method", "UNKNOWN")
        uri = raw_data.get("uri", "")
        host = raw_data.get("host", "")
        
        event_obj.network = NetworkInfo(
            protocol="http",
            application="http",
            direction="outbound" # 简单假设，组员3会进行更宽容的关联
        )
        event_obj.message = f"HTTP {method} {host}{uri}"
        return event_obj.to_dict()

    def handle_files(self, raw_data):
        """文件指纹提取"""
        event_obj = self._create_base_event(raw_data, "file", "zeek.files")
        event_obj.file = FileInfo(
            name=raw_data.get("filename", "unknown"), 
            hash=FileHash(md5=raw_data.get("md5", ""), sha256=raw_data.get("sha256", ""))
        )
        event_obj.message = f"网络传输文件: {event_obj.file.name}"
        return event_obj.to_dict()

    # --- 核心引擎 ---

    def follow_log(self, filename, handler_func):
        filepath = os.path.join(self.log_dir, filename)
        # 等待日志文件生成
        while not os.path.exists(filepath): time.sleep(1)
        
        f = open(filepath, "r")
        f.seek(0, 2)  # 启动时跳过旧历史数据
        last_ino = os.fstat(f.fileno()).st_ino
        batch_data = []
        last_flush_time = time.time()

        while True:
            line = f.readline()
            current_time = time.time()
            
            # 批量写入与超时强制写入
            if batch_data and (len(batch_data) >= self.batch_size or (current_time - last_flush_time > self.flush_interval)):
                self.es_client.write_events_bulk(batch_data, index_prefix="network-flows")
                batch_data = []
                last_flush_time = current_time

            if not line:
                # Inode 轮转检测 (Log Rotation Support)
                try:
                    if os.path.exists(filepath) and os.stat(filepath).st_ino != last_ino:
                        print(f"[*] 日志轮转 [{filename}]：重载新文件")
                        f.close()
                        f = open(filepath, "r")
                        last_ino = os.fstat(f.fileno()).st_ino
                        continue
                except: pass
                time.sleep(0.5)
                continue

            if not line.strip().startswith('{'): continue
            
            try:
                raw_log = json.loads(line)
                unified_data = handler_func(raw_log)
                batch_data.append(unified_data)
                
                # 实时控制台输出 (高亮告警)
                msg = unified_data.get('message', '')
                alert_tag = ""
                # 检查 threat 字段是否存在且包含 technique.name
                if 'threat' in unified_data and unified_data['threat']:
                    # 注意：unified_data 此时是 dict，不是对象
                    tech = unified_data['threat'].get('technique', {})
                    if tech and tech.get('name'):
                        alert_tag = f" [!! ALERT: {tech.get('name')} !!]"
                
                print(f"[PROCESS][{filename}] {raw_log.get('id.orig_h')} -> {raw_log.get('id.resp_h')} | {msg}{alert_tag}")

            except Exception as e:
                print(f"[Error][{filename}] 解析失败: {e}")

    def start(self):
        print(f"[*] TraceX 网络探针启动 (Schema v4.0 Compatible)")
        print(f"[*] 检测模型: DNS Tunneling / ICMP Tunneling / Weak SSL / File Hash")
        print(f"[*] 数据输出: Elasticsearch (network-flows-*)")
        
        for log_file, handler in self.log_configs.items():
            t = threading.Thread(target=self.follow_log, args=(log_file, handler), daemon=True)
            t.start()
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] 监控引擎已手动停止")

if __name__ == "__main__":
    ZeekParser().start()
