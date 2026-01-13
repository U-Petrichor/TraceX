import json
import os
import sys
import time
import threading
import math
from collections import Counter
from datetime import datetime, timezone

# 确保项目根目录在路径中，以便加载公共模块
sys.path.append('/root/TraceX')

try:
    from collector.common.es_client import ESClient
    from collector.common.schema import (
        UnifiedEvent, EventInfo, SourceInfo, DestinationInfo, NetworkInfo, 
        ThreatInfo, TacticInfo, TechniqueInfo, FileInfo, FileHash
    )
except ImportError:
    print("错误: 无法加载 TraceX 公共模块，请检查目录结构是否正确")
    sys.exit(1)

class ZeekParser:
    def __init__(self):
        # 初始化 ES 客户端，目标地址 localhost:9200
        self.es_client = ESClient(hosts=["http://localhost:9200"])
        self.log_dir = "/root/TraceX/data/zeek-logs"
        
        # 配置监控目标：日志文件与其处理器
        self.log_configs = {
            "conn.log": self.handle_conn,
            "dns.log": self.handle_dns,
            "http.log": self.handle_http,
            "ssl.log": self.handle_ssl,
            "files.log": self.handle_files
        }
        
        # 批量处理参数
        self.batch_size = 50       # 积攒 50 条写入一次
        self.flush_interval = 2    # 不满 50 条，每 2 秒强制刷入一次

    def calculate_entropy(self, text):
        """计算字符串的香农熵 (Shannon Entropy)"""
        if not text: return 0
        counter = Counter(text)
        length = len(text)
        return round(-sum((count/length) * math.log2(count/length) for count in counter.values()), 2)

    def _create_base_event(self, raw_data, category, dataset):
        """标准化基础事件创建，默认 threat 设为 None"""
        ts = raw_data.get("ts")
        iso_ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z") if ts else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        event_obj = UnifiedEvent(
            timestamp=iso_ts,
            event=EventInfo(category=category, dataset=dataset, severity=3),
            source=SourceInfo(ip=raw_data.get("id.orig_h", ""), port=raw_data.get("id.orig_p", 0)),
            destination=DestinationInfo(ip=raw_data.get("id.resp_h", ""), port=raw_data.get("id.resp_p", 0)),
            raw=raw_data
        )
        event_obj.threat = None 
        return event_obj

    # --- 协议处理器逻辑 ---

    def handle_dns(self, raw_data):
        """三维 DNS 隧道检测：长度 > 70, 深度 > 7, 熵值 > 5.0"""
        event_obj = self._create_base_event(raw_data, "network", "zeek.dns")
        query = raw_data.get("query", "")
        event_obj.network = NetworkInfo(protocol="dns")
        
        reasons = []
        if len(query) > 70: reasons.append(f"Length({len(query)})")
        sub_depth = len(query.split('.'))
        if sub_depth > 7: reasons.append(f"Depth({sub_depth})")
        
        entropy = self.calculate_entropy(query)
        if entropy > 5.0: reasons.append(f"Entropy({entropy})")

        if reasons:
            event_obj.threat = ThreatInfo(technique=TechniqueInfo(id="T1071.004", name="DNS Tunneling"))
            event_obj.event.severity = 7
            event_obj.message = f"DNS隧道检测 [{', '.join(reasons)}]: {query}"
        else:
            event_obj.message = f"DNS Query: {query}"
        return event_obj.to_dict()

    def handle_conn(self, raw_data):
        """ICMP 隧道检测：载荷 > 800 字节"""
        event_obj = self._create_base_event(raw_data, "network", "zeek.conn")
        event_obj.network = NetworkInfo(protocol=raw_data.get("proto", "unknown"))
        
        if raw_data.get("proto") == "icmp" and (raw_data.get("orig_bytes") or 0) > 800:
            event_obj.threat = ThreatInfo(technique=TechniqueInfo(id="T1071.004", name="ICMP Tunneling"))
            event_obj.message = "疑似 ICMP 隧道告警"
        else:
            event_obj.message = f"Conn: {raw_data.get('proto')} flow"
        return event_obj.to_dict()

    def handle_ssl(self, raw_data):
        """异常协议建模：检测 SSLv2, SSLv3, TLSv10 弱加密"""
        event_obj = self._create_base_event(raw_data, "network", "zeek.ssl")
        version = raw_data.get("version", "unknown")
        
        # 已还原：只针对真正的弱加密协议告警
        if version in ["SSLv2", "SSLv3", "TLSv10"]:
            event_obj.threat = ThreatInfo(technique=TechniqueInfo(id="T1573", name="Insecure TLS Version"))
            event_obj.event.severity = 7
            event_obj.message = f"弱加密协议检测: {version}"
        else:
            event_obj.message = f"SSL/TLS: {version}"
        return event_obj.to_dict()

    def handle_http(self, raw_data):
        """网络会话重建：提取完整 URI"""
        event_obj = self._create_base_event(raw_data, "network", "zeek.http")
        event_obj.message = f"HTTP {raw_data.get('method')} {raw_data.get('host', '')}{raw_data.get('uri', '')}"
        return event_obj.to_dict()

    def handle_files(self, raw_data):
        """网络会话重建：文件传输指纹提取"""
        event_obj = self._create_base_event(raw_data, "file", "zeek.files")
        event_obj.file = FileInfo(
            name=raw_data.get("filename", "unknown"), 
            hash=FileHash(md5=raw_data.get("md5", ""), sha256=raw_data.get("sha256", ""))
        )
        event_obj.message = f"网络传输文件: {event_obj.file.name}"
        return event_obj.to_dict()

    # --- 核心驱动引擎 ---

    def follow_log(self, filename, handler_func):
        filepath = os.path.join(self.log_dir, filename)
        while not os.path.exists(filepath): time.sleep(1)
        
        f = open(filepath, "r")
        f.seek(0, 2)  # 只处理启动后的实时流量
        last_ino = os.fstat(f.fileno()).st_ino
        batch_data = []
        last_flush_time = time.time()

        while True:
            line = f.readline()
            if not line:
                # 定时刷入缓冲区数据
                if batch_data and (time.time() - last_flush_time > self.flush_interval):
                    self.es_client.write_events_bulk(batch_data, index_prefix="network-flows")
                    batch_data = []
                    last_flush_time = time.time()
                
                # Inode 轮转感知
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
                
                # --- 严格告警判断与实时显示 ---
                msg = unified_data.get('message', '')
                alert_tag = ""
                threat = unified_data.get('threat')
                # 只有当 technique 里的 name 确实存在时才标记为告警
                if threat and isinstance(threat, dict):
                    tech = threat.get('technique', {})
                    if tech and tech.get('name'):
                        alert_tag = f" [!! ALERT: {tech.get('name')} !!]"
                
                # 实时显示每条数据的解析摘要
                print(f"[PROCESS][{filename}] {raw_log.get('id.orig_h')} -> {raw_log.get('id.resp_h')} | {msg}{alert_tag}")

                if len(batch_data) >= self.batch_size:
                    self.es_client.write_events_bulk(batch_data, index_prefix="network-flows")
                    batch_data = []
                    last_flush_time = time.time()
            except Exception as e:
                print(f"[Error][{filename}] 解析失败: {e}")

    def start(self):
        print(f"[*] TraceX 引擎启动成功：已开启批量处理与 Inode 轮转感知")
        print(f"[*] 当前检测模型：DNS隧道、ICMP隧道、弱加密版本、HTTP行为、文件指纹")
        for log_file, handler in self.log_configs.items():
            t = threading.Thread(target=self.follow_log, args=(log_file, handler), daemon=True)
            t.start()
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] 监控引擎已手动停止")

if __name__ == "__main__":
    ZeekParser().start()
