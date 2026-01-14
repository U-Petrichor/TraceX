# /root/TraceX/collector/network_collector/flow_parser_cowrie.py
import json
import os
import sys
import time
import socket
from datetime import datetime, timezone

# 导入公共模块
sys.path.append('/root/TraceX')
try:
    from collector.common.es_client import ESClient
    from collector.common.schema import (
        UnifiedEvent, EventInfo, SourceInfo, DestinationInfo, 
        HostInfo, UserInfo, ProcessInfo, MetaData,
        ThreatInfo, TechniqueInfo, DetectionInfo
    )
except ImportError:
    print("错误: 无法找到公共模块，请确认目录结构。")
    sys.exit(1)

class CowrieParser:
    def __init__(self):
        self.es_client = ESClient(hosts=["http://localhost:9200"])
        self.log_path = "/root/TraceX/infrastructure/range/honeypots/cowrie/var/log/cowrie/cowrie.json"
        # [Schema v4.0 关键] 获取真实主机名，确保图谱节点 ID 一致
        self.hostname = socket.gethostname()

    def _analyze_command(self, cmd: str):
        """
        针对 TraceX v5.1 剧本进行命令审计
        返回: (ThreatInfo, DetectionInfo, severity_int)
        """
        threat = None
        detection = DetectionInfo()
        severity = 5 # 默认关注

        if not cmd:
            return threat, detection, 3

        # 规则 1: 外部工具下载 (Ingress Tool Transfer)
        if "curl" in cmd or "wget" in cmd:
            threat = ThreatInfo(
                technique=TechniqueInfo(id="T1105", name="Ingress Tool Transfer")
            )
            detection = DetectionInfo(
                rules=["Suspicious Downloader (curl/wget)"],
                confidence=1.0,
                severity="high"
            )
            severity = 8

        # 规则 2: 敏感文件访问 (Discovery)
        elif "/etc/passwd" in cmd or "/etc/shadow" in cmd or "whoami" in cmd:
            threat = ThreatInfo(
                technique=TechniqueInfo(id="T1087", name="Account Discovery")
            )
            detection = DetectionInfo(
                rules=["Sensitive File Access"],
                confidence=0.9,
                severity="medium"
            )
            severity = 7

        # 规则 3: 隐蔽操作/清除痕迹 (Defense Evasion)
        elif "rm " in cmd or "mv " in cmd or "chmod" in cmd:
            threat = ThreatInfo(
                technique=TechniqueInfo(id="T1070", name="Indicator Removal")
            )
            detection = DetectionInfo(
                rules=["File Manipulation"],
                confidence=0.7,
                severity="medium"
            )
            severity = 6

        return threat, detection, severity

    def map_to_unified(self, raw_log: dict) -> dict:
        """Schema v4.0 标准化映射"""
        event_id = raw_log.get("eventid", "")
        ts = raw_log.get("timestamp")
        # 确保时间戳格式统一
        if ts:
             # Cowrie 默认可能是 ISO 格式，直接使用或微调
            iso_ts = ts if "T" in ts else datetime.utcnow().isoformat() + "Z"
        else:
            iso_ts = datetime.utcnow().isoformat() + "Z"

        # 1. 基础字段初始化
        category = "host"
        action = event_id.split('.')[-1] if '.' in event_id else event_id
        severity = 3
        outcome = "success"
        
        # 2. 预处理对象
        threat_obj = None
        detect_obj = DetectionInfo()
        
        # 3. 场景逻辑分支
        cmd_line = ""
        
        if "login" in event_id:
            category = "authentication"
            if "failed" in event_id:
                outcome = "failure"
                severity = 5
                detect_obj = DetectionInfo(rules=["Brute Force Attempt"], confidence=0.6, severity="low")
            else:
                severity = 1 # 攻击者成功登录是严重事件，但在蜜罐中我们先标记为低，等他执行命令再告警
        
        elif "command.input" in event_id:
            category = "process"
            cmd_line = raw_log.get("input", "")
            # 调用命令审计引擎
            threat_obj, detect_obj, severity = self._analyze_command(cmd_line)
            
        elif "direct-tcpip" in event_id:
            category = "network"
            severity = 5
            action = "proxy_attempt"

        # 4. 构建 UnifiedEvent
        event_obj = UnifiedEvent(
            timestamp=iso_ts,
            event=EventInfo(
                category=category,
                type="info",
                action=action,
                outcome=outcome,
                severity=severity,
                dataset="cowrie"
            ),
            source=SourceInfo(
                ip=raw_log.get("src_ip", ""),
                port=raw_log.get("src_port", 0)
            ),
            destination=DestinationInfo(
                ip=raw_log.get("dst_ip", ""),
                port=raw_log.get("dst_port", 2222)
            ),
            # [关键] 注入真实主机信息，供 GraphBuilder 使用
            host=HostInfo(
                name=self.hostname,
                ip=[raw_log.get("dst_ip", "")]
            ),
            user=UserInfo(
                name=raw_log.get("username", "unknown"),
                session_id=raw_log.get("session", "")  # 关键：用于区分不同攻击会话
            ),
            process=ProcessInfo(
                command_line=cmd_line,
                name=cmd_line.split()[0] if cmd_line else ""
            ),
            # v4.0 新增字段注入
            threat=threat_obj if threat_obj else ThreatInfo(), # 保持空对象结构
            detection=detect_obj,
            metadata=MetaData(),
            message=raw_log.get("message", f"Cowrie Event: {event_id}"),
            raw=raw_log
        )
        
        return event_obj.to_dict()

    def start_parsing(self):
        print(f"[*] Cowrie 蜜罐解析器 v5.1 启动 (Schema v4.0)")
        print(f"[*] 审计模式: 监听 APT 命令 (curl/wget/mv) 与 暴力破解")
        
        if not os.path.exists(self.log_path):
            print(f"等待日志文件生成: {self.log_path}")
            while not os.path.exists(self.log_path): time.sleep(1)

        # 打开文件并跳到末尾，只处理实时攻击
        f = open(self.log_path, "r")
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                raw_log = json.loads(line)
                eid = raw_log.get("eventid", "")
                
                # 关注列表：只处理有价值的攻击行为
                valid_events = [
                    "cowrie.session.connect", 
                    "cowrie.login.success", 
                    "cowrie.login.failed", 
                    "cowrie.command.input",
                    "cowrie.session.file_download"
                ]
                
                if eid in valid_events:
                    unified_data = self.map_to_unified(raw_log)
                    self.es_client.write_event(unified_data, index_prefix="honeypot-logs")
                    
                    # 实时控制台反馈
                    src = raw_log.get('src_ip')
                    msg = unified_data.get('message')
                    
                    # 告警高亮
                    alert_tag = ""
                    if unified_data.get('event', {}).get('severity', 0) >= 7:
                        alert_tag = f" [!! ALERT: {unified_data['threat']['technique']['name']} !!]"
                    
                    print(f"[HONEYPOT] {src} | {eid} -> {msg}{alert_tag}")
                    
            except Exception as e:
                # 忽略 JSON 解析错误
                pass

if __name__ == "__main__":
    CowrieParser().start_parsing()
