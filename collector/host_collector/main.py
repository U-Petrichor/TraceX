import time
import subprocess
import os
import sys

# 添加项目根目录到 Python 路径，防止找不到模块
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from collector.host_collector.auditd_config import AuditdConfig
from collector.host_collector.log_parser import HostLogParser
from collector.common.es_client import ESClient

AUDIT_LOG_FILE = "/var/log/audit/audit.log"

def follow(file):
    """生成器：类似 tail -f 实时读取文件"""
    file.seek(0, 2) # 移动到文件末尾
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def main():
    print("[*] 启动主机行为采集模块...")
    
    # 1. 初始化配置 (应用规则)
    config = AuditdConfig()
    try:
        config.apply_rules()
    except Exception as e:
        print(f"[!] 警告: 规则应用失败 (可能需要 root 权限): {e}")

    # 2. 初始化组件
    parser = HostLogParser()
    # 注意：这里连接的是本机的 Docker ES，IP 用服务器内网 IP 或 localhost
    es = ESClient(hosts=["http://localhost:9200"]) 
    
    # 3. 开始监听日志
    print(f"[*] 开始监听日志文件: {AUDIT_LOG_FILE}")
    
    try:
        with open(AUDIT_LOG_FILE, "r") as f:
            for line in follow(f):
                try:
                    # 解析日志
                    raw_data = parser.parse_auditd_line(line)
                    if raw_data:
                        # 转换为统一格式
                        unified_event = parser.to_unified_event(raw_data)
                        
                        # 写入 Elasticsearch
                        # 注意：只写入我们关心的类型，过滤掉大量无关日志
                        if unified_event.event.category in ["process", "authentication"]:
                            doc_id = es.write_event(unified_event.to_dict())
                            print(f"[+] 日志已采集: {unified_event.event.category} - {doc_id}")
                            
                except Exception as e:
                    # 生产环境应该记录错误日志，这里为了调试直接打印
                    # print(f"[-] 解析错误: {e}")
                    pass
                    
    except PermissionError:
        print(f"[!] 错误: 无法读取 {AUDIT_LOG_FILE}，请使用 sudo 运行此脚本")

if __name__ == "__main__":
    main()