#!/bin/bash

echo "[*] Stopping TraceX Collectors..."

# 1. 杀死 Python 采集进程
# 使用 -f (full command line) 匹配脚本名
pkill -f "collector/host_collector/auditd_agent.py" && echo "  [-] Stopped Host Agent"
pkill -f "collector/network_collector/flow_parser_zeek.py" && echo "  [-] Stopped Zeek Agent"
pkill -f "collector/network_collector/flow_parser_cowrie.py" && echo "  [-] Stopped Cowrie Agent"

# 2. 杀死内存扫描器 (mem_scanner)
# 注意：scanner 可能是由 auditd_agent 调用的子进程，或者独立运行的
pkill -x "mem_scanner" && echo "  [-] Stopped Memory Scanner (Binary)"
pkill -f "mem_scanner/bin/scanner" && echo "  [-] Stopped Memory Scanner (Dev Path)"

echo "✅ All TraceX collection services stopped."
