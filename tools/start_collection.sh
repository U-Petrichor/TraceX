#!/bin/bash
export PYTHONPATH=$PYTHONPATH:.

# 1. 审计规则下发
auditctl -D
auditctl -a always,exit -F arch=b64 -S execve -k process_spawn

# 2. 检查内存防御引擎是否存在
if [ ! -f "/opt/tracex/bin/mem_scanner" ]; then
    echo "⚠️ Warning: mem_scanner not found, memory anomaly detection may fail."
fi

# 3. 清理旧进程
pkill -f auditd_agent.py
pkill -f flow_parser_zeek.py
pkill -f flow_parser_cowrie.py

# 4. 后台启动采集插件
nohup python3 -u collector/host_collector/auditd_agent.py > /tmp/agent_host.log 2>&1 &
nohup python3 -u collector/network_collector/flow_parser_zeek.py > /tmp/agent_zeek.log 2>&1 &
nohup python3 -u collector/network_collector/flow_parser_cowrie.py > /tmp/agent_cowrie.log 2>&1 &

echo "✅ TraceX Collection Layer Started."
