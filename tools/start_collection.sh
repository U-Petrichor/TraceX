#!/bin/bash

# Ensure we are running from the project root
cd "$(dirname "$0")/.." || exit

export PYTHONPATH=$PYTHONPATH:.

# 1. 审计规则下发 (使用统一配置)
echo "[*] Applying Auditd rules from configuration..."
python3 collector/host_collector/auditd_config.py

# 2. 检查内存防御引擎是否存在 (兼容 Prod 和 Dev 路径)
PROD_SCANNER="/opt/tracex/bin/mem_scanner"
DEV_SCANNER="collector/host_collector/mem_scanner/bin/scanner"

if [ -f "$PROD_SCANNER" ]; then
    echo "[*] Memory Scanner found: $PROD_SCANNER (Production)"
elif [ -f "$DEV_SCANNER" ]; then
    echo "[*] Memory Scanner found: $DEV_SCANNER (Development)"
else
    echo "⚠️ Warning: mem_scanner not found in Prod or Dev paths. Memory anomaly detection may fail."
fi

# 3. 清理旧进程
echo "[*] Cleaning up old processes..."
pkill -f auditd_agent.py
pkill -f flow_parser_zeek.py
pkill -f flow_parser_cowrie.py

# 4. 后台启动采集插件
echo "[*] Starting collectors in background..."
nohup python3 -u collector/host_collector/auditd_agent.py > /tmp/agent_host.log 2>&1 &
echo "  [+] Host Agent started (PID: $!)"

nohup python3 -u collector/network_collector/flow_parser_zeek.py > /tmp/agent_zeek.log 2>&1 &
echo "  [+] Zeek Agent started (PID: $!)"

nohup python3 -u collector/network_collector/flow_parser_cowrie.py > /tmp/agent_cowrie.log 2>&1 &
echo "  [+] Cowrie Agent started (PID: $!)"

echo "✅ TraceX Collection Layer Started."
