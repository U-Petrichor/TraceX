# TraceX - 恶意攻击行为溯源分析系统

## 项目简介
TraceX 是一个基于多源数据（主机日志、网络流量、蜜罐）的攻击溯源分析系统。它能够实现 ATT&CK 攻击链识别、时间线关联分析以及攻击路径重建。

## 目录结构
- `collector/`: 数据采集层 (Host Logs, Network Flows)
- `analyzer/`: 分析引擎 (ATT&CK Mapping, Graph Building)
- `infrastructure/`: 靶场环境 (Docker Range)
- `frontend/`: 可视化与展示

## 快速开始
1. 启动环境: `docker compose up -d`
2. 访问 Kibana: `http://localhost:5601`
3. 运行分析: `python analyzer/main.py`