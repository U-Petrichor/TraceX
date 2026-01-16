# TraceX - 恶意攻击行为溯源分析系统

## 项目简介
TraceX 是一个面向安全分析与攻防演练的攻击溯源分析系统。它从主机日志、网络流量与蜜罐事件中统一采集数据，基于规则与上下文识别攻击技术（ATT&CK），构建多实体图谱（主机/进程/文件/网络/认证/内存），重建攻击路径，并结合威胁情报进行 APT 归因与 IOC 富化，最终通过 Web 前端进行可视化展示与交互分析。

你可以把 TraceX 理解为“从原始多源数据到可读攻击链”的完整流水线：采集 → 归一化 → 规则检测与标注 → 图构建与溯源 → 情报归因 → 前端展示。

## 目录结构
- `collector/`: 采集与统一事件格式（ECS 映射、ES 写入）
- `analyzer/attack_analyzer/`: Sigma 规则匹配与 ATT&CK 技术标注
- `analyzer/graph_analyzer/`: ATLAS 语义映射、图构建、情报富化与溯源门面
- `tools/`: 采集、校验与演示脚本（启动采集、验证结果、攻击剧本）
- `web/`: 前端页面与交互脚本
- `docs/`: 说明、测试报告、优化规格与计划文档

## 环境与配置
- 依赖：`Docker`、`Python 3.9+`、`Elasticsearch/Kibana`
- 启动 ES/Kibana：在项目根目录执行 `docker compose up -d`
- 配置 ES 地址：设置环境变量 `ES_HOST`（如 `http://localhost:9200`）
- 默认索引前缀：`unified-logs*`、`network-flows*`、`honeypot-logs*`

## 已实现能力
- 多源采集与统一格式
  - 支持主机日志、网络流量、蜜罐等数据源；统一为 `UnifiedEvent v4.1`，包含进程、文件、网络、用户、威胁与内存异常等结构化字段
  - 自动推断事件类别与字段映射，写入 Elasticsearch 索引（可配置前缀）
- 规则检测与技术标注（ATT&CK）
  - 加载丰富的 Sigma 规则库（Windows/Linux/网络/应用/云等），针对多源事件进行匹配
  - 输出 ATT&CK 技术节点（T-node），包含战术/技术、置信度、严重度与上下文（IP/用户/进程等）
- 图构建与语义抽象（ATLAS）
  - 将事件抽象为多类型节点与边：主机、进程、文件、网络、认证、内存；解决 PID 复用带来的唯一性问题
  - 为事件打上 ATLAS 语义标签（如 DOWNLOAD_AND_EXECUTE、MEMFD_EXEC），生成“路径签名”便于链路描述与统计
- 溯源路径重建
  - 以“高置信种子事件”为起点，结合时间与实体关联重建攻击路径，输出节点与边的结构化结果
- 情报富化与 APT 归因
  - 从图节点提取 IOC（IP/域名/哈希）进行风险查询（本地库/可选外部 API）
  - 基于技术序列与真实 MITRE ATT&CK STIX 数据进行组织归因，输出候选组织、匹配技术与置信度
- 前端可视化与交互
  - 提供 FastAPI 后端与静态页面：威胁视图、日志视图、攻击图谱、API 文档
  - 支持 ES 不可用时的模拟模式（演示数据），保证界面与交互可用
- 工具脚本与验证
  - `tools/start_collection.sh`：启动采集器与相关解析程序
  - `tools/attack_playbook.sh`：集成示例攻击链，便于端到端验证
  - `tools/verify_final.py`：校验溯源结果与统计输出，检查链路重建质量

## 快速开始（Windows 示例）
1. 启动基础环境：
   ```powershell
   docker compose up -d
   ```
2. 启动采集器：
   ```powershell
   bash .\tools\start_collection.sh
   ```
3. 执行测试攻击链（可选）：
   ```powershell
   bash .\tools\attack_playbook.sh
   ```
4. 校验溯源结果：
   ```powershell
   python .\tools\verify_final.py
   ```
5. 访问 Kibana：`http://localhost:5601`

## 前端启动（Linux）
- 一键脚本：
  ```bash
  cd /path/to/TraceX/web
  chmod +x start_web.sh
  ./start_web.sh
  ```
- Uvicorn 方式：
  ```bash
  cd /path/to/TraceX/web/backend
  python3 -m pip install -r requirements.txt
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
  ```
- 访问地址：`http://<服务器IP>:8000`（页面：`/threats.html`, `/logs.html`, `/docs`）

## 分析引擎
- `attack_analyzer`：加载 `rules/` 下的 Sigma 规则，归一化多源事件，输出命中与 ATT&CK 技术节点。
- `graph_analyzer`：将事件构造成多类型节点与边，生成 ATLAS 标签序列与路径签名，结合 TTP 做 APT 归因与 IOC 富化，并提供溯源总控输出。

## 常见说明
- `.sh` 脚本可在 Git Bash 或 WSL 中运行；Windows 原生环境请使用 PowerShell 调用 `bash`。
- 蜜罐与网络模块端口如需调整，请在 `docker-compose.yml` 中修改并重启相关服务。

## 验证与排错
- 采集端：确认 `ES_HOST` 可访问且索引有新增文档。
- 分析端：运行 `tools/verify_final.py` 查看溯源链与统计输出。