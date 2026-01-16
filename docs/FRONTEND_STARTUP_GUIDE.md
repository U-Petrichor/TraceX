# TraceX 前端启动指南

本文档说明如何从零开始配置并启动 TraceX 分析引擎的前端 Web 界面。

## 1. 环境要求

*   **操作系统**: Linux / macOS / Windows
*   **Python 版本**: Python 3.8 或更高版本
*   **网络**: 确保端口 `8000` 未被占用

## 2. 快速启动 (推荐)

项目提供了一键启动脚本，位于 `/root/TraceX/web/` 目录下。

### Linux / macOS

1.  打开终端并进入 `web` 目录：
    ```bash
    cd /root/TraceX/web
    ```

2.  运行启动脚本：
    ```bash
    bash start_web.sh
    ```

脚本会自动安装所需的依赖包并启动服务。

### Windows

直接双击运行 `start_web.bat` (如果存在)，或者在 CMD/PowerShell 中运行：
```cmd
cd \path\to\TraceX\web
start_web.bat
```

## 3. 手动安装与启动

如果脚本无法运行，您可以按照以下步骤手动启动。

### 步骤 1: 安装依赖

进入后端目录并安装 Python 依赖库：

```bash
cd /root/TraceX/web/backend
pip3 install -r requirements.txt
```

**依赖列表**:
*   `fastapi`
*   `uvicorn`
*   `elasticsearch`
*   `pydantic`
*   ... (详见 requirements.txt)

### 步骤 2: 设置环境变量 (可选)

如果遇到模块导入错误，可能需要将项目根目录添加到 PYTHONPATH：

```bash
export PYTHONPATH=/root/TraceX:$PYTHONPATH
```

### 步骤 3: 启动服务

使用 Python 直接运行后端主程序：

```bash
# 确保在 /root/TraceX/web/backend 目录或正确引用路径
python3 main.py
```

或者使用 uvicorn 命令（生产环境推荐）：

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## 4. 访问界面

服务启动成功后，终端会显示如下信息：
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

此时打开浏览器访问：
*   **主页**: [http://localhost:8000](http://localhost:8000)
*   **威胁视图**: [http://localhost:8000/threats.html](http://localhost:8000/threats.html)
*   **日志视图**: [http://localhost:8000/logs.html](http://localhost:8000/logs.html)
*   **API 文档**: [http://localhost:8000/docs](http://localhost:8000/docs)

## 5. 常见问题排查

### Q: 启动时提示 `Address already in use`
**A**: 端口 8000 被占用。
解决方法：
1.  查找占用进程：`lsof -i :8000`
2.  终止进程：`kill -9 <PID>`
3.  重新启动服务。

### Q: 界面显示无数据
**A**:
1.  确保 Elasticsearch 容器正在运行 (`docker ps`)。
2.  如果 ES 不可用，后端会自动启用**模拟模式** (Simulation Mode)，提供演示数据。
3.  检查后端控制台是否有报错日志。

### Q: 页面样式加载失败
**A**: 确保从 `/root/TraceX/web` 的父级或正确路径启动，以便静态文件 (`/assets`) 能被正确挂载。推荐使用 `start_web.sh` 脚本启动。
