# 本地开发与构建

本项目是前后端分离结构，包含 Python 后端、React 前端与 Go 速度测试服务。

## 后端（Python/FastAPI）

```bash
# 创建虚拟环境
uv venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 安装依赖
uv pip install -r requirements.txt

# 启动服务
python server.py
```

## 前端（React/Vite）

```bash
cd submerger
npm install
npm run build
```

## Go 速度测试服务

```bash
cd speedtest
go build -o speedtest
```

Windows 下生成 `speedtest.exe` 后，后端会自动拉起进程。
