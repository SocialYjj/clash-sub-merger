# ✈️ SubMerger

[English](README.md)

一个现代美观的 Clash/Mihomo 订阅聚合管理面板。

SubMerger 能够将多个分散的机场订阅、自建节点合并为一个统一的订阅链接。它拥有精美的现代化 UI，支持拖拽排序、智能重命名、用户独立管理以及详细的节点健康状况检测。

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Go](https://img.shields.io/badge/go-1.22+-00ADD8.svg)
![React](https://img.shields.io/badge/react-19-blue.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)

## 📸 截图预览

| 仪表盘 | 节点地图 |
|:-:|:-:|
| ![Dashboard](screenshots/dashboard.png) | ![Map](screenshots/map.png) |

| 添加订阅 | 节点管理 |
|:-:|:-:|
| ![Subscriptions](screenshots/add-subscriptio.png) | ![Nodes](screenshots/nodes.png) |

| 添加节点 | 模板管理 |
|:-:|:-:|
| ![Add Node](screenshots/add-node.png) | ![Templates](screenshots/templates.png) |

| 系统设置 | 用户管理 |
|:-:|:-:|
| ![Settings](screenshots/settings.png) | ![Users](screenshots/users.png) |

## ✨ 核心特性

### 🎨 现代化界面

- **精美卡片式设计** - 采用最新的现代化 UI 设计语言，支持暗色模式。
- **智能配色系统** - 根据订阅名称自动生成专属主题色，视觉层次分明。
- **流畅交互** - 丝滑的动画效果和响应式布局，完美适配各类设备。

### 📡 订阅管理

- **多源聚合** - 无缝合并多个 Clash/V2Ray/SS 订阅源。
- **智能解析** - 自动识别并处理多种格式的订阅内容。
- **本地导入** - 支持从本地 YAML/Base64 文件导入订阅。
- **定时自动更新** - 支持 Cron 表达式级的定时更新策略，确保节点实时可用。
- **流量监控** - 直观展示每个订阅源的流量使用情况（上传/下载/总量）及到期时间提醒。
- **可视化排序** - 支持拖拽方式调整订阅源优先级。

### 🌍 节点管理

- **全局节点地图** - 使用 ECharts 可视化展示节点地理分布。
- **Go 测速微服务** - 基于 mihomo 库的高性能测速服务
  - TCP 延迟测试
  - 下载速度测试（峰值模式）
  - 落地 IP 检测
- **在线 GeoIP API** - 无需本地数据库
  - 内置 API：ip-api.com（45次/分钟，支持中文）、ipwhois.app、ipinfo.io
  - 支持自定义 API（使用 `{ip}` 和 `{key}` 占位符）
  - Token 安全保护
  - 城市名称翻译（Tokyo→东京、Seoul→首尔）
  - 特殊地区显示（HK→中国香港、TW→中国台湾、MO→中国澳门）
- **链式代理** - 创建链式代理配置（节点A → 节点B → 目标服务）
- **端口映射** - 将节点映射到本地端口，直接访问（生成 Clash listeners 配置）
- **高级筛选器** - 支持按协议类型、国家地区、延迟状态进行多维度筛选。
- **灵活排序** - 支持按名称、延迟、速度排序，可选升序/降序。
- **协议分布统计** - 直观的饼图分析节点协议构成。

### 📝 模板管理

- **自定义模板** - 创建和管理 Clash 配置模板
- **占位符系统** - 使用 `{{ALL_PROXIES}}`、`{{COUNTRY_GROUPS}}` 动态生成内容
- **导入导出** - 支持上传 YAML 文件或从头创建

### 👥 用户系统

- **多用户隔离** - 支持创建多个子用户，每个用户拥有独立的订阅 Token。
- **灵活分配** - 管理员可将特定节点或订阅源分配给指定用户。
- **访问控制** - 支持设置用户账号过期时间，便于管理。

### 📤 智能输出

- **自适应格式** - 根据请求客户端（Clash, Stash, V2RayN, Shadowrocket）自动返回 YAML 或 Base64 格式配置。
- **一键导入** - 支持 `clash://` 协议唤起客户端一键导入。
- **移动端友好** - 提供二维码快速扫描订阅。
- **自定义模板** - 允许用户自定义输出的 Clash 配置文件模板（Rules, DNS 等）。

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────┐
│                    Docker 容器                       │
├─────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────────────┐ │
│  │  Python/FastAPI │◄──►│   Go 测速微服务          │ │
│  │   (端口 8666)   │    │    (端口 9876)          │ │
│  │                 │    │  - mihomo 库            │ │
│  │  - API 服务     │    │  - 延迟/速度测试         │ │
│  │  - 前端静态文件  │    │  - 落地 IP 检测         │ │
│  └─────────────────┘    └─────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

## 🚀 快速部署

### 方式一：Docker Compose（推荐）

这是最简单的部署方式。

1. **创建工作目录**：

   ```bash
   mkdir submerger && cd submerger
   ```

2. **创建 `docker-compose.yml` 文件**：

   ```yaml
   services:
     submerger:
       image: ghcr.io/socialyjj/submerger:latest
       container_name: submerger
       restart: unless-stopped
       ports:
         - "8666:8666"
       volumes:
         - ./data:/app/data
       environment:
         - TZ=Asia/Shanghai
   ```

3. **启动服务**：

   ```bash
   docker-compose up -d
   ```

4. **访问面板**：
   打开浏览器访问 `http://你的IP:8666`。首次登录需设置管理员密码。

### 方式二：手动构建运行

如果你需要修改源码或在不支持 Docker 的环境运行：

```bash
# 1. 克隆仓库
git clone https://github.com/SocialYjj/clash-sub-merger.git
cd clash-sub-merger

# 2. 启动（会自动构建镜像）
docker-compose up -d --build
```

## 📖 使用指南

### 基础配置
1. **设置密码**：首次访问时系统会提示设置全局管理密码。
2. **添加订阅**：
   - 点击“添加订阅”按钮。
   - 输入机场订阅链接（支持 Clash YAML 或 Base64 链接）。
   - 系统会自动解析并保存节点。
3. **获取链接**：
   - 点击右上角的“订阅”按钮。
   - 复制显示的订阅地址，或使用手机扫描二维码。
   - 将地址导入你的代理客户端即可。

### 进阶技巧
- **自定义排序**：在订阅管理页面，长按并拖拽订阅卡片即可调整它们在最终合并文件中的顺序。
- **延迟测试**：进入“节点管理”页面，选中节点并点击“批量检测”可测试节点连通性。
- **排除干扰**：系统会自动过滤包含“过期”、“剩余流量”、“官网”等关键词的无效节点。

## 🔧 环境变量与配置

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `TZ` | `UTC` (建议 Asia/Shanghai) | 容器时区设置 |
| `DATA_DIR` | `/app/data` | 数据存储路径 |
| `PORT` | `8666` | 服务监听端口 |

数据目录说明 (`/app/data`)：
- `config.json`: 核心配置文件，包含订阅列表、用户数据等。
- `uploads/`: 存放下载的订阅文件缓存。

## 🛠️ 本地开发

本项目采用前后端分离架构。

### 后端 (Python/FastAPI)

```bash
# 激活环境
uv venv
source .venv/bin/activate  # 或 Windows: .venv\Scripts\activate

# 安装依赖
uv pip install -r requirements.txt

# 启动服务
python server.py
```

### 前端 (React/Vite)

详情请参阅 `submerger/README.md`。

```bash
cd submerger
npm install
npm run dev
```

## 📝 支持的协议列表

SubMerger 目前支持解析和输出以下协议节点：

- **Shadowsocks (SS)**
- **ShadowsocksR (SSR)**
- **VMess**
- **VLESS** (包含 Reality, XTLS 等变种)
- **Trojan**
- **Hysteria / Hysteria2**
- **TUIC**
- **WireGuard**
- **SOCKS5 / HTTP**

## 📄 许可证

[Apache License 2.0](LICENSE)

