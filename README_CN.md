# ✈️ Clash 订阅聚合管理

[English](README.md)

一个简洁美观的 Clash 订阅聚合管理面板，支持多订阅合并、自建节点、智能格式输出。

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.14-blue.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)

## ✨ 功能特性

### 订阅管理

- 🔗 **多订阅聚合** - 合并多个机场订阅为一个
- 🛠️ **自建节点** - 支持添加自己的节点（vmess/vless/ss/trojan/hysteria2 等）
- 🔄 **一键刷新** - 批量更新所有订阅
- 📊 **流量统计** - 显示各订阅的流量使用情况和到期时间
- 🎯 **拖拽排序** - 自定义节点顺序

### 订阅输出

- 📱 **智能格式** - 根据客户端自动返回 YAML 或 Base64 格式
- 🐱 **一键导入** - 支持 `clash://` 协议一键导入 Clash 客户端
- 📷 **二维码** - 扫码订阅，方便手机端使用
- 📝 **自定义模板** - 支持自定义 Clash 配置模板

### 安全特性

- 🔐 **密码保护** - 面板访问需要密码
- 🎫 **Token 认证** - 订阅地址带 Token，防止泄露
- 🔑 **可重置 Token** - 随时重新生成订阅 Token

## 🚀 快速部署

### Docker Compose（推荐）

1. 创建 `docker-compose.yml`：

```yaml
services:
  clash-sub-merger:
    image: ghcr.io/SocialYjj/clash-sub-merger:latest
    container_name: clash-sub-merger
    restart: unless-stopped
    ports:
      - "8666:8666"
    volumes:
      - ./data:/app/data
    environment:
      - TZ=Asia/Shanghai
```

2. 启动服务：

```bash
docker-compose up -d
```

3. 访问 `http://你的IP:8666`

### 手动构建

```bash
git clone https://github.com/SocialYjj/clash-sub-merger.git
cd clash-sub-merger
docker-compose up -d --build
```

## 📖 使用说明

### 首次使用

1. 访问面板，设置管理密码
2. 添加机场订阅或自建节点
3. 点击右上角「订阅」按钮获取聚合地址

### 订阅格式

| 客户端              | 格式        | 说明                                   |
| ------------------- | ----------- | -------------------------------------- |
| Clash/FlClash/Stash | YAML        | 自动识别                               |
| V2RayN/V2RayNG      | Base64      | 自动识别                               |
| Shadowrocket        | YAML/Base64 | 自动识别                               |
| 手动指定            | -           | `?format=yaml` 或 `?format=base64` |

### 支持的节点协议

- VMess
- VLESS (含 Reality)
- Shadowsocks (SS)
- ShadowsocksR (SSR)
- Trojan
- Hysteria / Hysteria2
- TUIC
- WireGuard
- SOCKS5 / HTTP

## 🔧 配置说明

### 环境变量

| 变量         | 默认值        | 说明     |
| ------------ | ------------- | -------- |
| `TZ`       | `UTC`       | 时区     |
| `DATA_DIR` | `/app/data` | 数据目录 |

### 数据持久化

所有数据保存在 `/app/data` 目录：

- `config.json` - 配置文件（订阅、节点、认证信息）
- `uploads/` - 订阅缓存文件

## 🛠️ 本地开发

### 后端

```bash
# 创建虚拟环境
uv venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# 安装依赖
uv pip install -r requirements.txt

# 运行
python server.py
```

### 前端

```bash
cd frontend
npm install
npm run dev
```

## 📝 API 接口

### 订阅接口

```
GET /sub?token=xxx
GET /sub?token=xxx&format=base64
GET /sub?token=xxx&format=yaml
```

### 管理接口

所有管理接口需要在 Header 中携带 `Authorization: <session_token>`

- `GET /api/subscriptions` - 获取订阅列表
- `POST /api/subscriptions` - 添加订阅
- `DELETE /api/subscriptions/{id}` - 删除订阅
- `POST /api/subscriptions/{id}/refresh` - 刷新订阅
- `GET /api/custom-nodes` - 获取自建节点
- `POST /api/custom-nodes` - 添加自建节点

## 🤝 致谢

- [Sub-Store](https://github.com/sub-store-org/Sub-Store) - 功能参考
- [Clash](https://github.com/Dreamacro/clash) - 代理内核

## 📄 License

MIT License
