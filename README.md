# ✈️ Clash Subscription Merger

[中文文档](README_CN.md)

A clean and beautiful Clash subscription aggregation management panel, supporting multi-subscription merging, custom nodes, and smart format output.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.14-blue.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)

## ✨ Features

### Subscription Management

- 🔗 **Multi-subscription Aggregation** - Merge multiple subscriptions into one
- 🛠️ **Custom Nodes** - Add your own nodes (vmess/vless/ss/trojan/hysteria2, etc.)
- 🔄 **One-click Refresh** - Batch update all subscriptions
- 📊 **Traffic Statistics** - Display traffic usage and expiration time
- 🎯 **Drag & Drop Sorting** - Customize node order

### Subscription Output

- 📱 **Smart Format** - Auto-detect client and return YAML or Base64
- 🐱 **One-click Import** - Support `clash://` protocol for Clash clients
- 📷 **QR Code** - Scan to subscribe on mobile
- 📝 **Custom Template** - Customize Clash configuration template

### Security

- 🔐 **Password Protection** - Panel access requires password
- 🎫 **Token Authentication** - Subscription URL with token
- 🔑 **Regenerate Token** - Reset subscription token anytime

## 🚀 Quick Deploy

### Docker Compose (Recommended)

1. Create `docker-compose.yml`:

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

2. Start:

```bash
docker-compose up -d
```

3. Visit `http://your-ip:8666`

### Build Manually

```bash
git clone https://github.com/SocialYjj/clash-sub-merger.git
cd clash-sub-merger
docker-compose up -d --build
```

## 📖 Usage

### First Time Setup

1. Visit the panel and set admin password
2. Add subscriptions or custom nodes
3. Click "Subscribe" button to get the aggregated URL

### Subscription Format

| Client              | Format      | Note                                   |
| ------------------- | ----------- | -------------------------------------- |
| Clash/FlClash/Stash | YAML        | Auto-detect                            |
| V2RayN/V2RayNG      | Base64      | Auto-detect                            |
| Shadowrocket        | YAML/Base64 | Auto-detect                            |
| Manual              | -           | `?format=yaml` or `?format=base64` |

### Supported Protocols

- VMess
- VLESS (with Reality)
- Shadowsocks (SS)
- ShadowsocksR (SSR)
- Trojan
- Hysteria / Hysteria2
- TUIC
- WireGuard
- SOCKS5 / HTTP

## 🔧 Configuration

### Environment Variables

| Variable     | Default       | Description    |
| ------------ | ------------- | -------------- |
| `TZ`       | `UTC`       | Timezone       |
| `DATA_DIR` | `/app/data` | Data directory |

### Data Persistence

All data is stored in `/app/data`:

- `config.json` - Configuration (subscriptions, nodes, auth)
- `uploads/` - Subscription cache files

## 🛠️ Development

### Backend

```bash
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
python server.py
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## 📄 License

MIT License
