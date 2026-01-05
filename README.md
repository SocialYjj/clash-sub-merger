# ✈️ SubMerger

[中文文档](README_CN.md)

A modern and beautiful subscription aggregation management panel for Clash/Mihomo, supporting multi-subscription merging, custom nodes, user management, and smart format output.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)

## ✨ Features

### Subscription Management

- 🔗 **Multi-subscription Aggregation** - Merge multiple subscriptions into one
- 🛠️ **Custom Nodes** - Add your own nodes (vmess/vless/ss/trojan/hysteria2, etc.)
- 🔄 **Auto Refresh** - Scheduled subscription updates
- 📊 **Traffic Statistics** - Display traffic usage and expiration time
- 🎯 **Drag & Drop Sorting** - Customize node order

### Node Management

- 🌍 **Global Node Map** - Interactive ECharts visualization
- 🔍 **Node Testing** - Latency and GeoIP detection
- 🏷️ **Smart Filtering** - Filter by country, protocol, subscription
- 📈 **Protocol Distribution** - Pie chart analytics

### User Management

- 👥 **Multi-user Support** - Create users with individual subscriptions
- 🎛️ **Node Allocation** - Assign specific nodes/subscriptions to users
- ⏱️ **Expiration Control** - Set user expiration dates

### Subscription Output

- 📱 **Smart Format** - Auto-detect client and return YAML or Base64
- 🐱 **One-click Import** - Support `clash://` protocol
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

| Client              | Format      | Note                               |
| ------------------- | ----------- | ---------------------------------- |
| Clash/FlClash/Stash | YAML        | Auto-detect                        |
| V2RayN/V2RayNG      | Base64      | Auto-detect                        |
| Shadowrocket        | YAML/Base64 | Auto-detect                        |
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
- AnyTLS
- SOCKS5 / HTTP
- Snell

## 🔧 Configuration

### Environment Variables

| Variable   | Default     | Description    |
| ---------- | ----------- | -------------- |
| `TZ`       | `UTC`       | Timezone       |
| `DATA_DIR` | `/app/data` | Data directory |
| `PORT`     | `8666`      | Server port    |

### Data Persistence

All data is stored in `/app/data`:

- `config.json` - Configuration (subscriptions, nodes, auth)
- `uploads/` - Subscription cache files

## 🛠️ Development

### Backend

```bash
# Create virtual environment
uv venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Install dependencies
uv pip install -r requirements.txt

# Run server
python server.py
```

### Frontend

```bash
cd submerger
npm install
npm run dev
```

### Build Frontend

```bash
cd submerger
npm run build
```

## 📄 License

MIT License
