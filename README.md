# ✈️ SubMerger

[中文文档](README_CN.md)

A modern and beautiful subscription aggregation management panel for Clash/Mihomo, supporting multi-subscription merging, custom nodes, user management, and smart format output.

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![Go](https://img.shields.io/badge/go-1.22+-00ADD8.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)

## 📸 Screenshots

|               Dashboard               |         Node Map         |
| :-----------------------------------: | :-----------------------: |
| ![Dashboard](screenshots/dashboard.png) | ![Map](screenshots/map.png) |

|                  Subscriptions                  |             Nodes             |
| :---------------------------------------------: | :---------------------------: |
| ![Subscriptions](screenshots/add-subscriptio.png) | ![Nodes](screenshots/nodes.png) |

|              Add Node              |               Templates               |
| :---------------------------------: | :-----------------------------------: |
| ![Add Node](screenshots/add-node.png) | ![Templates](screenshots/templates.png) |

|              Settings              |             Users             |
| :---------------------------------: | :---------------------------: |
| ![Settings](screenshots/settings.png) | ![Users](screenshots/users.png) |

## ✨ Features

### Subscription Management

- 🔗 **Multi-subscription Aggregation** - Merge multiple subscriptions into one
- 🛠️ **Custom Nodes** - Add your own nodes (vmess/vless/ss/trojan/hysteria2, etc.)
- 📁 **Local Import** - Import subscriptions from local YAML/Base64 files
- 🔄 **Auto Refresh** - Scheduled subscription updates with Cron expression
- 📊 **Traffic Statistics** - Display traffic usage and expiration time
- 🎯 **Drag & Drop Sorting** - Customize node order

### Node Management

- 🌍 **Global Node Map** - Interactive ECharts world map visualization
- ⚡ **Go Speedtest Service** - High-performance testing via mihomo library
  - Delay test (TCP latency)
  - Speed test with peak mode
  - Exit IP detection
- 🌐 **Online GeoIP APIs** - No local database needed
  - Built-in: ip-api.com (45 req/min, Chinese), ipwhois.app, ipinfo.io
  - Custom API support with `{ip}` and `{key}` placeholders
  - Token security protection
  - City name translations (Tokyo→东京, Seoul→首尔)
  - Special region display (HK→中国香港, TW→中国台湾)
- 🔗 **Proxy Chain** - Create chained proxy configurations (Node A → Node B → Target)
- 🔌 **Port Mapping** - Map nodes to local ports for direct access (generates Clash listeners)
- 🏷️ **Smart Filtering** - Filter by country, protocol, subscription, latency status
- ↕️ **Flexible Sorting** - Sort by name, latency, speed (ascending/descending)
- 📈 **Protocol Distribution** - Pie chart analytics

### Template Management

- 📝 **Custom Templates** - Create and manage Clash configuration templates
- 🔄 **Placeholder System** - Use `{{ALL_PROXIES}}`, `{{COUNTRY_GROUPS}}` for dynamic content
- 📤 **Import/Export** - Upload YAML files or create from scratch

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

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Docker Container                  │
├─────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────────────┐ │
│  │  Python/FastAPI │◄──►│  Go Speedtest Service   │ │
│  │   (port 8666)   │    │     (port 9876)         │ │
│  │                 │    │  - mihomo library       │ │
│  │  - API Server   │    │  - delay/speed test     │ │
│  │  - Frontend     │    │  - exit IP detection    │ │
│  └─────────────────┘    └─────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

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
- AnyTLS
- SOCKS5 / HTTP
- Snell

## 🔧 Configuration

### Environment Variables

| Variable     | Default       | Description    |
| ------------ | ------------- | -------------- |
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

[Apache License 2.0](LICENSE)
