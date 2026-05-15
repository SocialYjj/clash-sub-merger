# Speedtest Service

基于 mihomo 库的代理节点测速服务。

## API

### 延迟测试
```
POST /api/delay
{
  "link": "vmess://...",
  "url": "https://cp.cloudflare.com/generate_204",  // 可选
  "timeout": 5000  // 毫秒，可选
}

Response:
{
  "success": true,
  "latency": 150  // 毫秒
}
```

### 出口IP检测
```
POST /api/ip
{
  "link": "vmess://...",
  "timeout": 5000  // 毫秒，可选
}

Response:
{
  "success": true,
  "ip": "1.2.3.4"
}
```

### 速度测试
```
POST /api/speed
{
  "link": "vmess://...",
  "url": "https://speed.cloudflare.com/__down?bytes=10000000",  // 可选
  "timeout": 10  // 秒，可选
}

Response:
{
  "success": true,
  "speed": 5.5,    // MB/s
  "latency": 150,  // 毫秒
  "bytes": 10000000
}
```

## 运行

```bash
# 本地运行
go run .

# Docker
docker build -t speedtest .
docker run -p 9876:9876 speedtest
```

## 环境变量

- `PORT`: 服务端口，默认 9876
