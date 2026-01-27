# Multi-stage build - Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/submerger
COPY submerger/package*.json ./
RUN npm ci
COPY submerger/ ./
RUN npm run build

# Multi-stage build - Go speedtest service
FROM golang:1.22-alpine AS go-builder
WORKDIR /app/speedtest
COPY speedtest/go.mod speedtest/go.sum ./
RUN go mod download
COPY speedtest/*.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o speedtest .

# Final image - Python backend + Go speedtest
FROM python:3.12-slim
WORKDIR /app

# Install system dependencies (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Install Python dependencies
COPY requirements.txt ./
RUN uv pip install --system --no-cache -r requirements.txt

# Copy backend code
COPY *.py ./

# Copy Go speedtest binary
COPY --from=go-builder /app/speedtest/speedtest /app/speedtest

# Copy frontend build
COPY --from=frontend-builder /app/submerger/dist ./submerger/dist

# Create data directory
RUN mkdir -p /app/data/uploads /app/data/logs

# Create startup script
RUN echo '#!/bin/sh\n\
/app/speedtest &\n\
exec python server.py' > /app/start.sh && chmod +x /app/start.sh

# Healthcheck - use the new /health endpoint that doesn't require auth
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8666/health || exit 1

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV DATA_DIR=/app/data
ENV TZ=Asia/Shanghai
ENV GO_SPEEDTEST_URL=http://localhost:9876

# Expose port (only main service, speedtest is internal)
EXPOSE 8666

# Start both services
CMD ["/app/start.sh"]
