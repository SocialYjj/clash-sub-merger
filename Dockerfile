# Multi-stage build - Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/submerger
COPY submerger/package*.json ./
RUN npm ci --prefer-offline
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
FROM python:3.12-slim AS runtime
WORKDIR /app

# Labels
LABEL org.opencontainers.image.title="Clash Sub Merger"
LABEL org.opencontainers.image.description="Modern subscription aggregation management panel for Clash/Mihomo"
LABEL org.opencontainers.image.source="https://github.com/SocialYjj/clash-sub-merger"
LABEL org.opencontainers.image.licenses="MIT"

# Install system dependencies (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Install Python dependencies (separate layer for better caching)
COPY requirements.txt ./
RUN uv pip install --system --no-cache -r requirements.txt

# Copy backend code
COPY *.py ./
COPY api/ ./api/
COPY services/ ./services/
COPY core/ ./core/

# Copy Go speedtest binary
COPY --from=go-builder /app/speedtest/speedtest /app/speedtest

# Copy frontend build
COPY --from=frontend-builder /app/submerger/dist ./submerger/dist

# Create data directory with proper permissions BEFORE switching user
RUN mkdir -p /app/data/uploads /app/data/logs /app/data/backups

# Create startup script
RUN echo '#!/bin/sh\n\
# Ensure data subdirectories exist\n\
mkdir -p /app/data/uploads /app/data/logs /app/data/backups\n\
# Start services\n\
/app/speedtest &\n\
exec python server.py' > /app/start.sh \
    && chmod +x /app/start.sh

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8666/health || exit 1

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/data \
    TZ=Asia/Shanghai \
    GO_SPEEDTEST_URL=http://localhost:9876

# Expose port
EXPOSE 8666

# Start both services
CMD ["/app/start.sh"]
