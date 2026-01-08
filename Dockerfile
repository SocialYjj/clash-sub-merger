# Multi-stage build - Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/submerger
COPY submerger/package*.json ./
RUN npm ci
COPY submerger/ ./
RUN npm run build

# Final image - Python backend
FROM python:3.12-slim
WORKDIR /app

# Install system dependencies (tzdata for timezone, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Install dependencies
COPY requirements.txt ./
RUN uv pip install --system --no-cache -r requirements.txt

# Copy backend code (all python files)
COPY *.py ./

# Copy GeoIP database if exists (optional, but good for caching)
COPY GeoLite2-Country.mmdb* ./

# Copy frontend build from builder stage
COPY --from=frontend-builder /app/submerger/dist ./submerger/dist

# Create data directory
RUN mkdir -p /app/data/uploads

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8666/api/stats/overview || exit 1

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV DATA_DIR=/app/data
ENV TZ=Asia/Shanghai

# Expose port
EXPOSE 8666

# Start command
CMD ["python", "server.py"]
