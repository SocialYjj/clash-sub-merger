# 多阶段构建 - 前端
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# 最终镜像 - Python 后端
FROM python:3.14-slim
WORKDIR /app

# 安装 uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# 安装依赖
COPY requirements.txt ./
RUN uv pip install --system --no-cache -r requirements.txt

# 复制后端代码
COPY server.py merge_config.py ./

# 从前端构建阶段复制静态文件
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# 创建数据目录
RUN mkdir -p /app/data/uploads

# 环境变量
ENV PYTHONUNBUFFERED=1
ENV DATA_DIR=/app/data

# 暴露端口
EXPOSE 8666

# 启动命令
CMD ["python", "server.py"]
