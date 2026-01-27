# Makefile for Clash Sub Merger
.PHONY: help install dev build test lint clean docker-build docker-run

# Default target
help:
	@echo "Available commands:"
	@echo "  make install     - Install all dependencies"
	@echo "  make dev         - Start development servers"
	@echo "  make build       - Build for production"
	@echo "  make test        - Run tests"
	@echo "  make lint        - Run linters"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run  - Run Docker container"

# Install dependencies
install:
	pip install -r requirements.txt
	cd submerger && npm install
	cd speedtest && go mod download

# Development
dev:
	@echo "Starting backend..."
	python server.py &
	@echo "Starting frontend..."
	cd submerger && npm run dev

# Build
build:
	cd submerger && npm run build
	cd speedtest && go build -o speedtest .

# Test
test:
	pytest -v
	cd speedtest && go test -v ./...

# Lint
lint:
	flake8 --max-line-length=120 *.py
	cd submerger && npm run lint 2>/dev/null || true

# Clean
clean:
	rm -rf __pycache__ .pytest_cache
	rm -rf submerger/dist submerger/node_modules/.cache
	rm -rf speedtest/speedtest speedtest/speedtest.exe
	find . -name "*.pyc" -delete

# Docker
docker-build:
	docker build -t clash-sub-merger:latest .

docker-run:
	docker run -d -p 8666:8666 -v ./data:/app/data --name submerger clash-sub-merger:latest

docker-stop:
	docker stop submerger && docker rm submerger

# Backup
backup:
	@mkdir -p backups
	@cp data/config.json backups/config_$$(date +%Y%m%d_%H%M%S).json
	@echo "Backup created in backups/"

# Pre-commit
pre-commit-install:
	pip install pre-commit
	pre-commit install
