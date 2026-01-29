"""
Health check and metrics API
"""
import os
import time
from fastapi import APIRouter
from fastapi.responses import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from core.config import AppConfig, CONFIG_FILE
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()

# HTTP client will be injected from server.py
_http_client = None


def set_http_client(client):
    """Set the HTTP client for health checks"""
    global _http_client
    _http_client = client


@router.get("/health", summary="Health Check")
async def health_check():
    """
    Health check endpoint for Docker/K8s.
    Does not require authentication.
    
    Returns:
        - status: "healthy" or "unhealthy"
        - timestamp: Current Unix timestamp
        - version: Application version
        - services: Status of dependent services
    """
    # Check if Go speedtest service is running
    speedtest_healthy = False
    if _http_client:
        try:
            response = await _http_client.get(
                f"{AppConfig.GO_SPEEDTEST_URL}/health",
                timeout=AppConfig.HEALTH_CHECK_TIMEOUT
            )
            speedtest_healthy = response.status_code == 200
        except Exception:
            speedtest_healthy = False
    
    # Check if config file is accessible
    config_healthy = os.path.exists(CONFIG_FILE)
    
    is_healthy = config_healthy
    
    return {
        "status": "healthy" if is_healthy else "unhealthy",
        "timestamp": int(time.time()),
        "version": AppConfig.VERSION,
        "services": {
            "config": config_healthy,
            "speedtest": speedtest_healthy
        }
    }


@router.get("/metrics", summary="Prometheus Metrics")
def metrics():
    """
    Prometheus metrics endpoint.
    Does not require authentication.
    """
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
