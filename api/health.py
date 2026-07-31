"""
Health check and metrics API
"""
import time
from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import JSONResponse, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from core.config import AppConfig
from core.database import ConfigLoadError, load_config
from core.token_utils import constant_time_equal
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
    # Check if Go speedtest service is running when enabled. Treat disabled
    # speedtest as non-blocking so deployments without the Go helper can still
    # report healthy.
    speedtest_required = AppConfig.GO_SPEEDTEST_ENABLED
    speedtest_healthy = not speedtest_required
    if speedtest_required and _http_client:
        try:
            response = await _http_client.get(
                f"{AppConfig.GO_SPEEDTEST_URL}/health",
                timeout=AppConfig.HEALTH_CHECK_TIMEOUT
            )
            speedtest_healthy = response.status_code == 200
        except Exception:
            speedtest_healthy = False
    
    # Parse the real configuration. A present but unreadable/corrupt file is
    # unhealthy and must not be mistaken for a ready instance.
    try:
        config = load_config()
        config_healthy = bool(config.get('auth', {}).get('password_hash'))
    except ConfigLoadError:
        config_healthy = False
    
    is_healthy = config_healthy and speedtest_healthy

    payload = {
        "status": "healthy" if is_healthy else "unhealthy",
        "timestamp": int(time.time()),
        "version": AppConfig.VERSION,
        "services": {
            "config": config_healthy,
            "speedtest": speedtest_healthy,
            "speedtest_enabled": speedtest_required,
        }
    }
    return JSONResponse(
        status_code=200 if is_healthy else 503,
        content=payload,
    )


@router.get("/metrics", summary="Prometheus Metrics")
def metrics(authorization: str | None = Header(None)):
    """
    Prometheus metrics endpoint protected by a dedicated bearer token.
    """
    if not AppConfig.METRICS_TOKEN:
        raise HTTPException(status_code=404, detail="Not found")
    scheme, _, supplied_token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not constant_time_equal(supplied_token, AppConfig.METRICS_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid metrics token")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
