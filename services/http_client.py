"""
HTTP client module
Lazy async HTTP client with connection pooling
"""
import httpx
from core.config import AppConfig


_http_client = None


def get_http_client() -> httpx.AsyncClient:
    """Create the shared HTTP client lazily instead of at import time."""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=AppConfig.CONNECT_TIMEOUT,
                read=AppConfig.READ_TIMEOUT,
                write=AppConfig.WRITE_TIMEOUT,
                pool=AppConfig.CONNECT_TIMEOUT
            ),
            follow_redirects=True,
            limits=httpx.Limits(
                max_keepalive_connections=AppConfig.HTTP_MAX_KEEPALIVE,
                max_connections=AppConfig.HTTP_MAX_CONNECTIONS
            ),
            verify=AppConfig.HTTP_VERIFY_SSL,
        )
    return _http_client


async def close_http_client():
    """Close HTTP client gracefully"""
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None
