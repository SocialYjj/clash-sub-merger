"""
HTTP client module
Global async HTTP client with connection pooling
"""
import httpx
from core.config import AppConfig

# Create global async HTTP client for better performance
http_client = httpx.AsyncClient(
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
    verify=False  # Disable SSL verification to handle certificates with hostname mismatch
)


async def close_http_client():
    """Close HTTP client gracefully"""
    await http_client.aclose()
