"""
Subscription Fetcher Service
Handles fetching subscriptions from URLs
"""
import httpx
from typing import Tuple

from logger_config import get_logger
from core.config import AppConfig
from helpers import Constants
from services.subscription_parser import (
    parse_subscription_info,
    parse_subscription_content,
    count_nodes,
)

logger = get_logger(__name__)


class FetchError(Exception):
    """Base exception for fetch errors"""
    pass


class DirectFetchError(FetchError):
    """Raised when direct fetch fails"""
    pass


class SubscriptionFetcher:
    """Fetches subscription content from URLs"""
    
    def __init__(self, http_client: httpx.AsyncClient):
        self._http_client = http_client
    
    async def fetch_direct(
        self,
        url: str,
        user_agent: str,
        timeout: float = None
    ) -> Tuple[str, dict, int]:
        """
        Fetch subscription directly.
        
        Args:
            url: Subscription URL
            user_agent: User-Agent header value
            timeout: Request timeout in seconds
            
        Returns:
            Tuple of (content, subscription_info, node_count)
            
        Raises:
            DirectFetchError: If fetch fails
        """
        if timeout is None:
            timeout = Constants.TIMEOUT_SUBSCRIPTION_FETCH
        
        headers = {'User-Agent': user_agent}
        
        try:
            logger.info(f"Fetching subscription directly from: {url}")
            response = await self._http_client.get(
                url,
                headers=headers,
                timeout=timeout
            )
            response.raise_for_status()
            
            sub_info = parse_subscription_info(dict(response.headers))
            content = self._extract_content(response)
            node_count = count_nodes(content)
            
            logger.info(f"Successfully fetched subscription, got {node_count} nodes")
            return content, sub_info, node_count
            
        except httpx.HTTPStatusError as e:
            raise DirectFetchError(
                f"HTTP {e.response.status_code}: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise DirectFetchError(f"Connection timeout: {e}") from e
        except httpx.RequestError as e:
            raise DirectFetchError(f"Request failed: {e}") from e
    
    async def fetch(
        self,
        url: str,
        user_agent: str
    ) -> Tuple[str, dict, int]:
        """
        Fetch subscription.
        
        Args:
            url: Subscription URL
            user_agent: User-Agent header value
            
        Returns:
            Tuple of (content, subscription_info, node_count)
            
        Raises:
            FetchError: If fetch fails
        """
        return await self.fetch_direct(url, user_agent)
    
    def _extract_content(self, response: httpx.Response) -> str:
        """Extract content from response"""
        try:
            content = response.content.decode('utf-8', errors='ignore').strip()
        except AttributeError:
            try:
                content = response.text.strip()
            except Exception as e:
                logger.error(f"Failed to get response content: {e}")
                content = ""
        except Exception as e:
            logger.error(f"Failed to decode response content: {e}")
            content = ""
        
        if not content:
            return ""
        
        try:
            return parse_subscription_content(content)
        except Exception as e:
            logger.warning(f"Failed to parse subscription content: {e}")
            return content


def ensure_sync_context(sync_name: str, async_name: str) -> None:
    """
    Prevent synchronous wrappers from being called inside a running event loop.
    
    Args:
        sync_name: Name of synchronous function
        async_name: Name of async function
        
    Raises:
        RuntimeError: If called from async context
    """
    import asyncio
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError(
        f"{sync_name}() cannot be called from an async context; "
        f"use await {async_name}() instead."
    )
