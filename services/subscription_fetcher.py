"""
Subscription Fetcher Service
Handles fetching subscriptions from URLs with proxy fallback
"""
import httpx
from typing import Tuple, Optional

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


class SubscriptionFetcher:
    """Fetches subscription content from URLs with optional proxy fallback"""
    
    def __init__(self, http_client: httpx.AsyncClient, proxy_url: Optional[str] = None):
        self._http_client = http_client
        self._proxy_url = proxy_url
    
    async def fetch(
        self,
        url: str,
        user_agent: str
    ) -> Tuple[str, dict, int]:
        """
        Fetch subscription: try direct first, fallback to proxy if configured.
        
        Args:
            url: Subscription URL
            user_agent: User-Agent header value
            
        Returns:
            Tuple of (content, subscription_info, node_count)
            
        Raises:
            FetchError: If all attempts fail
        """
        headers = {'User-Agent': user_agent}
        timeout = Constants.TIMEOUT_SUBSCRIPTION_FETCH
        
        # Step 1: Try direct connection
        try:
            logger.info(f"Fetching subscription directly: {url}")
            response = await self._http_client.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            return self._process_response(response)
        except Exception as e:
            logger.warning(f"Direct fetch failed: {e}")
            
            # Step 2: Try proxy if configured
            if self._proxy_url:
                try:
                    logger.info(f"Fetching via proxy: {url}")
                    async with httpx.AsyncClient(
                        proxy=self._proxy_url,
                        timeout=httpx.Timeout(timeout),
                        follow_redirects=True,
                    ) as proxy_client:
                        response = await proxy_client.get(url, headers=headers)
                        response.raise_for_status()
                        return self._process_response(response)
                except Exception as proxy_err:
                    logger.error(f"Proxy fetch also failed: {proxy_err}")
                    raise FetchError(f"Direct and proxy fetch both failed: {e}; {proxy_err}")
            
            raise FetchError(f"Fetch failed: {e}")
    
    def _process_response(self, response: httpx.Response) -> Tuple[str, dict, int]:
        """Process response into content, info, and node count."""
        sub_info = parse_subscription_info(dict(response.headers))
        content = self._extract_content(response)
        node_count = count_nodes(content)
        logger.info(f"Successfully fetched subscription, got {node_count} nodes")
        return content, sub_info, node_count
    
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
