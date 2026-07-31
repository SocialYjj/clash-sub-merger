"""
Subscription Fetcher Service
Handles fetching subscriptions from URLs with proxy fallback
"""
import asyncio
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

    @staticmethod
    def _is_transient_error(exc: Exception) -> bool:
        if isinstance(exc, httpx.HTTPStatusError):
            status_code = exc.response.status_code
            return status_code in {408, 429} or status_code >= 500
        return isinstance(
            exc,
            (
                httpx.TimeoutException,
                httpx.NetworkError,
                httpx.RemoteProtocolError,
            ),
        )

    @staticmethod
    def _describe_error(exc: Exception) -> str:
        """Describe a failure without copying a credential-bearing URL."""
        if isinstance(exc, FetchError):
            return str(exc)
        if isinstance(exc, httpx.HTTPStatusError):
            return f"HTTP {exc.response.status_code}"
        if isinstance(exc, httpx.TimeoutException):
            return "request timed out"
        if isinstance(exc, httpx.ConnectError):
            return "connection failed"
        if isinstance(exc, (httpx.NetworkError, httpx.RemoteProtocolError)):
            return "network transport error"
        return type(exc).__name__

    async def _fetch_with_retries(
        self,
        http_client: httpx.AsyncClient,
        url: str,
        headers: dict,
        connection_name: str,
    ) -> Tuple[str, dict, int]:
        max_attempts = AppConfig.SUBSCRIPTION_FETCH_RETRIES + 1
        timeout = Constants.TIMEOUT_SUBSCRIPTION_FETCH

        for attempt_number in range(1, max_attempts + 1):
            try:
                async with http_client.stream(
                    "GET",
                    url,
                    headers=headers,
                    timeout=timeout,
                ) as response:
                    response.raise_for_status()
                    payload = await self._read_limited_body(response)
                    return self._process_payload(dict(response.headers), payload)
            except Exception as exc:
                failure_description = self._describe_error(exc)
                should_retry = (
                    attempt_number < max_attempts
                    and self._is_transient_error(exc)
                )
                if not should_retry:
                    raise FetchError(
                        f"{connection_name} subscription fetch failed: {failure_description}"
                    ) from None

                retry_delay = (
                    AppConfig.SUBSCRIPTION_FETCH_RETRY_DELAY_SECONDS
                    * (2 ** (attempt_number - 1))
                )
                logger.warning(
                    "%s subscription fetch attempt %s/%s failed: %s; retrying in %ss",
                    connection_name,
                    attempt_number,
                    max_attempts,
                    failure_description,
                    retry_delay,
                )
                if retry_delay:
                    await asyncio.sleep(retry_delay)
    
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
        # Step 1: Try direct connection. Never log the URL because subscription
        # paths and query strings commonly contain account tokens.
        try:
            logger.info("Fetching subscription directly")
            return await self._fetch_with_retries(
                self._http_client,
                url,
                headers,
                "Direct",
            )
        except FetchError as direct_error:
            logger.warning("Direct subscription attempt sequence failed: %s", direct_error)
            
            # Step 2: Try proxy if configured
            if self._proxy_url:
                try:
                    logger.info("Fetching subscription via configured proxy")
                    async with httpx.AsyncClient(
                        proxy=self._proxy_url,
                        timeout=httpx.Timeout(Constants.TIMEOUT_SUBSCRIPTION_FETCH),
                        follow_redirects=True,
                        trust_env=False,
                    ) as proxy_client:
                        return await self._fetch_with_retries(
                            proxy_client,
                            url,
                            headers,
                            "Proxy",
                        )
                except Exception as proxy_exception:
                    if isinstance(proxy_exception, FetchError):
                        proxy_error = proxy_exception
                    else:
                        proxy_error = FetchError(
                            "Proxy subscription fetch failed: "
                            f"{self._describe_error(proxy_exception)}"
                        )
                    logger.error("Proxy subscription fetch failed: %s", proxy_error)
                    raise FetchError(
                        f"{direct_error}; {proxy_error}"
                    ) from None
            
            raise direct_error from None
    
    async def _read_limited_body(self, response: httpx.Response) -> bytes:
        """Read the decoded response incrementally and stop at the configured limit."""
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError:
                raise FetchError("Subscription response has an invalid Content-Length header") from None
            if declared_size < 0:
                raise FetchError("Subscription response has an invalid Content-Length header")
            if declared_size > AppConfig.SUBSCRIPTION_MAX_BYTES:
                raise FetchError("Subscription response exceeds the configured size limit")

        payload = bytearray()
        async for chunk in response.aiter_bytes():
            payload.extend(chunk)
            if len(payload) > AppConfig.SUBSCRIPTION_MAX_BYTES:
                raise FetchError("Subscription response exceeds the configured size limit")
        return bytes(payload)

    def _process_payload(self, headers: dict, payload: bytes) -> Tuple[str, dict, int]:
        """Process already bounded response bytes into normalized subscription YAML."""
        sub_info = parse_subscription_info(headers)
        content = self._extract_content(payload, headers)
        node_count = count_nodes(content)
        if node_count <= 0:
            raise FetchError("Subscription response contains no valid nodes; existing data was kept")
        logger.info("Successfully fetched subscription, got %s nodes", node_count)
        return content, sub_info, node_count

    def _process_response(self, response: httpx.Response) -> Tuple[str, dict, int]:
        """Process response into content, info, and node count."""
        payload = response.content
        if len(payload) > AppConfig.SUBSCRIPTION_MAX_BYTES:
            raise FetchError("Subscription response exceeds the configured size limit")
        return self._process_payload(dict(response.headers), payload)
    
    def _extract_content(self, payload: bytes, headers: dict) -> str:
        """Extract content from response"""
        try:
            content = payload.decode('utf-8', errors='ignore').strip()
        except Exception as e:
            logger.error("Failed to decode subscription response: %s", type(e).__name__)
            content = ""
        
        if not content:
            raise FetchError("Subscription response is empty; existing data was kept")

        content_type = headers.get('content-type', '').lower()
        content_prefix = content[:2048].lstrip('\ufeff \t\r\n').lower()
        if content_prefix.startswith(('<!doctype html', '<html', '<body', '<head')):
            raise FetchError("Subscription endpoint returned an HTML page; existing data was kept")

        try:
            return parse_subscription_content(content)
        except Exception:
            if 'text/html' in content_type:
                raise FetchError(
                    "Subscription endpoint returned an HTML page; existing data was kept"
                ) from None
            raise FetchError(
                "Subscription response could not be parsed; existing data was kept"
            ) from None


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
