"""Subscription fetch and local-parse helpers shared by API routes and jobs.

Config and HTTP-client access go through the ``server`` module namespace at
call time (the app-wide late-binding seam) so ``patch.object(server, ...)``
keeps its meaning for the extracted functions.
"""

import asyncio
import base64

import yaml

from logger_config import get_logger
from services.node_parser import parse_node_link

# Use C-accelerated safe YAML loader for better performance.
# Remote subscription content must never be parsed with yaml.Loader/CLoader
# because those loaders can construct arbitrary Python objects from YAML tags.
try:
    from yaml import CSafeDumper as YAMLDumper
    from yaml import CSafeLoader as YAMLLoader
except ImportError:
    from yaml import SafeDumper as YAMLDumper
    from yaml import SafeLoader as YAMLLoader

logger = get_logger(__name__)


def fetch_subscription(url: str) -> tuple:
    """Fetch subscription content from URL (synchronous wrapper for async call)"""
    _ensure_sync_context("fetch_subscription", "fetch_subscription_async")
    return asyncio.run(fetch_subscription_async(url))


def _ensure_sync_context(sync_name: str, async_name: str) -> None:
    """Prevent synchronous wrappers from being called inside a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError(f"{sync_name}() cannot be called from an async context; use await {async_name}() instead.")


async def fetch_subscription_async(url: str) -> tuple:
    """
    Fetch subscription content from URL using SubscriptionFetcher (with proxy fallback).

    Args:
        url: Subscription URL

    Returns:
        Tuple of (content, subscription_info, node_count)
    """
    import server as srv
    from helpers_ua import get_subscription_user_agent
    from services.subscription_fetcher import SubscriptionFetcher

    try:
        config = srv.load_config()
        proxy_url = config.get("settings", {}).get("subscription_proxy_url")
        user_agent = get_subscription_user_agent()

        fetcher = SubscriptionFetcher(srv.http_client, proxy_url=proxy_url)
        content, sub_info, node_count = await fetcher.fetch(url, user_agent=user_agent)

        logger.info(f"Successfully fetched subscription, got {node_count} nodes")
        return content, sub_info, node_count
    except Exception as exc:
        from services.subscription_fetcher import FetchError

        raise FetchError(f"Failed to fetch subscription: {exc}") from None


def _process_subscription_content_str(content: str) -> str:
    """Process subscription content string and return YAML format"""
    from services.subscription_parser import parse_subscription_content

    if not content:
        return ""

    try:
        return parse_subscription_content(content)
    except Exception as e:
        logger.warning(f"Failed to parse subscription content: {e}")
        return content


def _pad_base64(value: str) -> str:
    """Add only the Base64 padding that is actually missing."""
    return value + "=" * (-len(value) % 4)


def parse_local_subscription(content: str) -> tuple:
    """
    Parse local subscription content.
    Supports: YAML (with proxies), Base64 encoded content, URI list (ss://, vmess://, etc.)

    Returns: (yaml_content, proxies_list, node_count)
    """
    original_content = content.strip()
    decoded_content = original_content

    # Try Base64 decode
    try:
        # Remove possible padding issues
        padded = _pad_base64(original_content)
        decoded = base64.b64decode(padded).decode("utf-8")
        decoded_content = decoded.strip()
        logger.debug("Successfully decoded Base64 content")
    except base64.binascii.Error as e:
        logger.debug(f"Content is not Base64 encoded: {e}")
    except UnicodeDecodeError as e:
        logger.warning(f"Base64 content is not valid UTF-8: {e}")
    except Exception as e:
        logger.warning(f"Failed to decode Base64: {e}")

    proxies = []

    # Check if it's YAML with proxies section
    try:
        cfg = yaml.load(decoded_content, Loader=YAMLLoader)
        if isinstance(cfg, dict) and "proxies" in cfg:
            proxies = cfg.get("proxies", [])
            yaml_content = decoded_content
            logger.info(f"Parsed {len(proxies)} nodes from YAML content")
            return yaml_content, proxies, len(proxies)
    except yaml.YAMLError as e:
        logger.debug(f"Content is not valid YAML: {e}")
    except Exception as e:
        logger.warning(f"Error parsing YAML content: {e}")

    # Try parsing as URI list (one link per line)
    lines = decoded_content.split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Parse various URI formats
        proxy = parse_node_link(line)
        if proxy:
            proxies.append(proxy)

    if proxies:
        # Convert to YAML format
        yaml_content = yaml.dump({"proxies": proxies}, allow_unicode=True, sort_keys=False, Dumper=YAMLDumper)
        return yaml_content, proxies, len(proxies)

    raise ValueError("无法识别订阅内容格式，请检查是否为有效的 YAML、Base64 或节点链接")
