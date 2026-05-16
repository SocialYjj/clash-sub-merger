"""
User-Agent Helper
Automatically fetch latest FlClash version and generate User-Agent
"""
import os
import platform
import httpx
from logger_config import get_logger
from helpers import atomic_write_text

logger = get_logger(__name__)

# Cache for version to avoid frequent API calls
_cached_version = None
_cache_file = "data/.flclash_version_cache"


def get_flclash_latest_version() -> str:
    """
    Get latest FlClash version from GitHub API
    Returns version string like "v0.8.91"
    """
    global _cached_version
    
    # Try to read from cache file first
    if _cached_version is None and os.path.exists(_cache_file):
        try:
            with open(_cache_file, 'r') as f:
                _cached_version = f.read().strip()
                logger.debug(f"Loaded FlClash version from cache: {_cached_version}")
        except Exception as e:
            logger.debug(f"Failed to read version cache: {e}")
    
    # If cache exists, return it
    if _cached_version:
        return _cached_version
    
    # Fetch from GitHub API
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get("https://api.github.com/repos/chen08209/FlClash/releases/latest")
            if resp.status_code == 200:
                version = resp.json().get("tag_name", "v0.8.91")
                _cached_version = version
                
                # Save to cache file
                try:
                    atomic_write_text(_cache_file, version)
                    logger.info(f"Fetched and cached FlClash version: {version}")
                except Exception as e:
                    logger.warning(f"Failed to cache version: {e}")
                
                return version
    except Exception as e:
        logger.warning(f"Failed to fetch FlClash version from GitHub: {e}")
    
    # Fallback to default
    default_version = "v0.8.91"
    logger.debug(f"Using default FlClash version: {default_version}")
    return default_version


def generate_flclash_ua(version: str = None, os_name: str = None) -> str:
    """
    Generate FlClash User-Agent string
    
    Args:
        version: FlClash version (e.g., "v0.8.91"), auto-fetch if None
        os_name: OS name (e.g., "windows"), auto-detect if None
    
    Returns:
        User-Agent string like "FlClash/v0.8.91 clash-verge Platform/windows"
    """
    if version is None:
        version = get_flclash_latest_version()
    
    if os_name is None:
        os_name = platform.system().lower()
    
    return f"FlClash/{version} clash-verge Platform/{os_name}"


def get_subscription_user_agent() -> str:
    """
    Get User-Agent for subscription fetching
    
    Mode selection (via SUBSCRIPTION_UA_MODE environment variable):
    - "flclash": Auto-generate from latest FlClash version (default)
    - "custom": Use custom UA from SUBSCRIPTION_CUSTOM_UA
    
    Returns:
        User-Agent string
    """
    mode = os.getenv('SUBSCRIPTION_UA_MODE', 'flclash').strip().lower()
    
    if mode == 'custom':
        # Use custom UA
        custom_ua = os.getenv('SUBSCRIPTION_CUSTOM_UA', '').strip()
        if custom_ua:
            logger.info(f"Using custom User-Agent: {custom_ua}")
            return custom_ua
        else:
            logger.warning("SUBSCRIPTION_UA_MODE=custom but SUBSCRIPTION_CUSTOM_UA is empty, falling back to FlClash mode")
            mode = 'flclash'
    
    # Default: FlClash mode
    ua = generate_flclash_ua()
    logger.info(f"Using FlClash User-Agent: {ua}")
    return ua


def refresh_version_cache():
    """
    Force refresh the version cache
    Call this periodically (e.g., daily) to keep version up-to-date
    """
    global _cached_version
    _cached_version = None
    
    # Remove cache file to force re-fetch
    if os.path.exists(_cache_file):
        try:
            os.remove(_cache_file)
            logger.info("Cleared FlClash version cache")
        except Exception as e:
            logger.warning(f"Failed to clear version cache: {e}")
    
    # Fetch new version
    return get_flclash_latest_version()
