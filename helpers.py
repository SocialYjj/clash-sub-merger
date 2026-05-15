"""
Helper functions and utilities
"""
import os
import yaml
import time
from typing import Dict, Optional
from fastapi import HTTPException
from dotenv import load_dotenv
from logger_config import get_logger
from core.proxy_compat import normalize_subscription_data
from core import (
    cache_hits_total, cache_misses_total,
    file_operations_total, file_operation_duration_seconds
)

# Load environment variables from .env file
load_dotenv()

logger = get_logger(__name__)

# Use C-accelerated YAML loader if available for better performance
try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
    logger.info("Using C-accelerated YAML loader")
except ImportError:
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper
    logger.warning("C-accelerated YAML loader not available, using pure Python")

# ==================== Constants ====================

class Constants:
    """Application constants"""
    
    # File extensions
    YAML_EXT = '.yaml'
    JSON_EXT = '.json'
    BACKUP_EXT = '.backup'
    
    # Node types
    NODE_TYPE_SUBSCRIPTION = 'subscription'
    NODE_TYPE_CUSTOM = 'custom'
    NODE_TYPE_CHAIN = 'chain'
    
    # Status codes
    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'
    STATUS_TIMEOUT = 'timeout'
    
    # Limits
    MAX_SUBSCRIPTION_NAME_LENGTH = 100
    MAX_NODE_NAME_LENGTH = 200
    MIN_CHAIN_NODES = 2
    MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB
    
    # Defaults
    DEFAULT_CACHE_DURATION = int(os.getenv('CONFIG_CACHE_DURATION', '60'))
    DEFAULT_PAGE_SIZE = 50
    SLOW_REQUEST_THRESHOLD = 1.0  # seconds
    
    # Timeouts (seconds) - configurable via .env
    TIMEOUT_SUBSCRIPTION_FETCH = int(os.getenv('DEFAULT_TIMEOUT', '30'))
    TIMEOUT_GEOIP_LOOKUP = int(os.getenv('HEALTH_CHECK_TIMEOUT', '10'))
    TIMEOUT_SPEEDTEST_PROXY = int(os.getenv('SPEEDTEST_TIMEOUT', '35'))
    TIMEOUT_PROCESS_TERMINATE = 5
    
    # Default ports
    DEFAULT_PORT_HTTPS = 443
    DEFAULT_PORT_HTTP = 80
    DEFAULT_PORT_SOCKS5 = 1080
    DEFAULT_PORT_WIREGUARD = 51820


# ==================== YAML Cache ====================

class YAMLCache:
    """YAML file cache manager"""
    
    def __init__(self):
        self._cache: Dict[str, dict] = {}
        self._cache_time: Dict[str, float] = {}
    
    def get(self, key: str, max_age: int = 60) -> Optional[dict]:
        """Get cached YAML data"""
        if key not in self._cache:
            return None
        
        # Check if cache is still valid
        if time.time() - self._cache_time.get(key, 0) > max_age:
            self.invalidate(key)
            return None
        
        return self._cache[key]
    
    def set(self, key: str, data: dict):
        """Set cached YAML data"""
        self._cache[key] = data
        self._cache_time[key] = time.time()
    
    def invalidate(self, key: Optional[str] = None):
        """Invalidate cache"""
        if key:
            self._cache.pop(key, None)
            self._cache_time.pop(key, None)
        else:
            self._cache.clear()
            self._cache_time.clear()
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        return {
            "size": len(self._cache),
            "keys": list(self._cache.keys())
        }


# Global YAML cache instance
yaml_cache = YAMLCache()


# ==================== YAML Operations ====================

def load_subscription_yaml(sub_id: str, yaml_source_dir: str, use_cache: bool = True) -> dict:
    """
    Load subscription YAML file safely with caching
    
    Args:
        sub_id: Subscription ID
        yaml_source_dir: Directory containing YAML files
        use_cache: Whether to use cache (default: True)
    
    Returns:
        Parsed YAML dict
    
    Raises:
        HTTPException: If file not found or parse error
    """
    start_time = time.time()
    
    # Check cache first
    if use_cache:
        cached = yaml_cache.get(sub_id)
        if cached is not None:
            logger.debug(f"YAML cache hit for {sub_id}")
            cache_hits_total.labels(cache_type='yaml').inc()
            return cached
        cache_misses_total.labels(cache_type='yaml').inc()
    
    filepath = os.path.join(yaml_source_dir, f"{sub_id}{Constants.YAML_EXT}")
    
    if not os.path.exists(filepath):
        file_operations_total.labels(operation='read', status='failed').inc()
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        
        # Check if content is Base64 encoded or node links (legacy format)
        if content and not content.startswith(('proxies:', 'proxy-groups:', '#')):
            # Use SubscriptionParser to handle Base64 and node links
            from services.subscription import SubscriptionParser
            logger.info(f"Parsing subscription content for {sub_id}")
            cfg = SubscriptionParser.parse_content(content)
        else:
            cfg = yaml.load(content, Loader=YAMLLoader)
        
        # Ensure result is a dict, not a string or other type
        if not isinstance(cfg, dict):
            logger.warning(f"YAML file {sub_id} parsed as {type(cfg)}, not dict. Returning empty dict.")
            result = {}
        else:
            result = cfg if cfg else {}

        normalized_count = normalize_subscription_data(result)
        if normalized_count:
            logger.info(f"Normalized {normalized_count} legacy xhttp node(s) in subscription {sub_id}")
        
        # Update cache
        if use_cache:
            yaml_cache.set(sub_id, result)
            logger.debug(f"YAML cached for {sub_id}")
        
        # Record metrics
        duration = time.time() - start_time
        file_operations_total.labels(operation='read', status='success').inc()
        file_operation_duration_seconds.labels(operation='read').observe(duration)
        
        return result
        
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse YAML {sub_id}: {e}")
        file_operations_total.labels(operation='read', status='failed').inc()
        raise HTTPException(status_code=500, detail="Invalid YAML format")
    except Exception as e:
        logger.error(f"Failed to load YAML {sub_id}: {e}")
        file_operations_total.labels(operation='read', status='failed').inc()
        raise HTTPException(status_code=500, detail="Failed to load subscription")


def save_subscription_yaml(sub_id: str, cfg: dict, yaml_source_dir: str):
    """
    Save subscription YAML file safely
    
    Args:
        sub_id: Subscription ID
        cfg: YAML config dict
        yaml_source_dir: Directory containing YAML files
    
    Raises:
        HTTPException: If save fails
    """
    start_time = time.time()
    filepath = os.path.join(yaml_source_dir, f"{sub_id}{Constants.YAML_EXT}")
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(cfg, f, allow_unicode=True, sort_keys=False, Dumper=YAMLDumper)
        
        # Invalidate cache
        yaml_cache.invalidate(sub_id)
        logger.debug(f"YAML saved and cache invalidated for {sub_id}")
        
        # Record metrics
        duration = time.time() - start_time
        file_operations_total.labels(operation='write', status='success').inc()
        file_operation_duration_seconds.labels(operation='write').observe(duration)
        
    except Exception as e:
        logger.error(f"Failed to save YAML {sub_id}: {e}")
        file_operations_total.labels(operation='write', status='failed').inc()
        raise HTTPException(status_code=500, detail="Failed to save subscription")



def save_subscription_content(sub_id: str, content: str, yaml_source_dir: str):
    """
    Save subscription raw content (already formatted YAML string)
    
    Args:
        sub_id: Subscription ID
        content: Raw YAML content string
        yaml_source_dir: Directory containing YAML files
    
    Raises:
        HTTPException: If save fails
    """
    start_time = time.time()
    filepath = os.path.join(yaml_source_dir, f"{sub_id}{Constants.YAML_EXT}")
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        # Invalidate cache
        yaml_cache.invalidate(sub_id)
        logger.debug(f"YAML content saved and cache invalidated for {sub_id}")
        
        # Record metrics
        duration = time.time() - start_time
        file_operations_total.labels(operation='write', status='success').inc()
        file_operation_duration_seconds.labels(operation='write').observe(duration)
        
    except Exception as e:
        logger.error(f"Failed to save YAML content {sub_id}: {e}")
        file_operations_total.labels(operation='write', status='failed').inc()
        raise HTTPException(status_code=500, detail="Failed to save subscription")


def generate_timestamp_id(prefix: str = '') -> str:
    """
    Generate timestamp-based ID
    
    Args:
        prefix: Optional prefix for the ID (e.g., 'sub_', 'node_', 'chain_')
    
    Returns:
        Timestamp-based ID string
    """
    timestamp = int(time.time() * 1000)
    return f"{prefix}{timestamp}" if prefix else str(timestamp)



# ==================== Error Handler Decorator ====================

from functools import wraps
import json

def handle_api_errors(func):
    """Decorator to handle common API errors"""
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except HTTPException:
            raise  # Re-raise HTTP exceptions
        except FileNotFoundError as e:
            logger.error(f"File not found: {e}")
            raise HTTPException(status_code=404, detail="Resource not found")
        except yaml.YAMLError as e:
            logger.error(f"YAML parse error: {e}")
            raise HTTPException(status_code=400, detail="Invalid YAML format")
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON format")
        except ValueError as e:
            logger.error(f"Validation error: {e}")
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error")
    
    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except HTTPException:
            raise
        except FileNotFoundError as e:
            logger.error(f"File not found: {e}")
            raise HTTPException(status_code=404, detail="Resource not found")
        except yaml.YAMLError as e:
            logger.error(f"YAML parse error: {e}")
            raise HTTPException(status_code=400, detail="Invalid YAML format")
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON format")
        except ValueError as e:
            logger.error(f"Validation error: {e}")
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error")
    
    # Return appropriate wrapper based on function type
    import asyncio
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper
