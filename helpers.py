"""
Helper functions and utilities
"""
import os
import yaml
import time
import aiofiles
from typing import Dict, Tuple, Optional
from fastapi import HTTPException
from logger_config import get_logger
from prometheus_client import Counter, Histogram

logger = get_logger(__name__)

# Use C-accelerated YAML loader if available for better performance
try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
    logger.info("Using C-accelerated YAML loader")
except ImportError:
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper
    logger.warning("C-accelerated YAML loader not available, using pure Python")

# ==================== Prometheus Metrics ====================

# Cache metrics
cache_hits_total = Counter(
    'cache_hits_total',
    'Total cache hits',
    ['cache_type']
)

cache_misses_total = Counter(
    'cache_misses_total',
    'Total cache misses',
    ['cache_type']
)

# File operation metrics
file_operations_total = Counter(
    'file_operations_total',
    'Total file operations',
    ['operation', 'status']  # read/write, success/failed
)

file_operation_duration_seconds = Histogram(
    'file_operation_duration_seconds',
    'File operation duration in seconds',
    ['operation']  # read/write
)

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
    DEFAULT_CACHE_DURATION = 60
    DEFAULT_PAGE_SIZE = 50
    SLOW_REQUEST_THRESHOLD = 1.0  # seconds
    
    # Timeouts (seconds)
    TIMEOUT_SUBSCRIPTION_FETCH = 30
    TIMEOUT_GEOIP_LOOKUP = 10
    TIMEOUT_SPEEDTEST_PROXY = 35
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
            cfg = yaml.load(f, Loader=YAMLLoader)
        
        result = cfg if cfg else {}
        
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


def get_subscription_node(sub_id: str, node_index: int, yaml_source_dir: str) -> Tuple[dict, dict, int]:
    """
    Get node from subscription by index
    
    Args:
        sub_id: Subscription ID
        node_index: Node index
        yaml_source_dir: Directory containing YAML files
    
    Returns:
        Tuple of (config_dict, node_dict, node_index)
    
    Raises:
        HTTPException: If subscription or node not found
    """
    cfg = load_subscription_yaml(sub_id, yaml_source_dir)
    proxies = cfg.get('proxies', [])
    
    if node_index < 0 or node_index >= len(proxies):
        raise HTTPException(status_code=404, detail="Node not found")
    
    return cfg, proxies[node_index], node_index


def save_custom_nodes_yaml(proxies: list, yaml_source_dir: str):
    """
    Save custom nodes YAML file
    
    Args:
        proxies: List of proxy nodes
        yaml_source_dir: Directory containing YAML files
    
    Raises:
        HTTPException: If save fails
    """
    save_subscription_yaml('custom_nodes', {'proxies': proxies}, yaml_source_dir)


def load_yaml_file_cached(filepath: str, cache_key: str = None, use_cache: bool = True) -> dict:
    """
    Load any YAML file with optional caching
    
    Args:
        filepath: Full path to YAML file
        cache_key: Optional cache key (defaults to filepath)
        use_cache: Whether to use cache
    
    Returns:
        Parsed YAML dict
    
    Raises:
        FileNotFoundError: If file doesn't exist
        HTTPException: If parse error
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    cache_key = cache_key or filepath
    start_time = time.time()
    
    # Check cache first
    if use_cache:
        cached = yaml_cache.get(cache_key)
        if cached is not None:
            cache_hits_total.labels(cache_type='yaml').inc()
            return cached
        cache_misses_total.labels(cache_type='yaml').inc()
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            cfg = yaml.load(f, Loader=YAMLLoader)
        
        result = cfg if cfg else {}
        
        # Update cache
        if use_cache:
            yaml_cache.set(cache_key, result)
        
        # Record metrics
        duration = time.time() - start_time
        file_operations_total.labels(operation='read', status='success').inc()
        file_operation_duration_seconds.labels(operation='read').observe(duration)
        
        return result
        
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse YAML {filepath}: {e}")
        file_operations_total.labels(operation='read', status='failed').inc()
        raise HTTPException(status_code=500, detail="Invalid YAML format")
    except Exception as e:
        logger.error(f"Failed to load YAML {filepath}: {e}")
        file_operations_total.labels(operation='read', status='failed').inc()
        raise HTTPException(status_code=500, detail="Failed to load file")


def save_custom_nodes_yaml(proxies: list, yaml_source_dir: str):
    """
    Save custom nodes YAML file
    
    Args:
        proxies: List of proxy nodes
        yaml_source_dir: Directory containing YAML files
    
    Raises:
        HTTPException: If save fails
    """
    save_subscription_yaml('custom_nodes', {'proxies': proxies}, yaml_source_dir)


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


def find_item_by_id(items: list, item_id: str) -> Optional[dict]:
    """
    Find item in list by ID
    
    Args:
        items: List of dictionaries with 'id' field
        item_id: ID to search for
    
    Returns:
        Found item or None
    """
    return next((item for item in items if item.get('id') == item_id), None)


# ==================== Validators ====================

class Validators:
    """Input validators"""
    
    @staticmethod
    def validate_port(port: int):
        """Validate port number"""
        if not (1024 <= port <= 65535):
            raise ValueError("Port must be between 1024 and 65535")
    
    @staticmethod
    def validate_node_index(index: int, max_index: int):
        """Validate node index"""
        if not (0 <= index < max_index):
            raise ValueError(f"Node index must be between 0 and {max_index-1}")
    
    @staticmethod
    def validate_chain_rows(rows: list):
        """Validate proxy chain rows"""
        if not rows:
            raise ValueError("Chain must have at least one row")
        for row in rows:
            if not row.nodes or len(row.nodes) < Constants.MIN_CHAIN_NODES:
                raise ValueError(f"Each row must have at least {Constants.MIN_CHAIN_NODES} nodes")
    
    @staticmethod
    def validate_name_length(name: str, max_length: int = Constants.MAX_NODE_NAME_LENGTH):
        """Validate name length"""
        if len(name) > max_length:
            raise ValueError(f"Name too long (max {max_length} characters)")
    
    @staticmethod
    def validate_path_traversal(name: str):
        """Validate no path traversal characters"""
        if '/' in name or '\\' in name or '..' in name:
            raise ValueError("Name contains invalid characters")


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
