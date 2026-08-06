"""
Helper functions and utilities
"""
import os
import yaml
import time
import tempfile
import threading
import secrets
from copy import deepcopy
from pathlib import Path
from contextlib import contextmanager
from typing import Dict, Optional
from fastapi import HTTPException
from dotenv import load_dotenv
from logger_config import get_logger
from core.proxy_compat import normalize_subscription_data
from core.config import AppConfig, env_int
from core import (
    cache_hits_total, cache_misses_total,
    file_operations_total, file_operation_duration_seconds
)

# Load environment variables from .env file
load_dotenv()

logger = get_logger(__name__)

# Use C-accelerated safe YAML loader if available for better performance.
# Never use yaml.Loader/CLoader here: subscription YAML can come from remote
# providers and user uploads, and unsafe loaders can instantiate Python objects.
try:
    from yaml import CSafeLoader as YAMLLoader, CSafeDumper as YAMLDumper
    logger.info("Using C-accelerated safe YAML loader")
except ImportError:
    from yaml import SafeLoader as YAMLLoader, SafeDumper as YAMLDumper
    logger.warning("C-accelerated safe YAML loader not available, using pure Python")

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
    MAX_REQUEST_SIZE = AppConfig.MAX_REQUEST_SIZE
    
    # Defaults
    DEFAULT_CACHE_DURATION = AppConfig.YAML_CACHE_DURATION
    DEFAULT_PAGE_SIZE = 50
    SLOW_REQUEST_THRESHOLD = 1.0  # seconds
    
    # Timeouts (seconds) - configurable via .env
    TIMEOUT_SUBSCRIPTION_FETCH = env_int('DEFAULT_TIMEOUT', 30, minimum=1)
    TIMEOUT_GEOIP_LOOKUP = env_int('GEOIP_LOOKUP_TIMEOUT', 10, minimum=1)
    TIMEOUT_SPEEDTEST_PROXY = env_int('SPEEDTEST_TIMEOUT', 10, minimum=1)
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
        self._cache: Dict[str, tuple[dict, float, tuple[int, int] | None, str | None]] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _key(key: str, source_path: str | os.PathLike | None = None) -> str:
        if source_path is None:
            return str(key)
        return f"{Path(source_path).resolve()}\0{key}"

    @staticmethod
    def _signature(source_path: str | os.PathLike | None) -> tuple[int, int] | None:
        if source_path is None:
            return None
        try:
            stat = os.stat(source_path)
            return stat.st_mtime_ns, stat.st_size
        except OSError:
            return None

    def get(
        self,
        key: str,
        max_age: int = 60,
        *,
        source_path: str | os.PathLike | None = None,
    ) -> Optional[dict]:
        """Get cached YAML data"""
        cache_key = self._key(key, source_path)
        signature = self._signature(source_path)
        with self._lock:
            entry = self._cache.get(cache_key)
            if entry is None:
                return None
            data, cached_at, cached_signature, _ = entry
            if (
                time.time() - cached_at > max_age
                or (source_path is not None and signature != cached_signature)
            ):
                self._cache.pop(cache_key, None)
                return None
            return deepcopy(data)

    def set(self, key: str, data: dict, *, source_path: str | os.PathLike | None = None):
        """Set cached YAML data"""
        cache_key = self._key(key, source_path)
        with self._lock:
            self._cache[cache_key] = (
                deepcopy(data),
                time.time(),
                self._signature(source_path),
                str(source_path) if source_path is not None else None,
            )

    def invalidate(self, key: Optional[str] = None):
        """Invalidate cache"""
        with self._lock:
            if key:
                suffix = f"\0{key}"
                for cache_key in list(self._cache):
                    if cache_key == key or cache_key.endswith(suffix):
                        self._cache.pop(cache_key, None)
            else:
                self._cache.clear()

    def get_stats(self) -> dict:
        """Get cache statistics"""
        with self._lock:
            return {"size": len(self._cache), "keys": list(self._cache.keys())}


# Global YAML cache instance
yaml_cache = YAMLCache()


# ==================== YAML Operations ====================

_yaml_file_locks_guard = threading.Lock()
_yaml_file_locks: Dict[str, threading.RLock] = {}


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _subscription_filepath(sub_id: str, yaml_source_dir: str) -> Path:
    """Resolve a subscription YAML path and reject path traversal in sub_id."""
    base_dir = Path(yaml_source_dir).resolve()
    target = (base_dir / f"{sub_id}{Constants.YAML_EXT}").resolve()
    if not _is_relative_to(target, base_dir):
        raise HTTPException(status_code=400, detail="Invalid subscription id")
    return target


def _get_yaml_file_lock(filepath: Path | str) -> threading.RLock:
    key = str(Path(filepath).resolve())
    with _yaml_file_locks_guard:
        lock = _yaml_file_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _yaml_file_locks[key] = lock
        return lock


def _looks_like_yaml_mapping(content: str) -> bool:
    """Heuristic for rejecting malformed YAML mappings instead of treating them as URI lists."""
    for line in (content or '').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or stripped.startswith('-'):
            continue
        if '://' in stripped:
            return False
        return ':' in stripped
    return False


@contextmanager
def subscription_yaml_lock(sub_id: str, yaml_source_dir: str):
    """Lock a subscription YAML file for a read-modify-write operation."""
    filepath = _subscription_filepath(sub_id, yaml_source_dir)
    lock = _get_yaml_file_lock(filepath)
    with lock:
        yield filepath


def atomic_write_text(path: str | os.PathLike, content: str, encoding: str = 'utf-8'):
    """Atomically write text using a same-directory temp file and os.replace()."""
    target = Path(path)
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)

    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding=encoding,
            dir=str(parent),
            prefix=f".{target.name}.",
            suffix='.tmp',
            delete=False,
        ) as tmp:
            tmp_name = tmp.name
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
        try:
            os.chmod(tmp_name, 0o600)
        except OSError:
            logger.warning("Could not restrict permissions for %s", target.name)
        os.replace(tmp_name, target)
    except Exception:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
            except Exception:
                logger.debug("Failed to remove temp file after atomic write failure: %s", tmp_name, exc_info=True)
        raise

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
    
    filepath = _subscription_filepath(sub_id, yaml_source_dir)

    # Check cache first. The absolute source path and mtime are part of the
    # cache identity so test directories and externally replaced files cannot
    # reuse a stale object from another data directory.
    if use_cache:
        cached = yaml_cache.get(
            sub_id,
            max_age=Constants.DEFAULT_CACHE_DURATION,
            source_path=filepath,
        )
        if cached is not None:
            logger.debug(f"YAML cache hit for {sub_id}")
            cache_hits_total.labels(cache_type='yaml').inc()
            return cached
        cache_misses_total.labels(cache_type='yaml').inc()
    
    if not os.path.exists(filepath):
        file_operations_total.labels(operation='read', status='failed').inc()
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    try:
        with _get_yaml_file_lock(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read().strip()
        
        cfg = None
        direct_yaml_error = None
        # Prefer YAML parsing for any mapping-shaped content instead of relying
        # on fragile startswith() heuristics. This preserves legal Clash/Mihomo
        # files that start with sections such as mixed-port:, dns:, or rules:.
        try:
            cfg = yaml.load(content, Loader=YAMLLoader)
        except yaml.YAMLError as e:
            direct_yaml_error = e
            logger.debug(f"Content is not direct YAML for {sub_id}: {e}")

        if not isinstance(cfg, dict):
            if direct_yaml_error and _looks_like_yaml_mapping(content):
                raise direct_yaml_error
            # Use SubscriptionParser to handle Base64 and node links
            from services.subscription import SubscriptionParser
            logger.info(f"Parsing subscription content for {sub_id}")
            cfg = SubscriptionParser.parse_content(content)
        
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
            yaml_cache.set(sub_id, result, source_path=filepath)
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
    filepath = _subscription_filepath(sub_id, yaml_source_dir)
    
    try:
        with _get_yaml_file_lock(filepath):
            content = yaml.dump(cfg, allow_unicode=True, sort_keys=False, Dumper=YAMLDumper)
            atomic_write_text(filepath, content)
        
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
    filepath = _subscription_filepath(sub_id, yaml_source_dir)
    
    try:
        with _get_yaml_file_lock(filepath):
            atomic_write_text(filepath, content)
        
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


def update_subscription_yaml(sub_id: str, yaml_source_dir: str, mutator):
    """Atomically mutate YAML under both process-local and cross-process locks."""
    from services.subscription_refresh_lock import subscription_write_slot

    with subscription_write_slot(sub_id):
        with subscription_yaml_lock(sub_id, yaml_source_dir):
            cfg = load_subscription_yaml(sub_id, yaml_source_dir, use_cache=False)
            if not isinstance(cfg, dict):
                cfg = {}
            result = mutator(cfg)
            save_subscription_yaml(sub_id, cfg, yaml_source_dir)
            return result


def generate_timestamp_id(prefix: str = '') -> str:
    """
    Generate a timestamp-prefixed ID with random entropy.
    
    Args:
        prefix: Optional prefix for the ID (e.g., 'sub_', 'node_', 'chain_')
    
    Returns:
        Timestamp-prefixed ID string that is safe under same-millisecond concurrency.
    """
    timestamp = int(time.time() * 1000)
    suffix = secrets.token_hex(4)
    value = f"{timestamp}_{suffix}"
    return f"{prefix}{value}" if prefix else value



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
