"""
Configuration database module
Handles loading, saving, and caching of config.json
"""
import json
import os
import time
import copy
import shutil
import threading
from typing import Callable, Optional, TypeVar
from filelock import FileLock, Timeout
from fastapi import HTTPException

from logger_config import get_logger
from .config import AppConfig, CONFIG_FILE
from .proxy_compat import normalize_config_nodes

logger = get_logger(__name__)

# Config cache for performance
_config_cache: Optional[dict] = None
_config_mtime: Optional[float] = None
_config_cached_at: Optional[float] = None
_config_cache_lock = threading.RLock()
T = TypeVar("T")


class ConfigLoadError(RuntimeError):
    """Raised when an existing configuration cannot be read safely."""


def get_default_config() -> dict:
    """Get default configuration structure"""
    return {
        'auth': {},
        'subscriptions': [],
        'custom_nodes': [],
        'source_order': [],
        'users': [],
        'templates': [],
        'admin_tokens': [],
        'proxy_chains': [],
    }


def _load_config_from_disk() -> dict:
    """Load config directly from disk without using cache."""
    default = get_default_config()

    if not os.path.exists(CONFIG_FILE):
        return default

    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        config = json.load(f)

    for key in default:
        if key not in config:
            config[key] = default[key]

    normalized_count = normalize_config_nodes(config)
    if normalized_count:
        logger.info("Normalized %s legacy xhttp node(s) from config", normalized_count)

    return config


def _write_config_locked(config: dict):
    """Write config to disk. Caller must already hold the file lock."""
    global _config_cache, _config_mtime, _config_cached_at

    temp_file = f"{CONFIG_FILE}.tmp"
    backup_temp_file = f"{CONFIG_FILE}.backup.tmp"
    try:
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(temp_file, 0o600)
        except OSError:
            logger.warning("Could not restrict temporary configuration permissions")

        if os.path.exists(CONFIG_FILE):
            backup_file = f"{CONFIG_FILE}.backup"
            # Build the fallback backup separately, then atomically publish it.
            # copy()/copy2() are intentionally avoided because bind mounts can
            # reject their metadata operations even when content writes work.
            shutil.copyfile(CONFIG_FILE, backup_temp_file)
            try:
                os.chmod(backup_temp_file, 0o600)
            except OSError:
                logger.warning("Could not restrict configuration backup permissions")
            os.replace(backup_temp_file, backup_file)

        os.replace(temp_file, CONFIG_FILE)
    finally:
        for unpublished_file in (temp_file, backup_temp_file):
            if os.path.exists(unpublished_file):
                try:
                    os.remove(unpublished_file)
                except OSError:
                    logger.debug("Failed to remove unpublished configuration file")

    with _config_cache_lock:
        _config_cache = None
        _config_mtime = None
        _config_cached_at = None


def load_config() -> dict:
    """Load unified config with caching"""
    global _config_cache, _config_mtime, _config_cached_at
    
    default = get_default_config()
    
    if not os.path.exists(CONFIG_FILE):
        logger.debug("Config file not found: %s, using default config", CONFIG_FILE)
        return default
    
    try:
        current_mtime = os.path.getmtime(CONFIG_FILE)
        current_time = time.monotonic()

        with _config_cache_lock:
            cache_is_fresh = (
                AppConfig.CONFIG_CACHE_DURATION > 0
                and _config_cached_at is not None
                and current_time - _config_cached_at < AppConfig.CONFIG_CACHE_DURATION
            )
            if _config_cache is not None and _config_mtime == current_mtime and cache_is_fresh:
                return copy.deepcopy(_config_cache)

            config = _load_config_from_disk()

            _config_cache = config
            _config_mtime = current_mtime
            _config_cached_at = current_time

            logger.debug("Config loaded successfully from %s", CONFIG_FILE)
            return copy.deepcopy(config)
    except json.JSONDecodeError as e:
        logger.critical("Configuration file contains invalid JSON", exc_info=True)
        raise ConfigLoadError("Configuration file contains invalid JSON") from e
    except (OSError, ValueError, TypeError) as e:
        logger.critical("Configuration file cannot be read safely", exc_info=True)
        raise ConfigLoadError("Configuration file cannot be read safely") from e


def save_config(config: dict):
    """Save unified config with file locking"""
    global _config_cache, _config_mtime
    
    lock_file = f"{CONFIG_FILE}.lock"
    lock = FileLock(lock_file, timeout=AppConfig.FILE_LOCK_TIMEOUT)
    
    try:
        with lock:
            _write_config_locked(config)
            
            logger.debug("Config saved successfully to %s", CONFIG_FILE)
    except Timeout:
        logger.error("Timeout waiting for config file lock")
        raise HTTPException(status_code=503, detail="Configuration is being updated, please try again")
    except Exception as e:
        logger.error("Failed to save config: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to save configuration")


def invalidate_config_cache():
    """Invalidate config cache"""
    global _config_cache, _config_mtime, _config_cached_at
    with _config_cache_lock:
        _config_cache = None
        _config_mtime = None
        _config_cached_at = None


def update_config(mutator: Callable[[dict], T]) -> T:
    """
    Atomically update config.json.

    The mutator is called while holding the file lock with the latest on-disk
    config. It may mutate the config in place and return any response value.
    This avoids read-modify-write races between concurrent API requests.
    """
    lock_file = f"{CONFIG_FILE}.lock"
    lock = FileLock(lock_file, timeout=AppConfig.FILE_LOCK_TIMEOUT)

    try:
        with lock:
            config = _load_config_from_disk()
            result = mutator(config)
            _write_config_locked(config)
            logger.debug("Atomically updated config")
            return result
    except Timeout:
        logger.error("Timeout waiting for config file lock while updating config")
        raise HTTPException(status_code=503, detail="Configuration is being updated, please try again")
    except HTTPException:
        raise
    except json.JSONDecodeError as e:
        logger.error("Config file is corrupted while updating config: %s", e)
        raise HTTPException(status_code=500, detail="Configuration file is corrupted")
    except Exception as e:
        logger.error("Failed to atomically update config: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to update configuration")


def update_subscription_fields(sub_id: str, updates: dict) -> Optional[dict]:
    """
    Atomically merge updates into one subscription record.

    This avoids concurrent refresh jobs overwriting each other's changes by
    always reloading the latest config while holding the file lock.
    """
    lock_file = f"{CONFIG_FILE}.lock"
    lock = FileLock(lock_file, timeout=AppConfig.FILE_LOCK_TIMEOUT)

    try:
        with lock:
            config = _load_config_from_disk()
            sub = find_subscription_by_id(config, sub_id)
            if not sub:
                logger.warning("Subscription %s not found while applying atomic update", sub_id)
                return None

            sub.update(updates or {})
            _write_config_locked(config)
            logger.debug("Atomically updated subscription %s", sub_id)
            return dict(sub)
    except Timeout:
        logger.error("Timeout waiting for config file lock while updating subscription %s", sub_id)
        raise HTTPException(status_code=503, detail="Configuration is being updated, please try again")
    except json.JSONDecodeError as e:
        logger.error("Config file is corrupted while updating subscription %s: %s", sub_id, e)
        raise HTTPException(status_code=500, detail="Configuration file is corrupted")
    except Exception as e:
        logger.error("Failed to atomically update subscription %s: %s", sub_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to update subscription")


# Helper functions for finding items
def find_subscription_by_id(config: dict, sub_id: str) -> Optional[dict]:
    """Fast subscription lookup by ID"""
    for s in config.get('subscriptions', []):
        if s['id'] == sub_id:
            return s
    return None


def find_custom_node_by_id(config: dict, node_id: str) -> Optional[dict]:
    """Fast custom node lookup by ID"""
    for node in config.get('custom_nodes', []):
        if node['id'] == node_id:
            return node
    return None


def find_user_by_id(config: dict, user_id: str) -> Optional[dict]:
    """Fast user lookup by ID"""
    for user in config.get('users', []):
        if user['id'] == user_id:
            return user
    return None


def find_template_by_id(config: dict, template_id: str) -> Optional[dict]:
    """Fast template lookup by ID"""
    for template in config.get('templates', []):
        if template['id'] == template_id:
            return template
    return None


def find_admin_token_by_id(config: dict, token_id: str) -> Optional[dict]:
    """Fast admin token lookup by ID"""
    for token in config.get('admin_tokens', []):
        if token['id'] == token_id:
            return token
    return None
