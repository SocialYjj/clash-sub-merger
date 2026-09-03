"""Transactional application configuration storage.

The public API intentionally remains dictionary-based so existing routers and
services do not need to know which persistence backend is active. SQLite is
the default; PostgreSQL and MySQL are selected through ``STORAGE_BACKEND``.
A patched ``CONFIG_FILE`` still enables the legacy JSON path for compatibility
with isolated tests and old recovery tooling.
"""

from __future__ import annotations

import copy
import json
import os
import threading
import time
from typing import Callable, Optional, TypeVar

from fastapi import HTTPException
from filelock import FileLock, Timeout

from logger_config import get_logger
from .config import AppConfig, CONFIG_FILE
from .proxy_compat import normalize_config_nodes
from . import storage

logger = get_logger(__name__)

_ORIGINAL_CONFIG_FILE = CONFIG_FILE
_config_cache: Optional[dict] = None
_config_cached_at: Optional[float] = None
_config_cache_lock = threading.RLock()
T = TypeVar("T")


class ConfigLoadError(RuntimeError):
    """Raised when an existing configuration cannot be read safely."""


def get_default_config() -> dict:
    return {
        "auth": {},
        "subscriptions": [],
        "custom_nodes": [],
        "source_order": [],
        "users": [],
        "templates": [],
        "admin_tokens": [],
        "proxy_chains": [],
        "node_pools": [],
    }


def _legacy_json_override_active() -> bool:
    """Return true only when a caller deliberately replaces CONFIG_FILE."""
    return str(CONFIG_FILE) != str(_ORIGINAL_CONFIG_FILE)


def _lock_path() -> str:
    if _legacy_json_override_active():
        return f"{CONFIG_FILE}.lock"
    return storage.database_lock_path()


def _normalize_config(config: dict) -> dict:
    default = get_default_config()
    for key, value in default.items():
        config.setdefault(key, copy.deepcopy(value))
    normalized_count = normalize_config_nodes(config)
    if normalized_count:
        logger.info("Normalized %s legacy xhttp node(s) from config", normalized_count)
    return config


def _load_legacy_config() -> dict:
    default = get_default_config()
    if not os.path.exists(CONFIG_FILE):
        return default
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
            config = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ConfigLoadError("Configuration file contains invalid JSON") from exc
    except (OSError, TypeError, ValueError) as exc:
        raise ConfigLoadError("Configuration file cannot be read safely") from exc
    if not isinstance(config, dict):
        raise ConfigLoadError("Configuration root must be an object")
    return _normalize_config(config)


def _load_config_from_disk() -> dict:
    """Load the latest configuration without the in-process cache."""
    if _legacy_json_override_active():
        return _load_legacy_config()

    storage.initialize_database()
    config = storage.read_app_document("config", default=None)
    if config is None:
        config = get_default_config()
    if not isinstance(config, dict):
        raise ConfigLoadError("Stored configuration root must be an object")
    return _normalize_config(config)


def _write_legacy_config(config: dict) -> None:
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    temporary_file = f"{CONFIG_FILE}.tmp"
    try:
        with open(temporary_file, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary_file, 0o600)
        except OSError:
            pass
        os.replace(temporary_file, CONFIG_FILE)
    finally:
        if os.path.exists(temporary_file):
            try:
                os.remove(temporary_file)
            except OSError:
                pass


def _write_config_locked(config: dict) -> None:
    """Persist config; caller must hold the storage lock."""
    global _config_cache, _config_cached_at
    normalized = _normalize_config(config)
    if _legacy_json_override_active():
        _write_legacy_config(normalized)
    else:
        storage.write_app_document("config", normalized)

    with _config_cache_lock:
        _config_cache = None
        _config_cached_at = None
    try:
        from services.stats_cache import invalidate as invalidate_stats_cache

        invalidate_stats_cache()
    except Exception:
        logger.debug("Failed to invalidate statistics cache after config write", exc_info=True)


def load_config() -> dict:
    """Load configuration with a short-lived deep-copy cache."""
    global _config_cache, _config_cached_at
    now = time.monotonic()
    with _config_cache_lock:
        if (
            _config_cache is not None
            and AppConfig.CONFIG_CACHE_DURATION > 0
            and _config_cached_at is not None
            and now - _config_cached_at < AppConfig.CONFIG_CACHE_DURATION
        ):
            return copy.deepcopy(_config_cache)

    config = _load_config_from_disk()
    with _config_cache_lock:
        _config_cache = config
        _config_cached_at = now
    logger.debug(
        "Config loaded from %s",
        storage.database_path() if not _legacy_json_override_active() else CONFIG_FILE,
    )
    return copy.deepcopy(config)


def save_config(config: dict) -> None:
    """Save configuration atomically under the SQLite/legacy lock."""
    try:
        with FileLock(_lock_path(), timeout=AppConfig.FILE_LOCK_TIMEOUT):
            _write_config_locked(config)
    except Timeout as exc:
        logger.error("Timeout waiting for configuration lock")
        raise HTTPException(status_code=503, detail="Configuration is being updated, please try again") from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to save config: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to save configuration") from exc


def replace_config_locked(config: dict) -> None:
    """Replace config while the caller already owns the storage lock."""
    if not isinstance(config, dict):
        raise ValueError("Configuration must be an object")
    _write_config_locked(copy.deepcopy(config))


def invalidate_config_cache() -> None:
    global _config_cache, _config_cached_at
    with _config_cache_lock:
        _config_cache = None
        _config_cached_at = None


def update_config(mutator: Callable[[dict], T]) -> T:
    """Atomically load, mutate and persist the latest configuration."""
    try:
        with FileLock(_lock_path(), timeout=AppConfig.FILE_LOCK_TIMEOUT):
            config = _load_config_from_disk()
            result = mutator(config)
            _write_config_locked(config)
            return result
    except Timeout as exc:
        logger.error("Timeout waiting for configuration lock while updating config")
        raise HTTPException(status_code=503, detail="Configuration is being updated, please try again") from exc
    except HTTPException:
        raise
    except ConfigLoadError as exc:
        logger.error("Configuration is corrupted while updating: %s", exc)
        raise HTTPException(status_code=500, detail="Configuration file is corrupted") from exc
    except Exception as exc:
        logger.error("Failed to atomically update configuration: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to update configuration") from exc


def update_subscription_fields(sub_id: str, updates: dict) -> Optional[dict]:
    """Atomically merge updates into one subscription record."""
    def apply(config: dict) -> Optional[dict]:
        subscription = find_subscription_by_id(config, sub_id)
        if not subscription:
            logger.warning("Subscription %s not found while applying atomic update", sub_id)
            return None
        subscription.update(updates or {})
        return dict(subscription)

    return update_config(apply)


def find_subscription_by_id(config: dict, sub_id: str) -> Optional[dict]:
    for subscription in config.get("subscriptions", []):
        if isinstance(subscription, dict) and subscription.get("id") == sub_id:
            return subscription
    return None


def find_custom_node_by_id(config: dict, node_id: str) -> Optional[dict]:
    for node in config.get("custom_nodes", []):
        if isinstance(node, dict) and node.get("id") == node_id:
            return node
    return None


def find_user_by_id(config: dict, user_id: str) -> Optional[dict]:
    for user in config.get("users", []):
        if isinstance(user, dict) and user.get("id") == user_id:
            return user
    return None


def find_template_by_id(config: dict, template_id: str) -> Optional[dict]:
    for template in config.get("templates", []):
        if isinstance(template, dict) and template.get("id") == template_id:
            return template
    return None


def find_admin_token_by_id(config: dict, token_id: str) -> Optional[dict]:
    for token in config.get("admin_tokens", []):
        if isinstance(token, dict) and token.get("id") == token_id:
            return token
    return None
