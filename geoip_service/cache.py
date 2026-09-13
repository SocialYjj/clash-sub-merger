"""
Online GeoIP lookup cache.

This module is the SINGLE OWNER of the lookup-cache state: the constants, the
cache dictionaries, the concurrency primitives and every function that mutates
them live here.

The live state is read and written through the ``geoip_service`` package
namespace (``_PKG``) instead of module globals.  The legacy implementation was
a single module, and tests/callers patch attributes on that namespace (for
example ``patch.object(geoip_service, "GEOIP_CACHE_FILE", ...)`` or
``patch.object(geoip_service, "_online_geoip_cache", ...)``).  Routing every
access through the package namespace keeps those patches working identically,
including the rebinding performed by :func:`load_geoip_cache_from_disk` and
:func:`clear_online_geoip_cache`.
"""

import asyncio
import json
import os
import threading
import time
from typing import Dict

import geoip_service as _PKG
from core.config import DATA_DIR, env_int
from core.storage import delete_cache_document, read_cache_document, write_cache_document
from logger_config import get_logger

from .normalize import _normalize_geo_result_fields

# Setup logger
logger = get_logger(__name__)

# Persistent cache configuration
GEOIP_CACHE_FILE = os.path.join(DATA_DIR, "geoip_cache.json")
_DEFAULT_GEOIP_CACHE_FILE = GEOIP_CACHE_FILE
GEOIP_CACHE_TTL = 7 * 24 * 3600  # 7 days in seconds
# A temporary provider/network failure must not poison lookups for a week.
GEOIP_NEGATIVE_CACHE_TTL = 5 * 60
GEOIP_CACHE_VERSION = 1

# Online GeoIP lookup cache (to avoid repeated requests)
_online_geoip_cache: Dict[str, Dict] = {}
_online_geoip_inflight: Dict[str, asyncio.Task] = {}
_online_geoip_semaphore = asyncio.Semaphore(env_int("GEOIP_MAX_CONCURRENCY", 8, minimum=1))
_online_geoip_cache_lock = threading.RLock()
_online_geoip_inflight_lock = asyncio.Lock()
_online_geoip_save_lock = asyncio.Lock()


def _geoip_cache_ttl(entry: dict) -> int:
    """Return the TTL appropriate for a positive or negative cache entry."""
    return _PKG.GEOIP_NEGATIVE_CACHE_TTL if entry.get("_negative") else _PKG.GEOIP_CACHE_TTL


def load_geoip_cache_from_disk():
    """Load GeoIP cache from SQLite (or an explicitly overridden legacy file)."""
    try:
        if _PKG.GEOIP_CACHE_FILE != _PKG._DEFAULT_GEOIP_CACHE_FILE:
            with open(_PKG.GEOIP_CACHE_FILE, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
        else:
            cache_data = read_cache_document("geoip", default=None)
            if cache_data is None:
                return

        if not isinstance(cache_data, dict):
            raise ValueError("GeoIP cache root must be an object")

        if "version" in cache_data or "entries" in cache_data:
            if cache_data.get("version") != _PKG.GEOIP_CACHE_VERSION:
                logger.info("Ignoring GeoIP cache with unsupported version %s", cache_data.get("version"))
                with _PKG._online_geoip_cache_lock:
                    _PKG._online_geoip_cache = {}
                return
            entries = cache_data.get("entries", {})
            if not isinstance(entries, dict):
                raise ValueError("GeoIP cache entries must be an object")
        else:
            # Legacy v0 cache format was a raw mapping of cache_key -> entry.
            entries = cache_data

        # Filter out expired entries
        current_time = time.time()
        valid_cache = {}
        expired_count = 0

        for key, entry in entries.items():
            if not isinstance(entry, dict):
                expired_count += 1
                continue
            if "timestamp" in entry:
                age = current_time - entry["timestamp"]
                if age < _geoip_cache_ttl(entry):
                    valid_cache[key] = entry
                else:
                    expired_count += 1
            else:
                # Old format without timestamp, keep it
                valid_cache[key] = entry

        with _PKG._online_geoip_cache_lock:
            _PKG._online_geoip_cache = valid_cache
        logger.info(
            f"Loaded {len(valid_cache)} GeoIP cache entries from disk ({expired_count} expired entries removed)"
        )
    except Exception as e:
        logger.warning(f"Failed to load GeoIP cache from disk: {e}")
        with _PKG._online_geoip_cache_lock:
            _PKG._online_geoip_cache = {}


async def save_geoip_cache_to_disk():
    """Persist GeoIP cache in SQLite with legacy-file compatibility for tests."""
    async with _PKG._online_geoip_save_lock:
        tmp_file = f"{_PKG.GEOIP_CACHE_FILE}.{os.getpid()}.tmp"
        try:
            with _PKG._online_geoip_cache_lock:
                cache_snapshot = dict(_PKG._online_geoip_cache)

            payload = {"version": _PKG.GEOIP_CACHE_VERSION, "entries": cache_snapshot}
            if _PKG.GEOIP_CACHE_FILE != _PKG._DEFAULT_GEOIP_CACHE_FILE:
                os.makedirs(os.path.dirname(_PKG.GEOIP_CACHE_FILE), exist_ok=True)
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(payload, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                try:
                    os.chmod(tmp_file, 0o600)
                except OSError:
                    logger.warning("Could not restrict GeoIP cache file permissions")
                os.replace(tmp_file, _PKG.GEOIP_CACHE_FILE)
            else:
                write_cache_document("geoip", payload)
            logger.debug(f"Saved {len(cache_snapshot)} GeoIP cache entries to disk")
        except Exception as exc:
            logger.error("Failed to save GeoIP cache to disk: %s", type(exc).__name__)
        finally:
            if os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except OSError:
                    logger.debug("Failed to remove GeoIP cache temp file")


def _normalize_cached_geo_entry(entry: Dict) -> Dict:
    """Normalize cached translated values without making network requests."""
    normalized = dict(entry)
    normalized.update(
        _normalize_geo_result_fields(
            entry.get("iso_code", ""), entry.get("country_name") or entry.get("country", ""), entry.get("city", "")
        )
    )
    return normalized


def _get_valid_cache_entry(cache_key: str):
    """Return ``(cache_hit, cached_result)`` for ``cache_key``.

    Expired entries are dropped and fresh entries are normalized in place,
    exactly like the legacy inlined closure inside ``lookup_ip_online``.
    """
    with _PKG._online_geoip_cache_lock:
        entry = _PKG._online_geoip_cache.get(cache_key)
        if not isinstance(entry, dict):
            return False, None

        ts = entry.get("timestamp")
        if ts and (time.time() - ts) < _geoip_cache_ttl(entry):
            if entry.get("_negative"):
                return True, None
            normalized_entry = _normalize_cached_geo_entry(entry)
            if normalized_entry != entry:
                _PKG._online_geoip_cache[cache_key] = normalized_entry
            return True, normalized_entry

        _PKG._online_geoip_cache.pop(cache_key, None)
        return False, None


def _store_cache_entry(cache_key: str, result) -> bool:
    """Store a lookup result (or a negative marker) and report state changes."""
    with _PKG._online_geoip_cache_lock:
        new_entry = result or {"timestamp": time.time(), "_negative": True}
        previous_entry = _PKG._online_geoip_cache.get(cache_key)
        cache_changed = previous_entry != new_entry
        _PKG._online_geoip_cache[cache_key] = new_entry
    return cache_changed


async def _register_inflight_task(cache_key: str, lookup_factory):
    """Atomically re-check the cache and register a single in-flight task.

    Returns ``(task, cached_result)``.  ``task`` is ``None`` when the
    double-check under the lock produced a cache hit; otherwise it is the
    shared in-flight task (created via ``lookup_factory`` while still holding
    the lock, exactly like the legacy code).
    """
    async with _PKG._online_geoip_inflight_lock:
        # Double-check under the lock so cache expiry and task creation are atomic.
        cache_hit, cached_result = _get_valid_cache_entry(cache_key)
        if cache_hit:
            return None, cached_result

        task = _PKG._online_geoip_inflight.get(cache_key)
        if task is None:
            task = lookup_factory()
            _PKG._online_geoip_inflight[cache_key] = task
        return task, None


async def _release_inflight_task(cache_key: str, task) -> None:
    """Drop a finished in-flight task so later lookups can start a new one."""
    if task.done():
        async with _PKG._online_geoip_inflight_lock:
            if _PKG._online_geoip_inflight.get(cache_key) is task:
                _PKG._online_geoip_inflight.pop(cache_key, None)


def get_online_geoip_cache_snapshot() -> Dict[str, Dict]:
    """Return a shallow snapshot of the online GeoIP cache for safe iteration."""
    with _PKG._online_geoip_cache_lock:
        return dict(_PKG._online_geoip_cache)


def get_online_geoip_cache_stats() -> dict:
    """Return positive/negative cache counts without exposing the live dict."""
    snapshot = get_online_geoip_cache_snapshot()
    positive = 0
    negative = 0
    for entry in snapshot.values():
        if isinstance(entry, dict) and entry.get("_negative"):
            negative += 1
        else:
            positive += 1
    return {
        "cache_size": len(snapshot),
        "positive": positive,
        "negative": negative,
    }


async def clear_online_geoip_cache():
    """Clear the online GeoIP lookup cache (both memory and disk)"""
    with _PKG._online_geoip_cache_lock:
        _PKG._online_geoip_cache = {}
    async with _PKG._online_geoip_inflight_lock:
        for task in _PKG._online_geoip_inflight.values():
            if not task.done():
                task.cancel()
        _PKG._online_geoip_inflight = {}
    try:
        if _PKG.GEOIP_CACHE_FILE != _PKG._DEFAULT_GEOIP_CACHE_FILE:
            if os.path.exists(_PKG.GEOIP_CACHE_FILE):
                os.remove(_PKG.GEOIP_CACHE_FILE)
        else:
            delete_cache_document("geoip")
        logger.info("GeoIP cache cleared")
    except Exception as e:
        logger.error(f"Failed to clear GeoIP cache file: {e}")
