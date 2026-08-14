"""Cloudflare Radar ASN-level bot traffic lookup.

Radar is deliberately kept as a backend integration.  The API token can be
configured in the administrator settings (with an environment-variable
fallback) and is never included in node metadata or API responses.  Results
are cached by ASN and date range because Radar returns an aggregate value, not
a node-specific measurement.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
from typing import Any, Dict, Optional

import httpx

from core.config import AppConfig, DATA_DIR, env_int
from logger_config import get_logger

logger = get_logger(__name__)

RADAR_ENDPOINT = "https://api.cloudflare.com/client/v4/radar/http/summary/BOT_CLASS"
RADAR_CACHE_FILE = os.path.join(DATA_DIR, "cloudflare_radar_cache.json")
RADAR_CACHE_VERSION = 1
RADAR_CACHE_TTL_SECONDS = env_int(
    "CLOUDFLARE_RADAR_CACHE_TTL_SECONDS",
    24 * 3600,
    minimum=300,
)
RADAR_NEGATIVE_CACHE_TTL_SECONDS = 5 * 60
RADAR_MAX_CONCURRENCY = env_int("CLOUDFLARE_RADAR_MAX_CONCURRENCY", 2, minimum=1, maximum=10)
RADAR_DEFAULT_DATE_RANGE = os.environ.get("CLOUDFLARE_RADAR_DATE_RANGE", "7d").strip() or "7d"
_DATE_RANGE_RE = re.compile(r"^\d{1,3}[dhm]$")

_radar_cache: Dict[str, Dict[str, Any]] = {}
_radar_inflight: Dict[str, asyncio.Task] = {}
_radar_cache_lock = threading.RLock()
_radar_inflight_lock = asyncio.Lock()
_radar_save_lock = asyncio.Lock()
_radar_semaphore = asyncio.Semaphore(RADAR_MAX_CONCURRENCY)
_configured_radar_token = ""


def _token() -> str:
    """Return the persisted admin token, falling back to the deployment env."""
    return _configured_radar_token or os.environ.get("CLOUDFLARE_RADAR_API_TOKEN", "").strip()


def apply_cloudflare_radar_runtime_config(config: Optional[dict]) -> None:
    """Apply the admin-configured token without exposing it to API callers."""
    global _configured_radar_token
    geoip_config = config.get("geoip_config", {}) if isinstance(config, dict) else {}
    _configured_radar_token = str(
        geoip_config.get("cloudflare_radar_token") or ""
    ).strip() if isinstance(geoip_config, dict) else ""


def is_radar_enabled() -> bool:
    """Return whether a backend Radar token is configured, without exposing it."""
    return bool(_token())


def normalize_radar_asn(value: Any) -> Optional[str]:
    """Normalize ``AS123``/``123`` into the numeric query value required by Radar."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    match = re.search(r"\bAS\s*(\d+)\b", text, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    if text.isdigit():
        return text
    return None


def normalize_date_range(value: Any = None) -> str:
    """Accept only the compact Radar date-range format used in query params."""
    candidate = str(value or RADAR_DEFAULT_DATE_RANGE).strip().lower()
    return candidate if _DATE_RANGE_RE.fullmatch(candidate) else "7d"


def _coerce_ratio(value: Any) -> Optional[float]:
    if isinstance(value, dict):
        for key in ("value", "percentage", "percent", "ratio"):
            if key in value:
                return _coerce_ratio(value[key])
        return None
    if isinstance(value, list):
        if len(value) == 1:
            return _coerce_ratio(value[0])
        return None
    if isinstance(value, bool) or value is None or value == "":
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if parsed < 0:
        return None
    return parsed


def _find_ratio(payload: Any, aliases: set[str]) -> Optional[float]:
    """Find a ratio in both legacy human/bot and current Radar bot-class keys."""
    if not isinstance(payload, dict):
        return None
    for key, value in payload.items():
        if str(key).strip().lower() in aliases:
            ratio = _coerce_ratio(value)
            if ratio is not None:
                return ratio
    return None


def parse_radar_bot_class_response(payload: Any, *, checked_at: Optional[float] = None,
                                   date_range: Any = None) -> Optional[Dict[str, Any]]:
    """Normalize Cloudflare's bot-class summary response.

    Cloudflare has returned both ``human``/``bot`` and
    ``LIKELY_HUMAN``/``LIKELY_AUTOMATED`` keys across endpoint revisions.  The
    parser accepts either shape and ignores unrelated response fields.
    """
    if not isinstance(payload, dict) or payload.get("success") is False:
        return None

    result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    candidates = [result]
    if isinstance(result, dict):
        candidates.extend(
            value for key in ("summary_0", "summary", "data")
            if isinstance((value := result.get(key)), dict)
        )

    human = bot = None
    human_aliases = {"human", "likely_human", "likely human"}
    bot_aliases = {"bot", "likely_automated", "likely automated"}
    for candidate in candidates:
        if human is None:
            human = _find_ratio(candidate, human_aliases)
        if bot is None:
            bot = _find_ratio(candidate, bot_aliases)
        if human is not None and bot is not None:
            break

    meta = result.get("meta") if isinstance(result, dict) and isinstance(result.get("meta"), dict) else {}
    confidence_info = meta.get("confidenceInfo") if isinstance(meta, dict) else {}
    confidence_level = confidence_info.get("level") if isinstance(confidence_info, dict) else None

    base_result = {
        "radar_checked_at": float(checked_at or time.time()),
        "radar_date_range": normalize_date_range(date_range),
        "radar_source": "cloudflare_radar",
    }
    if confidence_level is not None:
        base_result["radar_confidence_level"] = confidence_level

    if human is None and bot is None:
        # Radar legitimately returns an empty summary for ASNs with no
        # observable Cloudflare traffic. Preserve that state so callers can
        # distinguish "tested with no data" from "never tested".
        base_result["radar_status"] = "no_data"
        return base_result

    # Some API clients expose proportions in [0, 1], while the Radar summary
    # normally uses percentages.  Convert only when both values clearly form a
    # unit interval, so a legitimate 1% value is not changed to 100%.
    if human is not None and bot is not None and human <= 1 and bot <= 1 and human + bot <= 1.01:
        human *= 100
        bot *= 100

    def bounded(value: Optional[float]) -> Optional[float]:
        if value is None:
            return None
        return round(min(100.0, max(0.0, value)), 2)

    return {
        **base_result,
        "radar_human_ratio": bounded(human),
        "radar_bot_ratio": bounded(bot),
        "radar_status": "success",
    }


def _cache_is_fresh(entry: Dict[str, Any]) -> bool:
    try:
        timestamp = float(entry.get("timestamp") or 0)
    except (TypeError, ValueError):
        return False
    ttl = RADAR_NEGATIVE_CACHE_TTL_SECONDS if entry.get("_negative") else RADAR_CACHE_TTL_SECONDS
    return timestamp > 0 and time.time() - timestamp < ttl


def _get_cached_profile(cache_key: str) -> tuple[bool, Optional[Dict[str, Any]]]:
    """Return ``(hit, profile)`` while treating short-lived failures as hits."""
    with _radar_cache_lock:
        cached = _radar_cache.get(cache_key)
        if not isinstance(cached, dict) or not _cache_is_fresh(cached):
            _radar_cache.pop(cache_key, None)
            return False, None
        if cached.get("_negative"):
            return True, None
        return True, {key: value for key, value in cached.items() if key != "timestamp"}


def load_radar_cache_from_disk() -> None:
    """Load only recent positive results; malformed cache data is ignored."""
    global _radar_cache
    try:
        if not os.path.exists(RADAR_CACHE_FILE):
            return
        with open(RADAR_CACHE_FILE, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if isinstance(payload, dict) and "entries" in payload:
            if payload.get("version") != RADAR_CACHE_VERSION:
                return
            entries = payload.get("entries", {})
        else:
            entries = payload
        if not isinstance(entries, dict):
            return
        valid = {key: value for key, value in entries.items()
                 if isinstance(value, dict) and _cache_is_fresh(value)}
        with _radar_cache_lock:
            _radar_cache = valid
    except (OSError, ValueError, TypeError) as exc:
        logger.warning("Failed to load Cloudflare Radar cache: %s", type(exc).__name__)


async def save_radar_cache_to_disk() -> None:
    """Persist positive Radar results with an atomic replace."""
    async with _radar_save_lock:
        temporary_path = f"{RADAR_CACHE_FILE}.{os.getpid()}.tmp"
        try:
            with _radar_cache_lock:
                snapshot = {
                    key: value
                    for key, value in _radar_cache.items()
                    if isinstance(value, dict) and not value.get("_negative")
                }
            os.makedirs(os.path.dirname(RADAR_CACHE_FILE) or ".", exist_ok=True)
            with open(temporary_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {"version": RADAR_CACHE_VERSION, "entries": snapshot},
                    handle,
                    ensure_ascii=False,
                    indent=2,
                )
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(temporary_path, 0o600)
            except OSError:
                logger.debug("Could not restrict Cloudflare Radar cache permissions")
            os.replace(temporary_path, RADAR_CACHE_FILE)
        except OSError as exc:
            logger.warning("Failed to save Cloudflare Radar cache: %s", type(exc).__name__)
        finally:
            if os.path.exists(temporary_path):
                try:
                    os.remove(temporary_path)
                except OSError:
                    pass


async def _fetch_radar(asn: str, date_range: str, timeout: int) -> Optional[Dict[str, Any]]:
    token = _token()
    if not token:
        return None
    try:
        async with _radar_semaphore:
            async with httpx.AsyncClient(
                verify=AppConfig.HTTP_VERIFY_SSL,
                follow_redirects=True,
            ) as client:
                response = await client.get(
                    RADAR_ENDPOINT,
                    params={"asn": asn, "dateRange": date_range, "format": "JSON"},
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                    timeout=timeout,
                )
        if response.status_code == 429:
            logger.warning("Cloudflare Radar rate limit reached for ASN %s", asn)
            return None
        if response.status_code < 200 or response.status_code >= 300:
            logger.debug("Cloudflare Radar returned HTTP %s for ASN %s", response.status_code, asn)
            return None
        payload = response.json()
        return parse_radar_bot_class_response(payload, date_range=date_range)
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        logger.debug("Cloudflare Radar lookup failed for ASN %s: %s", asn, type(exc).__name__)
        return None


async def lookup_radar_for_asn(asn: Any, *, timeout: Optional[int] = None,
                               date_range: Any = None) -> Optional[Dict[str, Any]]:
    """Get a cached ASN-level bot ratio, deduplicating concurrent lookups."""
    normalized_asn = normalize_radar_asn(asn)
    if not normalized_asn or not is_radar_enabled():
        return None

    selected_range = normalize_date_range(date_range)
    cache_key = f"{normalized_asn}|{selected_range}"
    cache_hit, cached_profile = _get_cached_profile(cache_key)
    if cache_hit:
        return cached_profile

    async def run_lookup() -> Optional[Dict[str, Any]]:
        current = await _fetch_radar(
            normalized_asn,
            selected_range,
            max(1, int(timeout or AppConfig.CLOUDFLARE_RADAR_TIMEOUT)),
        )
        if not current:
            with _radar_cache_lock:
                _radar_cache[cache_key] = {"_negative": True, "timestamp": time.time()}
            return None
        entry = {**current, "timestamp": time.time()}
        with _radar_cache_lock:
            _radar_cache[cache_key] = entry
        await save_radar_cache_to_disk()
        return current

    async with _radar_inflight_lock:
        task = _radar_inflight.get(cache_key)
        if task is None:
            task = asyncio.create_task(run_lookup())
            _radar_inflight[cache_key] = task

    try:
        return await asyncio.shield(task)
    finally:
        if task.done():
            async with _radar_inflight_lock:
                if _radar_inflight.get(cache_key) is task:
                    _radar_inflight.pop(cache_key, None)


load_radar_cache_from_disk()
