"""
Runtime GeoIP configuration holder and the online lookup orchestrator.

``lookup_ip_online`` implements the cache fast-path, in-flight task dedupe,
concurrency limiting, preferred-API-then-fallback ordering and negative
caching.  All cache-state mutations are delegated to :mod:`geoip_service.cache`
(the single state owner); provider functions, the custom-API lookup and the
disk save routine are resolved through the ``geoip_service`` package namespace
(``_PKG``) at call time so patches applied to the legacy module namespace keep
working identically.
"""

import asyncio
import time
from copy import deepcopy
from typing import Dict, Optional

import geoip_service as _PKG
from logger_config import get_logger
from translation_service import translate_location_fields

from .cache import _get_valid_cache_entry, _register_inflight_task, _release_inflight_task, _store_cache_entry
from .normalize import _extract_provider_metadata, _normalize_geo_result_fields, convert_to_simplified
from .providers import BUILTIN_GEOIP_APIS

# Setup logger
logger = get_logger(__name__)

# Online API configuration
_online_geoip_config: Dict = {
    "ipinfo_token": "",
    "preferred_api": "ip-api.com",
    "custom_apis": [],  # User-defined custom APIs
    "api_settings": {},  # Per-API settings like enabled/disabled
}


def apply_geoip_runtime_config(config: Dict) -> Dict:
    """Replace runtime GeoIP state from one complete persisted config snapshot."""
    persisted = config.get("geoip_config", {}) if isinstance(config, dict) else {}
    if not isinstance(persisted, dict):
        persisted = {}
    _PKG._online_geoip_config = {
        "ipinfo_token": str(persisted.get("ipinfo_token") or ""),
        "preferred_api": str(persisted.get("preferred_api") or "ip-api.com"),
        "custom_apis": deepcopy(persisted.get("custom_apis") or []),
        "api_settings": deepcopy(persisted.get("api_settings") or {}),
    }
    from services.cloudflare_radar import apply_cloudflare_radar_runtime_config
    from translation_service import apply_translation_runtime_config

    apply_cloudflare_radar_runtime_config(config)
    apply_translation_runtime_config(config)
    return deepcopy(_PKG._online_geoip_config)


def get_all_geoip_apis() -> list:
    """Get all available GeoIP APIs (builtin + custom)"""
    apis = []
    api_settings = _PKG._online_geoip_config.get("api_settings", {})

    # Add builtin APIs
    for api in BUILTIN_GEOIP_APIS:
        api_copy = api.copy()
        # Apply user settings
        if api["id"] in api_settings:
            api_copy.update(api_settings[api["id"]])
        apis.append(api_copy)

    # Add custom APIs
    for api in _PKG._online_geoip_config.get("custom_apis", []):
        api_copy = api.copy()
        api_copy["builtin"] = False
        # Mask token for security - only indicate if it exists
        if api_copy.get("token"):
            api_copy["has_token"] = True
            api_copy["token"] = ""  # Don't expose actual token
        apis.append(api_copy)

    return apis


async def lookup_ip_online(ip: str, timeout: int = 5, api_id: str = None) -> Optional[Dict]:
    """
    Lookup IP location using online API (ASYNC)
    Default: ip-api.com (45/min), alternatives: ipwhois (10k/month), ipinfo (needs token), or custom APIs

    Args:
        ip: IP address to lookup
        timeout: Request timeout in seconds
        api_id: Preferred API to use first (optional, uses preferred_api from config if not specified).
            Other enabled providers are tried automatically when the preferred provider fails.

    Returns: {"iso_code": "KR", "country_name": "韩国", "city": "首尔", "flag": "🇰🇷"} or None
    """
    requested_api_id = api_id or _PKG._online_geoip_config.get("preferred_api", "ip-api.com")
    # The effective requested API is part of the key. A generic ``default``
    # key would keep returning results from the previous preferred provider
    # after an operator changes the setting.
    cache_key = f"{ip}|{requested_api_id}"

    # Fast path before taking the lock.
    cache_hit, cached_result = _get_valid_cache_entry(cache_key)
    if cache_hit:
        return cached_result

    async def _do_lookup():
        target_api = requested_api_id

        builtin_api_map = {
            "ip-api.com": _PKG._lookup_ip_api_com,
            "ipwhois": _PKG._lookup_ipwhois,
            "ipinfo": _PKG._lookup_ipinfo,
        }

        raw_data = None
        selected_api_id = None

        async with _PKG._online_geoip_semaphore:
            api_settings = _PKG._online_geoip_config.get("api_settings", {})
            custom_apis = {
                api.get("id"): api
                for api in _PKG._online_geoip_config.get("custom_apis", [])
                if isinstance(api, dict) and api.get("id")
            }

            async def query_api(candidate_id: str):
                if candidate_id in builtin_api_map:
                    if not api_settings.get(candidate_id, {}).get("enabled", True):
                        return None
                    return await builtin_api_map[candidate_id](ip, timeout)
                custom_api = custom_apis.get(candidate_id)
                if custom_api and custom_api.get("enabled", True):
                    return await _PKG._lookup_custom_api(ip, custom_api, timeout)
                return None

            # A selected provider is a preference, not a single point of
            # failure. VPS networks commonly cannot reach ip-api.com while a
            # different enabled provider remains reachable.
            candidate_ids = []
            for candidate_id in [target_api, *builtin_api_map, *custom_apis]:
                if candidate_id and candidate_id not in candidate_ids:
                    candidate_ids.append(candidate_id)
            for candidate_id in candidate_ids:
                try:
                    raw_data = await query_api(candidate_id)
                except Exception as exc:
                    logger.warning(
                        "GeoIP provider %s failed for %s: %s",
                        candidate_id,
                        ip,
                        type(exc).__name__,
                    )
                    raw_data = None
                if raw_data:
                    selected_api_id = candidate_id
                    break

        if not raw_data:
            return None

        raw_country = str(raw_data.get("country") or "").strip()
        raw_region = str(raw_data.get("region") or raw_data.get("regionName") or "").strip()
        raw_city = str(raw_data.get("city") or "").strip()
        translated_fields = await translate_location_fields(
            country_name=raw_country,
            region_name=raw_region,
            city_name=raw_city,
            country_code=raw_data.get("countryCode", ""),
        )
        normalized = _normalize_geo_result_fields(
            raw_data.get("countryCode", ""),
            translated_fields["country"],
            translated_fields["city"],
        )

        return {
            **normalized,
            **_extract_provider_metadata(raw_data),
            "region_name": convert_to_simplified(translated_fields["region"]) or None,
            "source": "online",
            "api_id": selected_api_id or target_api,
            "timestamp": time.time(),
        }

    task, cached_result = await _register_inflight_task(cache_key, lambda: asyncio.create_task(_do_lookup()))
    if task is None:
        return cached_result

    try:
        # Shield the shared task so a cancelled client request does not cancel
        # the lookup that other waiters may still be awaiting.
        result = await asyncio.shield(task)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.warning("Online GeoIP lookup task failed for %s: %s", cache_key, e)
        return None
    finally:
        await _release_inflight_task(cache_key, task)

    # Persist every changed entry, including negative results and updates to an
    # existing key. A modulo-based trigger loses the final 1-9 writes on
    # shutdown and made the disk cache diverge from memory.
    if _store_cache_entry(cache_key, result):
        await _PKG.save_geoip_cache_to_disk()

    return result
