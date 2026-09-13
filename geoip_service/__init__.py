"""
GeoIP Service Package
Provides IP geolocation functionality using online APIs.

This package mirrors the legacy single-module ``geoip_service`` namespace: the
package namespace re-exports the complete public *and* private surface, and
the mutable lookup-cache state (defined in :mod:`geoip_service.cache`) is read
and written through this namespace so that callers patching
``geoip_service.<name>`` — as the legacy module allowed — keep observing
identical behavior.

Module layout:
- ``cache``: single owner of the online-lookup cache state (constants, dicts,
  locks, disk load/save, snapshot/stats/clear).
- ``providers``: built-in provider lookups (ip-api.com, ipwhois, ipinfo).
- ``custom_api``: user-defined API lookups with the SSRF-pinned transport.
- ``normalize``: provider payload / country / city normalization helpers and
  the :class:`GeoIPService` static utilities.
- ``translate``: display helpers for saved locations.
- ``orchestrator``: runtime configuration plus :func:`lookup_ip_online`.
"""

import os
import socket

import httpx

from .cache import (
    _DEFAULT_GEOIP_CACHE_FILE,
    GEOIP_CACHE_FILE,
    GEOIP_CACHE_TTL,
    GEOIP_CACHE_VERSION,
    GEOIP_NEGATIVE_CACHE_TTL,
    _geoip_cache_ttl,
    _normalize_cached_geo_entry,
    _online_geoip_cache,
    _online_geoip_cache_lock,
    _online_geoip_inflight,
    _online_geoip_inflight_lock,
    _online_geoip_save_lock,
    _online_geoip_semaphore,
    clear_online_geoip_cache,
    get_online_geoip_cache_snapshot,
    get_online_geoip_cache_stats,
    load_geoip_cache_from_disk,
    save_geoip_cache_to_disk,
)
from .custom_api import (
    _PUBLIC_CUSTOM_URL_RESOLUTIONS,
    CUSTOM_GEOIP_MAX_RESPONSE_BYTES,
    _auto_detect_json_paths,
    _first_json_value,
    _get_json_path,
    _is_public_custom_api_url,
    _lookup_custom_api,
    _PinnedHTTPTransport,
    _PinnedNetworkBackend,
    _read_limited_json_response,
    _resolve_public_custom_api_url,
)
from .normalize import (
    GeoIPService,
    _build_provider_result,
    _coerce_optional_bool,
    _coerce_optional_number,
    _extract_provider_metadata,
    _normalize_asn_value,
    _normalize_geo_result_fields,
    _strip_asn_prefix,
    convert_to_simplified,
    normalize_country_name,
    normalize_ippure_profile,
)
from .orchestrator import (
    _online_geoip_config,
    apply_geoip_runtime_config,
    get_all_geoip_apis,
    lookup_ip_online,
)
from .providers import (
    BUILTIN_GEOIP_APIS,
    _lookup_ip_api_com,
    _lookup_ipinfo,
    _lookup_ipwhois,
)
from .translate import format_location_display, translate_city_name

# ``os``/``socket``/``httpx`` are exposed on the package namespace on purpose:
# tests patch through them exactly as they did against the legacy module
# (e.g. ``patch("geoip_service.socket.getaddrinfo", ...)`` or
# ``patch.object(geoip_service.httpx, "AsyncClient", ...)``).

__all__ = [
    "BUILTIN_GEOIP_APIS",
    "CUSTOM_GEOIP_MAX_RESPONSE_BYTES",
    "GEOIP_CACHE_FILE",
    "GEOIP_CACHE_TTL",
    "GEOIP_CACHE_VERSION",
    "GEOIP_NEGATIVE_CACHE_TTL",
    "GeoIPService",
    "_DEFAULT_GEOIP_CACHE_FILE",
    "_PUBLIC_CUSTOM_URL_RESOLUTIONS",
    "_PinnedHTTPTransport",
    "_PinnedNetworkBackend",
    "_auto_detect_json_paths",
    "_build_provider_result",
    "_coerce_optional_bool",
    "_coerce_optional_number",
    "_extract_provider_metadata",
    "_first_json_value",
    "_geoip_cache_ttl",
    "_get_json_path",
    "_is_public_custom_api_url",
    "_lookup_custom_api",
    "_lookup_ip_api_com",
    "_lookup_ipinfo",
    "_lookup_ipwhois",
    "_normalize_asn_value",
    "_normalize_cached_geo_entry",
    "_normalize_geo_result_fields",
    "_online_geoip_cache",
    "_online_geoip_cache_lock",
    "_online_geoip_config",
    "_online_geoip_inflight",
    "_online_geoip_inflight_lock",
    "_online_geoip_save_lock",
    "_online_geoip_semaphore",
    "_read_limited_json_response",
    "_resolve_public_custom_api_url",
    "_strip_asn_prefix",
    "apply_geoip_runtime_config",
    "clear_online_geoip_cache",
    "convert_to_simplified",
    "format_location_display",
    "get_all_geoip_apis",
    "get_online_geoip_cache_snapshot",
    "get_online_geoip_cache_stats",
    "load_geoip_cache_from_disk",
    "lookup_ip_online",
    "normalize_country_name",
    "normalize_ippure_profile",
    "save_geoip_cache_to_disk",
    "translate_city_name",
]

# Load cache on module import (the legacy module performed this at import
# time; running it here, after the namespace above is fully populated, keeps
# that behavior identical).
load_geoip_cache_from_disk()
