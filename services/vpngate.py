"""VPN Gate dynamic OpenVPN node source.

The source is cached through the project's backend-neutral cache storage.  The
cache keeps the complete Mihomo OpenVPN material on the server while the APIs
expose only safe node metadata and stable references.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any

from core import storage
from logger_config import get_logger


logger = get_logger(__name__)

VPNGATE_SOURCE_ID = "vpngate"
VPNGATE_SOURCE_NAME = "VPN Gate"
VPNGATE_GROUP_SOURCE = "vpngate"
VPNGATE_POOL_NAME = "VPN Gate 动态池"
VPNGATE_API_URL = "https://www.vpngate.net/api/iphone/"
VPNGATE_CACHE_NAMESPACE = "vpngate"
VPNGATE_DEFAULT_INTERVAL_MINUTES = 60
VPNGATE_MIN_INTERVAL_MINUTES = 15
VPNGATE_MAX_INTERVAL_MINUTES = 7 * 24 * 60
VPNGATE_DEFAULT_MAX_NODES = 100
VPNGATE_MIN_MAX_NODES = 1
VPNGATE_MAX_MAX_NODES = 500
VPNGATE_DEFAULT_TIMEOUT_SECONDS = 30
VPNGATE_UNKNOWN_COUNTRY_CODE = "XX"

_ALLOWED_CIPHERS = {
    "AES-128-GCM",
    "AES-256-GCM",
    "AES-128-CBC",
    "AES-256-CBC",
    "CHACHA20-POLY1305",
}
_ALLOWED_AUTH = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}
_ALLOWED_COMP_LZO = {"yes", "no", "adaptive"}
_REFRESH_LOCK = threading.RLock()
_NODE_TEST_METADATA_FIELDS = (
    "last_latency",
    "last_latency_time",
    "last_speed",
    "last_speed_time",
    "last_peak_speed",
    "last_peak_speed_time",
    "exit_ip",
    "ip_profile",
    "region",
    "city",
)


class VpnGateRefreshError(RuntimeError):
    """Raised when a complete VPN Gate snapshot cannot be produced."""


def _safe_integer(value: object, default: int = 0) -> int:
    try:
        return int(str(value or default).strip())
    except (TypeError, ValueError):
        return default


def normalize_vpngate_country_code(value: object) -> str | None:
    """Normalize one VPN Gate country code or return ``None`` when invalid."""

    country = str(value or "").strip().upper()
    return country if re.fullmatch(r"[A-Z]{2}", country) else None


def _normalize_country_codes(value: object) -> list[str]:
    if isinstance(value, str):
        candidates = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        candidates = value
    else:
        candidates = []
    normalized = []
    for candidate in candidates:
        country = normalize_vpngate_country_code(candidate)
        if country and country not in normalized:
            normalized.append(country)
    return normalized


def get_vpngate_settings(config: dict | None = None) -> dict[str, Any]:
    """Return normalized persisted VPN Gate refresh settings."""

    if config is None:
        from core.database import load_config

        config = load_config()
    settings = config.get("settings", {}) if isinstance(config, dict) else {}
    raw = settings.get(VPNGATE_SOURCE_ID, {}) if isinstance(settings, dict) else {}
    if not isinstance(raw, dict):
        raw = {}

    interval = _safe_integer(raw.get("interval_minutes"), VPNGATE_DEFAULT_INTERVAL_MINUTES)
    interval = max(VPNGATE_MIN_INTERVAL_MINUTES, min(interval, VPNGATE_MAX_INTERVAL_MINUTES))
    max_nodes = _safe_integer(raw.get("max_nodes"), VPNGATE_DEFAULT_MAX_NODES)
    max_nodes = max(VPNGATE_MIN_MAX_NODES, min(max_nodes, VPNGATE_MAX_MAX_NODES))
    return {
        "enabled": bool(raw.get("enabled", False)),
        "interval_minutes": interval,
        "max_nodes": max_nodes,
        "countries": _normalize_country_codes(raw.get("countries")),
    }


def _get_cache_payload() -> dict[str, Any]:
    record = storage.read_cache_document_record(VPNGATE_CACHE_NAMESPACE, default=None)
    if not isinstance(record, dict):
        return {
            "nodes": [],
            "last_attempt_at": None,
            "last_success_at": None,
            "last_error": None,
        }
    payload = record.get("payload")
    if not isinstance(payload, dict):
        payload = {}
    nodes = payload.get("nodes")
    if not isinstance(nodes, list):
        nodes = []
    return {
        **payload,
        "nodes": [node for node in nodes if isinstance(node, dict)],
        "last_attempt_at": payload.get("last_attempt_at"),
        "last_success_at": payload.get("last_success_at"),
        "last_error": payload.get("last_error"),
    }


def _write_cache_payload(payload: dict[str, Any]) -> None:
    storage.write_cache_document(VPNGATE_CACHE_NAMESPACE, payload, expires_at=None)


def _get_directive(configuration: str, directive: str) -> str | None:
    pattern = rf"(?m)^\s*{re.escape(directive)}(?:\s+(?P<value>[^\r\n#;]+?))?\s*(?:[#;].*)?$"
    match = re.search(pattern, configuration)
    return match.group("value").strip() if match and match.group("value") else None


def _get_block(configuration: str, block_name: str) -> str | None:
    match = re.search(
        rf"(?is)<{re.escape(block_name)}>\s*(?P<value>.*?)\s*</{re.escape(block_name)}>",
        configuration,
    )
    return match.group("value").strip() if match else None


def parse_vpngate_csv(content: str) -> list[dict[str, str]]:
    """Parse the public VPN Gate CSV while ignoring comments and malformed rows."""

    lines = content.splitlines()
    header_line = next((line for line in lines if line.startswith("#HostName,")), None)
    if not header_line:
        raise VpnGateRefreshError("VPN Gate API 未返回预期的 CSV 表头")

    headers = next(csv.reader([header_line]))
    if headers:
        headers[0] = headers[0].lstrip("#")
    records: list[dict[str, str]] = []
    for line in lines:
        if not line or line.startswith("#") or line.startswith("*"):
            continue
        row = next(csv.reader([line]), [])
        if len(row) != len(headers):
            continue
        record = dict(zip(headers, row, strict=True))
        if not record.get("IP") or not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", record["IP"]):
            continue
        records.append(record)
    if not records:
        raise VpnGateRefreshError("VPN Gate API 未返回可用服务器记录")
    return records


def _stable_node_id(record: dict[str, str], server: str, port: int, proto: str) -> str:
    """Build an ID from the advertised endpoint, not rotating credentials."""

    identity = {
        "ip": record.get("IP", "").strip(),
        "host_name": record.get("HostName", "").strip(),
        "server": server,
        "port": port,
        "proto": proto,
    }
    digest = hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"vpngate_{digest}"


def _country_name(country_code: str) -> str:
    try:
        from services.name_transformer import NameTransformer

        return NameTransformer.ISO_TO_COUNTRY.get(country_code, country_code or "未知")
    except Exception:
        return country_code or "未知"


def _country_flag(country_code: str) -> str:
    """Return the ISO flag used by the frontend for a country pool."""

    try:
        from geoip_service import GeoIPService

        return GeoIPService.iso_to_flag(country_code) or "🏳️"
    except Exception:
        return "🏳️"


def _build_display_name(record: dict[str, str], country_code: str, server: str, port: int) -> str:
    host_name = str(record.get("HostName") or "").strip()
    base = host_name or f"{server}:{port}"
    return base[:200]


def parse_vpngate_record(record: dict[str, str]) -> dict[str, Any]:
    """Convert one VPN Gate API record into a Mihomo OpenVPN proxy."""

    encoded_configuration = str(record.get("OpenVPN_ConfigData_Base64") or "").strip()
    if not encoded_configuration:
        raise ValueError("缺少 OpenVPN 配置")
    try:
        configuration = base64.b64decode(encoded_configuration, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"OpenVPN 配置解码失败: {exc}") from exc

    remote = re.search(r"(?m)^\s*remote\s+(?P<host>\S+)\s+(?P<port>\d+)\b", configuration)
    ca = _get_block(configuration, "ca")
    cert = _get_block(configuration, "cert")
    key = _get_block(configuration, "key")
    if not remote or not ca or not cert or not key:
        raise ValueError("OpenVPN 配置缺少 remote、CA、客户端证书或客户端私钥")

    server = remote.group("host")
    port = int(remote.group("port"))
    proto_value = (_get_directive(configuration, "proto") or "").casefold()
    proto = "tcp" if proto_value in {"tcp", "tcp-client"} else "udp"
    cipher = (_get_directive(configuration, "cipher") or "").strip().upper()
    cipher = cipher if cipher in _ALLOWED_CIPHERS else None
    data_ciphers = []
    raw_data_ciphers = _get_directive(configuration, "data-ciphers")
    if raw_data_ciphers:
        data_ciphers = list(
            dict.fromkeys(
                item
                for item in re.split(r"[:,\s]+", raw_data_ciphers.upper())
                if item in _ALLOWED_CIPHERS
            )
        )
    auth = (_get_directive(configuration, "auth") or "").strip().upper()
    auth = auth if auth in _ALLOWED_AUTH else None
    comp_lzo = (_get_directive(configuration, "comp-lzo") or "").strip().lower()
    comp_lzo = comp_lzo if comp_lzo in _ALLOWED_COMP_LZO else None
    country_code = str(record.get("CountryShort") or "").strip().upper()
    node_id = _stable_node_id(record, server, port, proto)

    proxy: dict[str, Any] = {
        "id": node_id,
        "name": _build_display_name(record, country_code, server, port),
        "type": "openvpn",
        "server": server,
        "port": port,
        "proto": proto,
        "username": "vpn",
        "password": "vpn",
        "ca": ca,
        "cert": cert,
        "key": key,
        "dev": "tun",
        "remote-dns-resolve": True,
        "dns": ["1.1.1.1", "8.8.8.8"],
        "_vpngate_ip": str(record.get("IP") or "").strip(),
        "_vpngate_country": country_code,
        "_vpngate_country_name": _country_name(country_code),
        "region": {
            "country_code": country_code or "XX",
            "country": _country_name(country_code),
        },
        "_vpngate_official_ping_ms": _safe_integer(record.get("Ping")),
        "_vpngate_official_mbps": round(_safe_integer(record.get("Speed")) * 8 / 1_000_000, 1),
        "_vpngate_sessions": _safe_integer(record.get("NumVpnSessions")),
        "_vpngate_last_seen_at": int(time.time()),
    }
    tls_crypt = _get_block(configuration, "tls-crypt")
    if tls_crypt:
        proxy["tls-crypt"] = tls_crypt
    if cipher:
        proxy["cipher"] = cipher
    if data_ciphers:
        proxy["data-ciphers"] = data_ciphers
    if auth:
        proxy["auth"] = auth
    if comp_lzo:
        proxy["comp-lzo"] = comp_lzo
    return proxy


def _unique_display_names(nodes: list[dict[str, Any]]) -> None:
    counts: dict[str, int] = {}
    for node in nodes:
        base_name = str(node.get("name") or "VPN Gate")
        occurrence = counts.get(base_name, 0) + 1
        counts[base_name] = occurrence
        if occurrence > 1:
            node["name"] = f"{base_name} #{occurrence}"[:200]


def _download_vpngate_csv(timeout_seconds: float = VPNGATE_DEFAULT_TIMEOUT_SECONDS) -> str:
    request = urllib.request.Request(
        VPNGATE_API_URL,
        headers={"User-Agent": "clash-sub-merger/VPNGate", "Accept": "text/plain,*/*"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise VpnGateRefreshError(f"VPN Gate CSV 下载失败: {exc}") from exc


def _select_vpngate_records(records: list[dict[str, str]], settings: dict[str, Any]) -> list[dict[str, str]]:
    countries = set(settings.get("countries") or [])
    if countries:
        records = [record for record in records if str(record.get("CountryShort") or "").upper() in countries]
    records = sorted(
        records,
        key=lambda record: (
            _safe_integer(record.get("Ping"), 2**31 - 1) <= 0,
            _safe_integer(record.get("Ping"), 2**31 - 1),
            -_safe_integer(record.get("Speed")),
        ),
    )
    return records[: int(settings["max_nodes"])]


def _merge_nodes_with_previous_cache(
    fresh_nodes: list[dict[str, Any]],
    previous_nodes: list[dict[str, Any]],
    refreshed_at: int,
) -> list[dict[str, Any]]:
    fresh_by_id = {str(node.get("id")): node for node in fresh_nodes if node.get("id")}
    previous_by_id = {str(node.get("id")): node for node in previous_nodes if node.get("id")}
    merged: list[dict[str, Any]] = []
    for node_id, node in fresh_by_id.items():
        previous = previous_by_id.get(node_id, {})
        merged_node = dict(node)
        # A fresh VPN Gate record contains the advertised server country in
        # ``region``. Preserve measurements made through the node, especially
        # the tested exit region/IP profile, when the same stable node returns
        # in a later snapshot.
        for field in _NODE_TEST_METADATA_FIELDS:
            if field in previous:
                merged_node[field] = previous[field]
        merged_node["enabled"] = True
        merged_node["stale"] = False
        merged_node["_vpngate_last_seen_at"] = refreshed_at
        merged.append(merged_node)
    for node_id, previous in previous_by_id.items():
        if node_id in fresh_by_id:
            continue
        stale = dict(previous)
        stale["enabled"] = False
        stale["stale"] = True
        merged.append(stale)
    return merged


def refresh_vpngate_cache() -> dict[str, Any]:
    """Download and atomically replace the VPN Gate cache."""

    with _REFRESH_LOCK:
        started_at = int(time.time())
        previous = _get_cache_payload()
        attempt_payload = dict(previous)
        attempt_payload["last_attempt_at"] = started_at
        try:
            from core.database import load_config

            settings = get_vpngate_settings(load_config())
            csv_content = _download_vpngate_csv()
            records = _select_vpngate_records(parse_vpngate_csv(csv_content), settings)
            fresh_nodes: list[dict[str, Any]] = []
            for record in records:
                try:
                    fresh_nodes.append(parse_vpngate_record(record))
                except ValueError as exc:
                    logger.info("Skipping malformed VPN Gate profile: %s", exc)
            if not fresh_nodes:
                raise VpnGateRefreshError("VPN Gate 没有可用的 OpenVPN 配置")
            _unique_display_names(fresh_nodes)
            merged_nodes = _merge_nodes_with_previous_cache(
                fresh_nodes,
                previous.get("nodes", []),
                started_at,
            )
            payload = {
                "source_url": VPNGATE_API_URL,
                "nodes": merged_nodes,
                "last_attempt_at": started_at,
                "last_success_at": started_at,
                "last_error": None,
                "fresh_node_count": len(fresh_nodes),
                "active_node_count": len(fresh_nodes),
                "stale_node_count": sum(1 for node in merged_nodes if node.get("stale")),
            }
            _write_cache_payload(payload)
            return get_vpngate_status()
        except Exception as exc:
            attempt_payload["last_error"] = str(exc)
            _write_cache_payload(attempt_payload)
            if isinstance(exc, VpnGateRefreshError):
                raise
            raise VpnGateRefreshError(f"VPN Gate 刷新失败: {exc}") from exc


def run_scheduled_vpngate_refresh() -> None:
    """Run one scheduled refresh without allowing scheduler errors to escape."""

    try:
        refresh_vpngate_cache()
        logger.info("VPN Gate cache refreshed successfully")
    except Exception:
        logger.warning("Scheduled VPN Gate refresh failed", exc_info=True)


def list_vpngate_nodes(
    *,
    include_stale: bool = False,
    country_code: str | None = None,
) -> list[dict[str, Any]]:
    """List cached nodes, optionally restricted to one country."""

    normalized_country = normalize_vpngate_country_code(country_code)
    if country_code is not None and normalized_country is None:
        return []

    payload = _get_cache_payload()
    nodes = []
    for node in payload.get("nodes", []):
        if not isinstance(node, dict) or not node.get("id"):
            continue
        node_country = normalize_vpngate_country_code(node.get("_vpngate_country"))
        if normalized_country and node_country != normalized_country:
            continue
        if node.get("stale") and not include_stale:
            continue
        if node.get("enabled", True) is False and not include_stale:
            continue
        nodes.append(dict(node))
    return nodes


def get_vpngate_node(node_id: str, *, include_stale: bool = False) -> dict[str, Any] | None:
    normalized_id = str(node_id or "").strip()
    if not normalized_id:
        return None
    return next(
        (node for node in list_vpngate_nodes(include_stale=include_stale) if str(node.get("id")) == normalized_id),
        None,
    )


def update_vpngate_node_test_metadata(node_id: str, updates: dict[str, Any]) -> bool:
    """Persist test metadata for one cached VPN Gate node without exposing credentials."""

    normalized_id = str(node_id or "").strip()
    if not normalized_id or not isinstance(updates, dict):
        return False

    with _REFRESH_LOCK:
        payload = _get_cache_payload()
        for node in payload.get("nodes", []):
            if not isinstance(node, dict) or str(node.get("id") or "") != normalized_id:
                continue
            for field in _NODE_TEST_METADATA_FIELDS:
                if field not in updates:
                    continue
                value = updates[field]
                if field == "ip_profile" and isinstance(value, dict):
                    previous = node.get("ip_profile")
                    value = {
                        **(previous if isinstance(previous, dict) else {}),
                        **value,
                    }
                node[field] = value
            _write_cache_payload(payload)
            return True
    return False


def get_vpngate_status() -> dict[str, Any]:
    payload = _get_cache_payload()
    nodes = payload.get("nodes", [])
    active_count = sum(1 for node in nodes if isinstance(node, dict) and not node.get("stale") and node.get("enabled", True) is not False)
    stale_count = sum(1 for node in nodes if isinstance(node, dict) and node.get("stale"))
    last_success_at = payload.get("last_success_at")
    age_seconds = None
    if last_success_at:
        age_seconds = max(0, int(time.time()) - int(last_success_at))
    return {
        "source_id": VPNGATE_SOURCE_ID,
        "source_name": VPNGATE_SOURCE_NAME,
        "source_url": VPNGATE_API_URL,
        "last_attempt_at": payload.get("last_attempt_at"),
        "last_success_at": last_success_at,
        "last_error": payload.get("last_error"),
        "active_node_count": active_count,
        "stale_node_count": stale_count,
        "cache_age_seconds": age_seconds,
    }


def public_vpngate_node(node: dict[str, Any]) -> dict[str, Any]:
    """Return metadata safe for the frontend and reference pickers."""

    display_name = node.get("name", "VPN Gate")
    try:
        from services.name_transformer import NameTransformer

        display_name = NameTransformer.transform_name(node, VPNGATE_SOURCE_NAME).get(
            "name",
            display_name,
        )
    except Exception:
        pass

    region = node.get("region") if isinstance(node.get("region"), dict) else {}
    return {
        "id": node.get("id"),
        "name": display_name,
        "display_name": display_name,
        "sub_id": VPNGATE_SOURCE_ID,
        "source_name": VPNGATE_SOURCE_NAME,
        "node_id": node.get("id"),
        "node_index": None,
        "node_name": display_name,
        "node_type": "openvpn",
        "type": "openvpn",
        "server": node.get("server", ""),
        "port": node.get("port"),
        "enabled": node.get("enabled", True) is not False,
        "country_code": node.get("_vpngate_country", ""),
        "country": node.get("_vpngate_country_name", ""),
        "flag": region.get("flag") or _country_flag(str(node.get("_vpngate_country") or "")),
        "region": region or None,
        "city": node.get("city", ""),
        "last_latency": node.get("last_latency"),
        "last_latency_time": node.get("last_latency_time"),
        "last_speed": node.get("last_speed"),
        "last_speed_time": node.get("last_speed_time"),
        "last_peak_speed": node.get("last_peak_speed"),
        "last_peak_speed_time": node.get("last_peak_speed_time"),
        "exit_ip": node.get("exit_ip"),
        "ip_profile": node.get("ip_profile") if isinstance(node.get("ip_profile"), dict) else None,
        "official_ping_ms": node.get("_vpngate_official_ping_ms", 0),
        "official_mbps": node.get("_vpngate_official_mbps", 0),
        "sessions": node.get("_vpngate_sessions", 0),
        "stale": bool(node.get("stale")),
    }


def public_vpngate_pool() -> dict[str, Any]:
    """Return the aggregate VPN Gate pool metadata used by the UI."""

    status = get_vpngate_status()
    return {
        "sub_id": VPNGATE_SOURCE_ID,
        "source_name": VPNGATE_SOURCE_NAME,
        "pool_name": VPNGATE_POOL_NAME,
        "active_node_count": status["active_node_count"],
        "stale_node_count": status["stale_node_count"],
        "available": status["active_node_count"] > 0,
    }


def list_vpngate_pools() -> list[dict[str, Any]]:
    """Build one dynamic pool descriptor for every active VPN Gate country."""

    active_nodes = list_vpngate_nodes()
    stale_nodes = list_vpngate_nodes(include_stale=True)
    active_counts: dict[str, int] = {}
    stale_counts: dict[str, int] = {}

    for node in active_nodes:
        country_code = normalize_vpngate_country_code(node.get("_vpngate_country")) or VPNGATE_UNKNOWN_COUNTRY_CODE
        active_counts[country_code] = active_counts.get(country_code, 0) + 1
    for node in stale_nodes:
        if not node.get("stale"):
            continue
        country_code = normalize_vpngate_country_code(node.get("_vpngate_country")) or VPNGATE_UNKNOWN_COUNTRY_CODE
        stale_counts[country_code] = stale_counts.get(country_code, 0) + 1

    # Only countries with at least one current node are selectable.  A country
    # represented solely by stale cache entries must not appear as a usable
    # dynamic landing pool.
    country_codes = set(active_counts)
    pools = []
    for country_code in sorted(country_codes, key=lambda code: (-active_counts.get(code, 0), code)):
        country = _country_name(country_code)
        pools.append({
            "pool_id": f"vpngate_country_{country_code.lower()}",
            "pool_name": f"VPN Gate {country}池",
            "country_code": country_code,
            "country": country,
            "flag": _country_flag(country_code),
            "active_node_count": active_counts.get(country_code, 0),
            "stale_node_count": stale_counts.get(country_code, 0),
            "available": active_counts.get(country_code, 0) > 0,
        })
    return pools
