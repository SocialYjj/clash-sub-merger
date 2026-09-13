"""
User-defined custom GeoIP API lookups.

Includes the SSRF guard (public-address resolution plus a pinned network
backend), the response size limiter and the JSON path auto-detection used to
map arbitrary provider payloads onto the common GeoIP result shape.
"""

import asyncio
import ipaddress
import json
import socket
from typing import Dict, Optional
from urllib.parse import urlsplit

import httpcore
import httpx

import geoip_service as _PKG
from core.config import env_int
from logger_config import get_logger

from .normalize import _build_provider_result

# Setup logger
logger = get_logger(__name__)


def _get_json_path(data: dict, path: str):
    """Get value from nested dict using dot notation path"""
    if not path:
        return None

    keys = path.split(".")
    value = data
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value


CUSTOM_GEOIP_MAX_RESPONSE_BYTES = env_int(
    "CUSTOM_GEOIP_MAX_RESPONSE_BYTES",
    1024 * 1024,
    minimum=1024,
    maximum=10 * 1024 * 1024,
)
_PUBLIC_CUSTOM_URL_RESOLUTIONS: dict[str, tuple[str, list[str]]] = {}


async def _resolve_public_custom_api_url(url: str) -> tuple[str, list[str]] | None:
    """Resolve and pin a custom API hostname, rejecting local networks."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        host = parsed.hostname
        if host.lower() == "localhost":
            return None
        try:
            addresses = {ipaddress.ip_address(host)}
        except ValueError:
            address_info = await asyncio.to_thread(
                socket.getaddrinfo,
                host,
                port,
                type=socket.SOCK_STREAM,
            )
            addresses = {ipaddress.ip_address(item[4][0].split("%", 1)[0]) for item in address_info}
        if not addresses or not all(address.is_global for address in addresses):
            return None
        return host.lower(), sorted(str(address) for address in addresses)
    except (OSError, ValueError, TypeError):
        return None


async def _is_public_custom_api_url(url: str) -> bool:
    """Compatibility wrapper that also retains the validated resolution."""
    resolved = await _resolve_public_custom_api_url(url)
    if resolved is None:
        return False
    _PUBLIC_CUSTOM_URL_RESOLUTIONS[url] = resolved
    return True


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect to the address validated before the HTTP request.

    The original hostname is still passed to httpcore for HTTP Host and TLS
    SNI, while the TCP dial uses the already-validated public address. This
    closes the DNS-rebinding gap between validation and connection.
    """

    def __init__(self, pinned_addresses: dict[str, str]):
        self._pinned_addresses = pinned_addresses
        self._delegate = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        target = self._pinned_addresses.get(str(host).lower(), host)
        return await self._delegate.connect_tcp(target, port, timeout, local_address, socket_options)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        return await self._delegate.connect_unix_socket(path, timeout, socket_options)

    async def sleep(self, seconds=0):
        return await self._delegate.sleep(seconds)


class _PinnedHTTPTransport(httpx.AsyncHTTPTransport):
    def __init__(self, pinned_addresses: dict[str, str], timeout: int):
        super().__init__(trust_env=False, retries=0)
        # httpx does not expose a public resolver hook. Replacing the network
        # backend keeps the supported HTTPX transport and TLS verification while
        # avoiding a second DNS lookup during connect.
        self._pool._network_backend = _PinnedNetworkBackend(pinned_addresses)


async def _read_limited_json_response(response: httpx.Response) -> dict | None:
    content_length = response.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > _PKG.CUSTOM_GEOIP_MAX_RESPONSE_BYTES:
                return None
        except ValueError:
            return None
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > _PKG.CUSTOM_GEOIP_MAX_RESPONSE_BYTES:
            return None
    try:
        decoded = json.loads(body.decode(response.encoding or "utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


async def _lookup_custom_api(ip: str, api_config: dict, timeout: int = 5) -> Optional[Dict]:
    """Lookup using a custom API configuration"""
    try:
        url = api_config["url"].replace("{ip}", ip)
        # Replace {key} or {token} placeholder if present
        token = api_config.get("token", "")
        if token:
            url = url.replace("{key}", token).replace("{token}", token)
        else:
            # Remove empty placeholders
            url = url.replace("{key}", "").replace("{token}", "")
        if not await _PKG._is_public_custom_api_url(url):
            logger.warning("Rejected custom GeoIP request to a non-public destination")
            return None
        resolved = _PUBLIC_CUSTOM_URL_RESOLUTIONS.pop(url, None)
        if resolved is None:
            # A caller may provide a trusted resolver wrapper. In normal
            # operation _is_public_custom_api_url always populates the cache;
            # retain the hostname only for that explicit integration path.
            parsed_url = urlsplit(url)
            if not parsed_url.hostname:
                return None
            resolved = (parsed_url.hostname.lower(), [parsed_url.hostname])
        hostname, addresses = resolved

        method = api_config.get("method", "GET").upper()
        headers = api_config.get("headers", {})

        if method not in {"GET", "POST"}:
            return None
        transport = _PinnedHTTPTransport({hostname: addresses[0]}, timeout)
        async with httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout),
            trust_env=False,
        ) as client:
            async with client.stream(method, url, headers=headers) as resp:
                if resp.status_code != 200:
                    return None
                data = await _read_limited_json_response(resp)
                if data is None:
                    return None

            # Check success condition if specified
            success_check = api_config.get("success_check", "")
            if success_check:
                # Simple check: "field==value" or just "field" (truthy check)
                if "==" in success_check:
                    field, expected = success_check.split("==", 1)
                    actual = _get_json_path(data, field.strip())
                    if str(actual) != expected.strip():
                        return None
                else:
                    if not _get_json_path(data, success_check):
                        return None

            # Get field paths, auto-detect if not specified
            country_code_path = api_config.get("country_code_path", "")
            country_name_path = api_config.get("country_name_path", "")
            region_path = api_config.get("region_path", "")
            city_path = api_config.get("city_path", "")

            # Auto-detect paths if not specified
            detected = _auto_detect_json_paths(data)
            if detected:
                if not country_code_path:
                    country_code_path = detected.get("country_code_path", "")
                if not country_name_path:
                    country_name_path = detected.get("country_name_path", "")
                if not region_path:
                    region_path = detected.get("region_path", "")
                if not city_path:
                    city_path = detected.get("city_path", "")

            country_code = _get_json_path(data, country_code_path) or "" if country_code_path else ""
            country_name = _get_json_path(data, country_name_path) or "" if country_name_path else ""
            region = _get_json_path(data, region_path) or "" if region_path else ""
            city = _get_json_path(data, city_path) or "" if city_path else ""

            if not country_code and not country_name:
                return None

            return _build_provider_result(
                data,
                country_code,
                country_name or country_code,
                city,
                region,
            )
    except Exception as exc:
        # The URL may contain a substituted token, so never log the exception
        # text produced by the HTTP client.
        logger.debug("Custom API lookup error for %s: %s", ip, type(exc).__name__)
        return None


def _auto_detect_json_paths(data: dict) -> Optional[Dict]:
    """Auto-detect common JSON field paths for GeoIP data"""
    if not isinstance(data, dict):
        return None

    result = {}

    # Common field names for country code (2-letter ISO code)
    country_code_fields = [
        "countryCode",
        "country_code",
        "country_code2",
        "countrycode",
        "cc",
        "country_iso",
        "iso_code",
        "iso",
        "code",
        "country_code3",
    ]

    # Common field names for country name
    country_name_fields = ["country", "country_name", "countryName", "nation"]

    # Common field names for city
    city_fields = ["city", "cityName", "city_name"]

    # Common field names for state/province/region
    region_fields = ["region", "regionName", "region_name", "state", "state_prov", "stateProv"]

    def find_field(fields, data, prefix="", check_2letter=False):
        """Recursively search for field in data"""
        for field in fields:
            if field in data:
                value = data[field]
                # Country code should be 2 or 3 letter string
                if check_2letter:
                    if isinstance(value, str) and 2 <= len(value) <= 3 and value.isupper():
                        return prefix + field if prefix else field
                else:
                    if isinstance(value, str) and value:
                        return prefix + field if prefix else field

        # Check nested objects (skip complex nested like currency, time_zone)
        for key, value in data.items():
            if isinstance(value, dict) and key not in ["currency", "time_zone", "dst_start", "dst_end"]:
                new_prefix = f"{prefix}{key}." if prefix else f"{key}."
                found = find_field(fields, value, new_prefix, check_2letter)
                if found:
                    return found
        return None

    # Find country code (check for 2-3 letter codes)
    code_path = find_field(country_code_fields, data, check_2letter=True)
    if code_path:
        result["country_code_path"] = code_path

    # Find country name
    name_path = find_field(country_name_fields, data)
    if name_path:
        result["country_name_path"] = name_path

    # Find city
    city_path = find_field(city_fields, data)
    if city_path:
        result["city_path"] = city_path

    # Find state/province/region
    region_path = find_field(region_fields, data)
    if region_path:
        result["region_path"] = region_path

    return result if result else None


def _first_json_value(data: dict, paths: tuple[str, ...]):
    """Return the first non-empty value from a list of common JSON paths."""
    if not isinstance(data, dict):
        return None
    for path in paths:
        value = _get_json_path(data, path)
        if value is None or value == "":
            continue
        return value
    return None
