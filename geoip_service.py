"""
GeoIP Service Module
Provides IP geolocation functionality using online APIs.
"""

import os
import re
import time
import json
import ipaddress
import socket
import httpx
import httpcore
import asyncio
import threading
from copy import deepcopy
from typing import Optional, Dict
from urllib.parse import urlsplit
from core.config import env_int
from logger_config import get_logger
from translation_service import get_cached_translation, translate_location_fields

# Setup logger
logger = get_logger(__name__)

# Persistent cache configuration
GEOIP_CACHE_FILE = os.path.join(os.environ.get('DATA_DIR', 'data'), 'geoip_cache.json')
GEOIP_CACHE_TTL = 7 * 24 * 3600  # 7 days in seconds
# A temporary provider/network failure must not poison lookups for a week.
GEOIP_NEGATIVE_CACHE_TTL = 5 * 60
GEOIP_CACHE_VERSION = 1

# Traditional to Simplified Chinese converter
try:
    from opencc import OpenCC
    _t2s_converter = OpenCC('t2s')  # Traditional to Simplified
    def convert_to_simplified(text: str) -> str:
        """Convert Traditional Chinese to Simplified Chinese"""
        if not text:
            return text
        return _t2s_converter.convert(text)
except ImportError:
    def convert_to_simplified(text: str) -> str:
        """Fallback: return text as-is if opencc not available"""
        return text

# Online GeoIP lookup cache (to avoid repeated requests)
_online_geoip_cache: Dict[str, Dict] = {}
_online_geoip_inflight: Dict[str, asyncio.Task] = {}
_online_geoip_semaphore = asyncio.Semaphore(env_int('GEOIP_MAX_CONCURRENCY', 8, minimum=1))
_online_geoip_cache_lock = threading.RLock()
_online_geoip_inflight_lock = asyncio.Lock()
_online_geoip_save_lock = asyncio.Lock()


def _geoip_cache_ttl(entry: dict) -> int:
    """Return the TTL appropriate for a positive or negative cache entry."""
    return GEOIP_NEGATIVE_CACHE_TTL if entry.get('_negative') else GEOIP_CACHE_TTL

def load_geoip_cache_from_disk():
    """Load GeoIP cache from disk on startup"""
    global _online_geoip_cache
    try:
        if os.path.exists(GEOIP_CACHE_FILE):
            with open(GEOIP_CACHE_FILE, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)

            if not isinstance(cache_data, dict):
                raise ValueError("GeoIP cache root must be an object")

            if 'version' in cache_data or 'entries' in cache_data:
                if cache_data.get('version') != GEOIP_CACHE_VERSION:
                    logger.info(
                        "Ignoring GeoIP cache with unsupported version %s",
                        cache_data.get('version')
                    )
                    with _online_geoip_cache_lock:
                        _online_geoip_cache = {}
                    return
                entries = cache_data.get('entries', {})
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
                if 'timestamp' in entry:
                    age = current_time - entry['timestamp']
                    if age < _geoip_cache_ttl(entry):
                        valid_cache[key] = entry
                    else:
                        expired_count += 1
                else:
                    # Old format without timestamp, keep it
                    valid_cache[key] = entry
            
            with _online_geoip_cache_lock:
                _online_geoip_cache = valid_cache
            logger.info(f"Loaded {len(valid_cache)} GeoIP cache entries from disk ({expired_count} expired entries removed)")
    except Exception as e:
        logger.warning(f"Failed to load GeoIP cache from disk: {e}")
        with _online_geoip_cache_lock:
            _online_geoip_cache = {}

async def save_geoip_cache_to_disk():
    """Save GeoIP cache to disk with in-process serialization and atomic replace."""
    async with _online_geoip_save_lock:
        tmp_file = f"{GEOIP_CACHE_FILE}.{os.getpid()}.tmp"
        try:
            with _online_geoip_cache_lock:
                cache_snapshot = dict(_online_geoip_cache)

            os.makedirs(os.path.dirname(GEOIP_CACHE_FILE), exist_ok=True)
            with open(tmp_file, 'w', encoding='utf-8') as f:
                json.dump(
                    {
                        "version": GEOIP_CACHE_VERSION,
                        "entries": cache_snapshot,
                    },
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp_file, 0o600)
            except OSError:
                logger.warning("Could not restrict GeoIP cache file permissions")
            os.replace(tmp_file, GEOIP_CACHE_FILE)
            logger.debug(f"Saved {len(cache_snapshot)} GeoIP cache entries to disk")
        except Exception as exc:
            logger.error("Failed to save GeoIP cache to disk: %s", type(exc).__name__)
        finally:
            if os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except OSError:
                    logger.debug("Failed to remove GeoIP cache temp file")

# Load cache on module import
load_geoip_cache_from_disk()

# Built-in API definitions
BUILTIN_GEOIP_APIS = [
    {
        "id": "ip-api.com",
        "name": "ip-api.com",
        "limit": "45次/分钟",
        "description": "免费，支持中文，推荐",
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "ipwhois",
        "name": "ipwhois.app",
        "limit": "10,000次/月",
        "description": "免费，支持中文",
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "ipinfo",
        "name": "ipinfo.io",
        "limit": "50,000次/月",
        "description": "免费额度较高",
        "builtin": True,
        "enabled": True,
        "needs_token": True,
    },
]

# Online API configuration
_online_geoip_config: Dict = {
    "ipinfo_token": "",
    "preferred_api": "ip-api.com",
    "custom_apis": [],  # User-defined custom APIs
    "api_settings": {},  # Per-API settings like enabled/disabled
}


def apply_geoip_runtime_config(config: Dict) -> Dict:
    """Replace runtime GeoIP state from one complete persisted config snapshot."""
    global _online_geoip_config
    persisted = config.get("geoip_config", {}) if isinstance(config, dict) else {}
    if not isinstance(persisted, dict):
        persisted = {}
    _online_geoip_config = {
        "ipinfo_token": str(persisted.get("ipinfo_token") or ""),
        "preferred_api": str(persisted.get("preferred_api") or "ip-api.com"),
        "custom_apis": deepcopy(persisted.get("custom_apis") or []),
        "api_settings": deepcopy(persisted.get("api_settings") or {}),
    }
    from services.cloudflare_radar import apply_cloudflare_radar_runtime_config
    from translation_service import apply_translation_runtime_config

    apply_cloudflare_radar_runtime_config(config)
    apply_translation_runtime_config(config)
    return deepcopy(_online_geoip_config)

def get_all_geoip_apis() -> list:
    """Get all available GeoIP APIs (builtin + custom)"""
    apis = []
    api_settings = _online_geoip_config.get("api_settings", {})
    
    # Add builtin APIs
    for api in BUILTIN_GEOIP_APIS:
        api_copy = api.copy()
        # Apply user settings
        if api["id"] in api_settings:
            api_copy.update(api_settings[api["id"]])
        apis.append(api_copy)
    
    # Add custom APIs
    for api in _online_geoip_config.get("custom_apis", []):
        api_copy = api.copy()
        api_copy["builtin"] = False
        # Mask token for security - only indicate if it exists
        if api_copy.get("token"):
            api_copy["has_token"] = True
            api_copy["token"] = ""  # Don't expose actual token
        apis.append(api_copy)
    
    return apis

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
    'CUSTOM_GEOIP_MAX_RESPONSE_BYTES',
    1024 * 1024,
    minimum=1024,
    maximum=10 * 1024 * 1024,
)
_PUBLIC_CUSTOM_URL_RESOLUTIONS: dict[str, tuple[str, list[str]]] = {}


async def _resolve_public_custom_api_url(url: str) -> tuple[str, list[str]] | None:
    """Resolve and pin a custom API hostname, rejecting local networks."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {'http', 'https'} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        port = parsed.port or (443 if parsed.scheme.lower() == 'https' else 80)
        host = parsed.hostname
        if host.lower() == 'localhost':
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
            addresses = {
                ipaddress.ip_address(item[4][0].split('%', 1)[0])
                for item in address_info
            }
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
    content_length = response.headers.get('content-length')
    if content_length:
        try:
            if int(content_length) > CUSTOM_GEOIP_MAX_RESPONSE_BYTES:
                return None
        except ValueError:
            return None
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > CUSTOM_GEOIP_MAX_RESPONSE_BYTES:
            return None
    try:
        decoded = json.loads(body.decode(response.encoding or 'utf-8'))
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
        if not await _is_public_custom_api_url(url):
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
        
        if method not in {'GET', 'POST'}:
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
        "countryCode", "country_code", "country_code2", "countrycode", "cc", 
        "country_iso", "iso_code", "iso", "code", "country_code3"
    ]
    
    # Common field names for country name
    country_name_fields = [
        "country", "country_name", "countryName", "nation"
    ]
    
    # Common field names for city
    city_fields = [
        "city", "cityName", "city_name"
    ]

    # Common field names for state/province/region
    region_fields = [
        "region", "regionName", "region_name", "state", "state_prov", "stateProv"
    ]
    
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
            if isinstance(value, dict) and key not in ['currency', 'time_zone', 'dst_start', 'dst_end']:
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


def _coerce_optional_bool(value) -> Optional[bool]:
    """Normalize provider boolean variants without turning missing into false."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value).strip().lower()
    if normalized in {"true", "yes", "y", "1", "on"}:
        return True
    if normalized in {"false", "no", "n", "0", "off"}:
        return False
    return None


def _coerce_optional_number(value):
    """Normalize numeric risk fields while preserving unavailable values."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return int(parsed) if parsed.is_integer() else parsed


def _normalize_asn_value(value) -> Optional[str]:
    """Extract a stable AS number from provider-specific values."""
    if isinstance(value, dict):
        value = (
            value.get("asn")
            or value.get("as_number")
            or value.get("number")
            or value.get("name")
        )
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    match = re.search(r"\bAS\s*\d+\b", text, flags=re.IGNORECASE)
    return match.group(0).replace(" ", "").upper() if match else text


def _strip_asn_prefix(value: Optional[str]) -> Optional[str]:
    """Remove a leading AS number from an organization string."""
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    return re.sub(r"^AS\s*\d+\s*[-:]?\s*", "", text, flags=re.IGNORECASE) or text


def _extract_provider_metadata(data: dict) -> Dict:
    """Extract stable ASN/network fields shared by GeoIP providers."""
    if not isinstance(data, dict):
        return {}

    raw_asn = _first_json_value(data, (
        "asn.as_number", "asn.number", "asn", "as", "asn_number", "network.asn",
    ))
    raw_org = _first_json_value(data, (
        "asn.organization", "asn.org", "asname", "org", "organization",
        "company.name", "company.organization", "network.organization",
    ))
    raw_isp = _first_json_value(data, (
        "isp", "company.name", "organization", "org",
    ))

    asn = _normalize_asn_value(raw_asn)
    if not asn and raw_org is not None:
        asn = _normalize_asn_value(raw_org)
    metadata = {
        "asn": asn,
        "asn_org": _strip_asn_prefix(str(raw_org)) if raw_org is not None else None,
        "isp": str(raw_isp).strip() if raw_isp not in (None, "") else None,
        "is_hosting": _coerce_optional_bool(_first_json_value(data, (
            "hosting", "is_hosting", "isHosting", "is_datacenter", "isDataCenter",
            "security.is_cloud_provider", "security.isCloudProvider",
        ))),
        "is_mobile": _coerce_optional_bool(_first_json_value(data, (
            "mobile", "is_mobile", "isMobile", "network.is_mobile",
        ))),
        "is_proxy": _coerce_optional_bool(_first_json_value(data, (
            "proxy", "is_proxy", "isProxy", "security.is_proxy", "security.isProxy",
        ))),
        "is_vpn": _coerce_optional_bool(_first_json_value(data, (
            "vpn", "is_vpn", "isVpn", "security.is_vpn", "security.isVpn",
        ))),
        "is_tor": _coerce_optional_bool(_first_json_value(data, (
            "tor", "is_tor", "isTor", "security.is_tor", "security.isTor",
        ))),
        "fraud_score": _coerce_optional_number(_first_json_value(data, (
            "fraudScore", "fraud_score", "security.fraud_score", "security.threat_score",
        ))),
    }

    # Remove empty values so a failed/partial provider cannot overwrite a
    # successful value from another provider or an older cached result.
    return {key: value for key, value in metadata.items() if value is not None}


def _build_provider_result(
    data: dict,
    country_code: str,
    country: str,
    city: str,
    region: str = "",
) -> Dict:
    """Build the normalized provider payload consumed by the online lookup."""
    return {
        "countryCode": country_code or "",
        "country": country or "",
        "region": region or "",
        "city": city or "",
        **_extract_provider_metadata(data),
    }


def normalize_ippure_profile(data: dict, exit_ip: Optional[str] = None) -> Optional[Dict]:
    """Normalize the small IPPure response used by node IP intelligence."""
    if not isinstance(data, dict):
        return None

    is_broadcast = _coerce_optional_bool(
        data.get("isBroadcast", data.get("is_broadcast"))
    )
    is_residential = _coerce_optional_bool(
        data.get("isResidential", data.get("is_residential"))
    )
    fraud_score = _coerce_optional_number(
        data.get("fraudScore", data.get("fraud_score"))
    )
    response_ip = str(data.get("ip") or exit_ip or "").strip()

    if not response_ip and is_broadcast is None and is_residential is None and fraud_score is None:
        return None

    profile = {
        "ip": response_ip or None,
        "is_broadcast": is_broadcast,
        "is_residential": is_residential,
        "fraud_score": fraud_score,
        "source": "ippure",
        "checked_at": time.time(),
    }
    if is_broadcast is not None:
        profile["ip_source"] = "broadcast" if is_broadcast else "native"
    if is_residential is not None:
        profile["network_type"] = "residential" if is_residential else "datacenter"
    return {key: value for key, value in profile.items() if value is not None}


async def _lookup_ip_api_com(ip: str, timeout: int = 5) -> Optional[Dict]:
    """Lookup location and network metadata using ip-api.com."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "http://ip-api.com/json/"
                f"{ip}?lang=zh-CN&fields=status,message,query,country,countryCode,"
                "regionName,city,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting",
                timeout=timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return _build_provider_result(
                        data,
                        data.get("countryCode", ""),
                        data.get("country", ""),
                        data.get("city", ""),
                        data.get("regionName", ""),
                    )
    except Exception as e:
        logger.debug("ip-api.com lookup error for %s: %s", ip, type(e).__name__)
    return None

async def _lookup_ipwhois(ip: str, timeout: int = 5) -> Optional[Dict]:
    """Lookup location and ASN metadata using ipwhois.app."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://ipwhois.app/json/{ip}?lang=zh-CN",
                timeout=timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    country_name = data.get("country", "")
                    return _build_provider_result(
                        data,
                        data.get("country_code", ""),
                        country_name,
                        data.get("city", ""),
                        data.get("region", ""),
                    )
    except Exception as e:
        logger.debug("ipwhois.app lookup error for %s: %s", ip, type(e).__name__)
    return None

async def _lookup_ipinfo(ip: str, timeout: int = 5, token: Optional[str] = None) -> Optional[Dict]:
    """Lookup location and network metadata using ipinfo.io."""
    try:
        if token is None:
            token = _online_geoip_config.get("ipinfo_token", "")
        url = f"https://ipinfo.io/{ip}/json"
        if token:
            url += f"?token={token}"
        
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                country_code = data.get("country", "")
                city = data.get("city", "")
                
                # ipinfo returns the ISO code as the country field.  The
                # translation layer resolves it before display.
                country_name = country_code

                # Older IPinfo responses put the AS number and organization in
                # ``org`` (for example ``AS15169 Google LLC``); newer plans may
                # expose a nested ``asn`` object.  The common extractor handles
                # both shapes without storing the token or raw response.
                return _build_provider_result(
                    data,
                    country_code,
                    country_name,
                    city,
                    data.get("region", ""),
                )
    except Exception as e:
        logger.debug("ipinfo.io lookup error for %s: %s", ip, type(e).__name__)
    return None

def normalize_country_name(country_name: str, iso_code: str = "") -> str:
    """Normalize provider output without applying a hard-coded name map."""
    source_text = str(country_name or "").strip()
    text = convert_to_simplified(get_cached_translation(source_text, "country") or source_text)
    return text or (iso_code or "").upper()


def _normalize_geo_result_fields(iso_code: str, country_name: str, city_name: str) -> Dict[str, Optional[str]]:
    """Apply unified country and city normalization to GeoIP results."""
    code = (iso_code or "").upper()
    display_country = normalize_country_name(country_name, code)
    translated_city = convert_to_simplified(str(city_name or "").strip())

    if translated_city and translated_city in display_country:
        translated_city = None

    return {
        "iso_code": code,
        "country_name": display_country,
        "city": translated_city or None,
        "flag": GeoIPService.iso_to_flag(code),
    }


def _normalize_cached_geo_entry(entry: Dict) -> Dict:
    """Normalize cached translated values without making network requests."""
    normalized = dict(entry)
    normalized.update(_normalize_geo_result_fields(
        entry.get("iso_code", ""),
        entry.get("country_name") or entry.get("country", ""),
        entry.get("city", "")
    ))
    return normalized

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
    global _online_geoip_cache, _online_geoip_inflight

    requested_api_id = api_id or _online_geoip_config.get("preferred_api", "ip-api.com")
    # The effective requested API is part of the key. A generic ``default``
    # key would keep returning results from the previous preferred provider
    # after an operator changes the setting.
    cache_key = f"{ip}|{requested_api_id}"

    def _get_valid_cache_entry():
        with _online_geoip_cache_lock:
            entry = _online_geoip_cache.get(cache_key)
            if not isinstance(entry, dict):
                return False, None

            ts = entry.get('timestamp')
            if ts and (time.time() - ts) < _geoip_cache_ttl(entry):
                if entry.get('_negative'):
                    return True, None
                normalized_entry = _normalize_cached_geo_entry(entry)
                if normalized_entry != entry:
                    _online_geoip_cache[cache_key] = normalized_entry
                return True, normalized_entry

            _online_geoip_cache.pop(cache_key, None)
            return False, None

    # Fast path before taking the lock.
    cache_hit, cached_result = _get_valid_cache_entry()
    if cache_hit:
        return cached_result

    async def _do_lookup():
        target_api = requested_api_id

        builtin_api_map = {
            "ip-api.com": _lookup_ip_api_com,
            "ipwhois": _lookup_ipwhois,
            "ipinfo": _lookup_ipinfo,
        }

        raw_data = None
        selected_api_id = None

        async with _online_geoip_semaphore:
            api_settings = _online_geoip_config.get("api_settings", {})
            custom_apis = {
                api.get("id"): api
                for api in _online_geoip_config.get("custom_apis", [])
                if isinstance(api, dict) and api.get("id")
            }

            async def query_api(candidate_id: str):
                if candidate_id in builtin_api_map:
                    if not api_settings.get(candidate_id, {}).get("enabled", True):
                        return None
                    return await builtin_api_map[candidate_id](ip, timeout)
                custom_api = custom_apis.get(candidate_id)
                if custom_api and custom_api.get("enabled", True):
                    return await _lookup_custom_api(ip, custom_api, timeout)
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
            "timestamp": time.time()
        }

    async with _online_geoip_inflight_lock:
        # Double-check under the lock so cache expiry and task creation are atomic.
        cache_hit, cached_result = _get_valid_cache_entry()
        if cache_hit:
            return cached_result

        task = _online_geoip_inflight.get(cache_key)
        if task is None:
            task = asyncio.create_task(_do_lookup())
            _online_geoip_inflight[cache_key] = task

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
        if task.done():
            async with _online_geoip_inflight_lock:
                if _online_geoip_inflight.get(cache_key) is task:
                    _online_geoip_inflight.pop(cache_key, None)

    with _online_geoip_cache_lock:
        new_entry = result or {"timestamp": time.time(), "_negative": True}
        previous_entry = _online_geoip_cache.get(cache_key)
        cache_changed = previous_entry != new_entry
        _online_geoip_cache[cache_key] = new_entry

    # Persist every changed entry, including negative results and updates to an
    # existing key. A modulo-based trigger loses the final 1-9 writes on
    # shutdown and made the disk cache diverge from memory.
    if cache_changed:
        await save_geoip_cache_to_disk()

    return result

def get_online_geoip_cache_snapshot() -> Dict[str, Dict]:
    """Return a shallow snapshot of the online GeoIP cache for safe iteration."""
    with _online_geoip_cache_lock:
        return dict(_online_geoip_cache)


def get_online_geoip_cache_stats() -> dict:
    """Return positive/negative cache counts without exposing the live dict."""
    snapshot = get_online_geoip_cache_snapshot()
    positive = 0
    negative = 0
    for entry in snapshot.values():
        if isinstance(entry, dict) and entry.get('_negative'):
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
    global _online_geoip_cache, _online_geoip_inflight
    with _online_geoip_cache_lock:
        _online_geoip_cache = {}
    async with _online_geoip_inflight_lock:
        for task in _online_geoip_inflight.values():
            if not task.done():
                task.cancel()
        _online_geoip_inflight = {}
    try:
        if os.path.exists(GEOIP_CACHE_FILE):
            os.remove(GEOIP_CACHE_FILE)
        logger.info("GeoIP cache cleared")
    except Exception as e:
        logger.error(f"Failed to clear GeoIP cache file: {e}")

def translate_city_name(city_name: str) -> str:
    """Normalize a saved city value without making a network request."""
    source_text = str(city_name or "").strip()
    return convert_to_simplified(get_cached_translation(source_text, "city") or source_text)

def format_location_display(country_code: str, country_name: str, city_name: str) -> str:
    """
    Format location for display, avoiding duplicates like "香港 香港"
    Returns: "国家/地区 城市" or just "国家/地区" if city is same as country or empty
    """
    display_country = normalize_country_name(country_name, country_code)
    
    if not city_name:
        return display_country
    
    # Translate city name
    translated_city = translate_city_name(city_name)
    
    # Avoid duplicates: if city name is same as country/region name, just show country
    # e.g., "Hong Kong" city in "Hong Kong" -> just "China Hong Kong"
    # e.g., "Singapore" city in "Singapore" -> just "Singapore"
    if translated_city == country_name or translated_city in display_country:
        return display_country
    
    return f"{display_country} {translated_city}"


class GeoIPService:
    """Static utility class for GeoIP-related functions (flag conversion, etc.)"""
    
    @staticmethod
    def iso_to_flag(iso_code: str) -> str:
        """
        Convert ISO 3166-1 alpha-2 country code to flag emoji
        Example: "US" -> "🇺🇸", "CN" -> "🇨🇳"
        
        Uses Unicode Regional Indicator Symbols:
        - 'A' (U+0041) maps to 🇦 (U+1F1E6)
        - 'Z' (U+005A) maps to 🇿 (U+1F1FF)
        """
        if not iso_code or len(iso_code) != 2:
            return "🌐"
        
        try:
            # Convert each letter to regional indicator symbol
            # Regional indicators start at U+1F1E6 for 'A'
            flag = ""
            for char in iso_code.upper():
                if 'A' <= char <= 'Z':
                    # Calculate offset from 'A' and add to base regional indicator
                    flag += chr(0x1F1E6 + ord(char) - ord('A'))
                else:
                    return "🌐"
            return flag
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid ISO code for flag conversion: {iso_code}, error: {e}")
            return "🌐"
        except Exception as e:
            logger.error(f"Error converting ISO to flag: {e}")
            return "🌐"
    
    @staticmethod
    def flag_to_iso(flag: str) -> Optional[str]:
        """
        Convert flag emoji back to ISO country code
        Example: "🇺🇸" -> "US"
        """
        if not flag or len(flag) < 1:
            return None
        
        try:
            # Each flag emoji is 2 regional indicator symbols
            # Regional indicator 🇦 (U+1F1E6) to 🇿 (U+1F1FF)
            iso = ""
            for char in flag:
                cp = ord(char)
                if 0x1F1E6 <= cp <= 0x1F1FF:
                    iso += chr(ord('A') + cp - 0x1F1E6)
            
            if len(iso) == 2:
                return iso
            return None
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid flag emoji for ISO conversion: {flag}, error: {e}")
            return None
        except Exception as e:
            logger.error(f"Error converting flag to ISO: {e}")
            return None
