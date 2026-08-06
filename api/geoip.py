"""
GeoIP API
GeoIP lookup endpoints
"""
import secrets
import ipaddress
import csv
import io
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from core.config import AppConfig
from core.database import load_config, update_config
from core.dependencies import verify_session
from core.rate_limit import limiter
from helpers import handle_api_errors
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()


# ==================== Data Models ====================

class GeoIPLookupRequest(BaseModel):
    ip: str = Field(min_length=1, max_length=45)

    @field_validator('ip')
    @classmethod
    def validate_ip(cls, value):
        return _normalize_ip_address(value)


class BatchGeoIPRequest(BaseModel):
    ips: list[str] = Field(min_length=1, max_length=100)

    @field_validator('ips')
    @classmethod
    def validate_ips(cls, values):
        return [_normalize_ip_address(value) for value in values]


def _normalize_ip_address(value: str) -> str:
    import ipaddress

    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise ValueError('Invalid IP address') from exc


# ==================== API Endpoints ====================

@router.post("/lookup")
@limiter.limit(AppConfig.RATE_LIMIT_GEOIP)
@handle_api_errors
async def lookup_ip_post(data: GeoIPLookupRequest, request: Request, _: bool = Depends(verify_session)):
    """Lookup GeoIP info for an IP address (POST)"""
    return await _do_lookup(data.ip)


@router.get("/lookup/{ip:path}")
@limiter.limit(AppConfig.RATE_LIMIT_GEOIP)
@handle_api_errors
async def lookup_ip_get(ip: str, request: Request, _: bool = Depends(verify_session)):
    """Lookup GeoIP info for an IP address (GET)"""
    from urllib.parse import unquote
    ip = unquote(ip)  # Handle URL-encoded IPv6
    return await _do_lookup(ip)


async def _do_lookup(ip: str):
    """Internal lookup function"""
    from geoip_service import lookup_ip_online

    try:
        ip = _normalize_ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IP address") from exc
    
    # Use online lookup
    try:
        result = await lookup_ip_online(ip)
        if result:
            return {"ip": ip, "result": result, "source": "online"}
    except Exception as exc:
        logger.warning("Online GeoIP lookup failed: %s", type(exc).__name__)
    
    return {"ip": ip, "result": None, "source": None}


@router.post("/batch")
@limiter.limit(AppConfig.RATE_LIMIT_GEOIP)
@handle_api_errors
async def batch_lookup_ips(data: BatchGeoIPRequest, request: Request, _: bool = Depends(verify_session)):
    """Batch lookup GeoIP info for multiple IPs"""
    from geoip_service import lookup_ip_online
    import asyncio
    
    results = {}
    ips = data.ips
    tasks = [asyncio.create_task(lookup_ip_online(ip)) for ip in ips]
    try:
        task_results = await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Batch GeoIP lookup cancelled; cancelled %d pending task(s)", len(tasks))
        raise
    for ip, res in zip(ips, task_results):
        if isinstance(res, BaseException):
            results[ip] = None
        else:
            results[ip] = res
    
    return {"results": results, "count": len(results)}


@router.get("/cache/stats")
@handle_api_errors
def get_geoip_cache_stats(_: bool = Depends(verify_session)):
    """Get GeoIP cache statistics"""
    from geoip_service import get_online_geoip_cache_stats

    stats = get_online_geoip_cache_stats()
    return {
        **stats,
        "database_available": False  # No local database
    }


@router.post("/cache/clear")
@handle_api_errors
async def clear_geoip_cache(_: bool = Depends(verify_session)):
    """Clear GeoIP cache"""
    from geoip_service import clear_online_geoip_cache

    await clear_online_geoip_cache()
    
    return {"status": "success", "message": "GeoIP cache cleared"}


def _filter_geoip_entries(entries, q=None, api_id=None, status=None, max_age=None):
    result = []
    q_lower = q.lower() if q else None
    for entry in entries:
        if api_id and api_id != 'all' and entry.get('api_id') != api_id:
            continue
        if status == 'positive' and entry.get('negative'):
            continue
        if status == 'negative' and not entry.get('negative'):
            continue
        if max_age is not None and entry.get('age') is not None and entry.get('age') > max_age:
            continue
        if q_lower:
            hay = ' '.join([
                entry.get('ip', ''),
                entry.get('country', '') or '',
                entry.get('city', '') or '',
                entry.get('iso_code', '') or '',
                entry.get('api_id', '') or ''
            ]).lower()
            if q_lower not in hay:
                continue
        result.append(entry)
    return result


def _build_geoip_entries():
    import time as _time
    from geoip_service import get_online_geoip_cache_snapshot

    entries = []
    now = _time.time()
    for key, entry in get_online_geoip_cache_snapshot().items():
        if not isinstance(entry, dict):
            continue
        if '|' in key:
            ip, api_id = key.rsplit('|', 1)
        elif ':' in key:
            ip, api_id = key.rsplit(':', 1)
        else:
            ip, api_id = key, 'default'
        api_id = entry.get('api_id') or api_id
        ts = entry.get('timestamp') or 0
        entries.append({
            "ip": ip,
            "api_id": api_id,
            "timestamp": ts,
            "age": int(now - ts) if ts else None,
            "negative": bool(entry.get('_negative')),
            "country": entry.get('country_name'),
            "city": entry.get('city'),
            "iso_code": entry.get('iso_code'),
            "flag": entry.get('flag')
        })
    entries.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    return entries


@router.get("/cache/entries")
@handle_api_errors
def get_geoip_cache_entries(
    limit: int = Query(100, ge=1, le=500),
    q: str | None = None,
    api_id: str | None = None,
    status: str | None = None,
    max_age: int | None = None,
    sort: str | None = Query('newest', pattern='^(newest|oldest|age_desc)$'),
    _: bool = Depends(verify_session)
):
    """Get GeoIP cache entries (latest first)"""
    entries = _build_geoip_entries()
    entries = _filter_geoip_entries(entries, q=q, api_id=api_id, status=status, max_age=max_age)
    if sort == 'oldest':
        entries.sort(key=lambda x: x.get('timestamp', 0))
    elif sort == 'age_desc':
        entries.sort(key=lambda x: x.get('age') or 0, reverse=True)
    else:
        entries.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    total = len(entries)
    entries = entries[:limit]
    return {"entries": entries, "count": len(entries), "total": total}


@router.get("/cache/export")
@handle_api_errors
def export_geoip_cache_entries(
    format: str = Query('csv', pattern='^(csv|json)$'),
    q: str | None = None,
    api_id: str | None = None,
    status: str | None = None,
    max_age: int | None = None,
    sort: str | None = Query('newest', pattern='^(newest|oldest|age_desc)$'),
    _: bool = Depends(verify_session)
):
    """Export GeoIP cache entries"""
    entries = _build_geoip_entries()
    entries = _filter_geoip_entries(entries, q=q, api_id=api_id, status=status, max_age=max_age)
    if sort == 'oldest':
        entries.sort(key=lambda x: x.get('timestamp', 0))
    elif sort == 'age_desc':
        entries.sort(key=lambda x: x.get('age') or 0, reverse=True)
    else:
        entries.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    if format == 'json':
        return JSONResponse(content={"entries": entries, "count": len(entries)})

    # Use the standard CSV writer so commas, quotes, newlines and spreadsheet
    # formula prefixes cannot corrupt or execute when the export is opened.
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(["ip", "api_id", "country", "city", "iso_code", "flag", "age", "negative", "timestamp"])

    def safe_cell(value):
        text = "" if value is None else str(value)
        if text.startswith(("=", "+", "-", "@")):
            return "'" + text
        return text

    for e in entries:
        writer.writerow([
            safe_cell(e.get('ip', '')),
            safe_cell(e.get('api_id', '')),
            safe_cell(e.get('country')),
            safe_cell(e.get('city')),
            safe_cell(e.get('iso_code')),
            safe_cell(e.get('flag')),
            safe_cell(e.get('age') or ''),
            '1' if e.get('negative') else '0',
            safe_cell(e.get('timestamp') or ''),
        ])
    csv_data = output.getvalue()
    headers = {
        "Content-Disposition": "attachment; filename=geoip-cache.csv"
    }
    return PlainTextResponse(content=csv_data, media_type="text/csv", headers=headers)


# ==================== Online GeoIP Config ====================

class OnlineGeoIPConfig(BaseModel):
    preferred_api: str | None = Field(None, max_length=100)
    ipinfo_token: str | None = Field(None, max_length=4096)

    @field_validator('preferred_api')
    @classmethod
    def normalize_preferred_api(cls, value):
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError('Preferred API cannot be empty')
        return normalized


class TestGeoIPApiRequest(BaseModel):
    token: str | None = Field(None, max_length=4096)


def _apply_persisted_geoip_config() -> None:
    from geoip_service import apply_geoip_runtime_config

    apply_geoip_runtime_config(load_config())


def _public_geoip_api(api: dict) -> dict:
    public_api = dict(api)
    token = str(public_api.pop('token', '') or '')
    public_api['has_token'] = bool(token or public_api.get('has_token'))
    return public_api


def _find_persisted_custom_api(config: dict, api_id: str) -> dict | None:
    return next(
        (
            api for api in config.get('geoip_config', {}).get('custom_apis', [])
            if isinstance(api, dict) and api.get('id') == api_id
        ),
        None,
    )


def _enabled_geoip_api_ids(geoip_config: dict) -> list[str]:
    api_settings = geoip_config.get('api_settings', {})
    enabled_ids = [
        api_id
        for api_id in ('ip-api.com', 'ipwhois', 'ipinfo')
        if api_settings.get(api_id, {}).get('enabled', True)
    ]
    enabled_ids.extend(
        api.get('id')
        for api in geoip_config.get('custom_apis', [])
        if isinstance(api, dict) and api.get('id') and api.get('enabled', True)
    )
    return enabled_ids


@router.get("/online-config")
@handle_api_errors
def get_online_geoip_config(_: bool = Depends(verify_session)):
    """Get online GeoIP configuration"""
    from geoip_service import get_all_geoip_apis
    
    config = load_config()
    geoip_config = config.get('geoip_config', {})
    
    # Get APIs from geoip_service (includes builtin + custom)
    apis = get_all_geoip_apis()
    
    public_apis = [_public_geoip_api(api) for api in apis]
    for api in public_apis:
        if api.get('id') == 'ipinfo':
            api['has_token'] = bool(geoip_config.get('ipinfo_token'))

    return {
        "apis": public_apis,
        "preferred_api": geoip_config.get('preferred_api', 'ip-api.com'),
        "has_ipinfo_token": bool(geoip_config.get('ipinfo_token')),
    }


@router.post("/online-config")
@handle_api_errors
def update_online_geoip_config(data: OnlineGeoIPConfig, _: bool = Depends(verify_session)):
    """Update online GeoIP configuration"""
    def set_geoip_config(config: dict):
        geoip_config = config.setdefault('geoip_config', {})
        if data.preferred_api is not None:
            if data.preferred_api not in _enabled_geoip_api_ids(geoip_config):
                raise HTTPException(status_code=400, detail="GeoIP API is unknown or disabled")
            geoip_config['preferred_api'] = data.preferred_api
        if data.ipinfo_token is not None:
            geoip_config['ipinfo_token'] = data.ipinfo_token

    update_config(set_geoip_config)
    _apply_persisted_geoip_config()
    return {"status": "success"}


# ==================== API Test Endpoints ====================

@router.post("/apis/{api_id}/test")
@limiter.limit(AppConfig.RATE_LIMIT_GEOIP)
@handle_api_errors
async def test_geoip_api(
    api_id: str,
    request: Request,
    data: TestGeoIPApiRequest | None = None,
    _: bool = Depends(verify_session),
):
    """Test a GeoIP API with a sample IP"""
    from geoip_service import (
        _lookup_ip_api_com, _lookup_ipwhois, _lookup_ipinfo,
        _lookup_custom_api,
    )
    
    # Test IP (Google DNS)
    test_ip = "8.8.8.8"
    
    try:
        result = None
        
        if api_id == "ip-api.com":
            result = await _lookup_ip_api_com(test_ip)
        elif api_id == "ipwhois":
            result = await _lookup_ipwhois(test_ip)
        elif api_id == "ipinfo":
            temporary_token = data.token if data and data.token is not None else None
            result = await _lookup_ipinfo(test_ip, token=temporary_token)
        else:
            # Read the persisted record because public API descriptions never
            # contain the real token.
            custom_api = _find_persisted_custom_api(load_config(), api_id)
            if custom_api:
                result = await _lookup_custom_api(test_ip, custom_api)
            else:
                raise HTTPException(status_code=404, detail="API not found")
        
        if result:
            return {
                "success": True,
                "test_ip": test_ip,
                "result": result
            }
        else:
            return {
                "success": False,
                "test_ip": test_ip,
                "error": "No result returned"
            }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("GeoIP API test failed for %s: %s", api_id, type(exc).__name__)
        return {
            "success": False,
            "test_ip": test_ip,
            "error": "GeoIP API test failed"
        }


@router.post("/apis/{api_id}/toggle")
@handle_api_errors
def toggle_geoip_api(api_id: str, _: bool = Depends(verify_session)):
    """Toggle a GeoIP API enabled/disabled"""
    def set_api_enabled_config(config: dict) -> bool:
        geoip_config = config.setdefault('geoip_config', {})
        if api_id in {'ip-api.com', 'ipwhois', 'ipinfo'}:
            api_settings = geoip_config.setdefault('api_settings', {})
            current_enabled = api_settings.get(api_id, {}).get('enabled', True)
            new_enabled = not current_enabled
            api_settings[api_id] = {"enabled": new_enabled}
        else:
            custom_api = _find_persisted_custom_api(config, api_id)
            if not custom_api:
                raise HTTPException(status_code=404, detail="API not found")
            custom_api['enabled'] = not custom_api.get('enabled', True)
            new_enabled = custom_api['enabled']

        enabled_ids = _enabled_geoip_api_ids(geoip_config)
        if not enabled_ids:
            raise HTTPException(status_code=400, detail="At least one GeoIP API must remain enabled")
        if not new_enabled and geoip_config.get('preferred_api', 'ip-api.com') == api_id:
            geoip_config['preferred_api'] = enabled_ids[0]
        return new_enabled

    new_enabled = update_config(set_api_enabled_config)
    _apply_persisted_geoip_config()
    return {"status": "success", "enabled": new_enabled}


# ==================== Custom API Test Endpoint ====================

class TestCustomApiRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4000)
    token: str = Field("", max_length=4096)
    country_code_path: str = Field("", max_length=200)
    country_name_path: str = Field("", max_length=200)
    city_path: str = Field("", max_length=200)
    success_check: str = Field("", max_length=500)
    test_ip: str = Field("8.8.8.8", max_length=45)

    @field_validator('url')
    @classmethod
    def validate_url(cls, value):
        return _validate_geoip_api_url(value)

    @field_validator('test_ip')
    @classmethod
    def validate_test_ip(cls, value):
        import ipaddress

        normalized = value.strip()
        try:
            return str(ipaddress.ip_address(normalized))
        except ValueError as exc:
            raise ValueError('Invalid IP address') from exc


@router.post("/test-custom-api")
@limiter.limit(AppConfig.RATE_LIMIT_GEOIP)
@handle_api_errors
async def test_custom_api(data: TestCustomApiRequest, request: Request, _: bool = Depends(verify_session)):
    """Test a custom GeoIP API configuration before saving"""
    from geoip_service import _lookup_custom_api
    
    # Build temporary API config for testing
    temp_api_config = {
        "url": data.url,
        "token": data.token,
        "country_code_path": data.country_code_path,
        "country_name_path": data.country_name_path,
        "city_path": data.city_path,
        "success_check": data.success_check,
        "method": "GET",
        "headers": {},
    }
    
    try:
        result = await _lookup_custom_api(data.test_ip, temp_api_config)
        
        if result:
            return {
                "success": True,
                "test_ip": data.test_ip,
                "result": result
            }
        else:
            return {
                "success": False,
                "test_ip": data.test_ip,
                "error": "No result returned - check URL and field paths"
            }
    except Exception as exc:
        logger.warning("Temporary GeoIP API test failed: %s", type(exc).__name__)
        return {
            "success": False,
            "test_ip": data.test_ip,
            "error": "GeoIP API test failed"
        }


# ==================== Custom API CRUD Endpoints ====================

class CustomApiConfig(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1, max_length=4000)
    token: str | None = Field(None, max_length=4096)
    limit: str = Field("", max_length=100)
    country_code_path: str = Field("", max_length=200)
    country_name_path: str = Field("", max_length=200)
    city_path: str = Field("", max_length=200)
    success_check: str = Field("", max_length=500)

    @field_validator('name')
    @classmethod
    def normalize_name(cls, value):
        normalized = value.strip()
        if not normalized:
            raise ValueError('Name cannot be empty')
        return normalized

    @field_validator('url')
    @classmethod
    def validate_url(cls, value):
        return _validate_geoip_api_url(value)


def _validate_geoip_api_url(value: str) -> str:
    normalized = value.strip()
    if any(character.isspace() or ord(character) < 32 for character in normalized):
        raise ValueError('API URL cannot contain whitespace or control characters')
    try:
        parsed = urlsplit(normalized)
    except ValueError as exc:
        raise ValueError('Invalid API URL') from exc
    if parsed.scheme.lower() not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('API URL must use HTTP or HTTPS')
    if parsed.username is not None or parsed.password is not None:
        raise ValueError('Put API credentials in the token field, not in the URL')
    if parsed.hostname.lower() == 'localhost':
        raise ValueError('API URL must use a public host')
    try:
        literal_ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal_ip = None
    if literal_ip is not None and not literal_ip.is_global:
        raise ValueError('API URL must use a public host')
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError('Invalid API URL port') from exc
    return normalized


def _geoip_url_key(value: str) -> tuple | None:
    """Return a comparison key without trusting historical persisted URLs."""
    try:
        parsed = urlsplit(str(value or '').strip())
        if parsed.scheme.lower() not in {'http', 'https'} or not parsed.hostname:
            return None
        port = parsed.port
    except (TypeError, ValueError):
        return None
    return (
        parsed.scheme.lower(),
        parsed.hostname.lower(),
        port,
        parsed.path,
        parsed.query,
    )


@router.post("/apis")
@handle_api_errors
def create_custom_api(data: CustomApiConfig, _: bool = Depends(verify_session)):
    """Create a new custom GeoIP API"""
    def add_custom_api_config(config: dict) -> dict:
        geoip_config = config.setdefault('geoip_config', {})
        custom_apis = geoip_config.setdefault('custom_apis', [])
        requested_url_key = _geoip_url_key(data.url)
        if any(
            str(api.get('name') or '').strip().casefold() == data.name.casefold()
            for api in custom_apis if isinstance(api, dict)
        ):
            raise HTTPException(status_code=409, detail="GeoIP API name already exists")
        if any(
            requested_url_key is not None
            and _geoip_url_key(str(api.get('url') or '')) == requested_url_key
            for api in custom_apis if isinstance(api, dict)
        ):
            raise HTTPException(status_code=409, detail="GeoIP API URL already exists")
        known_ids = {
            api.get('id') for api in custom_apis
            if isinstance(api, dict)
        }
        api_id = f"custom_{secrets.token_urlsafe(9)}"
        while api_id in known_ids:
            api_id = f"custom_{secrets.token_urlsafe(9)}"
        new_api = {
            "id": api_id,
            "name": data.name,
            "url": data.url,
            "token": data.token or "",
            "limit": data.limit,
            "method": "GET",
            "headers": {},
            "country_code_path": data.country_code_path,
            "country_name_path": data.country_name_path,
            "city_path": data.city_path,
            "success_check": data.success_check,
            "enabled": True,
            "builtin": False,
        }
        custom_apis.append(new_api)
        return dict(new_api)

    new_api = update_config(add_custom_api_config)
    _apply_persisted_geoip_config()
    return {"status": "success", "api": _public_geoip_api(new_api)}


@router.put("/apis/{api_id}")
@handle_api_errors
def update_custom_api(api_id: str, data: CustomApiConfig, _: bool = Depends(verify_session)):
    """Update an existing custom GeoIP API"""
    if api_id in {'ip-api.com', 'ipwhois'}:
        raise HTTPException(status_code=400, detail="Cannot modify builtin API")
    if api_id == 'ipinfo':
        if data.token is None:
            return {"status": "success", "message": "Token unchanged"}

        def set_ipinfo_token(config: dict):
            config.setdefault('geoip_config', {})['ipinfo_token'] = data.token

        update_config(set_ipinfo_token)
        _apply_persisted_geoip_config()
        return {"status": "success", "message": "Token updated"}

    def update_custom_api_config(config: dict) -> dict:
        custom_api = _find_persisted_custom_api(config, api_id)
        if not custom_api:
            raise HTTPException(status_code=404, detail="API not found")
        custom_apis = config.setdefault('geoip_config', {}).setdefault('custom_apis', [])
        requested_url_key = _geoip_url_key(data.url)
        if any(
            api.get('id') != api_id
            and str(api.get('name') or '').strip().casefold() == data.name.casefold()
            for api in custom_apis if isinstance(api, dict)
        ):
            raise HTTPException(status_code=409, detail="GeoIP API name already exists")
        if any(
            api.get('id') != api_id
            and requested_url_key is not None
            and _geoip_url_key(str(api.get('url') or '')) == requested_url_key
            for api in custom_apis if isinstance(api, dict)
        ):
            raise HTTPException(status_code=409, detail="GeoIP API URL already exists")
        custom_api.update({
            "name": data.name,
            "url": data.url,
            "limit": data.limit,
            "country_code_path": data.country_code_path,
            "country_name_path": data.country_name_path,
            "city_path": data.city_path,
            "success_check": data.success_check,
        })
        # Omitted means unchanged; an explicitly empty string clears the token.
        if data.token is not None:
            custom_api['token'] = data.token
        return dict(custom_api)

    updated_api = update_config(update_custom_api_config)
    _apply_persisted_geoip_config()
    return {"status": "success", "api": _public_geoip_api(updated_api)}


@router.delete("/apis/{api_id}")
@handle_api_errors
def delete_custom_api(api_id: str, _: bool = Depends(verify_session)):
    """Delete a custom GeoIP API"""
    if api_id in {'ip-api.com', 'ipwhois', 'ipinfo'}:
        raise HTTPException(status_code=400, detail="Cannot delete builtin API")

    def delete_custom_api_config(config: dict):
        custom_apis = config.setdefault('geoip_config', {}).setdefault('custom_apis', [])
        remaining = [api for api in custom_apis if api.get('id') != api_id]
        if len(remaining) == len(custom_apis):
            raise HTTPException(status_code=404, detail="API not found")
        config['geoip_config']['custom_apis'] = remaining
        if config['geoip_config'].get('preferred_api') == api_id:
            enabled_ids = _enabled_geoip_api_ids(config['geoip_config'])
            if not enabled_ids:
                raise HTTPException(status_code=400, detail="At least one GeoIP API must remain enabled")
            config['geoip_config']['preferred_api'] = enabled_ids[0]

    update_config(delete_custom_api_config)
    _apply_persisted_geoip_config()
    return {"status": "success"}
