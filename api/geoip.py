"""
GeoIP API
GeoIP lookup endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from core.dependencies import verify_session
from helpers import handle_api_errors
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()


# ==================== Data Models ====================

class GeoIPLookupRequest(BaseModel):
    ip: str


class BatchGeoIPRequest(BaseModel):
    ips: list


# ==================== API Endpoints ====================

@router.post("/lookup")
@handle_api_errors
async def lookup_ip_post(data: GeoIPLookupRequest, _: bool = Depends(verify_session)):
    """Lookup GeoIP info for an IP address (POST)"""
    return await _do_lookup(data.ip)


@router.get("/lookup/{ip:path}")
@handle_api_errors
async def lookup_ip_get(ip: str, _: bool = Depends(verify_session)):
    """Lookup GeoIP info for an IP address (GET)"""
    from urllib.parse import unquote
    ip = unquote(ip)  # Handle URL-encoded IPv6
    return await _do_lookup(ip)


async def _do_lookup(ip: str):
    """Internal lookup function"""
    from geoip_service import lookup_ip_online
    
    # Use online lookup
    try:
        result = await lookup_ip_online(ip)
        if result:
            return {"ip": ip, "result": result, "source": "online"}
    except Exception as e:
        logger.warning(f"Online GeoIP lookup failed: {e}")
    
    return {"ip": ip, "result": None, "source": None}


@router.post("/batch")
@handle_api_errors
async def batch_lookup_ips(data: BatchGeoIPRequest, _: bool = Depends(verify_session)):
    """Batch lookup GeoIP info for multiple IPs"""
    from geoip_service import lookup_ip_online
    import asyncio
    
    results = {}
    ips = data.ips[:100]  # Limit to 100 IPs
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
        if ':' in key:
            ip, api_id = key.rsplit(':', 1)
        else:
            ip, api_id = key, 'default'
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
    entries = entries[:limit]
    return {"entries": entries, "count": len(entries), "total": len(entries)}


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

    # CSV
    lines = ["ip,api_id,country,city,iso_code,flag,age,negative,timestamp"]
    for e in entries:
        line = ",".join([
            e.get('ip', ''),
            e.get('api_id', ''),
            (e.get('country') or '').replace(',', ' '),
            (e.get('city') or '').replace(',', ' '),
            e.get('iso_code') or '',
            e.get('flag') or '',
            str(e.get('age') or ''),
            '1' if e.get('negative') else '0',
            str(e.get('timestamp') or '')
        ])
        lines.append(line)
    csv_data = "\n".join(lines)
    headers = {
        "Content-Disposition": "attachment; filename=geoip-cache.csv"
    }
    return PlainTextResponse(content=csv_data, media_type="text/csv", headers=headers)


# ==================== Online GeoIP Config ====================

class OnlineGeoIPConfig(BaseModel):
    preferred_api: str = None
    ipinfo_token: str = None


@router.get("/online-config")
@handle_api_errors
def get_online_geoip_config(_: bool = Depends(verify_session)):
    """Get online GeoIP configuration"""
    from core.database import load_config
    from geoip_service import get_all_geoip_apis
    
    config = load_config()
    geoip_config = config.get('geoip_config', {})
    
    # Get APIs from geoip_service (includes builtin + custom)
    apis = get_all_geoip_apis()
    
    return {
        "apis": apis,
        "preferred_api": geoip_config.get('preferred_api', 'ip-api.com'),
        "ipinfo_token": geoip_config.get('ipinfo_token', '')
    }


@router.post("/online-config")
@handle_api_errors
def update_online_geoip_config(data: OnlineGeoIPConfig, _: bool = Depends(verify_session)):
    """Update online GeoIP configuration"""
    from core.database import update_config
    from geoip_service import set_online_geoip_config

    if data.preferred_api is not None:
        set_online_geoip_config(preferred_api=data.preferred_api)
    if data.ipinfo_token is not None:
        set_online_geoip_config(ipinfo_token=data.ipinfo_token)

    def set_geoip_config(config: dict):
        geoip_config = config.setdefault('geoip_config', {})
        if data.preferred_api is not None:
            geoip_config['preferred_api'] = data.preferred_api
        if data.ipinfo_token is not None:
            geoip_config['ipinfo_token'] = data.ipinfo_token

    update_config(set_geoip_config)
    return {"status": "success"}


# ==================== API Test Endpoints ====================

@router.post("/apis/{api_id}/test")
@handle_api_errors
async def test_geoip_api(api_id: str, _: bool = Depends(verify_session)):
    """Test a GeoIP API with a sample IP"""
    from geoip_service import (
        _lookup_ip_api_com, _lookup_ipwhois, _lookup_ipinfo,
        _lookup_custom_api, get_all_geoip_apis
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
            # _lookup_ipinfo reads token from global config internally
            result = await _lookup_ipinfo(test_ip)
        else:
            # Check custom APIs
            apis = get_all_geoip_apis()
            custom_api = next((a for a in apis if a.get("id") == api_id), None)
            if custom_api and not custom_api.get("builtin"):
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
    except Exception as e:
        return {
            "success": False,
            "test_ip": test_ip,
            "error": str(e)
        }


@router.post("/apis/{api_id}/toggle")
@handle_api_errors
def toggle_geoip_api(api_id: str, _: bool = Depends(verify_session)):
    """Toggle a GeoIP API enabled/disabled"""
    from geoip_service import set_api_enabled, get_all_geoip_apis
    from core.database import update_config
    
    apis = get_all_geoip_apis()
    api = next((a for a in apis if a.get("id") == api_id), None)
    
    if not api:
        raise HTTPException(status_code=404, detail="API not found")
    
    new_enabled = not api.get("enabled", True)
    set_api_enabled(api_id, new_enabled)

    def set_api_enabled_config(config: dict):
        geoip_config = config.setdefault('geoip_config', {})
        api_settings = geoip_config.setdefault('api_settings', {})
        api_settings[api_id] = {"enabled": new_enabled}

    update_config(set_api_enabled_config)
    
    return {"status": "success", "enabled": new_enabled}


# ==================== Custom API Test Endpoint ====================

class TestCustomApiRequest(BaseModel):
    url: str
    token: str = ""
    country_code_path: str = ""
    country_name_path: str = ""
    city_path: str = ""
    success_check: str = ""
    test_ip: str = "8.8.8.8"


@router.post("/test-custom-api")
@handle_api_errors
async def test_custom_api(data: TestCustomApiRequest, _: bool = Depends(verify_session)):
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
    except Exception as e:
        return {
            "success": False,
            "test_ip": data.test_ip,
            "error": str(e)
        }


# ==================== Custom API CRUD Endpoints ====================

class CustomApiConfig(BaseModel):
    name: str
    url: str
    token: str = ""
    limit: str = ""
    country_code_path: str = ""
    country_name_path: str = ""
    city_path: str = ""
    success_check: str = ""


@router.post("/apis")
@handle_api_errors
def create_custom_api(data: CustomApiConfig, _: bool = Depends(verify_session)):
    """Create a new custom GeoIP API"""
    from geoip_service import add_custom_geoip_api
    from core.database import update_config
    
    api_config = {
        "name": data.name,
        "url": data.url,
        "token": data.token,
        "limit": data.limit,
        "country_code_path": data.country_code_path,
        "country_name_path": data.country_name_path,
        "city_path": data.city_path,
        "success_check": data.success_check,
    }
    
    new_api = add_custom_geoip_api(api_config)

    def add_custom_api_config(config: dict):
        geoip_config = config.setdefault('geoip_config', {})
        geoip_config.setdefault('custom_apis', []).append(new_api)

    update_config(add_custom_api_config)
    
    return {"status": "success", "api": new_api}


@router.put("/apis/{api_id}")
@handle_api_errors
def update_custom_api(api_id: str, data: CustomApiConfig, _: bool = Depends(verify_session)):
    """Update an existing custom GeoIP API"""
    from geoip_service import update_custom_geoip_api, get_all_geoip_apis
    from core.database import update_config
    
    # Check if it's a builtin API (only allow updating ipinfo token)
    apis = get_all_geoip_apis()
    api = next((a for a in apis if a.get("id") == api_id), None)
    
    if not api:
        raise HTTPException(status_code=404, detail="API not found")
    
    if api.get("builtin"):
        # For builtin APIs, only allow updating token (for ipinfo)
        if api_id == "ipinfo" and data.token:
            from geoip_service import set_online_geoip_config
            set_online_geoip_config(ipinfo_token=data.token)

            def set_ipinfo_token(config: dict):
                config.setdefault('geoip_config', {})['ipinfo_token'] = data.token

            update_config(set_ipinfo_token)
            
            return {"status": "success", "message": "Token updated"}
        else:
            raise HTTPException(status_code=400, detail="Cannot modify builtin API")
    
    # Update custom API
    api_config = {
        "name": data.name,
        "url": data.url,
        "limit": data.limit,
        "country_code_path": data.country_code_path,
        "country_name_path": data.country_name_path,
        "city_path": data.city_path,
        "success_check": data.success_check,
    }
    
    # Only update token if provided (don't clear existing token)
    if data.token:
        api_config["token"] = data.token
    
    updated_api = update_custom_geoip_api(api_id, api_config)

    def update_custom_api_config(config: dict):
        geoip_config = config.setdefault('geoip_config', {})
        custom_apis = geoip_config.setdefault('custom_apis', [])

        # Update in config
        for i, api in enumerate(custom_apis):
            if api.get('id') == api_id:
                custom_apis[i] = updated_api
                break

    update_config(update_custom_api_config)
    
    return {"status": "success", "api": updated_api}


@router.delete("/apis/{api_id}")
@handle_api_errors
def delete_custom_api(api_id: str, _: bool = Depends(verify_session)):
    """Delete a custom GeoIP API"""
    from geoip_service import delete_custom_geoip_api, get_all_geoip_apis
    from core.database import update_config
    
    # Check if it's a builtin API
    apis = get_all_geoip_apis()
    api = next((a for a in apis if a.get("id") == api_id), None)
    
    if not api:
        raise HTTPException(status_code=404, detail="API not found")
    
    if api.get("builtin"):
        raise HTTPException(status_code=400, detail="Cannot delete builtin API")
    
    # Delete from memory
    if not delete_custom_geoip_api(api_id):
        raise HTTPException(status_code=404, detail="API not found")
    
    def delete_custom_api_config(config: dict):
        if 'geoip_config' in config and 'custom_apis' in config['geoip_config']:
            config['geoip_config']['custom_apis'] = [
                a for a in config['geoip_config']['custom_apis'] if a.get('id') != api_id
            ]

    update_config(delete_custom_api_config)
    
    return {"status": "success"}
