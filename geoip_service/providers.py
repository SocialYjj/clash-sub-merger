"""
Built-in online GeoIP provider lookups (ip-api.com, ipwhois, ipinfo) and the
catalog describing them.
"""

from typing import Dict, Optional

import httpx

import geoip_service as _PKG
from logger_config import get_logger

from .normalize import _build_provider_result

# Setup logger
logger = get_logger(__name__)

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


async def _lookup_ip_api_com(ip: str, timeout: int = 5) -> Optional[Dict]:
    """Lookup location and network metadata using ip-api.com."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "http://ip-api.com/json/"
                f"{ip}?lang=zh-CN&fields=status,message,query,country,countryCode,"
                "regionName,city,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting",
                timeout=timeout,
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
            resp = await client.get(f"https://ipwhois.app/json/{ip}?lang=zh-CN", timeout=timeout)
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
            token = _PKG._online_geoip_config.get("ipinfo_token", "")
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
