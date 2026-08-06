"""
Settings API
Application settings endpoints
"""
import ipaddress
from typing import Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.config import AppConfig
from core.dependencies import verify_session
from core.database import load_config, update_config
from core.rate_limit import limiter
from helpers import handle_api_errors
from helpers import load_subscription_yaml
from services.name_transformer import NameTransformer
from services.node_visibility import is_node_enabled
from services.proxy_chain_references import list_proxy_chain_virtual_references
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()

YAML_SOURCE_DIR = AppConfig.YAML_SOURCE_DIR

# Lazy import server module (only for functions that truly need it)
_server_module = None


def _get_server():
    global _server_module
    if _server_module is None:
        import server as srv
        _server_module = srv
    return _server_module


# ==================== API Endpoints ====================


class SourceOrderUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')

    order: list[str] = Field(max_length=500)

    @field_validator('order')
    @classmethod
    def validate_order(cls, value):
        if len(value) != len(set(value)):
            raise ValueError('Source order contains duplicate IDs')
        if any(not source_id or len(source_id) > 200 for source_id in value):
            raise ValueError('Source order contains an invalid ID')
        return value

@router.get("/source-order")
@handle_api_errors
def get_source_order(_: bool = Depends(verify_session)):
    """Get source order"""
    srv = _get_server()
    return {"sources": srv.get_ordered_sources()}


@router.put("/source-order")
@handle_api_errors
def update_source_order(data: SourceOrderUpdate, _: bool = Depends(verify_session)):
    """Update source order"""
    def set_source_order(config: dict):
        known_source_ids = {
            str(subscription.get('id'))
            for subscription in config.get('subscriptions', [])
            if isinstance(subscription, dict) and subscription.get('id')
        }
        if config.get('custom_nodes'):
            known_source_ids.add('custom_nodes')
        if any(source_id not in known_source_ids for source_id in data.order):
            raise HTTPException(status_code=400, detail="Source order contains an unknown source")
        config['source_order'] = list(data.order)

    update_config(set_source_order)
    return {"status": "success"}


# ==================== Port Mappings API ====================
# These routes are under /api/port-mappings but registered in api/__init__.py

class PortMappingCreate(BaseModel):
    final_name: str
    port: int = Field(ge=1024, le=65535)


port_mappings_router = APIRouter()


@port_mappings_router.get("")
@handle_api_errors
def get_port_mappings(_: bool = Depends(verify_session)):
    """Get all port mappings"""
    config = load_config()
    mappings = config.get('port_mappings', {})
    
    # Get all available node names to check if mapping is active
    available_nodes = set()
    
    # Add custom nodes
    custom_nodes = config.get('custom_nodes', [])
    for node in custom_nodes:
        if not is_node_enabled(node):
            continue
        transformed = NameTransformer.transform_name(node, 'Custom')
        available_nodes.add(transformed.get('name', ''))
    
    # Add subscription nodes
    for sub in config.get('subscriptions', []):
        if not sub.get('enabled', True):
            continue
        
        try:
            sub_data = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=True)
            sub_nodes = sub_data.get('proxies', []) if sub_data else []
            
            for node in sub_nodes:
                if not is_node_enabled(node):
                    continue
                transformed = NameTransformer.transform_name(node, sub['name'])
                available_nodes.add(transformed.get('name', ''))
        except Exception as e:
            logger.warning(f"Failed to load subscription {sub['id']}: {e}")
    

    chain_references = list_proxy_chain_virtual_references(
        config,
        base_node_names=available_nodes,
    )
    chain_reference_names = {
        reference.stable_id: reference.name
        for reference in chain_references
        if reference.enabled
    }
    available_nodes.update(chain_reference_names.values())
    # Convert to list format for frontend with active status
    result = []
    for stored_reference, port in mappings.items():
        node_name = chain_reference_names.get(stored_reference, stored_reference)
        result.append({
            "final_name": node_name,
            "port": port,
            "active": stored_reference in chain_reference_names or node_name in available_nodes,
        })
    
    return {"mappings": result, "count": len(result)}


@port_mappings_router.post("")
@handle_api_errors
def create_port_mapping(data: PortMappingCreate, _: bool = Depends(verify_session)):
    """Create a port mapping"""
    def add_port_mapping(config: dict):
        mappings = config.setdefault('port_mappings', {})
        chain_reference = next(
            (
                reference
                for reference in list_proxy_chain_virtual_references(config)
                if reference.name == data.final_name
            ),
            None,
        )
        stored_reference = (
            chain_reference.stable_id
            if chain_reference is not None
            else data.final_name
        )

        # Check if port is already used against latest config while locked.
        for reference, port in mappings.items():
            if port == data.port and reference != stored_reference:
                raise HTTPException(status_code=400, detail=f"Port {data.port} is already mapped")

        mappings.pop(data.final_name, None)
        mappings[stored_reference] = data.port

    update_config(add_port_mapping)
    
    return {"status": "success", "mapping": {"final_name": data.final_name, "port": data.port}}


@port_mappings_router.delete("/{port}")
@handle_api_errors
def delete_port_mapping(port: int, _: bool = Depends(verify_session)):
    """Delete a port mapping by port number"""
    def remove_port_mapping(config: dict):
        mappings = config.get('port_mappings', {})

        # Find and remove the mapping with this port
        to_remove = None
        for name, p in mappings.items():
            if p == port:
                to_remove = name
                break

        if not to_remove:
            raise HTTPException(status_code=404, detail="Port mapping not found")

        del mappings[to_remove]

    update_config(remove_port_mapping)
    return {"status": "success"}


# ==================== IPv6 Test Proxy API ====================

class IPv6ProxySetting(BaseModel):
    enabled: bool = False
    proxy_url: Optional[str] = Field(None, max_length=2048)
    ipv6_only: bool = True

    @field_validator('proxy_url')
    @classmethod
    def validate_proxy_url(cls, value):
        return _normalize_proxy_url(value)


class IPv6ProxyTest(BaseModel):
    proxy_url: str = Field(min_length=1, max_length=2048)

    @field_validator('proxy_url')
    @classmethod
    def validate_proxy_url(cls, value):
        return _normalize_proxy_url(value)


def _normalize_proxy_url(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if any(character.isspace() for character in normalized):
        raise ValueError('Proxy URL cannot contain whitespace')
    try:
        parsed = urlsplit(normalized)
        if parsed.scheme.lower() not in {'http', 'https', 'socks5'}:
            raise ValueError('Proxy URL must use http, https, or socks5')
        if not parsed.hostname:
            raise ValueError('Proxy URL must include a host')
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError('Proxy URL contains an invalid port')
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    return normalized


@router.get("/ipv6-proxy")
@handle_api_errors
def get_ipv6_proxy_setting(_: bool = Depends(verify_session)):
    """Get IPv6 test proxy setting"""
    config = load_config()
    settings = config.get('settings', {})
    ipv6_proxy = settings.get('ipv6_proxy', {})
    return {
        "enabled": ipv6_proxy.get('enabled', False),
        "has_proxy_url": bool(ipv6_proxy.get('proxy_url')),
        "ipv6_only": ipv6_proxy.get('ipv6_only', True),
    }


@router.put("/ipv6-proxy")
@handle_api_errors
def update_ipv6_proxy_setting(data: IPv6ProxySetting, _: bool = Depends(verify_session)):
    """Update IPv6 test proxy setting"""
    def set_ipv6_proxy(config: dict):
        settings = config.setdefault('settings', {})
        settings['ipv6_proxy'] = {
            'enabled': data.enabled,
            'proxy_url': data.proxy_url,
            'ipv6_only': data.ipv6_only,
        }

    update_config(set_ipv6_proxy)
    return {"status": "success"}


@router.post("/ipv6-proxy/test")
@limiter.limit(AppConfig.RATE_LIMIT_SPEEDTEST)
@handle_api_errors
async def test_ipv6_proxy(data: IPv6ProxyTest, request: Request, _: bool = Depends(verify_session)):
    """Test IPv6 proxy and return IP addresses"""
    import httpx
    import asyncio
    
    proxy_url = data.proxy_url
    
    if not proxy_url:
        raise HTTPException(status_code=400, detail="Proxy URL is required")
    
    headers = {"Accept": "text/plain"}
    ip = None
    
    async def fetch_ip(client):
        nonlocal ip
        try:
            resp = await client.get("https://ifconfig.co/ip", headers=headers)
            resp.raise_for_status()
            candidate_ip = resp.text.strip()
            ip = str(ipaddress.ip_address(candidate_ip))
        except Exception:
            raise HTTPException(status_code=502, detail="Proxy connection failed") from None
    
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=httpx.Timeout(10),
            follow_redirects=True,
            trust_env=False,
        ) as client:
            await fetch_ip(client)
        
        if not ip:
            raise HTTPException(status_code=502, detail="Proxy connection failed")
        
        is_ipv6 = ':' in ip
        return {
            "status": "success",
            "ip": ip,
            "ipv4": ip if not is_ipv6 else None,
            "ipv6": ip if is_ipv6 else None,
        }
    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Proxy connection failed") from None
    except Exception:
        raise HTTPException(status_code=500, detail="Proxy test failed") from None


@router.post("/ipv6-proxy/test-connectivity")
@limiter.limit(AppConfig.RATE_LIMIT_SPEEDTEST)
@handle_api_errors
async def test_ipv6_connectivity(request: Request, _: bool = Depends(verify_session)):
    """Test if the server has IPv6 connectivity"""
    import httpx
    import asyncio
    
    async def check_ipv6():
        # Bind the transport to an IPv6 wildcard address. Without this
        # constraint a dual-stack resolver may choose IPv4 and report a false
        # positive on hosts that have no usable IPv6 route.
        transport = httpx.AsyncHTTPTransport(local_address="::", retries=0)
        async with httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(5),
            follow_redirects=True,
            trust_env=False,
        ) as client:
            try:
                response = await client.get("https://ifconfig.co/ip", headers={"Accept": "text/plain"})
                response.raise_for_status()
                parsed_ip = ipaddress.ip_address(response.text.strip())
                return {"has_ipv6": parsed_ip.version == 6, "ip": str(parsed_ip)}
            except Exception:
                return {"has_ipv6": False, "ip": None}
    
    try:
        result = await asyncio.wait_for(check_ipv6(), timeout=10)
        return {
            "status": "success",
            "has_ipv6": result["has_ipv6"],
            "ip": result["ip"],
            "message": "IPv6 available" if result["has_ipv6"] else "IPv6 not available"
        }
    except Exception:
        return {
            "status": "success",
            "has_ipv6": False,
            "ip": None,
            "message": "IPv6 check failed"
        }


# ==================== Subscription Proxy API ====================

class SubscriptionProxySetting(BaseModel):
    proxy_url: Optional[str] = Field(None, max_length=2048)

    @field_validator('proxy_url')
    @classmethod
    def validate_proxy_url(cls, value):
        return _normalize_proxy_url(value)


@router.get("/subscription-proxy")
@handle_api_errors
def get_subscription_proxy_setting(_: bool = Depends(verify_session)):
    """Get subscription proxy URL"""
    config = load_config()
    settings = config.get('settings', {})
    return {
        "has_proxy_url": bool(settings.get('subscription_proxy_url')),
    }


@router.put("/subscription-proxy")
@handle_api_errors
def update_subscription_proxy_setting(data: SubscriptionProxySetting, _: bool = Depends(verify_session)):
    """Update subscription proxy URL"""
    def set_proxy(config: dict):
        settings = config.setdefault('settings', {})
        settings['subscription_proxy_url'] = data.proxy_url

    update_config(set_proxy)
    return {"status": "success"}
