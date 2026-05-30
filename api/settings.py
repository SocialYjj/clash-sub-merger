"""
Settings API
Application settings endpoints
"""
import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.config import AppConfig
from core.dependencies import verify_session
from core.database import load_config, update_config
from helpers import handle_api_errors
from services.name_transformer import NameTransformer
from services.node_visibility import is_node_enabled
from services.proxy_chain_utils import unique_group_name, unique_name
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

@router.get("/source-order")
@handle_api_errors
def get_source_order(_: bool = Depends(verify_session)):
    """Get source order"""
    srv = _get_server()
    return {"sources": srv.get_ordered_sources()}


@router.put("/source-order")
@handle_api_errors
def update_source_order(data: dict, _: bool = Depends(verify_session)):
    """Update source order"""
    def set_source_order(config: dict):
        config['source_order'] = data.get('order', [])

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
    

    # Add generated chain node names and chain pool groups.
    # Keep naming in sync with services.subscription_output so mappings to
    # generated names such as "🔗 美国家宽" are treated as active.
    existing_names = available_nodes
    existing_group_names = set()

    for chain in config.get('proxy_chains', []):
        if not chain.get('enabled', True):
            continue
        rows = chain.get('rows', [])
        for row_idx, row in enumerate(rows):
            nodes = row.get('nodes', [])
            if len(nodes) < 2:
                continue

            chain_name = chain.get('name', 'Chain')
            if len(rows) > 1:
                chain_name = f"{chain_name} #{row_idx + 1}"

            terminal_group = None
            transit_group_idx = 0
            for node in nodes:
                if isinstance(node, dict) and node.get('type') == 'group':
                    is_terminal = node is nodes[-1]
                    if is_terminal:
                        terminal_group = node
                        group_base_name = node.get('group_name') or f"{chain_name} 落地池"
                    else:
                        transit_group_idx += 1
                        group_base_name = node.get('group_name') or f"{chain_name} 中转池{transit_group_idx}"

                    group_name = unique_group_name(
                        f"🔀 {group_base_name}",
                        existing_group_names,
                        node.get('group_id'),
                    )
                    available_nodes.add(group_name)

            if not terminal_group:
                unique_name(f"🔗 {chain_name}", existing_names)
    # Convert to list format for frontend with active status
    result = []
    for node_name, port in mappings.items():
        result.append({
            "final_name": node_name,
            "port": port,
            "active": node_name in available_nodes
        })
    
    return {"mappings": result, "count": len(result)}


@port_mappings_router.post("")
@handle_api_errors
def create_port_mapping(data: PortMappingCreate, _: bool = Depends(verify_session)):
    """Create a port mapping"""
    def add_port_mapping(config: dict):
        mappings = config.setdefault('port_mappings', {})

        # Check if port is already used against latest config while locked.
        for name, port in mappings.items():
            if port == data.port and name != data.final_name:
                raise HTTPException(status_code=400, detail=f"Port {data.port} is already mapped to {name}")

        mappings[data.final_name] = data.port

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
    proxy_url: Optional[str] = None
    ipv6_only: bool = True


class IPv6ProxyTest(BaseModel):
    proxy_url: str


@router.get("/ipv6-proxy")
@handle_api_errors
def get_ipv6_proxy_setting(_: bool = Depends(verify_session)):
    """Get IPv6 test proxy setting"""
    config = load_config()
    settings = config.get('settings', {})
    ipv6_proxy = settings.get('ipv6_proxy', {})
    return {
        "enabled": ipv6_proxy.get('enabled', False),
        "proxy_url": ipv6_proxy.get('proxy_url'),
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
@handle_api_errors
async def test_ipv6_proxy(data: IPv6ProxyTest, _: bool = Depends(verify_session)):
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
            resp = await client.get("http://ifconfig.co/ip", headers=headers)
            resp.raise_for_status()
            ip = resp.text.strip()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Proxy connection failed: {e}")
    
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=httpx.Timeout(10),
            follow_redirects=True
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
    except httpx.ConnectError as e:
        raise HTTPException(status_code=502, detail=f"Connection failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")


@router.post("/ipv6-proxy/test-connectivity")
@handle_api_errors
async def test_ipv6_connectivity(_: bool = Depends(verify_session)):
    """Test if the server has IPv6 connectivity"""
    import httpx
    import asyncio
    
    async def check_ipv6():
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5),
            follow_redirects=True
        ) as client:
            try:
                response = await client.get("http://ifconfig.co", headers={"Accept": "text/plain"})
                ip = response.text.strip()
                is_ipv6 = ':' in ip
                return {"has_ipv6": is_ipv6, "ip": ip}
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
    except Exception as e:
        return {
            "status": "success",
            "has_ipv6": False,
            "ip": None,
            "message": f"IPv6 check failed: {str(e)}"
        }


# ==================== Subscription Proxy API ====================

class SubscriptionProxySetting(BaseModel):
    proxy_url: Optional[str] = None


@router.get("/subscription-proxy")
@handle_api_errors
def get_subscription_proxy_setting(_: bool = Depends(verify_session)):
    """Get subscription proxy URL"""
    config = load_config()
    settings = config.get('settings', {})
    return {
        "proxy_url": settings.get('subscription_proxy_url'),
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
