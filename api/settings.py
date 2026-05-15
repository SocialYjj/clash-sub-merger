"""
Settings API
Application settings endpoints
"""
import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.dependencies import verify_session
from core.database import load_config, update_config
from helpers import handle_api_errors, load_subscription_yaml
from services.name_transformer import NameTransformer
from services.proxy_chain_utils import unique_group_name, unique_name
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Get YAML_SOURCE_DIR from environment or default
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(BASE_DIR, 'data'))
YAML_SOURCE_DIR = os.path.join(DATA_DIR, 'uploads')

# Lazy import server module (only for functions that truly need it)
_server_module = None


def _get_server():
    global _server_module
    if _server_module is None:
        import server as srv
        _server_module = srv
    return _server_module


# ==================== Data Models ====================

class ProxyNodeSetting(BaseModel):
    proxy_node_id: Optional[str] = None
    proxy_node_name: Optional[str] = None


# ==================== API Endpoints ====================

@router.get("/proxy-node")
@handle_api_errors
def get_proxy_node_setting(_: bool = Depends(verify_session)):
    """Get proxy node setting for subscription fetching"""
    config = load_config()
    settings = config.get('settings', {})
    return {
        "proxy_node_id": settings.get('proxy_node_id'),
        "proxy_node_name": settings.get('proxy_node_name')
    }


@router.put("/proxy-node")
@handle_api_errors
def update_proxy_node_setting(data: ProxyNodeSetting, _: bool = Depends(verify_session)):
    """Update proxy node setting"""
    def set_proxy_node(config: dict):
        settings = config.setdefault('settings', {})
        settings['proxy_node_id'] = data.proxy_node_id
        settings['proxy_node_name'] = data.proxy_node_name

    update_config(set_proxy_node)
    return {"status": "success"}


@router.get("/available-proxy-nodes")
@handle_api_errors
def get_available_proxy_nodes(_: bool = Depends(verify_session)):
    """Get all available nodes that can be used as proxy"""
    config = load_config()
    nodes = []
    
    # Add custom nodes
    custom_nodes = config.get('custom_nodes', [])
    for i, node in enumerate(custom_nodes):
        transformed = NameTransformer.transform_name(node, 'Custom')
        final_name = transformed.get('name', node.get('name', 'Unknown'))
        
        nodes.append({
            "id": f"custom_{i}",
            "name": node.get('name', 'Unknown'),
            "display_name": final_name,
            "type": node.get('type', 'unknown'),
            "server": node.get('server', ''),
            "source": "custom"
        })
    
    # Add subscription nodes
    for sub in config.get('subscriptions', []):
        sub_id = sub.get('id')
        if not sub.get('enabled', True):
            continue
        
        try:
            sub_data = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=True)
            sub_nodes = sub_data.get('proxies', []) if sub_data else []
            
            for i, node in enumerate(sub_nodes):
                if not node.get('server'):
                    continue
                transformed = NameTransformer.transform_name(node, sub['name'])
                final_name = transformed.get('name', node.get('name', 'Unknown'))
                
                nodes.append({
                    "id": f"{sub_id}_{i}",
                    "name": node.get('name', 'Unknown'),
                    "display_name": final_name,
                    "type": node.get('type', 'unknown'),
                    "server": node.get('server', ''),
                    "source": sub['name']
                })
        except Exception as e:
            logger.warning(f"Failed to load subscription {sub_id}: {e}")
    
    return {"nodes": nodes, "count": len(nodes)}


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
