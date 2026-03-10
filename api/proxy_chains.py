"""
Proxy Chains API
Proxy chain management endpoints
"""
import os
import time
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.dependencies import verify_session
from core.database import load_config, save_config
from helpers import handle_api_errors, generate_timestamp_id, load_subscription_yaml
from services.name_transformer import NameTransformer
from services.proxy_filter import ProxyFilter
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Get YAML_SOURCE_DIR from environment or default
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(BASE_DIR, 'data'))
YAML_SOURCE_DIR = os.path.join(DATA_DIR, 'uploads')


# ==================== Data Models ====================

class ProxyChainNode(BaseModel):
    # type: 'node' (default) or 'group'
    type: str = 'node'
    sub_id: str | None = None
    node_index: int | None = None
    node_name: str | None = None
    # group fields (used when type == 'group')
    group_name: str | None = None
    group_strategy: str | None = None
    lb_strategy: str | None = None
    group_nodes: list | None = None


class ProxyChainRow(BaseModel):
    nodes: List[ProxyChainNode]


class CreateProxyChain(BaseModel):
    name: str
    rows: List[ProxyChainRow]


class UpdateProxyChain(BaseModel):
    name: Optional[str] = None
    rows: Optional[List[ProxyChainRow]] = None
    enabled: Optional[bool] = None


class ReorderProxyChains(BaseModel):
    order: List[str]


# ==================== Helper Functions ====================

def _get_all_nodes_for_chain():
    """Get all available nodes for proxy chain selection"""
    config = load_config()
    nodes = []
    
    # Get subscription nodes
    for sub in config.get('subscriptions', []):
        if not sub.get('enabled', True):
            continue
        try:
            sub_data = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=True)
            for i, proxy in enumerate(sub_data.get('proxies', [])):
                # Skip invalid/info nodes but keep original index
                if not ProxyFilter.is_valid_proxy(proxy):
                    continue
                transformed = NameTransformer.transform_name(proxy, sub['name'])
                nodes.append({
                    'sub_id': sub['id'],
                    'sub_name': sub['name'],
                    'node_index': i,
                    'node_name': transformed.get('name', proxy.get('name', 'Unknown')),
                    'node_type': proxy.get('type', 'unknown'),
                    'type': proxy.get('type', 'unknown'),
                    'server': proxy.get('server', '')
                })
        except Exception as e:
            logger.warning(f"Failed to load subscription {sub['id']}: {e}")
    
    # Get custom nodes
    for i, node in enumerate(config.get('custom_nodes', [])):
        transformed = NameTransformer.transform_name(node, 'Custom')
        nodes.append({
            'sub_id': 'custom',
            'sub_name': 'Custom',
            'node_index': i,
            'node_name': transformed.get('name', node.get('name', 'Unknown')),
            'node_type': node.get('type', 'unknown'),
            'type': node.get('type', 'unknown'),
            'server': node.get('server', '')
        })
    
    return nodes


# ==================== API Endpoints ====================

@router.get("")
@handle_api_errors
def list_proxy_chains(_: bool = Depends(verify_session)):
    """List all proxy chains"""
    config = load_config()
    chains = config.get('proxy_chains', [])
    return {"chains": chains, "count": len(chains)}


@router.get("/available-nodes")
@handle_api_errors
def get_available_nodes_for_chain(_: bool = Depends(verify_session)):
    """Get all available nodes for proxy chain"""
    nodes = _get_all_nodes_for_chain()
    return {"nodes": nodes, "count": len(nodes)}


@router.post("")
@handle_api_errors
def create_proxy_chain(data: CreateProxyChain, _: bool = Depends(verify_session)):
    """Create a new proxy chain"""
    config = load_config()
    
    chain_id = generate_timestamp_id('chain_')
    chain = {
        'id': chain_id,
        'name': data.name,
        'rows': [{'nodes': [n.dict() for n in row.nodes]} for row in data.rows],
        'enabled': True,
        'created_at': int(time.time())
    }
    
    if 'proxy_chains' not in config:
        config['proxy_chains'] = []
    config['proxy_chains'].append(chain)
    save_config(config)
    
    return {"status": "success", "chain": chain}


@router.get("/{chain_id}")
@handle_api_errors
def get_proxy_chain(chain_id: str, _: bool = Depends(verify_session)):
    """Get proxy chain by ID"""
    config = load_config()
    
    for chain in config.get('proxy_chains', []):
        if chain['id'] == chain_id:
            return {"chain": chain}
    
    raise HTTPException(status_code=404, detail="Proxy chain not found")


@router.put("/{chain_id}")
@handle_api_errors
def update_proxy_chain(chain_id: str, data: UpdateProxyChain, _: bool = Depends(verify_session)):
    """Update proxy chain"""
    config = load_config()
    
    for chain in config.get('proxy_chains', []):
        if chain['id'] == chain_id:
            if data.name is not None:
                chain['name'] = data.name
            if data.rows is not None:
                chain['rows'] = [{'nodes': [n.dict() for n in row.nodes]} for row in data.rows]
            if data.enabled is not None:
                chain['enabled'] = data.enabled
            save_config(config)
            return {"status": "success", "chain": chain}
    
    raise HTTPException(status_code=404, detail="Proxy chain not found")


@router.put("/{chain_id}/toggle")
@handle_api_errors
def toggle_proxy_chain(chain_id: str, _: bool = Depends(verify_session)):
    """Toggle proxy chain enabled status"""
    config = load_config()
    
    for chain in config.get('proxy_chains', []):
        if chain['id'] == chain_id:
            chain['enabled'] = not chain.get('enabled', True)
            save_config(config)
            return {"status": "success", "enabled": chain['enabled']}
    
    raise HTTPException(status_code=404, detail="Proxy chain not found")


@router.delete("/{chain_id}")
@handle_api_errors
def delete_proxy_chain(chain_id: str, _: bool = Depends(verify_session)):
    """Delete proxy chain"""
    config = load_config()
    chains = config.get('proxy_chains', [])
    
    original_count = len(chains)
    config['proxy_chains'] = [c for c in chains if c['id'] != chain_id]
    
    if len(config['proxy_chains']) == original_count:
        raise HTTPException(status_code=404, detail="Proxy chain not found")
    
    save_config(config)
    return {"status": "success"}


@router.put("/reorder")
@handle_api_errors
def reorder_proxy_chains(data: ReorderProxyChains, _: bool = Depends(verify_session)):
    """Reorder proxy chains"""
    config = load_config()
    chains = config.get('proxy_chains', [])
    chain_map = {c['id']: c for c in chains}
    
    new_chains = []
    for chain_id in data.order:
        if chain_id in chain_map:
            new_chains.append(chain_map.pop(chain_id))
    new_chains.extend(chain_map.values())
    
    config['proxy_chains'] = new_chains
    save_config(config)
    return {"status": "success"}
