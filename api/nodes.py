"""
Nodes API
Custom nodes and subscription nodes management
"""
import os
import time
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, validator

from core.dependencies import verify_session
from core.database import load_config, save_config
from helpers import handle_api_errors, generate_timestamp_id, load_subscription_yaml, save_subscription_yaml
from services.name_transformer import NameTransformer
from services.node_parser import parse_node_link
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

class CustomNode(BaseModel):
    link: str = Field(min_length=1, max_length=2000)
    name: Optional[str] = Field(None, max_length=200)
    
    @validator('name')
    def validate_name(cls, v):
        if v and ('/' in v or '\\' in v or '..' in v):
            raise ValueError('Name contains invalid characters')
        return v


class UpdateNodeName(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    
    @validator('name')
    def validate_name(cls, v):
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError('Name contains invalid characters')
        return v


class UpdateNodeFull(BaseModel):
    node: dict


class UpdateSubNode(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class UpdateSubNodeFull(BaseModel):
    node: dict


class ReorderNodes(BaseModel):
    order: List[str]


# ==================== Custom Nodes API ====================

@router.get("/custom-nodes")
@handle_api_errors
def get_custom_nodes(_: bool = Depends(verify_session)):
    """Get all custom nodes with enhanced info"""
    config = load_config()
    nodes = config.get('custom_nodes', [])
    
    enhanced_nodes = []
    for node in nodes:
        enhanced = dict(node)
        transformed = NameTransformer.transform_name(node, 'Custom')
        enhanced['display_name'] = transformed.get('name', node.get('name', 'Unknown'))
        
        # Add region info (frontend expects 'region' field)
        country_info = transformed.get('_country', {})
        enhanced['region'] = {
            'country_code': country_info.get('country_code', 'XX'),
            'country': country_info.get('country', 'Unknown'),
            'flag': country_info.get('flag', '🏳️')
        }
        
        enhanced_nodes.append(enhanced)
    
    return {"nodes": enhanced_nodes, "count": len(enhanced_nodes)}


@router.post("/custom-nodes")
@handle_api_errors
def add_custom_node(data: CustomNode, _: bool = Depends(verify_session)):
    """Add a custom node from link"""
    srv = _get_server()
    config = load_config()
    
    parsed = parse_node_link(data.link)
    if not parsed:
        raise HTTPException(status_code=400, detail="Invalid node link format")
    
    node_id = generate_timestamp_id('node_')
    node = {
        'id': node_id,
        'link': data.link,
        **parsed
    }
    
    if data.name:
        node['name'] = data.name
    
    if 'custom_nodes' not in config:
        config['custom_nodes'] = []
    config['custom_nodes'].append(node)
    save_config(config)
    srv.update_custom_nodes_yaml()
    srv.invalidate_stats_cache()
    
    return {"status": "success", "node": node}


@router.delete("/custom-nodes/{node_id}")
@handle_api_errors
def delete_custom_node(node_id: str, _: bool = Depends(verify_session)):
    """Delete a custom node"""
    srv = _get_server()
    config = load_config()
    nodes = config.get('custom_nodes', [])
    config['custom_nodes'] = [n for n in nodes if n['id'] != node_id]
    save_config(config)
    srv.update_custom_nodes_yaml()
    srv.invalidate_stats_cache()
    return {"status": "success"}


@router.put("/custom-nodes/reorder")
@handle_api_errors
def reorder_custom_nodes(data: ReorderNodes, _: bool = Depends(verify_session)):
    """Reorder custom nodes"""
    srv = _get_server()
    config = load_config()
    nodes = config.get('custom_nodes', [])
    node_map = {n['id']: n for n in nodes}
    
    new_nodes = []
    for node_id in data.order:
        if node_id in node_map:
            new_nodes.append(node_map.pop(node_id))
    new_nodes.extend(node_map.values())
    
    config['custom_nodes'] = new_nodes
    save_config(config)
    srv.update_custom_nodes_yaml()
    return {"status": "success"}


@router.post("/custom-nodes/reparse")
@handle_api_errors
def reparse_all_custom_nodes(_: bool = Depends(verify_session)):
    """Reparse all custom nodes from their links"""
    srv = _get_server()
    config = load_config()
    nodes = config.get('custom_nodes', [])
    
    updated_count = 0
    for node in nodes:
        if 'link' in node:
            parsed = parse_node_link(node['link'])
            if parsed:
                node.update(parsed)
                updated_count += 1
    
    save_config(config)
    srv.update_custom_nodes_yaml()
    return {"status": "success", "updated": updated_count}


@router.post("/custom-nodes/{node_id}/reparse")
@handle_api_errors
def reparse_custom_node(node_id: str, _: bool = Depends(verify_session)):
    """Reparse a single custom node"""
    srv = _get_server()
    config = load_config()
    
    for node in config.get('custom_nodes', []):
        if node['id'] == node_id and 'link' in node:
            parsed = parse_node_link(node['link'])
            if parsed:
                node.update(parsed)
                save_config(config)
                srv.update_custom_nodes_yaml()
                return {"status": "success", "node": node}
            raise HTTPException(status_code=400, detail="Failed to parse node link")
    
    raise HTTPException(status_code=404, detail="Node not found")


@router.put("/custom-nodes/{node_id}")
@handle_api_errors
def update_custom_node(node_id: str, data: UpdateNodeName, _: bool = Depends(verify_session)):
    """Update custom node name"""
    srv = _get_server()
    config = load_config()
    
    for node in config.get('custom_nodes', []):
        if node['id'] == node_id:
            node['name'] = data.name
            save_config(config)
            srv.update_custom_nodes_yaml()
            return {"status": "success", "node": node}
    
    raise HTTPException(status_code=404, detail="Node not found")


@router.put("/custom-nodes/{node_id}/full")
@handle_api_errors
def update_custom_node_full(node_id: str, data: UpdateNodeFull, _: bool = Depends(verify_session)):
    """Update custom node with full config"""
    srv = _get_server()
    config = load_config()
    
    for i, node in enumerate(config.get('custom_nodes', [])):
        if node['id'] == node_id:
            updated = {'id': node_id, 'link': node.get('link', '')}
            updated.update(data.node)
            config['custom_nodes'][i] = updated
            save_config(config)
            srv.update_custom_nodes_yaml()
            return {"status": "success", "node": updated}
    
    raise HTTPException(status_code=404, detail="Node not found")


# ==================== Subscription Nodes API ====================

@router.get("/subscriptions/{sub_id}/nodes")
@handle_api_errors
def get_subscription_nodes(sub_id: str, _: bool = Depends(verify_session)):
    """Get nodes from a subscription"""
    config = load_config()
    
    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    sub_data = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=True)
    
    # Handle case where YAML content is a string (invalid format)
    if isinstance(sub_data, str):
        logger.warning(f"Subscription {sub_id} YAML is a string, not a dict. Returning empty nodes.")
        nodes = []
    else:
        nodes = sub_data.get('proxies', []) if sub_data else []
    
    enhanced_nodes = []
    for i, node in enumerate(nodes):
        enhanced = dict(node)
        enhanced['index'] = i
        transformed = NameTransformer.transform_name(node, sub['name'])
        enhanced['display_name'] = transformed.get('name', node.get('name', 'Unknown'))
        
        # Add region info (frontend expects 'region' field)
        country_info = transformed.get('_country', {})
        enhanced['region'] = {
            'country_code': country_info.get('country_code', 'XX'),
            'country': country_info.get('country', 'Unknown'),
            'flag': country_info.get('flag', '🏳️')
        }
        
        enhanced_nodes.append(enhanced)
    
    return {"nodes": enhanced_nodes, "count": len(enhanced_nodes)}


@router.put("/subscriptions/{sub_id}/nodes/{node_index}")
@handle_api_errors
def update_subscription_node(sub_id: str, node_index: int, data: UpdateSubNode, _: bool = Depends(verify_session)):
    """Update subscription node name"""
    sub_data = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=False)
    nodes = sub_data.get('proxies', []) if sub_data else []
    
    if node_index < 0 or node_index >= len(nodes):
        raise HTTPException(status_code=404, detail="Node not found")
    
    nodes[node_index]['name'] = data.name
    save_subscription_yaml(sub_id, {'proxies': nodes}, YAML_SOURCE_DIR)
    
    return {"status": "success", "node": nodes[node_index]}


@router.put("/subscriptions/{sub_id}/nodes/{node_index}/full")
@handle_api_errors
def update_subscription_node_full(sub_id: str, node_index: int, data: UpdateSubNodeFull, _: bool = Depends(verify_session)):
    """Update subscription node with full config"""
    sub_data = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=False)
    nodes = sub_data.get('proxies', []) if sub_data else []
    
    if node_index < 0 or node_index >= len(nodes):
        raise HTTPException(status_code=404, detail="Node not found")
    
    nodes[node_index] = data.node
    save_subscription_yaml(sub_id, {'proxies': nodes}, YAML_SOURCE_DIR)
    
    return {"status": "success", "node": nodes[node_index]}


@router.delete("/subscriptions/{sub_id}/nodes/{node_index}")
@handle_api_errors
def delete_subscription_node(sub_id: str, node_index: int, _: bool = Depends(verify_session)):
    """Delete a node from subscription"""
    config = load_config()
    
    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    sub_data = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=False)
    nodes = sub_data.get('proxies', []) if sub_data else []
    
    if node_index < 0 or node_index >= len(nodes):
        raise HTTPException(status_code=404, detail="Node not found")
    
    del nodes[node_index]
    save_subscription_yaml(sub_id, {'proxies': nodes}, YAML_SOURCE_DIR)
    
    sub['node_count'] = len(nodes)
    save_config(config)
    
    return {"status": "success"}


class NodeTestRequest(BaseModel):
    test_latency: bool = True
    test_speed: bool = False
    test_region: bool = False
    geoip_api: Optional[str] = None
    batch_mode: bool = False  # 批量模式下不立即保存


class BatchSaveRequest(BaseModel):
    results: dict  # {source_id: {node_index: {latency, speed, region, etc}}}


@router.post("/nodes/batch-save")
@handle_api_errors
async def batch_save_test_results(data: BatchSaveRequest, _: bool = Depends(verify_session)):
    """批量保存所有测试结果"""
    from datetime import datetime
    
    saved_count = 0
    
    for source_id, nodes_data in data.results.items():
        if source_id == "custom":
            # 保存自定义节点
            config = load_config()
            for node_index_str, result in nodes_data.items():
                node_index = int(node_index_str)
                if 0 <= node_index < len(config.get('custom_nodes', [])):
                    node = config['custom_nodes'][node_index]
                    if 'latency' in result:
                        node['last_latency'] = result['latency']
                        node['last_latency_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if 'speed' in result:
                        node['last_speed'] = result['speed']
                        node['last_speed_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if 'exit_ip' in result:
                        node['exit_ip'] = result['exit_ip']
                    if 'region' in result:
                        node['region'] = result['region']
                    if 'city' in result:
                        node['city'] = result['city']
                    saved_count += 1
            save_config(config)
        else:
            # 保存订阅节点
            sub_data = load_subscription_yaml(source_id, YAML_SOURCE_DIR, use_cache=False)
            if sub_data:
                for node_index_str, result in nodes_data.items():
                    node_index = int(node_index_str)
                    nodes = sub_data.get('proxies', [])
                    if 0 <= node_index < len(nodes):
                        node = nodes[node_index]
                        if 'latency' in result:
                            node['last_latency'] = result['latency']
                            node['last_latency_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        if 'speed' in result:
                            node['last_speed'] = result['speed']
                            node['last_speed_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        if 'exit_ip' in result:
                            node['exit_ip'] = result['exit_ip']
                        if 'region' in result:
                            node['region'] = result['region']
                        if 'city' in result:
                            node['city'] = result['city']
                        saved_count += 1
                save_subscription_yaml(source_id, sub_data, YAML_SOURCE_DIR)
    
    return {"status": "success", "saved_count": saved_count}


@router.post("/nodes/{source_id}/{node_index}/test")
@handle_api_errors
async def test_node(source_id: str, node_index: int, data: NodeTestRequest, _: bool = Depends(verify_session)):
    """Test latency/speed/region for any node (subscription or custom)"""
    import aiohttp
    import asyncio
    from datetime import datetime
    
    if source_id == "custom":
        # Test custom node
        config = load_config()
        nodes = config.get('custom_nodes', [])
        
        if node_index < 0 or node_index >= len(nodes):
            raise HTTPException(status_code=404, detail="Node not found")
        
        node = nodes[node_index]
        is_custom = True
    else:
        # Test subscription node
        sub_data = load_subscription_yaml(source_id, YAML_SOURCE_DIR, use_cache=True)
        nodes = sub_data.get('proxies', []) if sub_data else []
        
        if node_index < 0 or node_index >= len(nodes):
            raise HTTPException(status_code=404, detail="Node not found")
        
        node = nodes[node_index]
        is_custom = False
    
    # Call Go speedtest service
    go_port = os.environ.get('GO_SPEEDTEST_PORT', '9876')
    result = {
        "success": True,
        "name": node.get('name', 'Unknown')
    }
    
    need_save = False
    
    try:
        async with aiohttp.ClientSession() as session:
            # Test latency
            if data.test_latency:
                async with session.post(
                    f"http://127.0.0.1:{go_port}/api/delay",
                    json={
                        "node": node,
                        "url": "http://www.gstatic.com/generate_204",
                        "timeout": 5000
                    },
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    latency_result = await resp.json()
                    latency = latency_result.get('latency', -1)
                    result['latency'] = latency
                    if not latency_result.get('success'):
                        result['error'] = latency_result.get('error', 'Latency test failed')
                    else:
                        # Save latency to node
                        node['last_latency'] = latency
                        node['last_latency_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        need_save = True
            
            # Test region (get exit IP)
            if data.test_region:
                async with session.post(
                    f"http://127.0.0.1:{go_port}/api/ip",
                    json={
                        "node": node,
                        "timeout": 5000
                    },
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    ip_result = await resp.json()
                    if ip_result.get('success'):
                        exit_ip = ip_result.get('ip')
                        result['exit_ip'] = exit_ip
                        
                        # Lookup region for the exit IP
                        if exit_ip:
                            from geoip_service import lookup_ip_online
                            geo_result = await lookup_ip_online(exit_ip, api_id=data.geoip_api)
                            if geo_result:
                                result['region'] = {
                                    'country': geo_result.get('country_name'),
                                    'country_code': geo_result.get('iso_code'),
                                    'flag': geo_result.get('flag'),
                                    'display': geo_result.get('country_name')
                                }
                                result['city'] = geo_result.get('city')
                                
                                # Save region info to node
                                node['exit_ip'] = exit_ip
                                node['region'] = {
                                    'country': geo_result.get('country_name'),
                                    'country_code': geo_result.get('iso_code'),
                                    'flag': geo_result.get('flag')
                                }
                                node['city'] = geo_result.get('city')
                                need_save = True
                    else:
                        result['error'] = ip_result.get('error', 'IP lookup failed')
            
            # Test speed
            if data.test_speed:
                async with session.post(
                    f"http://127.0.0.1:{go_port}/api/speed",
                    json={
                        "node": node,
                        "url": "https://speed.cloudflare.com/__down?bytes=10000000",
                        "timeout": 10,
                        "mode": "average"
                    },
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    speed_result = await resp.json()
                    if speed_result.get('success'):
                        speed = speed_result.get('speed', 0)
                        result['speed'] = speed
                        result['bytes'] = speed_result.get('bytes', 0)
                        
                        # Save speed to node
                        node['last_speed'] = speed
                        node['last_speed_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        need_save = True
                    else:
                        result['error'] = speed_result.get('error', 'Speed test failed')
        
        # Async save in background (don't block response)
        if need_save and not data.batch_mode:
            async def save_in_background():
                try:
                    if is_custom:
                        config['custom_nodes'][node_index] = node
                        save_config(config)
                    else:
                        sub_data['proxies'][node_index] = node
                        save_subscription_yaml(source_id, sub_data, YAML_SOURCE_DIR)
                except Exception as e:
                    logger.error(f"Failed to save node test results: {e}")
            
            # Fire and forget - don't wait for save to complete
            asyncio.create_task(save_in_background())
        
        return result
        
    except Exception as e:
        logger.error(f"Node test error: {e}", exc_info=True)
        return {
            "success": False,
            "name": node.get('name', 'Unknown'),
            "error": str(e)
        }
