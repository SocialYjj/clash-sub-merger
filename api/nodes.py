"""
Nodes API
Custom nodes and subscription nodes management
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from core.config import AppConfig
from core.dependencies import verify_session
from core.database import load_config
from core.rate_limit import limiter
from helpers import (
    handle_api_errors,
    generate_timestamp_id,
    load_subscription_yaml,
)
from services.name_transformer import NameTransformer
from services.node_visibility import is_node_enabled
from services.node_parser import parse_node_link
from services.node_identity import (
    custom_node_id as get_custom_node_id,
    find_subscription_node_index,
    subscription_node_ids,
)
from services.custom_node_storage import update_custom_nodes
from services.node_reference_updates import update_subscription_yaml_with_references
from services.proxy_filter import ProxyFilter
from services.region_history import inherit_regions_for_nodes, remember_nodes_region
from geoip_service import GeoIPService, normalize_country_name, translate_city_name
from logger_config import SensitiveDataFilter, get_logger

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


def _resolve_region_info(node: dict, transformed: dict) -> dict:
    """Prefer tested/saved region info and fall back to name-derived country info."""
    derived = transformed.get('_country', {}) if isinstance(transformed, dict) else {}
    saved = node.get('region', {}) if isinstance(node, dict) else {}
    if not isinstance(saved, dict):
        saved = {}

    country_code = str(saved.get('country_code') or derived.get('country_code') or 'XX').upper()
    country = saved.get('country') or derived.get('country') or 'Unknown'
    flag = saved.get('flag') or derived.get('flag')

    if not flag:
        flag = GeoIPService.iso_to_flag(country_code) if country_code != 'XX' else '🏳️'

    if (not country or country == 'Unknown') and country_code:
        country = NameTransformer.ISO_TO_COUNTRY.get(country_code, country or 'Unknown')
    else:
        country = normalize_country_name(country, country_code) or country

    return {
        'country_code': country_code or 'XX',
        'country': country or 'Unknown',
        'flag': flag or '🏳️'
    }


def _resolve_city_name(node: dict) -> str:
    """Normalize saved city names so old English values also display in Chinese."""
    if not isinstance(node, dict):
        return ''
    city = str(node.get('city') or '').strip()
    return translate_city_name(city) if city else ''


# ==================== Data Models ====================

_NODE_ADMIN_FIELDS = {
    'id', 'link', 'enabled', 'display_name', 'index',
    'last_latency', 'last_latency_time', 'last_speed',
    'last_peak_speed', 'last_speed_time', 'exit_ip', 'geoip',
    'region', 'city',
}

class CustomNode(BaseModel):
    link: str = Field(min_length=1, max_length=2000)
    name: Optional[str] = Field(None, max_length=200)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v is None:
            return None
        normalized = v.strip()
        if not normalized:
            raise ValueError('Name cannot be empty')
        if '/' in normalized or '\\' in normalized or '..' in normalized:
            raise ValueError('Name contains invalid characters')
        return normalized


class UpdateNodeName(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        normalized = v.strip()
        if not normalized:
            raise ValueError('Name cannot be empty')
        if '/' in normalized or '\\' in normalized or '..' in normalized:
            raise ValueError('Name contains invalid characters')
        return normalized


class UpdateNodeFull(BaseModel):
    node: dict
    
    @field_validator('node')
    @classmethod
    def validate_node(cls, v):
        if not isinstance(v, dict):
            raise ValueError('Node must be a dictionary')
        # Ensure required fields exist
        if any(field in v for field in _NODE_ADMIN_FIELDS):
            raise ValueError('Node metadata fields cannot be changed')
        if any(str(key).startswith('_') for key in v):
            raise ValueError('Internal node fields cannot be changed')
        if not str(v.get('name') or '').strip():
            raise ValueError('Node must have a name')
        if not str(v.get('type') or '').strip():
            raise ValueError('Node must have a type')
        normalized = dict(v)
        normalized['name'] = str(v['name']).strip()
        normalized['type'] = str(v['type']).strip().lower()
        invalid_reason = ProxyFilter.get_structural_invalid_reason(normalized)
        if invalid_reason:
            raise ValueError(f'Invalid node configuration: {invalid_reason}')
        return normalized


class UpdateSubNode(BaseModel):
    name: str = Field(min_length=1, max_length=200)

    @field_validator('name')
    @classmethod
    def normalize_name(cls, value):
        normalized = value.strip()
        if not normalized:
            raise ValueError('Name cannot be empty')
        return normalized


class UpdateSubNodeFull(BaseModel):
    node: dict

    @field_validator('node')
    @classmethod
    def validate_node(cls, value):
        if not str(value.get('name') or '').strip() or not str(value.get('type') or '').strip():
            raise ValueError('Node must have a name and type')
        if any(field in value for field in _NODE_ADMIN_FIELDS):
            raise ValueError('Node metadata fields cannot be changed')
        if any(str(key).startswith('_') for key in value):
            raise ValueError('Internal node fields cannot be changed')
        normalized = dict(value)
        normalized['name'] = str(value['name']).strip()
        normalized['type'] = str(value['type']).strip().lower()
        invalid_reason = ProxyFilter.get_structural_invalid_reason(normalized)
        if invalid_reason:
            raise ValueError(f'Invalid node configuration: {invalid_reason}')
        return normalized


class ReorderNodes(BaseModel):
    order: List[str]


class BatchCustomNodes(BaseModel):
    links: List[str] = Field(min_items=1)
    names: Optional[List[str]] = None


class BatchDeleteNodes(BaseModel):
    ids: List[str] = Field(min_items=1)


def _display_enabled(node: dict) -> bool:
    return is_node_enabled(node)


def _subscription_node_index(nodes: list, sub_id: str, node_id: str) -> int:
    try:
        node_index = find_subscription_node_index(nodes, sub_id, node_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if node_index is None:
        raise HTTPException(status_code=404, detail="Node not found or subscription changed")
    return node_index


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
        enhanced['region'] = _resolve_region_info(node, transformed)
        enhanced['city'] = _resolve_city_name(node)
        enhanced['enabled'] = _display_enabled(node)
        
        enhanced_nodes.append(enhanced)
    
    return {"nodes": enhanced_nodes, "count": len(enhanced_nodes)}


@router.post("/custom-nodes")
@handle_api_errors
def add_custom_node(data: CustomNode, _: bool = Depends(verify_session)):
    """Add a custom node from link"""
    srv = _get_server()
    
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

    inherit_regions_for_nodes([node], source='custom:add')

    def append_custom_node(config: dict):
        config.setdefault('custom_nodes', []).append(node)
        return dict(node)

    node = update_custom_nodes(append_custom_node)
    srv.invalidate_stats_cache()
    
    return {"status": "success", "node": node}


@router.post("/custom-nodes/batch")
@handle_api_errors
def add_custom_nodes_batch(data: BatchCustomNodes, _: bool = Depends(verify_session)):
    """Batch add custom nodes from links"""
    srv = _get_server()

    links = [link.strip() for link in (data.links or []) if link and link.strip()]
    if not links:
        raise HTTPException(status_code=400, detail="No valid links provided")
    names = [name.strip() for name in (data.names or [])]

    added_nodes = []
    errors = []

    for idx, link in enumerate(links):
        parsed = parse_node_link(link)
        if not parsed:
            errors.append({'link': link, 'reason': 'Invalid node link format'})
            continue

        node_id = f"{generate_timestamp_id('node_')}_{idx}"
        node = {
            'id': node_id,
            'link': link,
            **parsed
        }
        if idx < len(names):
            custom_name = names[idx]
            if custom_name:
                node['name'] = custom_name
        added_nodes.append(node)

    if not added_nodes:
        raise HTTPException(status_code=400, detail="No valid nodes parsed")

    inherit_regions_for_nodes(added_nodes, source='custom:batch-add')

    def extend_custom_nodes(config: dict):
        config.setdefault('custom_nodes', []).extend(added_nodes)
        return len(added_nodes)

    update_custom_nodes(extend_custom_nodes)
    srv.invalidate_stats_cache()

    return {
        "status": "success",
        "added": len(added_nodes),
        "failed": len(errors),
        "errors": errors
    }


@router.delete("/custom-nodes/{node_id}")
@handle_api_errors
def delete_custom_node(node_id: str, _: bool = Depends(verify_session)):
    """Delete a custom node"""
    srv = _get_server()

    def remove_custom_node(config: dict):
        nodes = config.get('custom_nodes', [])
        remaining_nodes = [n for n in nodes if get_custom_node_id(n) != node_id]
        if len(remaining_nodes) == len(nodes):
            raise HTTPException(status_code=404, detail="Node not found")
        config['custom_nodes'] = remaining_nodes

    update_custom_nodes(remove_custom_node)
    srv.invalidate_stats_cache()
    return {"status": "success"}


@router.put("/custom-nodes/{node_id}/toggle")
@handle_api_errors
def toggle_custom_node(node_id: str, _: bool = Depends(verify_session)):
    """Toggle whether a custom node is included in generated subscriptions."""
    srv = _get_server()

    def toggle_node(config: dict) -> bool:
        for node in config.get('custom_nodes', []):
            if node.get('id') == node_id:
                node['enabled'] = not is_node_enabled(node)
                return node['enabled']

        raise HTTPException(status_code=404, detail="Node not found")

    enabled = update_custom_nodes(toggle_node)
    srv.invalidate_stats_cache()
    return {"status": "success", "enabled": enabled}


@router.post("/custom-nodes/batch-delete")
@handle_api_errors
def batch_delete_custom_nodes(data: BatchDeleteNodes, _: bool = Depends(verify_session)):
    """Batch delete custom nodes by IDs"""
    srv = _get_server()
    id_set = set(data.ids or [])

    if not id_set:
        raise HTTPException(status_code=400, detail="No node IDs provided")

    def remove_custom_nodes(config: dict) -> int:
        nodes = config.get('custom_nodes', [])
        remaining = [n for n in nodes if n.get('id') not in id_set]
        deleted_count = len(nodes) - len(remaining)
        if deleted_count:
            config['custom_nodes'] = remaining
        return deleted_count

    deleted_count = update_custom_nodes(remove_custom_nodes)
    if deleted_count == 0:
        return {"status": "success", "deleted": 0}

    srv.invalidate_stats_cache()
    return {"status": "success", "deleted": deleted_count}


@router.put("/custom-nodes/reorder")
@handle_api_errors
def reorder_custom_nodes(data: ReorderNodes, _: bool = Depends(verify_session)):
    """Reorder custom nodes"""
    srv = _get_server()

    def apply_custom_node_order(config: dict):
        nodes = config.get('custom_nodes', [])
        node_map = {n['id']: n for n in nodes}

        new_nodes = []
        for node_id in data.order:
            if node_id in node_map:
                new_nodes.append(node_map.pop(node_id))
        new_nodes.extend(node_map.values())

        config['custom_nodes'] = new_nodes

    update_custom_nodes(apply_custom_node_order)
    return {"status": "success"}


@router.post("/custom-nodes/reparse")
@handle_api_errors
def reparse_all_custom_nodes(_: bool = Depends(verify_session)):
    """Reparse all custom nodes from their links"""
    srv = _get_server()

    def reparse_nodes(config: dict) -> int:
        nodes = config.get('custom_nodes', [])

        updated_count = 0
        existing_nodes = [dict(node) for node in nodes]
        for node in nodes:
            if 'link' in node:
                parsed = parse_node_link(node['link'])
                if parsed:
                    node.update(parsed)
                    updated_count += 1

        remember_nodes_region(existing_nodes, source='custom:reparse-existing')
        inherit_regions_for_nodes(nodes, source='custom:reparse')
        return updated_count

    updated_count = update_custom_nodes(reparse_nodes)
    return {"status": "success", "updated": updated_count}


@router.post("/custom-nodes/{node_id}/reparse")
@handle_api_errors
def reparse_custom_node(node_id: str, _: bool = Depends(verify_session)):
    """Reparse a single custom node"""
    srv = _get_server()

    def reparse_node(config: dict) -> dict:
        for node in config.get('custom_nodes', []):
            if node['id'] == node_id and 'link' in node:
                previous = dict(node)
                parsed = parse_node_link(node['link'])
                if parsed:
                    previous_enabled = node.get('enabled')
                    remember_nodes_region([previous], source='custom:reparse-one-existing')
                    node.update(parsed)
                    if previous_enabled is not None:
                        node['enabled'] = previous_enabled
                    inherit_regions_for_nodes([node], source='custom:reparse-one')
                    return dict(node)
                raise HTTPException(status_code=400, detail="Failed to parse node link")

        raise HTTPException(status_code=404, detail="Node not found")

    node = update_custom_nodes(reparse_node)
    return {"status": "success", "node": node}


@router.put("/custom-nodes/{node_id}")
@handle_api_errors
def update_custom_node(node_id: str, data: UpdateNodeName, _: bool = Depends(verify_session)):
    """Update custom node name"""
    srv = _get_server()

    def rename_custom_node(config: dict) -> dict:
        for node in config.get('custom_nodes', []):
            if node['id'] == node_id:
                node['name'] = data.name
                return dict(node)

        raise HTTPException(status_code=404, detail="Node not found")

    node = update_custom_nodes(rename_custom_node)
    return {"status": "success", "node": node}


@router.put("/custom-nodes/{node_id}/full")
@handle_api_errors
def update_custom_node_full(node_id: str, data: UpdateNodeFull, _: bool = Depends(verify_session)):
    """Update custom node with full config"""
    srv = _get_server()

    def replace_custom_node(config: dict) -> dict:
        for i, node in enumerate(config.get('custom_nodes', [])):
            if node['id'] == node_id:
                updated = {'id': node_id, 'link': node.get('link', '')}
                updated.update(data.node)
                if 'enabled' not in updated and 'enabled' in node:
                    updated['enabled'] = node['enabled']
                config['custom_nodes'][i] = updated
                return dict(updated)

        raise HTTPException(status_code=404, detail="Node not found")

    updated = update_custom_nodes(replace_custom_node)
    return {"status": "success", "node": updated}


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

    node_ids = subscription_node_ids(sub_id, nodes)
    enhanced_nodes = []
    for i, node in enumerate(nodes):
        enhanced = dict(node)
        enhanced['index'] = i
        enhanced['id'] = node_ids[i]
        transformed = NameTransformer.transform_name(node, sub['name'])
        enhanced['display_name'] = transformed.get('name', node.get('name', 'Unknown'))
        enhanced['region'] = _resolve_region_info(node, transformed)
        enhanced['city'] = _resolve_city_name(node)
        enhanced['enabled'] = _display_enabled(node)
        
        enhanced_nodes.append(enhanced)
    
    return {"nodes": enhanced_nodes, "count": len(enhanced_nodes)}


@router.put("/subscriptions/{sub_id}/nodes/{node_id}")
@handle_api_errors
def update_subscription_node(sub_id: str, node_id: str, data: UpdateSubNode, _: bool = Depends(verify_session)):
    """Update subscription node name"""
    def rename_node(sub_data: dict):
        nodes = sub_data.get('proxies', []) if sub_data else []

        node_index = _subscription_node_index(nodes, sub_id, node_id)
        nodes[node_index]['name'] = data.name
        return dict(nodes[node_index])

    updated_node = update_subscription_yaml_with_references(sub_id, rename_node)

    return {"status": "success", "node": updated_node}


@router.put("/subscriptions/{sub_id}/nodes/{node_id}/full")
@handle_api_errors
def update_subscription_node_full(sub_id: str, node_id: str, data: UpdateSubNodeFull, _: bool = Depends(verify_session)):
    """Update subscription node with full config"""
    def replace_node(sub_data: dict):
        nodes = sub_data.get('proxies', []) if sub_data else []

        node_index = _subscription_node_index(nodes, sub_id, node_id)
        previous = nodes[node_index]
        updated = dict(data.node)
        if 'enabled' not in updated and isinstance(previous, dict) and 'enabled' in previous:
            updated['enabled'] = previous['enabled']
        nodes[node_index] = updated
        return dict(nodes[node_index])

    updated_node = update_subscription_yaml_with_references(sub_id, replace_node)

    return {"status": "success", "node": updated_node}


@router.put("/subscriptions/{sub_id}/nodes/{node_id}/toggle")
@handle_api_errors
def toggle_subscription_node(sub_id: str, node_id: str, _: bool = Depends(verify_session)):
    """Toggle whether a subscription node is included in generated subscriptions."""
    srv = _get_server()
    config = load_config()

    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    def toggle_node(sub_data: dict):
        nodes = sub_data.get('proxies', []) if sub_data else []

        node_index = _subscription_node_index(nodes, sub_id, node_id)
        nodes[node_index]['enabled'] = not is_node_enabled(nodes[node_index])
        return nodes[node_index]['enabled']

    enabled = update_subscription_yaml_with_references(sub_id, toggle_node)
    srv.invalidate_stats_cache()
    return {"status": "success", "enabled": enabled}


@router.delete("/subscriptions/{sub_id}/nodes/{node_id}")
@handle_api_errors
def delete_subscription_node(sub_id: str, node_id: str, _: bool = Depends(verify_session)):
    """Delete a node from subscription"""
    config = load_config()
    
    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    def remove_node(sub_data: dict):
        nodes = sub_data.get('proxies', []) if sub_data else []

        node_index = _subscription_node_index(nodes, sub_id, node_id)
        del nodes[node_index]
        return len(nodes)

    update_subscription_yaml_with_references(sub_id, remove_node)
    _get_server().invalidate_stats_cache()
    
    return {"status": "success"}


class NodeTestRequest(BaseModel):
    test_latency: bool = True
    test_speed: bool = False
    test_region: bool = False
    geoip_api: Optional[str] = None
    batch_mode: bool = False  # 批量模式下不立即保存
    # The node-management UI sends milliseconds, matching the Go delay/IP API.
    timeout: int = Field(
        default=AppConfig.SPEEDTEST_TIMEOUT * 1000,
        ge=1000,
        le=60000,
    )


class BatchSaveRequest(BaseModel):
    results: dict  # {source_id: {stable_node_id: {latency, speed, region, etc}}}


@router.post("/nodes/batch-save")
@limiter.limit(AppConfig.RATE_LIMIT_NODE_SAVE)
@handle_api_errors
async def batch_save_test_results(data: BatchSaveRequest, request: Request, _: bool = Depends(verify_session)):
    """批量保存所有测试结果"""
    from datetime import datetime
    
    saved_count = 0
    
    for source_id, nodes_data in data.results.items():
        if source_id == "custom":
            # 保存自定义节点
            def save_custom_results(config: dict):
                updated_region_nodes = []
                saved = 0
                custom_nodes = config.get('custom_nodes', [])
                for node_id, result in nodes_data.items():
                    node_index = next(
                        (
                            index
                            for index, candidate in enumerate(custom_nodes)
                            if get_custom_node_id(candidate) == node_id
                        ),
                        None,
                    )
                    if node_index is not None:
                        node = custom_nodes[node_index]
                        normalized_node = ProxyFilter.sanitize_proxy(node)
                        if normalized_node != node:
                            custom_nodes[node_index] = normalized_node
                            node = normalized_node
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
                        if 'region' in result:
                            updated_region_nodes.append(dict(node))
                        saved += 1
                return saved, updated_region_nodes

            custom_saved_count, updated_region_nodes = update_custom_nodes(save_custom_results)
            saved_count += custom_saved_count
            if updated_region_nodes:
                remember_nodes_region(updated_region_nodes, source='speedtest:custom-batch')
        else:
            # 保存订阅节点
            def save_subscription_results(sub_data: dict):
                saved = 0
                updated_region_nodes = []
                if not sub_data:
                    return saved, updated_region_nodes
                for node_id, result in nodes_data.items():
                    nodes = sub_data.get('proxies', [])
                    try:
                        node_index = find_subscription_node_index(nodes, source_id, node_id)
                    except ValueError:
                        logger.warning("Skipped ambiguous node identity while saving batch results")
                        continue
                    if node_index is not None:
                        node = nodes[node_index]
                        normalized_node = ProxyFilter.sanitize_proxy(node)
                        if normalized_node != node:
                            nodes[node_index] = normalized_node
                            node = normalized_node
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
                        if 'region' in result:
                            updated_region_nodes.append(node)
                        saved += 1
                return saved, updated_region_nodes

            source_saved_count, updated_region_nodes = update_subscription_yaml_with_references(
                source_id,
                save_subscription_results,
            )
            saved_count += source_saved_count
            if updated_region_nodes:
                remember_nodes_region(updated_region_nodes, source=f'speedtest:subscription-batch:{source_id}')
    
    return {"status": "success", "saved_count": saved_count}


@router.post("/nodes/{source_id}/{node_id}/test")
@limiter.limit(AppConfig.RATE_LIMIT_NODE_TEST)
@handle_api_errors
async def test_node(source_id: str, node_id: str, data: NodeTestRequest, request: Request, _: bool = Depends(verify_session)):
    """Test latency/speed/region for any node (subscription or custom)"""
    import asyncio
    import math
    from datetime import datetime
    from api.speedtest import (
        _go_speedtest_request,
        build_node_speedtest_payload,
    )
    
    if source_id == "custom":
        # Test custom node
        config = load_config()
        nodes = config.get('custom_nodes', [])
        node_index = next(
            (
                index
                for index, candidate in enumerate(nodes)
                if get_custom_node_id(candidate) == node_id
            ),
            None,
        )
        if node_index is None:
            raise HTTPException(status_code=404, detail="Node not found")

        node = nodes[node_index]
        persistent_custom_node_id = get_custom_node_id(node)
        is_custom = True
    else:
        # Test subscription node
        sub_data = load_subscription_yaml(source_id, YAML_SOURCE_DIR, use_cache=True)
        nodes = sub_data.get('proxies', []) if sub_data else []
        node_index = _subscription_node_index(nodes, source_id, node_id)
        node = nodes[node_index]
        persistent_custom_node_id = None
        is_custom = False

    normalized_node = ProxyFilter.sanitize_proxy(node)
    normalization_changed = normalized_node != node
    if normalization_changed:
        node = normalized_node
    
    result = {
        "success": True,
        "name": node.get('name', 'Unknown')
    }

    timeout_ms = data.timeout
    timeout_seconds = max(1, math.ceil(timeout_ms / 1000))
    
    need_save = normalization_changed
    
    try:
        base_payload, using_proxy = build_node_speedtest_payload(node)
        if using_proxy:
            result['using_proxy'] = True

        # Test latency
        if data.test_latency:
            latency_result = await _go_speedtest_request(
                "/api/delay",
                {
                    **base_payload,
                    "url": "https://cp.cloudflare.com/generate_204",
                    "timeout": timeout_ms,
                },
                # The Go service can try the primary latency URL plus two
                # fallbacks, each with the requested node timeout.
                timeout_seconds * 3 + 2,
            )
            latency = latency_result.get('latency', -1)
            result['latency'] = latency
            if not latency_result.get('success'):
                result['success'] = False
                result['error'] = latency_result.get('error', 'Latency test failed')
            else:
                node['last_latency'] = latency
                node['last_latency_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                need_save = True
            
        # Test region (get exit IP)
        if data.test_region:
            ip_result = await _go_speedtest_request(
                "/api/ip",
                {**base_payload, "timeout": timeout_ms},
                timeout_seconds + 2,
            )
            if ip_result.get('success'):
                exit_ip = ip_result.get('ip')
                result['exit_ip'] = exit_ip
                    
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
                            
                        node['exit_ip'] = exit_ip
                        node['region'] = {
                            'country': geo_result.get('country_name'),
                            'country_code': geo_result.get('iso_code'),
                            'flag': geo_result.get('flag')
                        }
                        node['city'] = geo_result.get('city')
                        remember_nodes_region([node], source=f'speedtest:single:{source_id}')
                        need_save = True
                    else:
                        result['success'] = False
                        result['error'] = 'GeoIP lookup failed'
            else:
                result['success'] = False
                result['error'] = ip_result.get('error', 'IP lookup failed')
            
        # Test speed
        if data.test_speed:
            speed_result = await _go_speedtest_request(
                "/api/speed",
                {
                    **base_payload,
                    "url": "https://speed.cloudflare.com/__down?bytes=10000000",
                    "timeout": timeout_seconds,
                    "mode": "average",
                },
                timeout_seconds + 5,
            )
            if speed_result.get('success'):
                speed = speed_result.get('speed', 0)
                result['speed'] = speed
                result['bytes'] = speed_result.get('bytes', 0)
                    
                node['last_speed'] = speed
                node['last_speed_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                need_save = True
            else:
                result['success'] = False
                result['error'] = speed_result.get('error', 'Speed test failed')
        
        # Do not acknowledge a successful test until its metadata is durable.
        if need_save and not data.batch_mode:
            def save_test_result():
                try:
                    if is_custom:
                        def save_custom_test_result(latest_config: dict):
                            latest_nodes = latest_config.get('custom_nodes', [])
                            target_index = None

                            for idx, candidate in enumerate(latest_nodes):
                                if get_custom_node_id(candidate) == persistent_custom_node_id:
                                    target_index = idx
                                    break

                            if target_index is None:
                                return

                            latest_node = ProxyFilter.sanitize_proxy(latest_nodes[target_index])
                            for field in (
                                'xhttp-opts', 'last_latency', 'last_latency_time',
                                'last_speed', 'last_speed_time', 'exit_ip', 'region', 'city'
                            ):
                                if field in node:
                                    latest_node[field] = node[field]
                            latest_nodes[target_index] = latest_node

                        update_custom_nodes(save_custom_test_result)
                    else:
                        def save_subscription_test_result(latest_sub_data: dict):
                            latest_nodes = latest_sub_data.get('proxies', []) if latest_sub_data else []
                            try:
                                target_index = find_subscription_node_index(
                                    latest_nodes,
                                    source_id,
                                    node_id,
                                )
                            except ValueError:
                                logger.warning("Skipped ambiguous node identity while saving test result")
                                return
                            if target_index is None:
                                return

                            latest_node = ProxyFilter.sanitize_proxy(latest_nodes[target_index])
                            for field in (
                                'xhttp-opts', 'last_latency', 'last_latency_time',
                                'last_speed', 'last_speed_time', 'exit_ip', 'region', 'city'
                            ):
                                if field in node:
                                    latest_node[field] = node[field]
                            latest_nodes[target_index] = latest_node

                        update_subscription_yaml_with_references(
                            source_id,
                            save_subscription_test_result,
                        )
                except Exception as e:
                    logger.error(f"Failed to save node test results: {e}")
                    raise
            
            await asyncio.to_thread(save_test_result)
        
        return result
        
    except Exception as e:
        logger.error(f"Node test error: {e}", exc_info=True)
        return {
            "success": False,
            "name": node.get('name', 'Unknown'),
            "error": SensitiveDataFilter.sanitize(str(e))[:500] or "Node test failed"
        }
