"""
Proxy Chains API
Proxy chain management endpoints
"""
from __future__ import annotations

import json
import time
from collections import Counter
from typing import Optional, List, Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.config import AppConfig
from core.dependencies import verify_session
from core.database import load_config, update_config
from helpers import handle_api_errors, generate_timestamp_id, load_subscription_yaml
from services.name_transformer import NameTransformer
from services.node_visibility import is_node_enabled
from services.proxy_filter import ProxyFilter
from services.node_identity import custom_node_id, subscription_node_ids
from services.vpngate import (
    VPNGATE_GROUP_SOURCE,
    get_vpngate_settings,
    get_vpngate_node,
    list_vpngate_nodes,
    list_vpngate_pools,
    normalize_vpngate_country_code,
    public_vpngate_pool,
    refresh_vpngate_cache,
)
from services.proxy_chain_references import (
    ensure_proxy_chain_component_ids,
    reconcile_proxy_chain_references,
    snapshot_with_chain_component_ids,
)
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()

YAML_SOURCE_DIR = AppConfig.YAML_SOURCE_DIR


# ==================== Data Models ====================

class ProxyChainNode(BaseModel):
    model_config = ConfigDict(extra='forbid')

    # type: 'node' (default) or 'group'
    type: Literal['node', 'group'] = 'node'
    sub_id: str | None = Field(None, max_length=200)
    node_id: str | None = Field(None, max_length=200)
    node_index: int | None = Field(None, ge=0)
    node_name: str | None = Field(None, max_length=300)
    # group fields (used when type == 'group')
    group_id: str | None = Field(None, max_length=100)
    group_name: str | None = Field(None, max_length=200)
    group_strategy: Literal['select', 'load-balance', 'url-test', 'fallback'] | None = None
    lb_strategy: Literal['round-robin', 'consistent-hashing', 'sticky-sessions'] | None = None
    group_url: str | None = Field(None, max_length=2048)
    group_interval: int | None = Field(None, ge=10, le=86400)
    group_tolerance: int | None = Field(None, ge=0, le=10000)
    group_source: Literal['nodes', 'vpngate'] | None = None
    vpngate_country_code: str | None = Field(None, max_length=2)
    group_nodes: list[ProxyChainNode] | None = Field(None, max_length=500)

    @field_validator('sub_id', 'node_id', 'node_name', 'group_name', 'group_id')
    @classmethod
    def normalize_text(cls, value):
        if value is None:
            return None
        return value.strip()

    @field_validator('vpngate_country_code')
    @classmethod
    def normalize_vpngate_country(cls, value):
        if value is None:
            return None
        normalized = normalize_vpngate_country_code(value)
        if normalized is None:
            raise ValueError('VPN Gate country code must be a two-letter ISO code')
        return normalized

    @model_validator(mode='after')
    def validate_reference(self):
        if self.type == 'group':
            if any(value is not None for value in (self.sub_id, self.node_id, self.node_index, self.node_name)):
                raise ValueError('Proxy group cannot contain a direct node reference')
            if not (self.group_name or '').strip():
                raise ValueError('Proxy group name cannot be empty')
            group_source = self.group_source or 'nodes'
            if group_source == VPNGATE_GROUP_SOURCE:
                if self.group_nodes:
                    raise ValueError('VPN Gate 动态池不能包含手动节点成员')
            else:
                if self.vpngate_country_code:
                    raise ValueError('VPN Gate country selection is only valid for VPN Gate groups')
                if not self.group_nodes:
                    raise ValueError('Proxy group must contain at least one node')
                if any(member.type != 'node' for member in self.group_nodes):
                    raise ValueError('Nested proxy groups are not supported')
            if self.group_url:
                from urllib.parse import urlsplit

                parsed_url = urlsplit(self.group_url)
                if parsed_url.scheme not in {'http', 'https'} or not parsed_url.hostname:
                    raise ValueError('Proxy group URL must use HTTP or HTTPS')
            return self
        if not self.sub_id or not self.node_id:
            raise ValueError('Proxy chain node requires sub_id and node_id')
        if any(
            value is not None
            for value in (
                self.group_id,
                self.group_name,
                self.group_strategy,
                self.lb_strategy,
                self.group_url,
                self.group_interval,
                self.group_tolerance,
                self.group_source,
                self.vpngate_country_code,
                self.group_nodes,
            )
        ):
            raise ValueError('Direct proxy node cannot contain group options')
        return self


class ProxyChainRow(BaseModel):
    model_config = ConfigDict(extra='forbid')

    row_id: str | None = Field(None, max_length=100, pattern=r'^[A-Za-z0-9_.-]+$')
    nodes: List[ProxyChainNode] = Field(min_length=2, max_length=20)

    @field_validator('nodes')
    @classmethod
    def validate_nodes(cls, value):
        if len(value) < 2:
            raise ValueError('Proxy chain row requires at least two hops')
        return value


class CreateProxyChain(BaseModel):
    model_config = ConfigDict(extra='forbid')

    name: str = Field(min_length=1, max_length=100)
    rows: List[ProxyChainRow] = Field(min_length=1, max_length=100)

    @field_validator('name')
    @classmethod
    def validate_name(cls, value):
        normalized_name = value.strip()
        if not normalized_name:
            raise ValueError('Name cannot be empty')
        return normalized_name


class UpdateProxyChain(BaseModel):
    model_config = ConfigDict(extra='forbid')

    name: Optional[str] = Field(None, max_length=100)
    rows: Optional[List[ProxyChainRow]] = Field(None, min_length=1, max_length=100)
    enabled: Optional[bool] = None

    @field_validator('name')
    @classmethod
    def validate_name(cls, value):
        if value is None:
            return None
        normalized_name = value.strip()
        if not normalized_name:
            raise ValueError('Name cannot be empty')
        return normalized_name


class ReorderProxyChains(BaseModel):
    order: List[str] = Field(max_length=1000)

    @field_validator('order')
    @classmethod
    def validate_order(cls, value):
        if len(value) != len(set(value)):
            raise ValueError('Proxy chain order contains duplicate IDs')
        return value


# ==================== Helper Functions ====================

def _get_all_nodes_for_chain(config: Optional[dict] = None):
    """Get all available nodes for proxy chain selection"""
    config = config if config is not None else load_config()
    nodes = []
    
    # Get subscription nodes
    for sub in config.get('subscriptions', []):
        if not sub.get('enabled', True):
            continue
        try:
            sub_data = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=True)
            proxies = sub_data.get('proxies', [])
            unique_ids = subscription_node_ids(sub['id'], proxies)
            for i, proxy in enumerate(proxies):
                if not is_node_enabled(proxy):
                    continue
                # Skip invalid/info nodes but keep original index
                if not ProxyFilter.is_valid_proxy(proxy):
                    continue
                transformed = NameTransformer.transform_name(proxy, sub['name'])
                nodes.append({
                    'sub_id': sub['id'],
                    'sub_name': sub['name'],
                    'node_id': unique_ids[i],
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
        if not is_node_enabled(node):
            continue
        if not ProxyFilter.is_valid_proxy(node):
            continue
        transformed = NameTransformer.transform_name(node, 'Custom')
        nodes.append({
            'sub_id': 'custom',
            'sub_name': 'Custom',
            'node_id': custom_node_id(node),
            'node_index': i,
            'node_name': transformed.get('name', node.get('name', 'Unknown')),
            'node_type': node.get('type', 'unknown'),
            'type': node.get('type', 'unknown'),
            'server': node.get('server', '')
        })

    # VPN Gate is represented as country-level dynamic pools in the chain
    # editor. Its individual OpenVPN profiles remain in the backend cache and
    # are expanded only when a subscription configuration is generated.
    if not list_vpngate_nodes() and get_vpngate_settings(config).get('enabled'):
        try:
            refresh_vpngate_cache()
        except Exception as exc:
            logger.warning("Failed to refresh VPN Gate nodes for chain picker: %s", type(exc).__name__)

    return nodes


def _validate_proxy_chain_references(rows: List[ProxyChainRow], config: Optional[dict] = None) -> None:
    reference_counts = Counter(
        (node.get('sub_id'), node.get('node_id'))
        for node in _get_all_nodes_for_chain(config)
    )
    for row in rows:
        for chain_node in row.nodes:
            if chain_node.type == 'group' and chain_node.group_source == VPNGATE_GROUP_SOURCE:
                if not list_vpngate_nodes(country_code=chain_node.vpngate_country_code):
                    detail = "VPN Gate 所选国家当前没有可用节点，请先更新节点源"
                    if not chain_node.vpngate_country_code:
                        detail = "VPN Gate 动态池当前没有可用节点，请先更新节点源"
                    raise HTTPException(status_code=400, detail=detail)
                continue
            if chain_node.type == 'node' and chain_node.sub_id == VPNGATE_GROUP_SOURCE:
                if not get_vpngate_node(
                    chain_node.node_id,
                    include_stale=False,
                ):
                    raise HTTPException(status_code=400, detail="Proxy chain contains a missing or disabled VPN Gate node")
                continue
            node_references = chain_node.group_nodes if chain_node.type == 'group' else [chain_node]
            for node_reference in node_references or []:
                count = reference_counts[(node_reference.sub_id, node_reference.node_id)]
                if count == 0:
                    raise HTTPException(status_code=400, detail="Proxy chain contains a missing or disabled node")
                if count > 1:
                    raise HTTPException(status_code=409, detail="Proxy chain contains an ambiguous duplicate node")


def _serialize_chain_node(node: ProxyChainNode, existing_node: dict | None = None) -> dict:
    stored_node = node.model_dump(
        exclude_none=True,
        exclude={'node_index', 'group_nodes'},
    )
    if node.type == 'group':
        if not stored_node.get('group_id') and isinstance(existing_node, dict):
            stored_node['group_id'] = existing_node.get('group_id')
        if not stored_node.get('group_id'):
            stored_node['group_id'] = generate_timestamp_id('grp_')
        if node.group_source != VPNGATE_GROUP_SOURCE:
            stored_node['group_nodes'] = [
                _serialize_chain_node(member)
                for member in node.group_nodes or []
            ]
    return stored_node


def _serialize_chain_rows(
    rows: List[ProxyChainRow],
    existing_rows: list[dict] | None = None,
) -> list[dict]:
    """Serialize rows while preserving their durable IDs across UI edits."""
    existing_rows = existing_rows if isinstance(existing_rows, list) else []
    serialized_rows = []
    used_row_ids: set[str] = set()
    used_existing_indexes: set[int] = set()

    def row_fingerprint(nodes) -> str:
        references = []
        for node in nodes or []:
            raw_node = node.model_dump(exclude_none=True) if isinstance(node, BaseModel) else node
            if not isinstance(raw_node, dict):
                references.append(None)
                continue
            if raw_node.get('type') == 'group':
                references.append({
                    'type': 'group',
                    'group_id': raw_node.get('group_id'),
                    'group_name': raw_node.get('group_name'),
                    'group_nodes': [
                        {
                            'sub_id': member.get('sub_id'),
                            'node_id': member.get('node_id'),
                        }
                        for member in raw_node.get('group_nodes', []) or []
                        if isinstance(member, dict)
                    ],
                })
            else:
                references.append({
                    'type': 'node',
                    'sub_id': raw_node.get('sub_id'),
                    'node_id': raw_node.get('node_id'),
                })
        return json.dumps(references, sort_keys=True, separators=(',', ':'))

    existing_fingerprints = [
        row_fingerprint(row.get('nodes', [])) if isinstance(row, dict) else ''
        for row in existing_rows
    ]
    for row_index, row in enumerate(rows):
        input_fingerprint = row_fingerprint(row.nodes)
        matching_index = next(
            (
                index for index, fingerprint in enumerate(existing_fingerprints)
                if index not in used_existing_indexes and fingerprint == input_fingerprint
            ),
            None,
        )
        if matching_index is None and row_index < len(existing_rows) and row_index not in used_existing_indexes:
            matching_index = row_index
        existing_row = existing_rows[matching_index] if matching_index is not None else None
        if matching_index is not None:
            used_existing_indexes.add(matching_index)
        existing_nodes = existing_row.get('nodes', []) if isinstance(existing_row, dict) else []
        stored_nodes = [
            _serialize_chain_node(
                node,
                existing_nodes[node_index] if node_index < len(existing_nodes) else None,
            )
            for node_index, node in enumerate(row.nodes)
        ]
        row_id = str(row.row_id or '').strip()
        if not row_id and isinstance(existing_row, dict):
            row_id = str(existing_row.get('row_id') or '').strip()
        if not row_id or row_id in used_row_ids:
            row_id = generate_timestamp_id('row_')
            while row_id in used_row_ids:
                row_id = generate_timestamp_id('row_')
        used_row_ids.add(row_id)
        serialized_rows.append({'row_id': row_id, 'nodes': stored_nodes})
    return serialized_rows


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
    return {
        "nodes": nodes,
        "count": len(nodes),
        "vpngate_pool": public_vpngate_pool(),
        "vpngate_pools": list_vpngate_pools(),
    }


@router.post("")
@handle_api_errors
def create_proxy_chain(data: CreateProxyChain, _: bool = Depends(verify_session)):
    """Create a new proxy chain"""
    def add_proxy_chain(config: dict) -> dict:
        ensure_proxy_chain_component_ids(config)
        previous_config = snapshot_with_chain_component_ids(config)
        _validate_proxy_chain_references(data.rows, config)
        if any(
            str(chain.get('name') or '').strip().casefold() == data.name.casefold()
            for chain in config.get('proxy_chains', [])
        ):
            raise HTTPException(status_code=409, detail="Proxy chain name already exists")
        chain_id = generate_timestamp_id('chain_')
        chain = {
            'id': chain_id,
            'name': data.name,
            'rows': _serialize_chain_rows(data.rows),
            'enabled': True,
            'created_at': int(time.time())
        }
        config.setdefault('proxy_chains', []).append(chain)
        ensure_proxy_chain_component_ids(config)
        reconcile_proxy_chain_references(config, previous_config)
        return dict(chain)

    chain = update_config(add_proxy_chain)
    
    return {"status": "success", "chain": chain}


@router.put("/reorder")
@handle_api_errors
def reorder_proxy_chains(data: ReorderProxyChains, _: bool = Depends(verify_session)):
    """Reorder proxy chains."""
    def apply_proxy_chain_order(config: dict):
        ensure_proxy_chain_component_ids(config)
        previous_config = snapshot_with_chain_component_ids(config)
        chains = config.get('proxy_chains', [])
        chain_by_id = {chain['id']: chain for chain in chains}

        ordered_chains = []
        for chain_id in data.order:
            if chain_id in chain_by_id:
                ordered_chains.append(chain_by_id.pop(chain_id))
        ordered_chains.extend(chain_by_id.values())

        config['proxy_chains'] = ordered_chains
        reconcile_proxy_chain_references(config, previous_config)

    update_config(apply_proxy_chain_order)
    return {"status": "success"}


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
    def apply_proxy_chain_update(config: dict) -> dict:
        ensure_proxy_chain_component_ids(config)
        previous_config = snapshot_with_chain_component_ids(config)
        if data.rows is not None:
            _validate_proxy_chain_references(data.rows, config)
        if data.name is not None and any(
            chain.get('id') != chain_id
            and str(chain.get('name') or '').strip().casefold() == data.name.casefold()
            for chain in config.get('proxy_chains', [])
        ):
            raise HTTPException(status_code=409, detail="Proxy chain name already exists")
        for chain in config.get('proxy_chains', []):
            if chain['id'] == chain_id:
                if data.name is not None:
                    chain['name'] = data.name
                if data.rows is not None:
                    chain['rows'] = _serialize_chain_rows(data.rows, chain.get('rows'))
                if data.enabled is not None:
                    chain['enabled'] = data.enabled
                ensure_proxy_chain_component_ids(config)
                reconcile_proxy_chain_references(config, previous_config)
                return dict(chain)

        raise HTTPException(status_code=404, detail="Proxy chain not found")

    chain = update_config(apply_proxy_chain_update)
    return {"status": "success", "chain": chain}


@router.put("/{chain_id}/toggle")
@handle_api_errors
def toggle_proxy_chain(chain_id: str, _: bool = Depends(verify_session)):
    """Toggle proxy chain enabled status"""
    def toggle_chain(config: dict) -> bool:
        ensure_proxy_chain_component_ids(config)
        previous_config = snapshot_with_chain_component_ids(config)
        for chain in config.get('proxy_chains', []):
            if chain['id'] == chain_id:
                chain['enabled'] = not chain.get('enabled', True)
                reconcile_proxy_chain_references(config, previous_config)
                return chain['enabled']

        raise HTTPException(status_code=404, detail="Proxy chain not found")

    enabled = update_config(toggle_chain)
    return {"status": "success", "enabled": enabled}


@router.delete("/{chain_id}")
@handle_api_errors
def delete_proxy_chain(chain_id: str, _: bool = Depends(verify_session)):
    """Delete proxy chain"""
    def remove_proxy_chain(config: dict):
        ensure_proxy_chain_component_ids(config)
        previous_config = snapshot_with_chain_component_ids(config)
        chains = config.get('proxy_chains', [])

        original_count = len(chains)
        config['proxy_chains'] = [c for c in chains if c['id'] != chain_id]

        if len(config['proxy_chains']) == original_count:
            raise HTTPException(status_code=404, detail="Proxy chain not found")
        reconcile_proxy_chain_references(config, previous_config)

    update_config(remove_proxy_chain)
    return {"status": "success"}
