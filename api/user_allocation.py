"""User allocation helper routes."""

from typing import Callable

from fastapi import APIRouter, Depends

from core.dependencies import verify_session
from helpers import load_subscription_yaml
from services.name_transformer import NameTransformer
from services.node_visibility import is_node_enabled
from services.node_identity import custom_node_id, subscription_node_ids
from services.proxy_chain_references import list_proxy_chain_virtual_references
from services.proxy_filter import ProxyFilter


def create_user_allocation_router(
    *,
    yaml_source_dir: str,
    load_config: Callable[[], dict],
    get_all_final_node_names: Callable[[], set],
    logger,
) -> APIRouter:
    """Create routes used by the user node-allocation UI."""
    router = APIRouter()
    YAML_SOURCE_DIR = yaml_source_dir

    @router.get("/api/available-nodes", tags=["users"])
    async def get_available_nodes_for_users(_: bool = Depends(verify_session)):
        """Get all available nodes grouped by source for user allocation"""
        config = load_config()
        sources = {}

        # Get custom nodes first
        custom_nodes = config.get('custom_nodes', [])
        if custom_nodes:
            available_nodes = []
            for node in custom_nodes:
                if not is_node_enabled(node):
                    continue
                original_name = node.get('name', '')
                if not ProxyFilter.is_valid_proxy(node):
                    continue
                transformed = NameTransformer.transform_name(node, 'Custom')
                available_nodes.append({
                    'id': custom_node_id(node),
                    'name': transformed.get('name', original_name),
                })
            if available_nodes:
                sources['custom_nodes'] = {
                    'name': '自建节点',
                    'nodes': available_nodes
                }

        # Get subscription nodes
        for sub in config.get('subscriptions', []):
            if not sub.get('enabled', True):
                continue

            try:
                cfg = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=True)
                proxies = cfg.get('proxies', []) if cfg else []

                available_nodes = []
                unique_ids = subscription_node_ids(sub['id'], proxies)
                for proxy_index, proxy in enumerate(proxies):
                    if not is_node_enabled(proxy):
                        continue
                    original_name = proxy.get('name', '')
                    if not ProxyFilter.is_valid_proxy(proxy):
                        continue
                    transformed = NameTransformer.transform_name(proxy, sub['name'])
                    available_nodes.append({
                        'id': unique_ids[proxy_index],
                        'name': transformed.get('name', original_name),
                    })

                if available_nodes:
                    sources[sub['id']] = {
                        'name': sub['name'],
                        'nodes': available_nodes
                    }
            except Exception as e:
                logger.warning(f"Failed to load subscription {sub['id']}: {e}")

        # Get chain nodes and chain pools
        chain_references = list_proxy_chain_virtual_references(
            config,
            base_node_names=get_all_final_node_names(),
        )
        chain_nodes = [
            reference for reference in chain_references
            if reference.enabled and reference.source_id == 'chain_nodes'
        ]
        chain_pools = [
            reference for reference in chain_references
            if reference.enabled and reference.source_id == 'chain_pools'
        ]
        if chain_nodes:
            sources['chain_nodes'] = {
                'name': '链式代理单节点',
                'nodes': [
                    {'id': reference.stable_id, 'name': reference.name}
                    for reference in chain_nodes
                ]
            }
        if chain_pools:
            sources['chain_pools'] = {
                'name': '链式代理池',
                'nodes': [
                    {'id': reference.stable_id, 'name': reference.name}
                    for reference in chain_pools
                ]
            }

        return {"sources": sources}


    return router
