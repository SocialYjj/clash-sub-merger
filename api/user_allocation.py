"""User allocation helper routes."""

from typing import Callable

from fastapi import APIRouter, Depends

from core.dependencies import verify_session
from helpers import load_subscription_yaml
from services.name_transformer import NameTransformer
from services.node_visibility import is_node_enabled
from services.proxy_chain_utils import unique_group_name, unique_name


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

        # Info node keywords to filter out
        info_keywords = [
            '剩余流量', '套餐到期', '距离下次重置', '建议', '官网', '未到期',
            '剩余', '到期', '重置', '流量', '过期', '订阅', '网址', '公告',
            '群组', 'Telegram', 'TG', '客服', '续费', '购买', '套餐',
            '使用说明', '教程', '更新', '通知', '邀请', '返利'
        ]

        def is_info_node(name: str) -> bool:
            if not name:
                return True
            return any(kw in name for kw in info_keywords)

        # Get custom nodes first
        custom_nodes = config.get('custom_nodes', [])
        if custom_nodes:
            node_names = []
            for node in custom_nodes:
                if not is_node_enabled(node):
                    continue
                original_name = node.get('name', '')
                if is_info_node(original_name):
                    continue
                transformed = NameTransformer.transform_name(node, 'Custom')
                node_names.append(transformed.get('name', original_name))
            if node_names:
                sources['custom_nodes'] = {
                    'name': '自建节点',
                    'nodes': node_names
                }

        # Get subscription nodes
        for sub in config.get('subscriptions', []):
            if not sub.get('enabled', True):
                continue

            try:
                cfg = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=True)
                proxies = cfg.get('proxies', []) if cfg else []

                node_names = []
                for proxy in proxies:
                    if not is_node_enabled(proxy):
                        continue
                    original_name = proxy.get('name', '')
                    if is_info_node(original_name):
                        continue
                    transformed = NameTransformer.transform_name(proxy, sub['name'])
                    node_names.append(transformed.get('name', original_name))

                if node_names:
                    sources[sub['id']] = {
                        'name': sub['name'],
                        'nodes': node_names
                    }
            except Exception as e:
                logger.warning(f"Failed to load subscription {sub['id']}: {e}")

        # Get chain nodes and chain pools
        proxy_chains = config.get('proxy_chains', [])
        if proxy_chains:
            chain_nodes = []
            chain_pools = []

            existing_names = get_all_final_node_names()
            existing_group_names = set()

            for chain in proxy_chains:
                if not chain.get('enabled', True):
                    continue

                rows = chain.get('rows', [])
                for row_idx, row in enumerate(rows):
                    nodes = row.get('nodes', [])
                    if len(nodes) < 2:
                        continue

                    chain_name = chain.get('name', '')
                    if len(rows) > 1:
                        chain_name = f"{chain_name} #{row_idx + 1}"

                    # Collect transit groups and terminal group
                    terminal_group = None
                    transit_groups = []
                    for idx, node_ref in enumerate(nodes):
                        if isinstance(node_ref, dict) and node_ref.get('type') == 'group':
                            if idx == len(nodes) - 1:
                                terminal_group = node_ref
                            else:
                                transit_groups.append(node_ref)

                    # Record transit pools
                    for t_idx, spec in enumerate(transit_groups):
                        base_name = spec.get('group_name') or f"{chain_name} 中转池{t_idx + 1}"
                        group_name = unique_group_name(
                            f"🔀 {base_name}",
                            existing_group_names,
                            spec.get('group_id'),
                        )
                        if group_name not in chain_pools:
                            chain_pools.append(group_name)

                    # Record terminal pool
                    if terminal_group:
                        group_base_name = terminal_group.get('group_name') or f"{chain_name} 落地池"
                        group_name = unique_group_name(
                            f"🔀 {group_base_name}",
                            existing_group_names,
                            terminal_group.get('group_id'),
                        )
                        if group_name not in chain_pools:
                            chain_pools.append(group_name)
                    else:
                        # Normal chain (no terminal pool)
                        chain_name_full = f"🔗 {chain_name}"
                        chain_nodes.append(unique_name(chain_name_full, existing_names))

            if chain_nodes:
                sources['chain_nodes'] = {
                    'name': '链式代理单节点',
                    'nodes': chain_nodes
                }
            if chain_pools:
                sources['chain_pools'] = {
                    'name': '链式代理池',
                    'nodes': chain_pools
                }

        return {"sources": sources}


    return router
