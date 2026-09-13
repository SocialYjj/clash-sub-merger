"""Proxy-group assembly helpers for node pools and chain pools."""

from dataclasses import dataclass
from typing import Callable, Optional

from services.config_merger import ProxyGroupGenerator
from services.node_pool_references import pool_strategy_config


@dataclass
class PoolContext:
    """Mutable accumulators shared by the pool/chain group assembly phase."""

    proxy_groups: list  # mutated in place by insert_pool_group
    pool_group_names: list[str]  # emitted chain/transit pool group names
    node_pool_group_names: list[str]  # emitted node pool group names
    emitted_chain_reference_names: dict[str, str]  # stable reference id -> emitted name


def is_allocated_proxy(
    proxy: dict,
    *,
    source_allocations: dict,
    node_pool_member_keys: set,
    is_name_allocated: Callable[[str, Optional[list]], bool],
) -> bool:
    source_id = proxy.get("_source_id")
    allocated_nodes = source_allocations.get(source_id)
    if allocated_nodes:
        if allocated_nodes == ["*"]:
            return True
        if is_name_allocated(
            proxy.get("name", ""),
            allocated_nodes,
            proxy.get("_allocation_id"),
        ):
            return True
    return (
        source_id,
        proxy.get("_allocation_id"),
    ) in node_pool_member_keys


def insert_pool_group(group_cfg: dict, ctx: PoolContext) -> None:
    group_name = group_cfg.get("name")
    if not group_name:
        return
    ctx.proxy_groups[:] = [g for g in ctx.proxy_groups if g.get("name") != group_name]

    insert_idx = next((i for i, g in enumerate(ctx.proxy_groups) if g.get("name") == "🔯 故障转移"), -1)
    if insert_idx == -1:
        country_names = set(ProxyGroupGenerator.COUNTRY_ORDER)
        insert_idx = next(
            (i for i, g in enumerate(ctx.proxy_groups) if g.get("name") in country_names), len(ctx.proxy_groups)
        )
    else:
        insert_idx += 1
        generated_pool_names = {*ctx.pool_group_names, *ctx.node_pool_group_names}
        while insert_idx < len(ctx.proxy_groups) and ctx.proxy_groups[insert_idx].get("name") in generated_pool_names:
            insert_idx += 1
    ctx.proxy_groups.insert(insert_idx, group_cfg)


def add_node_pool_groups(
    ctx: PoolContext,
    *,
    proxies: list,
    node_pools: list,
    selected_node_pool_ids: set,
    resolved_node_pool_references: list,
) -> None:
    """Emit one group per enabled pool and its selected leaf nodes."""
    for pool in node_pools:
        pool_id = str(pool.get("id") or "")
        reference = next(
            (item for item in resolved_node_pool_references if item.pool_id == pool_id),
            None,
        )
        if reference is None or not reference.enabled or pool_id not in selected_node_pool_ids:
            continue
        member_names: list[str] = []
        for member in pool.get("nodes", []) or []:
            if not isinstance(member, dict):
                continue
            member_source = str(member.get("sub_id") or "")
            if member_source in {"custom", "custom_nodes"}:
                member_source = "custom_nodes"
            member_id = str(member.get("node_id") or "")
            for proxy in proxies:
                if not isinstance(proxy, dict):
                    continue
                if proxy.get("_source_id") == member_source and proxy.get("_allocation_id") == member_id:
                    name = proxy.get("name")
                    if name and name not in member_names:
                        member_names.append(name)
                    break
        if not member_names:
            continue
        group_cfg = {
            "name": reference.name,
            "proxies": member_names,
        }
        group_cfg.update(pool_strategy_config(pool))
        if reference.name not in ctx.node_pool_group_names:
            ctx.node_pool_group_names.append(reference.name)
        insert_pool_group(group_cfg, ctx)
        ctx.emitted_chain_reference_names[reference.stable_id] = reference.name
