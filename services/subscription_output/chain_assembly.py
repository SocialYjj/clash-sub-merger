"""Proxy-chain assembly helpers extracted from the subscription route."""

import re
from dataclasses import dataclass
from typing import Callable, Optional

from services.name_transformer import NameTransformer
from services.node_identity import proxy_chain_virtual_node_id, virtual_node_id
from services.node_manager import normalize_alloc_name
from services.proxy_chain_utils import coerce_group_strategy, unique_group_name, unique_name
from services.vpngate import VPNGATE_SOURCE_ID

from .pool_assembly import PoolContext, insert_pool_group


@dataclass
class ChainContext:
    """Mutable accumulators and injected lookups shared by chain assembly."""

    pool: PoolContext
    user_allocations: Optional[dict]
    existing_names: set[str]
    existing_group_names: set[str]
    resolved_chain_reference_names: dict[str, str]
    chain_proxies: list
    chain_dependency_proxies: list
    chain_dependency_names: set[str]
    chain_proxy_names: list[str]
    find_node_by_reference: Callable
    filter_underscore_fields: Callable
    extract_country_from_name: Callable


def short_node_name(name: str) -> str:
    if not name:
        return ""
    clean = NameTransformer.remove_flags(name)
    if " " in clean:
        clean = clean.split(" ", 1)[1]
    return clean.strip()


def hop_name(hop: dict) -> str:
    if not hop:
        return ""
    if hop.get("type") == "group":
        return hop.get("name", "")
    return hop.get("name", "")


def build_chain_entry(
    ctx: ChainContext,
    chain_display_name: str,
    chain_nodes: list,
    add_to_manual: bool = True,
    include_country_info: bool = True,
    allow_name: Callable[[str], bool] | None = None,
    owned_name: str | None = None,
) -> str | None:
    """Build chain proxies for given nodes and return the final chain proxy name."""
    if len(chain_nodes) < 2:
        return None

    last_node = chain_nodes[-1]
    if last_node.get("type") == "group":
        return None
    chain_proxy = dict(last_node)

    last_node_name = last_node.get("name", "")
    last_node_server = last_node.get("server", "")
    chain_country_info = ctx.extract_country_from_name(last_node_name, last_node_server)

    if owned_name:
        final_chain_name = owned_name
        ctx.existing_names.add(final_chain_name)
    else:
        final_chain_name = unique_name(chain_display_name, ctx.existing_names)
    if allow_name and not allow_name(final_chain_name):
        return None

    chain_proxy["name"] = final_chain_name
    if include_country_info and chain_country_info:
        chain_proxy["_country_info"] = chain_country_info

    if len(chain_nodes) == 2:
        prev_name = hop_name(chain_nodes[0])
        if not prev_name:
            return None
        chain_proxy["dialer-proxy"] = prev_name
    else:
        prev_proxy_name = hop_name(chain_nodes[0])
        if not prev_proxy_name:
            return None
        intermediates = []
        for i in range(1, len(chain_nodes) - 1):
            hop = chain_nodes[i]
            hop_display = hop_name(hop)
            if hop.get("type") == "group":
                if not hop_display:
                    return None
                prev_proxy_name = hop_display
                continue
            intermediate = dict(hop)
            intermediate_name = unique_name(f"{chain_display_name} (via {i})", ctx.existing_names)
            intermediate["name"] = intermediate_name
            intermediate["dialer-proxy"] = prev_proxy_name
            intermediates.append(intermediate)
            if add_to_manual:
                ctx.chain_proxy_names.append(intermediate_name)
            prev_proxy_name = intermediate_name
        chain_proxy["dialer-proxy"] = prev_proxy_name
        for intermediate in intermediates:
            ctx.chain_proxies.append(intermediate)

    ctx.chain_proxies.append(chain_proxy)
    if add_to_manual:
        ctx.chain_proxy_names.append(chain_proxy["name"])
    return chain_proxy["name"]


def include_chain_dependency(ctx: ChainContext, node_proxy: dict | None) -> None:
    """Include referenced first hops when the user only owns a chain."""
    if not isinstance(node_proxy, dict):
        return
    node_name = str(node_proxy.get("name") or "").strip()
    if not node_name or node_name in ctx.existing_names:
        return
    dependency = ctx.filter_underscore_fields(dict(node_proxy))
    if dependency.get("name") and not dependency["name"].startswith("📊"):
        ctx.chain_dependency_proxies.append(dependency)
        ctx.chain_dependency_names.add(str(dependency["name"]))
        ctx.existing_names.add(node_name)


def is_allocated_chain_name(
    ctx: ChainContext,
    name: str,
    alloc_key: str,
    stable_allocation_id: str | None = None,
) -> bool:
    if ctx.user_allocations is None:
        return True
    if not name:
        return False
    allocated = ctx.user_allocations.get(alloc_key)
    if not allocated:
        return False
    if allocated == ["*"]:
        return True
    if stable_allocation_id and stable_allocation_id in allocated:
        return True
    if virtual_node_id(alloc_key, name) in allocated:
        return True
    name_clean = normalize_alloc_name(name)
    base_name = re.sub(r" \\([A-Za-z0-9]{4}\\)$", "", name)
    base_clean = normalize_alloc_name(base_name)
    for alloc in allocated:
        if not alloc:
            continue
        if alloc == name:
            return True
        alloc_clean = normalize_alloc_name(alloc)
        if alloc_clean and (alloc_clean == name_clean or alloc_clean == base_clean):
            return True
    return False


def resolve_proxy_group_members(ctx: ChainContext, group_spec: dict) -> list[dict]:
    """Resolve a static group or expand the dynamic VPN Gate pool."""

    if str(group_spec.get("group_source") or "nodes").strip() == VPNGATE_SOURCE_ID:
        # ``services.subscription_output.list_vpngate_nodes`` is a patch target in
        # the test-suite; resolve it through the package namespace at call time so
        # those overrides stay effective after the module-to-package split.
        from . import list_vpngate_nodes

        member_proxies = []
        country_code = group_spec.get("vpngate_country_code")
        for vpngate_node in list_vpngate_nodes(country_code=country_code):
            node_proxy = ctx.find_node_by_reference(
                VPNGATE_SOURCE_ID,
                None,
                None,
                node_id=vpngate_node.get("id"),
            )
            if node_proxy:
                member_proxies.append(dict(node_proxy))
        return member_proxies

    member_proxies = []
    for member_ref in group_spec.get("group_nodes", []) or []:
        node_proxy = ctx.find_node_by_reference(
            member_ref.get("sub_id"),
            member_ref.get("node_index"),
            member_ref.get("node_name"),
            node_id=member_ref.get("node_id"),
        )
        if node_proxy:
            member_proxies.append(dict(node_proxy))
    return member_proxies


def build_transit_group(
    ctx: ChainContext,
    base_name: str,
    spec: dict,
    node_index: int,
    member_proxies: list[dict],
    *,
    chain_id: str,
    row_idx: int,
) -> str | None:
    group_base_name = spec.get("group_name") or base_name
    group_allocation_id = proxy_chain_virtual_node_id(
        "chain_pools",
        chain_id,
        str(spec.get("group_id") or f"legacy_group_{row_idx}_{node_index}"),
    )
    group_name = ctx.resolved_chain_reference_names.get(group_allocation_id)
    if not group_name:
        group_name = unique_group_name(
            f"🔀 {group_base_name}",
            ctx.existing_group_names,
            spec.get("group_id"),
        )
    if ctx.user_allocations is not None and not is_allocated_chain_name(
        ctx,
        group_name,
        "chain_pools",
        group_allocation_id,
    ):
        return None
    for node_proxy in member_proxies:
        include_chain_dependency(ctx, node_proxy)
    if not member_proxies:
        return None
    member_names = [p.get("name", "") for p in member_proxies if p.get("name")]
    if not member_names:
        return None
    group_cfg = {"name": group_name, "proxies": member_names}
    group_cfg.update(coerce_group_strategy(spec))
    insert_pool_group(group_cfg, ctx.pool)
    ctx.chain_proxy_names.append(group_name)
    ctx.pool.emitted_chain_reference_names[group_allocation_id] = group_name
    if group_name not in ctx.pool.pool_group_names:
        ctx.pool.pool_group_names.append(group_name)
    return group_name
