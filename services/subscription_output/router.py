"""Subscription output route factory.

This module owns the `/sub` subscription generation endpoint.  The endpoint is
registered through a small factory so the legacy helpers that still live in
``server.py`` can be injected without creating import cycles.
"""

import asyncio
from typing import AsyncContextManager, Awaitable, Callable, Optional

from fastapi import APIRouter, Header, HTTPException, Query

from services.config_merger import ConfigMerger
from services.node_identity import proxy_chain_virtual_node_id
from services.node_pool_references import list_node_pool_virtual_references
from services.proxy_chain_references import (
    CHAIN_NODE_SOURCE,
    list_proxy_chain_virtual_references,
)
from services.proxy_chain_utils import coerce_group_strategy, unique_group_name

from .auth import resolve_auth, resolve_sub_name
from .chain_assembly import (
    ChainContext,
    build_chain_entry,
    build_transit_group,
    include_chain_dependency,
    is_allocated_chain_name,
    resolve_proxy_group_members,
    short_node_name,
)
from .clash_assembly import finalize_group_layout
from .export_renderers import (
    RenderContext,
    compute_traffic_totals,
    normalize_requested_format,
    render_clash_response,
    render_singbox_response,
    render_socks_response,
    render_v2ray_response,
)
from .pool_assembly import PoolContext, add_node_pool_groups, insert_pool_group
from .source_parsing import apply_template_proxy_groups, apply_user_allocations
from .sources import (
    build_source_file_aliases,
    collect_subscription_sources,
    find_missing_subscriptions,
    refresh_missing_subscription_files,
)
from .template_resolver import resolve_template
from .traffic_info import build_traffic_info_nodes


def create_subscription_output_router(
    *,
    yaml_source_dir: str,
    output_file: str,
    load_config: Callable[[], dict],
    update_config: Callable[[Callable[[dict], object]], object],
    fetch_subscription: Callable[..., tuple],
    find_node_by_reference: Callable[..., Optional[dict]],
    is_name_allocated: Callable[[str, Optional[list]], bool],
    filter_underscore_fields: Callable[[dict], dict],
    extract_country_from_name: Callable[..., Optional[dict]],
    split_template: Callable[[str], tuple[str, str]],
    logger,
    fetch_subscription_async: Optional[Callable[..., Awaitable[tuple]]] = None,
    subscription_refresh_lock: Optional[Callable[[str], AsyncContextManager[None]]] = None,
) -> APIRouter:
    """Create the router for subscription output endpoints."""
    router = APIRouter()
    YAML_SOURCE_DIR = yaml_source_dir
    OUTPUT_FILE = output_file

    @router.get("/sub", tags=["Subscription Output"])
    async def get_merged_subscription(
        token: Optional[str] = None,
        format: Optional[str] = None,
        start_port: int = Query(42000, ge=1, le=65535),
        exclude_ports: Optional[str] = Query(None, max_length=2000),
        user_agent: Optional[str] = Header(None, alias="User-Agent"),
    ):
        config = load_config()
        auth = config.get("auth", {})

        auth_context = resolve_auth(token, config)
        user_info = auth_context.user_info
        user_allocations = auth_context.user_allocations
        admin_token_info = auth_context.admin_token_info
        template_id = auth_context.template_id
        group_config_subject = auth_context.group_config_subject

        source_collection = collect_subscription_sources(
            config,
            user_allocations=user_allocations,
            is_name_allocated=is_name_allocated,
        )
        enabled_subs = source_collection.enabled_subs
        custom_nodes = source_collection.custom_nodes
        node_pools = source_collection.node_pools
        selected_node_pool_ids = source_collection.selected_node_pool_ids
        node_pool_member_keys = source_collection.node_pool_member_keys

        # Check and auto-refresh missing subscription files
        # This prevents slow first-time access by ensuring files exist
        missing_subs = find_missing_subscriptions(enabled_subs, YAML_SOURCE_DIR)
        await refresh_missing_subscription_files(
            missing_subs,
            yaml_source_dir=YAML_SOURCE_DIR,
            load_config=load_config,
            update_config=update_config,
            fetch_subscription=fetch_subscription,
            fetch_subscription_async=fetch_subscription_async,
            subscription_refresh_lock=subscription_refresh_lock,
            logger=logger,
        )

        format = normalize_requested_format(format, user_agent)

        # Get template based on template_id
        template = resolve_template(
            config,
            template_id,
            split_template=split_template,
            update_config=update_config,
            logger=logger,
        )
        header = template.header
        suffix = template.suffix
        template_proxy_groups = template.proxy_groups

        file_aliases = build_source_file_aliases(config, enabled_subs, custom_nodes)

        merger = ConfigMerger(
            yaml_dir=YAML_SOURCE_DIR,
            output_file=OUTPUT_FILE,
            custom_header=header,
            custom_suffix=suffix,
            file_aliases=file_aliases,
            include_source_metadata=True,
            output_format=format,
        )

        try:
            # YAML parsing and node transformation are CPU/IO-heavy synchronous
            # operations. Keep them off the event loop so health checks and other
            # requests remain responsive while a large subscription is rendered.
            cfg = await asyncio.to_thread(merger.merge_and_generate)
            proxies = cfg.get("proxies", [])
            proxy_groups = cfg.get("proxy-groups", [])

            proxies, proxy_groups = apply_user_allocations(
                proxies=proxies,
                proxy_groups=proxy_groups,
                user_allocations=user_allocations,
                enabled_subs=enabled_subs,
                node_pool_member_keys=node_pool_member_keys,
                is_name_allocated=is_name_allocated,
            )
            proxy_groups = apply_template_proxy_groups(
                template_proxy_groups=template_proxy_groups,
                proxies=proxies,
                proxy_groups=proxy_groups,
                filter_underscore_fields=filter_underscore_fields,
            )
            # Get custom config name
            # Priority: user's sub_name > admin_token's sub_name > global sub_name
            sub_name = resolve_sub_name(auth=auth, user_info=user_info, admin_token_info=admin_token_info)

            # Generate traffic info nodes for each subscription
            traffic_info_nodes, traffic_info_names = build_traffic_info_nodes(enabled_subs)

            # Prepend traffic info nodes to proxies
            proxies = traffic_info_nodes + proxies

            # Process proxy chains - add chain proxies with dialer-proxy
            proxy_chains = config.get("proxy_chains", [])
            chain_proxies = []
            chain_dependency_proxies = []
            chain_dependency_names: set[str] = set()
            chain_proxy_names = []
            emitted_chain_reference_names = {}

            existing_names = {p.get("name") for p in proxies if isinstance(p, dict) and p.get("name")}

            pool_group_names = []

            existing_group_names = {g.get("name") for g in proxy_groups if isinstance(g, dict) and g.get("name")}
            existing_names.update(existing_group_names)
            resolved_node_pool_references = list_node_pool_virtual_references(
                config,
                base_node_names=existing_names,
                reserved_group_names=existing_group_names,
            )
            node_pool_group_names: list[str] = []
            # Pool names are proxy-group names. Reserve them before resolving
            # chain references so a chain cannot silently shadow a pool.
            existing_names.update(reference.name for reference in resolved_node_pool_references)
            existing_group_names.update(reference.name for reference in resolved_node_pool_references)

            pool_context = PoolContext(
                proxy_groups=proxy_groups,
                pool_group_names=pool_group_names,
                node_pool_group_names=node_pool_group_names,
                emitted_chain_reference_names=emitted_chain_reference_names,
            )

            resolved_chain_references = list_proxy_chain_virtual_references(
                config,
                base_node_names=existing_names,
                reserved_group_names=existing_group_names,
            )
            resolved_chain_reference_names = {
                reference.stable_id: reference.name for reference in resolved_chain_references
            }
            for reference in resolved_chain_references:
                if reference.source_id == CHAIN_NODE_SOURCE:
                    existing_names.add(reference.name)
                else:
                    existing_group_names.add(reference.name)

            chain_context = ChainContext(
                pool=pool_context,
                user_allocations=user_allocations,
                existing_names=existing_names,
                existing_group_names=existing_group_names,
                resolved_chain_reference_names=resolved_chain_reference_names,
                chain_proxies=chain_proxies,
                chain_dependency_proxies=chain_dependency_proxies,
                chain_dependency_names=chain_dependency_names,
                chain_proxy_names=chain_proxy_names,
                find_node_by_reference=find_node_by_reference,
                filter_underscore_fields=filter_underscore_fields,
                extract_country_from_name=extract_country_from_name,
            )

            add_node_pool_groups(
                pool_context,
                proxies=proxies,
                node_pools=node_pools,
                selected_node_pool_ids=selected_node_pool_ids,
                resolved_node_pool_references=resolved_node_pool_references,
            )

            for chain_idx, chain in enumerate(proxy_chains):
                if not chain.get("enabled", True):
                    continue

                for row_idx, row in enumerate(chain.get("rows", [])):
                    nodes = row.get("nodes", [])
                    if len(nodes) < 2:
                        continue
                    chain_id = str(chain.get("id") or f"legacy_chain_{chain_idx}")
                    row_id = str(row.get("row_id") or f"legacy_row_{row_idx}")

                    # Build the chain by setting dialer-proxy on each node
                    # For chain [A, B, C]: B.dialer-proxy = A, C.dialer-proxy = B
                    # We create a new proxy entry based on the last node with dialer-proxy set

                    # Parse chain hops (nodes + transit groups), terminal group is handled separately
                    chain_hops = []
                    group_spec = None
                    group_spec_index = None
                    for idx, node_ref in enumerate(nodes):
                        if isinstance(node_ref, dict) and node_ref.get("type") == "group":
                            if idx == len(nodes) - 1:
                                group_spec = node_ref
                                group_spec_index = idx
                                break
                            chain_hops.append({"type": "group", "spec": node_ref, "node_index": idx})
                            continue
                        chain_hops.append({"type": "node", "ref": node_ref})

                    if not chain_hops:
                        continue

                    # Set chain display name (with row suffix when multiple rows)
                    chain_name = chain["name"]
                    if len(chain.get("rows", [])) > 1:
                        chain_name = f"{chain_name} #{row_idx + 1}"

                    # Resolve the row's own allocation before touching any of
                    # its base nodes.  Previously a user who owned one chain
                    # could cause dependencies from unrelated, unallocated
                    # rows to be appended while those rows were later skipped.
                    # The row must be selected first; only then may its
                    # referenced nodes be included as required dialer
                    # dependencies.
                    chain_name_full = f"🔗 {chain_name}"
                    chain_allocation_id = proxy_chain_virtual_node_id(
                        "chain_nodes",
                        chain_id,
                        row_id,
                    )

                    final_group_allocation_id = None
                    if group_spec:
                        final_group_allocation_id = proxy_chain_virtual_node_id(
                            "chain_pools",
                            chain_id,
                            str(group_spec.get("group_id") or f"legacy_group_{row_idx}_{group_spec_index}"),
                        )
                        final_group_name = resolved_chain_reference_names.get(final_group_allocation_id)
                        if not final_group_name:
                            final_group_name = unique_group_name(
                                f"🔀 {group_spec.get('group_name') or f'{chain_name} 落地池'}",
                                set(existing_group_names),
                                group_spec.get("group_id"),
                            )
                        if user_allocations is not None and not is_allocated_chain_name(
                            chain_context,
                            final_group_name,
                            "chain_pools",
                            final_group_allocation_id,
                        ):
                            continue
                    elif user_allocations is not None and not is_allocated_chain_name(
                        chain_context,
                        chain_name_full,
                        "chain_nodes",
                        chain_allocation_id,
                    ):
                        continue

                    # Transit pools are also allocation boundaries.  Check all
                    # of them up front so an earlier accepted pool cannot add
                    # its member nodes before a later, unallocated pool aborts
                    # the row.
                    if user_allocations is not None:
                        transit_group_names = set(existing_group_names)
                        transit_group_index = 0
                        transit_unallocated = False
                        for hop in chain_hops:
                            if hop.get("type") != "group":
                                continue
                            transit_group_index += 1
                            spec = hop["spec"]
                            group_id = str(spec.get("group_id") or f"legacy_group_{row_idx}_{hop['node_index']}")
                            group_allocation_id = proxy_chain_virtual_node_id(
                                "chain_pools",
                                chain_id,
                                group_id,
                            )
                            group_name = resolved_chain_reference_names.get(group_allocation_id)
                            if not group_name:
                                group_name = unique_group_name(
                                    f"🔀 {spec.get('group_name') or f'{chain_name} 中转池{transit_group_index}'}",
                                    transit_group_names,
                                    spec.get("group_id"),
                                )
                            if not is_allocated_chain_name(
                                chain_context,
                                group_name,
                                "chain_pools",
                                group_allocation_id,
                            ):
                                transit_unallocated = True
                                break
                        if transit_unallocated:
                            continue

                    # Resolve every referenced node before mutating proxy
                    # groups or dependency lists.  A disabled/deleted base
                    # node must invalidate the row without leaving behind
                    # transit pools from a partially processed chain.
                    resolved_hops = []
                    unresolved_hop = False
                    for hop in chain_hops:
                        if hop["type"] == "node":
                            node_ref = hop["ref"]
                            node_proxy = find_node_by_reference(
                                node_ref.get("sub_id"),
                                node_ref.get("node_index"),
                                node_ref.get("node_name"),
                                node_id=node_ref.get("node_id"),
                            )
                            if not node_proxy:
                                unresolved_hop = True
                                break
                            resolved_hops.append(
                                {
                                    "type": "node",
                                    "proxy": dict(node_proxy),
                                }
                            )
                            continue

                        member_proxies = resolve_proxy_group_members(chain_context, hop["spec"])
                        if not member_proxies:
                            unresolved_hop = True
                            break
                        resolved_hops.append(
                            {
                                "type": "group",
                                "spec": hop["spec"],
                                "node_index": hop["node_index"],
                                "members": member_proxies,
                            }
                        )
                    if unresolved_hop:
                        continue

                    resolved_final_members = []
                    if group_spec:
                        resolved_final_members = resolve_proxy_group_members(chain_context, group_spec)
                        if not resolved_final_members:
                            continue

                    # Resolve hops into chain nodes (proxies + group placeholders)
                    chain_nodes = []
                    base_allowed = True
                    transit_idx = 0
                    for hop in resolved_hops:
                        if hop["type"] == "node":
                            node_proxy = hop["proxy"]
                            include_chain_dependency(chain_context, node_proxy)
                            chain_nodes.append(dict(node_proxy))
                        else:
                            transit_idx += 1
                            base_name = hop["spec"].get("group_name") or f"{chain_name} 中转池{transit_idx}"
                            group_name = build_transit_group(
                                chain_context,
                                base_name,
                                hop["spec"],
                                hop["node_index"],
                                hop["members"],
                                chain_id=chain_id,
                                row_idx=row_idx,
                            )
                            if not group_name:
                                base_allowed = False
                                break
                            chain_nodes.append({"type": "group", "name": group_name})

                    if not base_allowed or not chain_nodes:
                        continue
                    if not group_spec and len(chain_nodes) < 2:
                        continue

                    if group_spec:
                        # Build group name first to check allocation
                        group_base_name = group_spec.get("group_name") or f"{chain_name} 落地池"
                        group_allocation_id = proxy_chain_virtual_node_id(
                            "chain_pools",
                            chain_id,
                            str(group_spec.get("group_id") or f"legacy_group_{row_idx}_{group_spec_index}"),
                        )
                        group_name = resolved_chain_reference_names.get(group_allocation_id)
                        if not group_name:
                            group_name = unique_group_name(
                                f"🔀 {group_base_name}",
                                existing_group_names,
                                group_spec.get("group_id"),
                            )
                        member_proxies = resolved_final_members
                        for node_proxy in member_proxies:
                            include_chain_dependency(chain_context, node_proxy)

                        chain_member_names = []
                        base_start_name = short_node_name(chain_nodes[0].get("name", "")) if chain_nodes else ""
                        for member_proxy in member_proxies:
                            chain_nodes_with_member = chain_nodes + [member_proxy]
                            end_name = short_node_name(member_proxy.get("name", ""))
                            path_name = (
                                f"{base_start_name} → {end_name}" if base_start_name and end_name else chain_name
                            )
                            chain_name_full = f"🔗 {chain_name}: {path_name}"
                            chain_proxy_name = build_chain_entry(
                                chain_context,
                                chain_name_full,
                                chain_nodes_with_member,
                                add_to_manual=False,
                                include_country_info=False,
                            )
                            if chain_proxy_name:
                                chain_member_names.append(chain_proxy_name)

                        if not chain_member_names:
                            continue

                        group_cfg = {"name": group_name, "proxies": chain_member_names}
                        group_cfg.update(coerce_group_strategy(group_spec))

                        insert_pool_group(group_cfg, pool_context)
                        chain_proxy_names.append(group_name)
                        emitted_chain_reference_names[group_allocation_id] = group_name
                        if group_name not in pool_group_names:
                            pool_group_names.append(group_name)
                    else:
                        # Normal chain (no group)
                        if len(chain_nodes) < 2:
                            continue
                        emitted_chain_name = build_chain_entry(
                            chain_context,
                            chain_name_full,
                            chain_nodes,
                            add_to_manual=True,
                            owned_name=resolved_chain_reference_names.get(chain_allocation_id),
                        )
                        if emitted_chain_name:
                            emitted_chain_reference_names[chain_allocation_id] = emitted_chain_name

            saved_group_config = (
                group_config_subject.get("group_config", {}) if isinstance(group_config_subject, dict) else {}
            )
            proxies = finalize_group_layout(
                chain_context,
                proxies=proxies,
                proxy_groups=proxy_groups,
                traffic_info_names=traffic_info_names,
                template_proxy_groups=template_proxy_groups,
                saved_group_config=saved_group_config,
            )

            # Calculate total traffic info from all subscriptions
            total_upload, total_download, total_traffic, total_expire = compute_traffic_totals(enabled_subs)

            render_context = RenderContext(
                sub_name=sub_name,
                user_info=user_info,
                admin_token_info=admin_token_info,
                auth=auth,
                total_upload=total_upload,
                total_download=total_download,
                total_traffic=total_traffic,
                total_expire=total_expire,
            )

            # V2Ray/v2rayN subscription output. The response is still the
            # standard Base64-encoded URI list expected by v2rayN; ``v2ray``
            # makes that protocol choice explicit in the URL and UI.
            if format == "v2ray":
                return render_v2ray_response(
                    proxies=proxies,
                    user_allocations=user_allocations,
                    chain_dependency_names=chain_dependency_names,
                    ctx=render_context,
                    logger=logger,
                )

            # Sing-box JSON output. Chain nodes are represented with detour
            # and transit pools with selector/urltest outbounds.
            if format == "singbox":
                return render_singbox_response(
                    proxies=proxies,
                    proxy_groups=proxy_groups,
                    ctx=render_context,
                    logger=logger,
                )

            # SOCKS output. ``socks-manual`` remains accepted as a compatibility
            # alias, but both names now use automatic allocation with optional
            # start/excluded ports.
            if format in {"socks", "socks-manual"}:
                return render_socks_response(
                    proxies=proxies,
                    proxy_groups=proxy_groups,
                    header=header,
                    start_port=start_port,
                    exclude_ports=exclude_ports,
                    filter_underscore_fields=filter_underscore_fields,
                    ctx=render_context,
                    logger=logger,
                )

            # Clash YAML format output (default)
            return render_clash_response(
                proxies=proxies,
                proxy_groups=proxy_groups,
                traffic_info_names=traffic_info_names,
                header=header,
                suffix=suffix,
                config=config,
                emitted_chain_reference_names=emitted_chain_reference_names,
                filter_underscore_fields=filter_underscore_fields,
                ctx=render_context,
            )
        except HTTPException:
            raise
        except Exception:
            logger.error("Failed to generate subscription", exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to generate subscription") from None

    @router.get("/sub/{path_format}", tags=["Subscription Output"])
    async def get_subscription_by_path(
        path_format: str,
        token: Optional[str] = None,
        start_port: int = Query(42000, ge=1, le=65535),
        exclude_ports: Optional[str] = Query(None, max_length=2000),
        user_agent: Optional[str] = Header(None, alias="User-Agent"),
    ):
        """Support protocol-oriented links such as ``/sub/v2ray``."""

        return await get_merged_subscription(
            token=token,
            format=path_format,
            start_port=start_port,
            exclude_ports=exclude_ports,
            user_agent=user_agent,
        )

    return router
