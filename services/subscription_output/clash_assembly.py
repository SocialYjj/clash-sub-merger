"""Clash group assembly helpers for the subscription endpoint.

Phase (j) of the ``/sub`` pipeline: after chains and pools were assembled,
apply saved group selections and integrate pools, chain proxies and traffic
info nodes into the clash proxy-group layout.
"""

from typing import Optional

from .chain_assembly import ChainContext


def _apply_saved_group_selections(
    proxy_groups: list,
    *,
    proxies: list,
    chain_proxies: list,
    saved_group_config: dict,
    template_proxy_groups: Optional[list],
    emitted_chain_reference_names: dict,
) -> None:
    if isinstance(saved_group_config, dict) and saved_group_config:
        emitted_proxy_names = {
            proxy.get("name") for proxy in [*proxies, *chain_proxies] if isinstance(proxy, dict) and proxy.get("name")
        }
        emitted_group_names = {
            group.get("name") for group in proxy_groups if isinstance(group, dict) and group.get("name")
        }
        template_groups_by_name = {
            group.get("name"): group
            for group in (template_proxy_groups or [])
            if isinstance(group, dict) and group.get("name")
        }

        for group in proxy_groups:
            group_name = group.get("name") if isinstance(group, dict) else None
            configured_references = saved_group_config.get(group_name)
            if not group_name or not isinstance(configured_references, list) or not configured_references:
                continue

            template_group = template_groups_by_name.get(group_name, {})
            retained_group_references = [
                reference
                for reference in template_group.get("proxies", [])
                if reference in emitted_group_names and reference != group_name
            ]
            selected_names = []
            for stored_reference in configured_references:
                resolved_name = emitted_chain_reference_names.get(
                    stored_reference,
                    stored_reference,
                )
                if (
                    resolved_name in ["DIRECT", "REJECT"]
                    or resolved_name in emitted_proxy_names
                    or (resolved_name in emitted_group_names and resolved_name != group_name)
                ):
                    selected_names.append(resolved_name)

            merged_names = []
            seen_names = set()
            for selected_name in [*retained_group_references, *selected_names]:
                if selected_name not in seen_names:
                    seen_names.add(selected_name)
                    merged_names.append(selected_name)
            # A saved selection becoming unavailable must not silently
            # expand back to every allocated node.
            group["proxies"] = merged_names or ["DIRECT"]


def _add_pool_groups_to_global(
    proxy_groups: list,
    *,
    pool_group_names: list,
    node_pool_group_names: list,
) -> None:
    # Add generated pool groups to GLOBAL after fallback.  Both
    # configured node pools and legacy chain pools are selectable
    # groups; they should not be hidden from the built-in GLOBAL group.
    all_pool_group_names = list(dict.fromkeys([*pool_group_names, *node_pool_group_names]))
    if all_pool_group_names:
        for group in proxy_groups:
            if group.get("name") == "GLOBAL":
                proxies_list = list(group.get("proxies", []))
                if "🔯 故障转移" in proxies_list:
                    insert_idx = proxies_list.index("🔯 故障转移") + 1
                else:
                    insert_idx = len(proxies_list)
                for name in all_pool_group_names:
                    if name not in proxies_list:
                        proxies_list.insert(insert_idx, name)
                        insert_idx += 1
                group["proxies"] = proxies_list
                break


def _add_pool_groups_to_manual_select(proxy_groups: list, *, node_pool_group_names: list) -> None:
    # The built-in manual group is the normal entry point for direct
    # node selection.  Include each node pool exactly once while
    # retaining DIRECT/REJECT and existing chain entries.
    if node_pool_group_names:
        for group in proxy_groups:
            if group.get("name") != "🚀 手动选择":
                continue
            current = list(group.get("proxies", []))
            insert_idx = 0
            if "REJECT" in current:
                insert_idx = current.index("REJECT") + 1
            elif "DIRECT" in current:
                insert_idx = current.index("DIRECT") + 1
            for name in node_pool_group_names:
                if name not in current:
                    current.insert(insert_idx, name)
                    insert_idx += 1
            group["proxies"] = current
            break


def _position_chain_proxies(
    proxies: list,
    *,
    proxy_groups: list,
    chain_proxies: list,
    chain_dependency_proxies: list,
) -> list:
    # Add chain proxies to the proxies list
    # Position: after custom nodes, before subscription nodes
    # Order: traffic_info -> custom_nodes -> chain_proxies -> subscription_nodes
    if chain_dependency_proxies:
        proxies = proxies + chain_dependency_proxies

    if chain_proxies:
        # Find the position after custom nodes
        # Custom nodes have "Custom" in their name (from file_aliases)
        custom_node_end_idx = 0
        for i, proxy in enumerate(proxies):
            proxy_name = proxy.get("name", "")
            # Traffic info nodes start with 📊, skip them
            if proxy_name.startswith("📊"):
                custom_node_end_idx = i + 1
                continue
            # Custom nodes have "Custom" as provider name
            if "Custom" in proxy_name:
                custom_node_end_idx = i + 1
            else:
                # First non-custom, non-traffic node found
                break

        # Insert chain proxies after custom nodes
        proxies = proxies[:custom_node_end_idx] + chain_proxies + proxies[custom_node_end_idx:]

        # Add chain proxies to corresponding country groups (only when country info is present)

        for chain_proxy in chain_proxies:
            chain_proxy_name = chain_proxy.get("name", "")
            # Use stored country info from exit node
            country_info = chain_proxy.get("_country_info")
            if country_info:
                country_group_name = f"{country_info['flag']} {country_info['country']}"
                # Find and update the country group
                for group in proxy_groups:
                    if group.get("name") == country_group_name:
                        if chain_proxy_name not in group.get("proxies", []):
                            group["proxies"].insert(0, chain_proxy_name)  # Add at beginning
                        break
                # Clean up temporary field before output
                del chain_proxy["_country_info"]

    return proxies


def _add_traffic_and_chains_to_manual_select(
    proxy_groups: list,
    *,
    traffic_info_names: list,
    chain_proxy_names: list,
) -> None:
    # Add traffic info nodes and chain proxies to manual select group
    if traffic_info_names or chain_proxy_names:
        for group in proxy_groups:
            if group.get("name") == "🚀 手动选择":
                current_proxies = group.get("proxies", [])

                # Insert chain proxies after REJECT (or DIRECT if REJECT not present)
                updated = list(current_proxies)
                if "REJECT" in updated:
                    insert_idx = updated.index("REJECT") + 1
                elif "DIRECT" in updated:
                    insert_idx = updated.index("DIRECT") + 1
                else:
                    insert_idx = 0

                for name in chain_proxy_names:
                    if name not in updated:
                        updated.insert(insert_idx, name)
                        insert_idx += 1

                # Prepend traffic info nodes, avoid duplicates
                final_proxies = traffic_info_names + [p for p in updated if p not in traffic_info_names]
                group["proxies"] = final_proxies
                break


def finalize_group_layout(
    chain_ctx: ChainContext,
    *,
    proxies: list,
    proxy_groups: list,
    traffic_info_names: list,
    template_proxy_groups: Optional[list],
    saved_group_config: dict,
) -> list:
    """Finalise the clash group layout after chain/pool assembly.

    Mutates ``proxy_groups`` in place (and the accumulated chain proxies) and
    returns the re-ordered proxies list.
    """
    _apply_saved_group_selections(
        proxy_groups,
        proxies=proxies,
        chain_proxies=chain_ctx.chain_proxies,
        saved_group_config=saved_group_config,
        template_proxy_groups=template_proxy_groups,
        emitted_chain_reference_names=chain_ctx.pool.emitted_chain_reference_names,
    )
    _add_pool_groups_to_global(
        proxy_groups,
        pool_group_names=chain_ctx.pool.pool_group_names,
        node_pool_group_names=chain_ctx.pool.node_pool_group_names,
    )
    _add_pool_groups_to_manual_select(proxy_groups, node_pool_group_names=chain_ctx.pool.node_pool_group_names)
    proxies = _position_chain_proxies(
        proxies,
        proxy_groups=proxy_groups,
        chain_proxies=chain_ctx.chain_proxies,
        chain_dependency_proxies=chain_ctx.chain_dependency_proxies,
    )
    _add_traffic_and_chains_to_manual_select(
        proxy_groups,
        traffic_info_names=traffic_info_names,
        chain_proxy_names=chain_ctx.chain_proxy_names,
    )
    return proxies
