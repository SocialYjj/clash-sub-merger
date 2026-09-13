"""Post-merge source parsing support for the subscription endpoint.

Phase (g) of the ``/sub`` pipeline: after ``ConfigMerger`` parsed and
transformed every source off the event loop, apply per-node user allocations
and regenerate/override the proxy groups accordingly.
"""

from typing import Callable, Optional

from services.config_merger import ProxyGroupGenerator

from .pool_assembly import is_allocated_proxy


def apply_user_allocations(
    *,
    proxies: list,
    proxy_groups: list,
    user_allocations: Optional[dict],
    enabled_subs: list[dict],
    node_pool_member_keys: set,
    is_name_allocated: Callable,
) -> tuple[list, list]:
    """Filter proxies by user allocations and regenerate the country groups."""
    # Filter proxies based on user allocations (specific nodes)
    if user_allocations is not None:
        source_allocations = {}
        for sub in enabled_subs:
            alloc_list = user_allocations.get(sub["id"])
            if alloc_list:
                source_allocations[sub["id"]] = alloc_list

        alloc_custom = user_allocations.get("custom_nodes")
        if alloc_custom:
            source_allocations["custom_nodes"] = alloc_custom

        proxies = [
            p
            for p in proxies
            if is_allocated_proxy(
                p,
                source_allocations=source_allocations,
                node_pool_member_keys=node_pool_member_keys,
                is_name_allocated=is_name_allocated,
            )
        ]

        # Regenerate proxy groups based on filtered proxies
        from services.country_grouper import CountryGrouper

        country_groups = CountryGrouper.group_by_country(proxies)
        proxy_groups = ProxyGroupGenerator.generate_groups(proxies, country_groups)

    return proxies, proxy_groups


def apply_template_proxy_groups(
    *,
    template_proxy_groups: Optional[list],
    proxies: list,
    proxy_groups: list,
    filter_underscore_fields: Callable,
) -> list:
    """Apply template-declared proxy groups on top of the generated ones."""
    # If using custom template with proxy-groups, process user config
    if not (template_proxy_groups and isinstance(template_proxy_groups, list) and len(template_proxy_groups) > 0):
        return proxy_groups

    # Get all proxy names
    all_proxy_names = [p["name"] for p in proxies]
    template_group_names = {
        group.get("name") for group in template_proxy_groups if isinstance(group, dict) and group.get("name")
    }

    # Process each group
    custom_groups = []
    for group in template_proxy_groups:
        new_group = dict(group)

        # Remove underscore fields
        new_group = filter_underscore_fields(new_group)

        # Build the template defaults first. Saved selections are
        # applied after proxy chains exist, so chain IDs can resolve
        # to the exact names emitted for this template.
        original_proxies = group.get("proxies", [])
        new_proxies = [
            item for item in original_proxies if item in ["DIRECT", "REJECT"] or item in template_group_names
        ]
        new_proxies.extend(all_proxy_names)
        seen = set()
        new_group["proxies"] = [item for item in new_proxies if not (item in seen or seen.add(item))]

        custom_groups.append(new_group)

    return custom_groups
