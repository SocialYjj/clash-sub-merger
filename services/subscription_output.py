"""Subscription output route factory.

This module owns the `/sub` subscription generation endpoint.  The endpoint is
registered through a small factory so the legacy helpers that still live in
``server.py`` can be injected without creating import cycles.
"""

import base64
import json
import os
import re
import time
import asyncio
from contextlib import asynccontextmanager
from collections import OrderedDict
from typing import AsyncContextManager, Awaitable, Callable, Optional
from urllib.parse import quote

import yaml
from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import PlainTextResponse

from core.dependencies import verify_admin_or_user_token
from helpers import load_subscription_yaml
from services.config_merger import ConfigMerger, ProxyGroupGenerator
from services.link_exporter import proxy_to_link
from services.name_transformer import NameTransformer
from services.node_visibility import (
    YAMLDumper,
    apply_node_visibility_to_yaml_content,
    is_node_enabled,
)
from services.proxy_chain_utils import coerce_group_strategy, unique_group_name, unique_name
from services.proxy_chain_references import (
    CHAIN_NODE_SOURCE,
    list_proxy_chain_virtual_references,
)
from services.region_history import apply_region_history_to_yaml_content
from services.node_identity import (
    custom_node_id,
    proxy_chain_virtual_node_id,
    virtual_node_id,
)
from services.node_manager import normalize_alloc_name
from services.subscription_state import (
    describe_refresh_error,
    refresh_attempt_fields,
    refresh_failure_fields,
    refresh_success_fields,
)
from services.subscription_storage import persist_subscription_content_and_record

try:
    from yaml import CSafeLoader as YAMLLoader
except ImportError:  # pragma: no cover - depends on optional PyYAML C extension
    from yaml import SafeLoader as YAMLLoader


def _safe_download_filename(value: object, fallback: str, extension: str) -> str:
    """Return a path-safe attachment filename while preserving custom names."""
    raw = str(value or '').strip()
    raw = os.path.basename(raw.replace('\\', '/'))
    if raw.lower().endswith(('.yaml', '.yml', '.txt')):
        raw = raw.rsplit('.', 1)[0]
    safe = ''.join(char for char in raw if char.isalnum() or char in ' _-' or '\u4e00' <= char <= '\u9fff')
    safe = safe.strip(' .') or fallback
    return f"{safe}.{extension.lstrip('.')}"


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

    @asynccontextmanager
    async def _noop_refresh_lock(_: str):
        yield

    def update_subscription_record(sub_id: str, updates: dict) -> bool:
        def mutator(latest_config: dict):
            for latest_sub in latest_config.get('subscriptions', []):
                if latest_sub.get('id') == sub_id:
                    latest_sub.update(updates)
                    return True
            return False

        return bool(update_config(mutator))

    def update_template_record(current_template_id: str, updates: dict) -> None:
        def mutator(latest_config: dict):
            for latest_template in latest_config.get('templates', []):
                if latest_template.get('id') == current_template_id:
                    latest_template.update(updates)
                    latest_template.pop('content', None)
                    return True
            return False

        update_config(mutator)

    @router.get("/sub", tags=["Subscription Output"])
    async def get_merged_subscription(
        token: Optional[str] = None,
        format: Optional[str] = None,
        user_agent: Optional[str] = Header(None, alias="User-Agent")
    ):
        config = load_config()
        auth = config.get('auth', {})

        is_admin = False
        user_info = None
        user_allocations = None
        template_id = 'builtin'  # Default template
        admin_token_info = None  # Store matched admin token for its settings

        token_result = verify_admin_or_user_token(token, config=config)
        if token_result.get('type') == 'admin':
            is_admin = True
            if token_result.get('legacy'):
                # Legacy admin uses current saved template (if any)
                if 'template' in config:
                    template_id = 'legacy'  # Special marker for legacy template
            else:
                admin_token_info = token_result.get('token_info') or {}
                template_id = admin_token_info.get('template_id', 'builtin')
        elif token_result.get('type') == 'user':
            user_info = token_result.get('user_info') or {}
            user_allocations = user_info.get('allocations', {})
            template_id = user_info.get('template_id', 'builtin')
        else:
            raise HTTPException(status_code=401, detail="Invalid subscription token")

        group_config_subject = user_info or admin_token_info

        subs = config.get('subscriptions', [])
        enabled_subs = [s for s in subs if s.get('enabled', True)]
        custom_nodes = [node for node in config.get('custom_nodes', []) if is_node_enabled(node)]

        # Filter subscriptions based on user allocations
        has_chain_allocations = False
        if user_allocations is not None:
            # User mode: only show allocated subscriptions
            all_sub_ids = {s['id'] for s in subs}
            allocated_sub_ids = {sid for sid in user_allocations.keys() if sid in all_sub_ids}
            enabled_subs = [s for s in enabled_subs if s['id'] in allocated_sub_ids]

            # Filter custom nodes if allocated
            if 'custom_nodes' in user_allocations:
                allocated_custom = user_allocations['custom_nodes']
                if allocated_custom != ['*']:
                    filtered = []
                    for node in custom_nodes:
                        if not is_node_enabled(node):
                            continue
                        transformed = NameTransformer.transform_name(node, 'Custom')
                        node_name = transformed.get('name', node.get('name', ''))
                        if is_name_allocated(node_name, allocated_custom, custom_node_id(node)):
                            filtered.append(node)
                    custom_nodes = filtered
            else:
                custom_nodes = []  # No custom nodes allocated

            # Chain allocations allow chain-only subscriptions even without sub/custom allocations
            has_chain_allocations = bool(user_allocations.get('chain_nodes') or user_allocations.get('chain_pools'))

        if not enabled_subs and not custom_nodes and not has_chain_allocations:
            raise HTTPException(status_code=404, detail="No enabled subscriptions or custom nodes")

        # Check and auto-refresh missing subscription files
        # This prevents slow first-time access by ensuring files exist
        missing_subs = []
        for sub in enabled_subs:
            filepath = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
            if not os.path.exists(filepath):
                missing_subs.append(sub)

        # If there are missing subscription files, fetch them now
        if missing_subs:
            logger.info(f"Auto-refreshing {len(missing_subs)} missing subscription(s)...")
            missing_refresh_failures = []
            for sub in missing_subs:
                attempted_at = int(time.time())
                try:
                    lock_factory = subscription_refresh_lock or _noop_refresh_lock
                    async with lock_factory(sub['id']):
                        filepath = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
                        if os.path.exists(filepath):
                            continue
                        latest_config = load_config()
                        latest_sub = next(
                            (
                                candidate
                                for candidate in latest_config.get('subscriptions', [])
                                if candidate.get('id') == sub['id']
                            ),
                            None,
                        )
                        if not latest_sub or not latest_sub.get('enabled', True):
                            continue
                        update_subscription_record(
                            sub['id'],
                            refresh_attempt_fields(latest_sub, attempted_at),
                        )
                        try:
                            existing_cfg = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=False)
                            existing_nodes = existing_cfg.get('proxies', []) if isinstance(existing_cfg, dict) else []
                        except Exception:
                            existing_nodes = []
                        if fetch_subscription_async is not None:
                            content, sub_info, node_count = await fetch_subscription_async(
                                latest_sub['url'],
                            )
                        else:
                            content, sub_info, node_count = await asyncio.to_thread(
                                fetch_subscription,
                                latest_sub['url'],
                            )
                        content, remembered, inherited = apply_region_history_to_yaml_content(
                            content,
                            existing_nodes=existing_nodes,
                            source=f"sub:auto-refresh-missing:{sub['id']}",
                        )
                        content, visibility_inherited = apply_node_visibility_to_yaml_content(
                            content,
                            existing_nodes=existing_nodes,
                        )
                        successful_refresh = {
                            'upload': sub_info.get('upload', 0),
                            'download': sub_info.get('download', 0),
                            'total': sub_info.get('total', 0),
                            'expire': sub_info.get('expire', 0),
                            'node_count': node_count,
                            **refresh_success_fields(
                                latest_sub,
                                attempted_at=attempted_at,
                                succeeded_at=int(time.time()),
                            ),
                        }
                        sub.update(successful_refresh)
                        if remembered or inherited or visibility_inherited:
                            logger.info(
                                "Missing subscription %s history: remembered=%s inherited_region=%s inherited_disabled=%s",
                                sub['id'],
                                remembered,
                                inherited,
                                visibility_inherited,
                            )
                        persist_subscription_content_and_record(
                            sub['id'],
                            content,
                            YAML_SOURCE_DIR,
                            lambda: (
                                dict(successful_refresh)
                                if update_subscription_record(sub['id'], successful_refresh)
                                else None
                            ),
                        )
                        logger.info(f"  ✓ Refreshed: {sub['name']}")
                except Exception as e:
                    error_message = describe_refresh_error(e)
                    logger.error("Missing subscription refresh failed for %s: %s", sub['id'], error_message)
                    missing_refresh_failures.append(sub['id'])
                    failure_state = refresh_failure_fields(sub, e, attempted_at)
                    sub.update(failure_state)
                    update_subscription_record(sub['id'], failure_state)
            if missing_refresh_failures:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "message": "One or more subscription files could not be refreshed",
                        "subscription_ids": missing_refresh_failures,
                    },
                )

        # Smart format detection: auto-select based on User-Agent
        # Clash clients → YAML, others → Base64
        if format is None and user_agent:
            ua_lower = user_agent.lower()
            # Clash client keywords
            clash_keywords = ['clash', 'stash', 'shadowrocket', 'quantumult', 'surge', 'loon']
            # If Clash client, use YAML; otherwise use Base64
            is_clash = any(kw in ua_lower for kw in clash_keywords)
            if not is_clash:
                # V2RayN, V2RayNG, Nekoray etc use Base64
                format = 'base64'

        # Get template based on template_id
        template_proxy_groups = None  # Will store template's proxy-groups if available

        if template_id == 'legacy':
            # Use legacy saved template
            tpl = config.get('template', {})
            header = tpl.get('header', ConfigMerger.DEFAULT_HEADER)
            suffix = tpl.get('suffix', ConfigMerger.DEFAULT_SUFFIX)
        elif template_id == 'builtin':
            # Check for user customization of builtin template
            override = config.get('builtin_template_override')
            if override:
                header = override.get('header', ConfigMerger.DEFAULT_HEADER)
                suffix = override.get('suffix', ConfigMerger.DEFAULT_SUFFIX)
                template_proxy_groups = override.get('proxy_groups', [])
            else:
                header = ConfigMerger.DEFAULT_HEADER
                suffix = ConfigMerger.DEFAULT_SUFFIX
        else:
            # Find template by ID
            template = next((t for t in config.get('templates', []) if t['id'] == template_id), None)
            if template:
                # Check if template needs migration (only if both header and suffix are missing)
                needs_migration = ('header' not in template or 'suffix' not in template) and 'content' in template

                if needs_migration:
                    # Auto-migrate old format templates
                    try:
                        parsed = yaml.load(template['content'], Loader=YAMLLoader)
                        if isinstance(parsed, dict):
                            # Split the content
                            header, suffix = split_template(template['content'])
                            template['header'] = header
                            template['suffix'] = suffix
                            if 'proxy_groups' not in template:
                                template['proxy_groups'] = parsed.get('proxy-groups', [])
                            # Remove old content field
                            del template['content']
                            # Save migrated template (only once) without overwriting concurrent config changes
                            update_template_record(template_id, {
                                'header': header,
                                'suffix': suffix,
                                'proxy_groups': template.get('proxy_groups', []),
                            })
                            logger.info(f"Template {template_id} migrated successfully")
                    except Exception as e:
                        logger.error(f"Template migration failed: {e}")
                        # If migration fails, use fallback
                        header = ConfigMerger.DEFAULT_HEADER
                        suffix = ConfigMerger.DEFAULT_SUFFIX
                        template_proxy_groups = None

                # Use template data (either already migrated or just migrated)
                if not needs_migration or ('header' in template and 'suffix' in template):
                    header = template.get('header', ConfigMerger.DEFAULT_HEADER)
                    suffix = template.get('suffix', ConfigMerger.DEFAULT_SUFFIX)
                    template_proxy_groups = template.get('proxy_groups')
            else:
                # Fallback to built-in
                header = ConfigMerger.DEFAULT_HEADER
                suffix = ConfigMerger.DEFAULT_SUFFIX

        # Build file_aliases based on filtered subscriptions (not all sources)
        file_aliases = OrderedDict()

        # Get order from source_order config
        config_order = config.get('source_order', [])

        # Add custom nodes first if allocated
        if custom_nodes:
            if 'custom_nodes' in config_order:
                # Will be added in order below
                pass
            else:
                file_aliases['custom_nodes.yaml'] = 'Custom'

        # Add sources in order
        for source_id in config_order:
            if source_id == 'custom_nodes' and custom_nodes:
                file_aliases['custom_nodes.yaml'] = 'Custom'
            else:
                # Check if this subscription is in enabled_subs (already filtered for user)
                for sub in enabled_subs:
                    if sub['id'] == source_id:
                        file_aliases[f"{sub['id']}.yaml"] = sub['name']
                        break

        # Add any remaining enabled_subs not in order
        for sub in enabled_subs:
            filename = f"{sub['id']}.yaml"
            if filename not in file_aliases:
                file_aliases[filename] = sub['name']

        merger = ConfigMerger(
            yaml_dir=YAML_SOURCE_DIR, output_file=OUTPUT_FILE,
            custom_header=header, custom_suffix=suffix, file_aliases=file_aliases,
            include_source_metadata=True
        )

        try:
            # YAML parsing and node transformation are CPU/IO-heavy synchronous
            # operations. Keep them off the event loop so health checks and other
            # requests remain responsive while a large subscription is rendered.
            cfg = await asyncio.to_thread(merger.merge_and_generate)
            proxies = cfg.get('proxies', [])
            proxy_groups = cfg.get('proxy-groups', [])

            # Filter proxies based on user allocations (specific nodes)
            if user_allocations is not None:
                source_allocations = {}
                for sub in enabled_subs:
                    alloc_list = user_allocations.get(sub['id'])
                    if alloc_list:
                        source_allocations[sub['id']] = alloc_list

                alloc_custom = user_allocations.get('custom_nodes')
                if alloc_custom:
                    source_allocations['custom_nodes'] = alloc_custom

                def is_allocated_proxy(proxy: dict) -> bool:
                    source_id = proxy.get('_source_id')
                    allocated_nodes = source_allocations.get(source_id)
                    if not allocated_nodes:
                        return False
                    if allocated_nodes == ['*']:
                        return True
                    return is_name_allocated(
                        proxy.get('name', ''),
                        allocated_nodes,
                        proxy.get('_allocation_id'),
                    )

                proxies = [p for p in proxies if is_allocated_proxy(p)]

                # Regenerate proxy groups based on filtered proxies
                from services.country_grouper import CountryGrouper
                country_groups = CountryGrouper.group_by_country(proxies)
                proxy_groups = ProxyGroupGenerator.generate_groups(proxies, country_groups)

            # If using custom template with proxy-groups, process user config
            if template_proxy_groups and isinstance(template_proxy_groups, list) and len(template_proxy_groups) > 0:
                # Get all proxy names
                all_proxy_names = [p['name'] for p in proxies]
                template_group_names = {
                    group.get('name')
                    for group in template_proxy_groups
                    if isinstance(group, dict) and group.get('name')
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
                    original_proxies = group.get('proxies', [])
                    new_proxies = [
                        item
                        for item in original_proxies
                        if item in ['DIRECT', 'REJECT'] or item in template_group_names
                    ]
                    new_proxies.extend(all_proxy_names)
                    seen = set()
                    new_group['proxies'] = [
                        item for item in new_proxies
                        if not (item in seen or seen.add(item))
                    ]

                    custom_groups.append(new_group)

                proxy_groups = custom_groups
            # Get custom config name
            # Priority: user's sub_name > admin_token's sub_name > global sub_name
            if user_info:
                # User subscription - use user's sub_name if set
                if user_info.get('sub_name'):
                    sub_name = f"{user_info['sub_name']} - {user_info['name']}"
                else:
                    # Fallback to global sub_name
                    sub_name = f"{auth.get('sub_name', 'Aggregated')} - {user_info['name']}"
            else:
                # Admin token subscription - use admin token's sub_name or global sub_name
                if admin_token_info and admin_token_info.get('sub_name'):
                    sub_name = admin_token_info['sub_name']
                else:
                    sub_name = auth.get('sub_name', 'Aggregated')

            # Generate traffic info nodes for each subscription
            def format_bytes(b):
                if not b or b == 0:
                    return '0B'
                for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                    if b < 1024:
                        return f'{b:.1f}{unit}' if b != int(b) else f'{int(b)}{unit}'
                    b /= 1024
                return f'{b:.1f}PB'

            def format_expire(ts):
                if not ts or ts == 0:
                    return '永久'
                from datetime import datetime
                return datetime.fromtimestamp(ts).strftime('%Y-%m-%d')

            traffic_info_nodes = []
            traffic_info_names = []

            # Calculate aggregated total first
            agg_used = sum((s.get('upload', 0) or 0) + (s.get('download', 0) or 0) for s in enabled_subs)
            agg_total = sum(s.get('total', 0) or 0 for s in enabled_subs)

            # Add aggregated total node first (only traffic, no time)
            if agg_total > 0:
                agg_name = f"📊 总计 | {format_bytes(agg_used)}/{format_bytes(agg_total)}"
                traffic_info_names.append(agg_name)
                traffic_info_nodes.append({
                    'name': agg_name,
                    'type': 'http',
                    'server': '1.0.0.1',
                    'port': 65535
                })

            # Add individual subscription traffic info
            for sub in enabled_subs:
                used = (sub.get('upload', 0) or 0) + (sub.get('download', 0) or 0)
                total = sub.get('total', 0) or 0
                expire = sub.get('expire', 0) or 0

                # Create info node name: "sub_name | used/total | expire_date"
                if total > 0:
                    info_name = f"📊 {sub['name']} | {format_bytes(used)}/{format_bytes(total)} | {format_expire(expire)}"
                else:
                    info_name = f"📊 {sub['name']} | {format_expire(expire)}"

                traffic_info_names.append(info_name)
                # Create a dummy HTTP node (looks valid but won't work, just for display)
                traffic_info_nodes.append({
                    'name': info_name,
                    'type': 'http',
                    'server': '1.0.0.1',
                    'port': 65535
                })

            # Prepend traffic info nodes to proxies
            proxies = traffic_info_nodes + proxies

            # Process proxy chains - add chain proxies with dialer-proxy
            proxy_chains = config.get('proxy_chains', [])
            chain_proxies = []
            chain_dependency_proxies = []
            chain_proxy_names = []
            emitted_chain_reference_names = {}

            existing_names = {p.get('name') for p in proxies if isinstance(p, dict) and p.get('name')}

            pool_group_names = []
            chain_allocations_enabled = user_allocations is not None and bool(
                user_allocations.get('chain_nodes') or user_allocations.get('chain_pools')
            )

            def short_node_name(name: str) -> str:
                if not name:
                    return ''
                clean = NameTransformer.remove_flags(name)
                if ' ' in clean:
                    clean = clean.split(' ', 1)[1]
                return clean.strip()

            existing_group_names = {g.get('name') for g in proxy_groups if isinstance(g, dict) and g.get('name')}
            existing_names.update(existing_group_names)
            resolved_chain_references = list_proxy_chain_virtual_references(
                config,
                base_node_names=existing_names,
                reserved_group_names=existing_group_names,
            )
            resolved_chain_reference_names = {
                reference.stable_id: reference.name
                for reference in resolved_chain_references
            }
            for reference in resolved_chain_references:
                if reference.source_id == CHAIN_NODE_SOURCE:
                    existing_names.add(reference.name)
                else:
                    existing_group_names.add(reference.name)

            def insert_pool_group(group_cfg: dict) -> None:
                group_name = group_cfg.get('name')
                if not group_name:
                    return
                proxy_groups[:] = [g for g in proxy_groups if g.get('name') != group_name]

                insert_idx = next((i for i, g in enumerate(proxy_groups) if g.get('name') == '🔯 故障转移'), -1)
                if insert_idx == -1:
                    country_names = set(ProxyGroupGenerator.COUNTRY_ORDER)
                    insert_idx = next((i for i, g in enumerate(proxy_groups) if g.get('name') in country_names), len(proxy_groups))
                else:
                    insert_idx += 1
                    while insert_idx < len(proxy_groups) and proxy_groups[insert_idx].get('name') in pool_group_names:
                        insert_idx += 1
                proxy_groups.insert(insert_idx, group_cfg)

            def build_chain_entry(
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
                def hop_name(hop: dict) -> str:
                    if not hop:
                        return ''
                    if hop.get('type') == 'group':
                        return hop.get('name', '')
                    return hop.get('name', '')

                last_node = chain_nodes[-1]
                if last_node.get('type') == 'group':
                    return None
                chain_proxy = dict(last_node)

                last_node_name = last_node.get('name', '')
                last_node_server = last_node.get('server', '')
                chain_country_info = extract_country_from_name(last_node_name, last_node_server)

                if owned_name:
                    final_chain_name = owned_name
                    existing_names.add(final_chain_name)
                else:
                    final_chain_name = unique_name(chain_display_name, existing_names)
                if allow_name and not allow_name(final_chain_name):
                    return None

                chain_proxy['name'] = final_chain_name
                if include_country_info and chain_country_info:
                    chain_proxy['_country_info'] = chain_country_info

                if len(chain_nodes) == 2:
                    prev_name = hop_name(chain_nodes[0])
                    if not prev_name:
                        return None
                    chain_proxy['dialer-proxy'] = prev_name
                else:
                    prev_proxy_name = hop_name(chain_nodes[0])
                    if not prev_proxy_name:
                        return None
                    intermediates = []
                    for i in range(1, len(chain_nodes) - 1):
                        hop = chain_nodes[i]
                        hop_display = hop_name(hop)
                        if hop.get('type') == 'group':
                            if not hop_display:
                                return None
                            prev_proxy_name = hop_display
                            continue
                        intermediate = dict(hop)
                        intermediate_name = unique_name(f"{chain_display_name} (via {i})", existing_names)
                        intermediate['name'] = intermediate_name
                        intermediate['dialer-proxy'] = prev_proxy_name
                        intermediates.append(intermediate)
                        if add_to_manual:
                            chain_proxy_names.append(intermediate_name)
                        prev_proxy_name = intermediate_name
                    chain_proxy['dialer-proxy'] = prev_proxy_name
                    for intermediate in intermediates:
                        chain_proxies.append(intermediate)

                chain_proxies.append(chain_proxy)
                if add_to_manual:
                    chain_proxy_names.append(chain_proxy['name'])
                return chain_proxy['name']

            def include_chain_dependency(node_proxy: dict | None) -> None:
                """Include referenced first hops when the user only owns a chain."""
                if not isinstance(node_proxy, dict):
                    return
                node_name = str(node_proxy.get('name') or '').strip()
                if not node_name or node_name in existing_names:
                    return
                dependency = filter_underscore_fields(dict(node_proxy))
                if dependency.get('name') and not dependency['name'].startswith('📊'):
                    chain_dependency_proxies.append(dependency)
                    existing_names.add(node_name)

            def is_allocated_ref(node_ref: dict, node_proxy: dict | None) -> bool:
                if user_allocations is None:
                    return True
                if not node_ref:
                    return False
                sub_id = node_ref.get('sub_id')
                if not sub_id:
                    return False
                alloc_key = 'custom_nodes' if sub_id == 'custom' else sub_id
                allocated_nodes = user_allocations.get(alloc_key)
                if not allocated_nodes:
                    return False
                if allocated_nodes == ['*']:
                    return True

                name = ''
                if node_proxy and node_proxy.get('name'):
                    name = node_proxy.get('name', '')
                if not name:
                    name = node_ref.get('node_name', '')

                if not name:
                    return False
                return is_name_allocated(
                    name,
                    allocated_nodes,
                    node_ref.get('node_id') or (node_proxy or {}).get('_allocation_id'),
                )

            def is_allocated_chain_name(
                name: str,
                alloc_key: str,
                stable_allocation_id: str | None = None,
            ) -> bool:
                if user_allocations is None:
                    return True
                if not name:
                    return False
                allocated = user_allocations.get(alloc_key)
                if not allocated:
                    return False
                if allocated == ['*']:
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
                    if alloc_clean and (
                        alloc_clean == name_clean
                        or alloc_clean == base_clean
                    ):
                        return True
                return False


            for chain_idx, chain in enumerate(proxy_chains):
                if not chain.get('enabled', True):
                    continue

                for row_idx, row in enumerate(chain.get('rows', [])):
                    nodes = row.get('nodes', [])
                    if len(nodes) < 2:
                        continue
                    chain_id = str(chain.get('id') or f"legacy_chain_{chain_idx}")
                    row_id = str(row.get('row_id') or f"legacy_row_{row_idx}")

                    # Build the chain by setting dialer-proxy on each node
                    # For chain [A, B, C]: B.dialer-proxy = A, C.dialer-proxy = B
                    # We create a new proxy entry based on the last node with dialer-proxy set

                    # Parse chain hops (nodes + transit groups), terminal group is handled separately
                    chain_hops = []
                    group_spec = None
                    group_spec_index = None
                    for idx, node_ref in enumerate(nodes):
                        if isinstance(node_ref, dict) and node_ref.get('type') == 'group':
                            if idx == len(nodes) - 1:
                                group_spec = node_ref
                                group_spec_index = idx
                                break
                            chain_hops.append({'type': 'group', 'spec': node_ref, 'node_index': idx})
                            continue
                        chain_hops.append({'type': 'node', 'ref': node_ref})

                    if not chain_hops:
                        continue

                    # Set chain display name (with row suffix when multiple rows)
                    chain_name = chain['name']
                    if len(chain.get('rows', [])) > 1:
                        chain_name = f"{chain_name} #{row_idx + 1}"

                    def build_transit_group(
                        base_name: str,
                        spec: dict,
                        node_index: int,
                    ) -> str | None:
                        group_base_name = spec.get('group_name') or base_name
                        group_allocation_id = proxy_chain_virtual_node_id(
                            'chain_pools',
                            chain_id,
                            str(spec.get('group_id') or f"legacy_group_{row_idx}_{node_index}"),
                        )
                        group_name = resolved_chain_reference_names.get(group_allocation_id)
                        if not group_name:
                            group_name = unique_group_name(
                                f"🔀 {group_base_name}",
                                existing_group_names,
                                spec.get('group_id'),
                            )
                        if user_allocations is not None and not is_allocated_chain_name(
                            group_name,
                            'chain_pools',
                            group_allocation_id,
                        ):
                            return None
                        group_nodes = spec.get('group_nodes', []) or []
                        member_proxies = []
                        for member_ref in group_nodes:
                            node_proxy = find_node_by_reference(
                                member_ref.get('sub_id'),
                                member_ref.get('node_index'),
                                member_ref.get('node_name'),
                                node_id=member_ref.get('node_id'),
                            )
                            if node_proxy and (chain_allocations_enabled or is_allocated_ref(member_ref, node_proxy)):
                                include_chain_dependency(node_proxy)
                                member_proxies.append(dict(node_proxy))
                        if not member_proxies:
                            return None
                        member_names = [p.get('name', '') for p in member_proxies if p.get('name')]
                        if not member_names:
                            return None
                        group_cfg = {'name': group_name, 'proxies': member_names}
                        group_cfg.update(coerce_group_strategy(spec))
                        insert_pool_group(group_cfg)
                        chain_proxy_names.append(group_name)
                        emitted_chain_reference_names[group_allocation_id] = group_name
                        if group_name not in pool_group_names:
                            pool_group_names.append(group_name)
                        return group_name

                    # Resolve hops into chain nodes (proxies + group placeholders)
                    chain_nodes = []
                    base_allowed = True
                    require_base_allocation = not (user_allocations is not None and chain_allocations_enabled)
                    transit_idx = 0
                    for hop in chain_hops:
                        if hop['type'] == 'node':
                            node_ref = hop['ref']
                            node_proxy = find_node_by_reference(
                                node_ref.get('sub_id'),
                                node_ref.get('node_index'),
                                node_ref.get('node_name'),
                                node_id=node_ref.get('node_id'),
                            )
                            if not node_proxy or (require_base_allocation and not is_allocated_ref(node_ref, node_proxy)):
                                base_allowed = False
                                break
                            include_chain_dependency(node_proxy)
                            chain_nodes.append(dict(node_proxy))
                        else:
                            transit_idx += 1
                            base_name = hop['spec'].get('group_name') or f"{chain_name} 中转池{transit_idx}"
                            group_name = build_transit_group(
                                base_name,
                                hop['spec'],
                                hop['node_index'],
                            )
                            if not group_name:
                                base_allowed = False
                                break
                            chain_nodes.append({'type': 'group', 'name': group_name})

                    if not base_allowed or not chain_nodes:
                        continue
                    if not group_spec and len(chain_nodes) < 2:
                        continue

                    if group_spec:
                        # Build group name first to check allocation
                        group_base_name = group_spec.get('group_name') or f"{chain_name} 落地池"
                        group_allocation_id = proxy_chain_virtual_node_id(
                            'chain_pools',
                            chain_id,
                            str(group_spec.get('group_id') or f"legacy_group_{row_idx}_{group_spec_index}"),
                        )
                        group_name = resolved_chain_reference_names.get(group_allocation_id)
                        if not group_name:
                            group_name = unique_group_name(
                                f"🔀 {group_base_name}",
                                existing_group_names,
                                group_spec.get('group_id'),
                            )
                        if user_allocations is not None and not is_allocated_chain_name(
                            group_name,
                            'chain_pools',
                            group_allocation_id,
                        ):
                            continue

                        group_nodes = group_spec.get('group_nodes', []) or []
                        member_proxies = []
                        for member_ref in group_nodes:
                            node_proxy = find_node_by_reference(
                                member_ref.get('sub_id'),
                                member_ref.get('node_index'),
                                member_ref.get('node_name'),
                                node_id=member_ref.get('node_id'),
                            )
                            if node_proxy and (chain_allocations_enabled or is_allocated_ref(member_ref, node_proxy)):
                                include_chain_dependency(node_proxy)
                                member_proxies.append(dict(node_proxy))

                        if not member_proxies:
                            continue

                        chain_member_names = []
                        base_start_name = short_node_name(chain_nodes[0].get('name', '')) if chain_nodes else ''
                        for member_proxy in member_proxies:
                            chain_nodes_with_member = chain_nodes + [member_proxy]
                            end_name = short_node_name(member_proxy.get('name', ''))
                            path_name = f"{base_start_name} → {end_name}" if base_start_name and end_name else chain_name
                            chain_name_full = f"🔗 {chain_name}: {path_name}"
                            chain_proxy_name = build_chain_entry(chain_name_full, chain_nodes_with_member, add_to_manual=False, include_country_info=False)
                            if chain_proxy_name:
                                chain_member_names.append(chain_proxy_name)

                        if not chain_member_names:
                            continue

                        group_cfg = {
                            'name': group_name,
                            'proxies': chain_member_names
                        }
                        group_cfg.update(coerce_group_strategy(group_spec))

                        insert_pool_group(group_cfg)
                        chain_proxy_names.append(group_name)
                        emitted_chain_reference_names[group_allocation_id] = group_name
                        if group_name not in pool_group_names:
                            pool_group_names.append(group_name)
                    else:
                        # Normal chain (no group)
                        if len(chain_nodes) < 2:
                            continue
                        chain_name_full = f"🔗 {chain_name}"
                        chain_allocation_id = proxy_chain_virtual_node_id(
                            'chain_nodes',
                            chain_id,
                            row_id,
                        )
                        if user_allocations is not None and not is_allocated_chain_name(
                            chain_name_full,
                            'chain_nodes',
                            chain_allocation_id,
                        ):
                            continue
                        emitted_chain_name = build_chain_entry(
                            chain_name_full,
                            chain_nodes,
                            add_to_manual=True,
                            owned_name=resolved_chain_reference_names.get(chain_allocation_id),
                        )
                        if emitted_chain_name:
                            emitted_chain_reference_names[chain_allocation_id] = emitted_chain_name

            saved_group_config = (
                group_config_subject.get('group_config', {})
                if isinstance(group_config_subject, dict)
                else {}
            )
            if isinstance(saved_group_config, dict) and saved_group_config:
                emitted_proxy_names = {
                    proxy.get('name')
                    for proxy in [*proxies, *chain_proxies]
                    if isinstance(proxy, dict) and proxy.get('name')
                }
                emitted_group_names = {
                    group.get('name')
                    for group in proxy_groups
                    if isinstance(group, dict) and group.get('name')
                }
                template_groups_by_name = {
                    group.get('name'): group
                    for group in (template_proxy_groups or [])
                    if isinstance(group, dict) and group.get('name')
                }

                for group in proxy_groups:
                    group_name = group.get('name') if isinstance(group, dict) else None
                    configured_references = saved_group_config.get(group_name)
                    if not group_name or not isinstance(configured_references, list) or not configured_references:
                        continue

                    template_group = template_groups_by_name.get(group_name, {})
                    retained_group_references = [
                        reference
                        for reference in template_group.get('proxies', [])
                        if reference in emitted_group_names and reference != group_name
                    ]
                    selected_names = []
                    for stored_reference in configured_references:
                        resolved_name = emitted_chain_reference_names.get(
                            stored_reference,
                            stored_reference,
                        )
                        if (
                            resolved_name in ['DIRECT', 'REJECT']
                            or resolved_name in emitted_proxy_names
                            or (
                                resolved_name in emitted_group_names
                                and resolved_name != group_name
                            )
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
                    group['proxies'] = merged_names or ['DIRECT']

            # Add pool groups to GLOBAL after fallback
            if pool_group_names:
                for group in proxy_groups:
                    if group.get('name') == 'GLOBAL':
                        proxies_list = list(group.get('proxies', []))
                        if '🔯 故障转移' in proxies_list:
                            insert_idx = proxies_list.index('🔯 故障转移') + 1
                        else:
                            insert_idx = len(proxies_list)
                        for name in pool_group_names:
                            if name not in proxies_list:
                                proxies_list.insert(insert_idx, name)
                                insert_idx += 1
                        group['proxies'] = proxies_list
                        break

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
                    proxy_name = proxy.get('name', '')
                    # Traffic info nodes start with 📊, skip them
                    if proxy_name.startswith('📊'):
                        custom_node_end_idx = i + 1
                        continue
                    # Custom nodes have "Custom" as provider name
                    if 'Custom' in proxy_name:
                        custom_node_end_idx = i + 1
                    else:
                        # First non-custom, non-traffic node found
                        break

                # Insert chain proxies after custom nodes
                proxies = proxies[:custom_node_end_idx] + chain_proxies + proxies[custom_node_end_idx:]

                # Add chain proxies to corresponding country groups (only when country info is present)

                for chain_proxy in chain_proxies:
                    chain_proxy_name = chain_proxy.get('name', '')
                    # Use stored country info from exit node
                    country_info = chain_proxy.get('_country_info')
                    if country_info:
                        country_group_name = f"{country_info['flag']} {country_info['country']}"
                        # Find and update the country group
                        for group in proxy_groups:
                            if group.get('name') == country_group_name:
                                if chain_proxy_name not in group.get('proxies', []):
                                    group['proxies'].insert(0, chain_proxy_name)  # Add at beginning
                                break
                        # Clean up temporary field before output
                        del chain_proxy['_country_info']


            # Add traffic info nodes and chain proxies to manual select group
            if traffic_info_names or chain_proxy_names:
                for group in proxy_groups:
                    if group.get('name') == '🚀 手动选择':
                        current_proxies = group.get('proxies', [])

                        # Insert chain proxies after REJECT (or DIRECT if REJECT not present)
                        updated = list(current_proxies)
                        if 'REJECT' in updated:
                            insert_idx = updated.index('REJECT') + 1
                        elif 'DIRECT' in updated:
                            insert_idx = updated.index('DIRECT') + 1
                        else:
                            insert_idx = 0

                        for name in chain_proxy_names:
                            if name not in updated:
                                updated.insert(insert_idx, name)
                                insert_idx += 1

                        # Prepend traffic info nodes, avoid duplicates
                        final_proxies = traffic_info_names + [p for p in updated if p not in traffic_info_names]
                        group['proxies'] = final_proxies
                        break

            # Calculate total traffic info from all subscriptions
            total_upload = sum(s.get('upload', 0) or 0 for s in enabled_subs)
            total_download = sum(s.get('download', 0) or 0 for s in enabled_subs)
            total_traffic = sum(s.get('total', 0) or 0 for s in enabled_subs)
            # Use the earliest expire time (ignore 0 which means permanent/unknown)
            expire_times = [s.get('expire', 0) or 0 for s in enabled_subs if (s.get('expire', 0) or 0) > 0]
            total_expire = min(expire_times) if expire_times else 0

            # Base64 format output
            if format == 'base64':
                links = []
                unsupported = []
                for proxy in proxies:
                    if proxy.get('name', '').startswith('📊'):
                        continue
                    if proxy.get('dialer-proxy') or proxy.get('type') == 'group':
                        unsupported.append(proxy.get('name', 'unnamed'))
                        continue
                    link = proxy_to_link(proxy)
                    if link:
                        links.append(link)
                    else:
                        unsupported.append(proxy.get('name', 'unnamed'))
                if unsupported:
                    raise HTTPException(
                        status_code=422,
                        detail={
                            'message': 'Base64 format cannot represent one or more nodes without losing configuration',
                            'nodes': unsupported[:50],
                            'count': len(unsupported),
                        },
                    )
                if not links:
                    raise HTTPException(status_code=422, detail='No exportable proxy nodes')
                content = base64.b64encode('\n'.join(links).encode()).decode()

                # Get custom config name
                encoded_name = quote(sub_name)
                subject = user_info or admin_token_info or {}
                filename = _safe_download_filename(
                    subject.get('sub_filename') or auth.get('sub_filename'),
                    sub_name or 'subscription',
                    'txt',
                )

                return PlainTextResponse(
                    content,
                    media_type='text/plain; charset=utf-8',
                    headers={
                        "Cache-Control": "private, no-store, max-age=0",
                        "Pragma": "no-cache",
                        "Vary": "User-Agent",
                        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}",
                        "profile-title": encoded_name,
                        "profile-update-interval": "24",
                        "subscription-userinfo": f"upload={total_upload}; download={total_download}; total={total_traffic}; expire={total_expire}",
                    }
                )

            # SOCKS format output - minimal config with listeners
            if format == 'socks' or format == 'socks-manual':
                # Get custom config name
                encoded_name = quote(sub_name)
                subject_filename = (
                    (user_info or admin_token_info or {}).get('sub_filename')
                    or auth.get('sub_filename')
                )
                safe_filename = _safe_download_filename(subject_filename, sub_name or 'socks-config', 'yaml')

                # Filter out traffic info nodes (those starting with 📊)
                socks_proxies = [p for p in proxies if not p.get('name', '').startswith('📊')]

                # Parse header to extract DNS configuration
                dns_config = None
                try:
                    header_yaml = yaml.load(header, Loader=YAMLLoader)
                    if isinstance(header_yaml, dict) and 'dns' in header_yaml:
                        dns_config = header_yaml['dns']
                except Exception as e:
                    logger.warning(f"Failed to parse DNS from header: {e}")

                # Build minimal YAML with only 4 sections
                output_parts = []

                # 1. allow-lan
                output_parts.append('allow-lan: true')

                # 2. DNS configuration (from template or fallback)
                if dns_config:
                    output_parts.append('\ndns:')
                    output_parts.append(yaml.dump({'dns': dns_config}, allow_unicode=True, default_flow_style=False).replace('dns:\n', '').rstrip())
                else:
                    # Fallback DNS config
                    fallback_dns = {
                        'dns': {
                            'enable': True,
                            'enhanced-mode': 'fake-ip',
                            'fake-ip-range': '198.18.0.1/16',
                            'default-nameserver': ['114.114.114.114'],
                            'nameserver': ['https://doh.pub/dns-query'],
                        }
                    }
                    output_parts.append(
                        yaml.dump(
                            fallback_dns,
                            allow_unicode=True,
                            sort_keys=False,
                            default_flow_style=False,
                            Dumper=YAMLDumper,
                        ).rstrip()
                    )

                # 3. Listeners
                output_parts.append('\nlisteners:')

                if format == 'socks-manual':
                    # Manual mode: only use configured port mappings
                    port_mappings = config.get('port_mappings', {})
                    if port_mappings:
                        # Get current proxy names for validation (excluding traffic info nodes)
                        proxy_names = {p.get('name', '') for p in socks_proxies}
                        proxy_names.update({g.get('name', '') for g in proxy_groups if isinstance(g, dict)})

                        # Build listeners for valid mappings only
                        listener_idx = 0
                        for node_reference, port in sorted(port_mappings.items(), key=lambda x: x[1]):
                            node_name = emitted_chain_reference_names.get(
                                node_reference,
                                node_reference,
                            )
                            if node_name in proxy_names:
                                listener = {
                                    'name': f'mixed{listener_idx}',
                                    'type': 'mixed',
                                    'port': port,
                                    'proxy': node_name
                                }
                                output_parts.append(f'  - {json.dumps(listener, ensure_ascii=False, separators=(",",":"))}')
                                listener_idx += 1
                else:
                    # Auto mode: generate listeners for all nodes starting from port 42000
                    start_port = 42000
                    for idx, proxy in enumerate(socks_proxies):
                        listener = {
                            'name': f'mixed{idx}',
                            'type': 'mixed',
                            'port': start_port + idx,
                            'proxy': proxy.get('name', '')
                        }
                        output_parts.append(f'  - {json.dumps(listener, ensure_ascii=False, separators=(",",":"))}')

                # 4. Proxies (excluding traffic info nodes)
                output_parts.append('\nproxies:')
                for proxy in socks_proxies:
                    output_parts.append(f'  - {json.dumps(filter_underscore_fields(proxy), ensure_ascii=False, separators=(",",":"))}')

                yaml_content = "\n".join(output_parts)
                response_headers = {
                    "Cache-Control": "private, no-store, max-age=0",
                    "Pragma": "no-cache",
                    "Vary": "User-Agent",
                        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(safe_filename)}",
                    "profile-title": encoded_name,
                    "profile-update-interval": "24",
                    "subscription-userinfo": f"upload={total_upload}; download={total_download}; total={total_traffic}; expire={total_expire}",
                }

                return PlainTextResponse(
                    yaml_content,
                    media_type='text/yaml',
                    headers=response_headers
                )

            # Clash YAML format output (default)
            serialized_name = yaml.dump(
                {'name': sub_name},
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                Dumper=YAMLDumper,
            ).rstrip()
            output_parts = [serialized_name + '\n' + header.rstrip()]

            # Generate listeners based on port mappings
            port_mappings = config.get('port_mappings', {})
            if port_mappings:
                # Get current proxy names for validation
                proxy_names = {p.get('name', '') for p in proxies}
                proxy_names.update({g.get('name', '') for g in proxy_groups if isinstance(g, dict)})

                # Build listeners for valid mappings only
                listeners = []
                for node_reference, port in sorted(port_mappings.items(), key=lambda x: x[1]):
                    node_name = emitted_chain_reference_names.get(
                        node_reference,
                        node_reference,
                    )
                    if node_name in proxy_names:
                        listener = {
                            'name': f'mixed-{port}',
                            'type': 'mixed',
                            'port': port,
                            'proxy': node_name
                        }
                        listeners.append(listener)

                if listeners:
                    output_parts.append('\nlisteners:')
                    for listener in listeners:
                        output_parts.append(f'  - {json.dumps(listener, ensure_ascii=False, separators=(",",":"))}')

            output_parts.append('\nproxies:')
            for proxy in proxies:
                output_parts.append(f'  - {json.dumps(filter_underscore_fields(proxy), ensure_ascii=False, separators=(",",":"))}')
            output_parts.append('\nproxy-groups:')
            for group in proxy_groups:
                output_parts.append(f'  - {json.dumps(group, ensure_ascii=False, separators=(",",":"))}')

            if suffix:
                output_parts.append('\n' + suffix)

            # Get custom filename and config name
            # Priority: user's sub_filename > admin_token's sub_filename > global sub_filename
            if user_info and user_info.get('sub_filename'):
                filename = user_info['sub_filename']
            elif admin_token_info and admin_token_info.get('sub_filename'):
                filename = admin_token_info['sub_filename']
            else:
                filename = auth.get('sub_filename', 'config.yaml')

            encoded_name = quote(sub_name)
            safe_filename = _safe_download_filename(filename, sub_name or 'config', 'yaml')

            yaml_content = "\n".join(output_parts)
            response_headers = {
                "Cache-Control": "private, no-store, max-age=0",
                "Pragma": "no-cache",
                "Vary": "User-Agent",
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(safe_filename)}",
                "profile-title": encoded_name,
                "profile-update-interval": "24",
                "subscription-userinfo": f"upload={total_upload}; download={total_download}; total={total_traffic}; expire={total_expire}",
            }

            return PlainTextResponse(
                yaml_content,
                media_type='text/yaml',
                headers=response_headers
            )
        except HTTPException:
            raise
        except Exception:
            logger.error("Failed to generate subscription", exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to generate subscription")


    return router
