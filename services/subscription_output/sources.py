"""Source collection, allocation filtering and missing-file auto-refresh.

Phases (b), (c) and (f) of the ``/sub`` pipeline: gather the enabled
subscriptions, custom nodes and node pools selected for the request, refresh
subscription files that are missing on disk, and order the sources for merge.
"""

import asyncio
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncContextManager, Awaitable, Callable, Optional

import yaml
from fastapi import HTTPException

from helpers import load_subscription_yaml, subscription_content_exists
from services.name_transformer import NameTransformer
from services.node_identity import custom_node_id
from services.node_pool_references import NODE_POOL_SOURCE, list_node_pool_virtual_references
from services.node_visibility import apply_node_visibility_to_yaml_content, is_node_enabled
from services.region_history import (
    apply_node_test_metadata_to_yaml_content,
    apply_region_history_to_yaml_content,
)
from services.subscription_node_count import count_effective_subscription_nodes
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


@dataclass
class SourceCollection:
    """Sources selected for a request plus the allocation bookkeeping they imply."""

    enabled_subs: list[dict]
    custom_nodes: list[dict]
    node_pools: list[dict]
    selected_node_pool_ids: set[str]
    node_pool_member_keys: set[tuple[str, str]]


@asynccontextmanager
async def _noop_refresh_lock(_: str):
    yield


def _update_subscription_record(update_config: Callable, sub_id: str, updates: dict) -> bool:
    def mutator(latest_config: dict):
        for latest_sub in latest_config.get("subscriptions", []):
            if latest_sub.get("id") == sub_id:
                latest_sub.update(updates)
                return True
        return False

    return bool(update_config(mutator))


def collect_subscription_sources(
    config: dict,
    *,
    user_allocations: Optional[dict],
    is_name_allocated: Callable[[str, Optional[list]], bool],
) -> SourceCollection:
    """Collect enabled sources and apply user-allocation filtering."""
    subs = config.get("subscriptions", [])
    enabled_subs = [s for s in subs if s.get("enabled", True)]
    custom_nodes = [node for node in config.get("custom_nodes", []) if is_node_enabled(node)]
    node_pools = [pool for pool in config.get("node_pools", []) if isinstance(pool, dict) and pool.get("enabled", True)]
    node_pool_references = list_node_pool_virtual_references(config)
    node_pool_reference_by_id = {reference.pool_id: reference for reference in node_pool_references}
    selected_node_pool_ids: set[str] = set()
    node_pool_member_keys: set[tuple[str, str]] = set()

    # Filter subscriptions based on user allocations
    has_chain_allocations = False
    if user_allocations is not None:
        # User mode: only show allocated subscriptions
        all_sub_ids = {s["id"] for s in subs}
        allocated_sub_ids = {sid for sid in user_allocations.keys() if sid in all_sub_ids}

        pool_allocations = user_allocations.get(NODE_POOL_SOURCE, [])
        for pool in node_pools:
            pool_id = str(pool.get("id") or "")
            reference = node_pool_reference_by_id.get(pool_id)
            if reference is None:
                continue
            if is_name_allocated(reference.name, pool_allocations, reference.stable_id):
                selected_node_pool_ids.add(pool_id)
                for member in pool.get("nodes", []) or []:
                    if not isinstance(member, dict):
                        continue
                    member_source = str(member.get("sub_id") or "")
                    if member_source in {"custom", "custom_nodes"}:
                        member_source = "custom_nodes"
                    member_id = str(member.get("node_id") or "")
                    if member_source and member_id:
                        node_pool_member_keys.add((member_source, member_id))
                    if member_source in all_sub_ids:
                        allocated_sub_ids.add(member_source)

        enabled_subs = [s for s in enabled_subs if s["id"] in allocated_sub_ids]

        # Filter custom nodes if allocated
        if "custom_nodes" in user_allocations:
            allocated_custom = user_allocations["custom_nodes"]
            if allocated_custom != ["*"]:
                filtered = []
                for node in custom_nodes:
                    if not is_node_enabled(node):
                        continue
                    transformed = NameTransformer.transform_name(node, "Custom")
                    node_name = transformed.get("name", node.get("name", ""))
                    if (
                        is_name_allocated(node_name, allocated_custom, custom_node_id(node))
                        or ("custom_nodes", custom_node_id(node)) in node_pool_member_keys
                    ):
                        filtered.append(node)
                custom_nodes = filtered
        else:
            custom_nodes = [
                node for node in custom_nodes if ("custom_nodes", custom_node_id(node)) in node_pool_member_keys
            ]

        # Virtual allocations allow chain/pool-only subscriptions even
        # when no source was selected directly.
        has_chain_allocations = bool(
            user_allocations.get("chain_nodes") or user_allocations.get("chain_pools") or selected_node_pool_ids
        )
    else:
        selected_node_pool_ids = {str(pool.get("id")) for pool in node_pools if pool.get("id")}

    if not enabled_subs and not custom_nodes and not has_chain_allocations:
        raise HTTPException(status_code=404, detail="No enabled subscriptions or custom nodes") from None

    return SourceCollection(
        enabled_subs=enabled_subs,
        custom_nodes=custom_nodes,
        node_pools=node_pools,
        selected_node_pool_ids=selected_node_pool_ids,
        node_pool_member_keys=node_pool_member_keys,
    )


def find_missing_subscriptions(enabled_subs: list[dict], yaml_source_dir: str) -> list[dict]:
    """Return the subscriptions whose cached YAML file does not exist yet."""
    missing_subs = []
    for sub in enabled_subs:
        if not subscription_content_exists(sub["id"], yaml_source_dir):
            missing_subs.append(sub)
    return missing_subs


async def refresh_missing_subscription_files(
    missing_subs: list[dict],
    *,
    yaml_source_dir: str,
    load_config: Callable[[], dict],
    update_config: Callable,
    fetch_subscription: Callable[..., tuple],
    fetch_subscription_async: Optional[Callable[..., Awaitable[tuple]]],
    subscription_refresh_lock: Optional[Callable[[str], AsyncContextManager[None]]],
    logger,
) -> None:
    """Auto-refresh subscription files missing on disk before rendering.

    Mutates the (shared) subscription dicts with the refreshed traffic and
    refresh-state fields and raises HTTP 502 when any refresh fails.
    """
    if not missing_subs:
        return

    # If there are missing subscription files, fetch them now
    logger.info(f"Auto-refreshing {len(missing_subs)} missing subscription(s)...")
    missing_refresh_failures = []
    for sub in missing_subs:
        attempted_at = int(time.time())
        try:
            lock_factory = subscription_refresh_lock or _noop_refresh_lock
            async with lock_factory(sub["id"]):
                if subscription_content_exists(sub["id"], yaml_source_dir):
                    continue
                latest_config = load_config()
                latest_sub = next(
                    (
                        candidate
                        for candidate in latest_config.get("subscriptions", [])
                        if candidate.get("id") == sub["id"]
                    ),
                    None,
                )
                if not latest_sub or not latest_sub.get("enabled", True):
                    continue
                _update_subscription_record(
                    update_config,
                    sub["id"],
                    refresh_attempt_fields(latest_sub, attempted_at),
                )
                try:
                    existing_cfg = load_subscription_yaml(sub["id"], yaml_source_dir, use_cache=False)
                    existing_nodes = existing_cfg.get("proxies", []) if isinstance(existing_cfg, dict) else []
                except Exception:
                    existing_nodes = []
                if fetch_subscription_async is not None:
                    content, sub_info, node_count = await fetch_subscription_async(
                        latest_sub["url"],
                    )
                else:
                    content, sub_info, node_count = await asyncio.to_thread(
                        fetch_subscription,
                        latest_sub["url"],
                    )
                content, remembered, inherited = apply_region_history_to_yaml_content(
                    content,
                    existing_nodes=existing_nodes,
                    source=f"sub:auto-refresh-missing:{sub['id']}",
                )
                content, test_metadata_inherited = apply_node_test_metadata_to_yaml_content(
                    content,
                    existing_nodes=existing_nodes,
                    source=f"sub:auto-refresh-missing:{sub['id']}",
                )
                content, visibility_inherited = apply_node_visibility_to_yaml_content(
                    content,
                    existing_nodes=existing_nodes,
                )
                try:
                    refreshed_cfg = yaml.load(content, Loader=YAMLLoader)
                    refreshed_nodes = refreshed_cfg.get("proxies", []) if isinstance(refreshed_cfg, dict) else []
                    node_count = count_effective_subscription_nodes(refreshed_nodes)
                except Exception:
                    logger.warning(
                        "Unable to recalculate node count for missing subscription %s",
                        sub["id"],
                        exc_info=True,
                    )
                    node_count = 0
                successful_refresh = {
                    "upload": sub_info.get("upload", 0),
                    "download": sub_info.get("download", 0),
                    "total": sub_info.get("total", 0),
                    "expire": sub_info.get("expire", 0),
                    "node_count": node_count,
                    **refresh_success_fields(
                        latest_sub,
                        attempted_at=attempted_at,
                        succeeded_at=int(time.time()),
                    ),
                }
                sub.update(successful_refresh)
                if remembered or inherited or test_metadata_inherited or visibility_inherited:
                    logger.info(
                        "Missing subscription %s history: remembered=%s inherited_region=%s inherited_test_metadata=%s inherited_disabled=%s",
                        sub["id"],
                        remembered,
                        inherited,
                        test_metadata_inherited,
                        visibility_inherited,
                    )
                persist_subscription_content_and_record(
                    sub["id"],
                    content,
                    yaml_source_dir,
                    lambda: (
                        dict(successful_refresh)  # noqa: B023 - closure is invoked synchronously within the same loop iteration
                        if _update_subscription_record(update_config, sub["id"], successful_refresh)  # noqa: B023 - closure is invoked synchronously within the same loop iteration
                        else None
                    ),
                )
                logger.info(f"  ✓ Refreshed: {sub['name']}")
        except Exception as e:
            error_message = describe_refresh_error(e)
            logger.error("Missing subscription refresh failed for %s: %s", sub["id"], error_message)
            missing_refresh_failures.append(sub["id"])
            failure_state = refresh_failure_fields(sub, e, attempted_at)
            sub.update(failure_state)
            _update_subscription_record(update_config, sub["id"], failure_state)
    if missing_refresh_failures:
        raise HTTPException(
            status_code=502,
            detail={
                "message": "One or more subscription files could not be refreshed",
                "subscription_ids": missing_refresh_failures,
            },
        ) from None


def build_source_file_aliases(config: dict, enabled_subs: list[dict], custom_nodes: list[dict]) -> OrderedDict:
    """Order the merged sources by ``source_order`` config."""
    # Build file_aliases based on filtered subscriptions (not all sources)
    file_aliases = OrderedDict()

    # Get order from source_order config
    config_order = config.get("source_order", [])

    # Add custom nodes first if allocated
    if custom_nodes:
        if "custom_nodes" in config_order:
            # Will be added in order below
            pass
        else:
            file_aliases["custom_nodes.yaml"] = "Custom"

    # Add sources in order
    for source_id in config_order:
        if source_id == "custom_nodes" and custom_nodes:
            file_aliases["custom_nodes.yaml"] = "Custom"
        else:
            # Check if this subscription is in enabled_subs (already filtered for user)
            for sub in enabled_subs:
                if sub["id"] == source_id:
                    file_aliases[f"{sub['id']}.yaml"] = sub["name"]
                    break

    # Add any remaining enabled_subs not in order
    for sub in enabled_subs:
        filename = f"{sub['id']}.yaml"
        if filename not in file_aliases:
            file_aliases[filename] = sub["name"]

    return file_aliases
