"""Stable identities and node-reference helpers for configured node pools."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Iterable

from core.config import AppConfig
from helpers import generate_timestamp_id, load_subscription_yaml
from logger_config import get_logger
from services.name_transformer import NameTransformer
from services.node_identity import (
    custom_node_id,
    node_pool_virtual_node_id,
    subscription_node_ids,
    virtual_node_id,
)
from services.node_visibility import clear_user_subscription_caches, is_node_enabled
from services.proxy_chain_utils import unique_group_name
from services.proxy_filter import ProxyFilter


logger = get_logger(__name__)

NODE_POOL_SOURCE = "node_pools"
VALID_NODE_POOL_STRATEGIES = {"select", "url-test", "fallback", "load-balance"}
VALID_NODE_POOL_LOAD_BALANCE_STRATEGIES = {
    "round-robin",
    "consistent-hashing",
    "sticky-sessions",
}


@dataclass(frozen=True)
class NodePoolVirtualReference:
    """A selectable node-pool group with a stable persisted identity."""

    pool_id: str
    name: str
    enabled: bool
    group_strategy: str
    lb_strategy: str
    member_count: int

    @property
    def source_id(self) -> str:
        return NODE_POOL_SOURCE

    @property
    def stable_id(self) -> str:
        return node_pool_virtual_node_id(self.pool_id)

    @property
    def legacy_id(self) -> str:
        return virtual_node_id(NODE_POOL_SOURCE, self.name)

    @property
    def identity_key(self) -> tuple[str, str]:
        return NODE_POOL_SOURCE, self.pool_id


class NodePoolValidationError(ValueError):
    """Raised when a pool or one of its member references is invalid."""


def _valid_identifier(value: object) -> str:
    return str(value or "").strip()


def ensure_node_pool_ids(config: dict) -> int:
    """Assign unique durable IDs to legacy or malformed node-pool records."""
    changed = 0
    used_ids: set[str] = set()
    pools = config.setdefault("node_pools", [])
    if not isinstance(pools, list):
        config["node_pools"] = pools = []

    for pool in pools:
        if not isinstance(pool, dict):
            continue
        pool_id = _valid_identifier(pool.get("id"))
        if not pool_id or pool_id in used_ids:
            pool_id = generate_timestamp_id("pool_")
            while pool_id in used_ids:
                pool_id = generate_timestamp_id("pool_")
            pool["id"] = pool_id
            changed += 1
        used_ids.add(pool_id)
    return changed


def _base_node_names(config: dict) -> set[str]:
    names: set[str] = set()
    for subscription in config.get("subscriptions", []):
        if not isinstance(subscription, dict) or not subscription.get("enabled", True):
            continue
        subscription_id = _valid_identifier(subscription.get("id"))
        if not subscription_id:
            continue
        try:
            source_yaml = load_subscription_yaml(
                subscription_id,
                AppConfig.YAML_SOURCE_DIR,
                use_cache=True,
            )
        except Exception as exc:
            logger.debug("Unable to load subscription %s for pool names: %s", subscription_id, type(exc).__name__)
            continue
        for node in source_yaml.get("proxies", []) if isinstance(source_yaml, dict) else []:
            if isinstance(node, dict) and is_node_enabled(node):
                name = NameTransformer.transform_name(
                    node,
                    subscription.get("name", subscription_id),
                ).get("name")
                if name:
                    names.add(name)

    for node in config.get("custom_nodes", []):
        if isinstance(node, dict) and is_node_enabled(node):
            name = NameTransformer.transform_name(node, "Custom").get("name")
            if name:
                names.add(name)
    return names


def list_node_pool_virtual_references(
    config: dict,
    *,
    base_node_names: Iterable[str] | None = None,
    reserved_group_names: Iterable[str] | None = None,
) -> list[NodePoolVirtualReference]:
    """Resolve display names while keeping pool IDs stable across refreshes."""
    ensure_node_pool_ids(config)
    existing_names = set(base_node_names) if base_node_names is not None else _base_node_names(config)
    existing_group_names = set(reserved_group_names or ())
    existing_names.update(existing_group_names)
    references: list[NodePoolVirtualReference] = []

    for pool in config.get("node_pools", []):
        if not isinstance(pool, dict):
            continue
        pool_id = _valid_identifier(pool.get("id"))
        if not pool_id:
            continue
        base_name = _valid_identifier(pool.get("name")) or "节点池"
        display_name = unique_group_name(base_name, existing_names, pool_id)
        existing_names.add(display_name)
        existing_group_names.add(display_name)
        strategy = _valid_identifier(pool.get("group_strategy")) or "select"
        if strategy not in VALID_NODE_POOL_STRATEGIES:
            strategy = "select"
        lb_strategy = _valid_identifier(pool.get("lb_strategy")) or "round-robin"
        if lb_strategy not in VALID_NODE_POOL_LOAD_BALANCE_STRATEGIES:
            lb_strategy = "round-robin"
        members = pool.get("nodes")
        member_count = len(members) if isinstance(members, list) else 0
        references.append(
            NodePoolVirtualReference(
                pool_id=pool_id,
                name=display_name,
                enabled=bool(pool.get("enabled", True)),
                group_strategy=strategy,
                lb_strategy=lb_strategy,
                member_count=member_count,
            )
        )
    return references


def list_available_node_catalog(config: dict) -> list[dict]:
    """Return valid, enabled leaf nodes that can be selected by a pool."""
    catalog: list[dict] = []
    for subscription in config.get("subscriptions", []):
        if not isinstance(subscription, dict) or not subscription.get("enabled", True):
            continue
        subscription_id = _valid_identifier(subscription.get("id"))
        if not subscription_id:
            continue
        try:
            source_yaml = load_subscription_yaml(
                subscription_id,
                AppConfig.YAML_SOURCE_DIR,
                use_cache=True,
            )
        except Exception as exc:
            logger.warning("Failed to load subscription %s for node pool catalog: %s", subscription_id, type(exc).__name__)
            continue
        nodes = source_yaml.get("proxies", []) if isinstance(source_yaml, dict) else []
        identities = subscription_node_ids(subscription_id, nodes)
        for index, node in enumerate(nodes):
            if not isinstance(node, dict) or not is_node_enabled(node) or not ProxyFilter.is_valid_proxy(node):
                continue
            transformed = NameTransformer.transform_name(node, subscription.get("name", subscription_id))
            catalog.append(
                {
                    "sub_id": subscription_id,
                    "source_name": subscription.get("name", subscription_id),
                    "node_id": identities[index],
                    "node_index": index,
                    "node_name": transformed.get("name", node.get("name", "未命名")),
                    "node_type": node.get("type", "unknown"),
                }
            )

    for index, node in enumerate(config.get("custom_nodes", [])):
        if not isinstance(node, dict) or not is_node_enabled(node) or not ProxyFilter.is_valid_proxy(node):
            continue
        transformed = NameTransformer.transform_name(node, "Custom")
        catalog.append(
            {
                "sub_id": "custom",
                "source_name": "自建节点",
                "node_id": custom_node_id(node),
                "node_index": index,
                "node_name": transformed.get("name", node.get("name", "未命名")),
                "node_type": node.get("type", "unknown"),
            }
        )
    return catalog


def normalize_node_pool_members(config: dict, members: object) -> list[dict]:
    """Validate and canonicalize pool members to stable leaf-node references."""
    if not isinstance(members, list) or not 1 <= len(members) <= 500:
        raise NodePoolValidationError("节点池至少需要 1 个、最多 500 个节点")

    catalog = list_available_node_catalog(config)
    by_key = {(item["sub_id"], item["node_id"]): item for item in catalog}
    normalized: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for raw_member in members:
        if not isinstance(raw_member, dict):
            raise NodePoolValidationError("节点池成员格式无效")
        sub_id = _valid_identifier(raw_member.get("sub_id"))
        if sub_id in {"custom_nodes", "custom"}:
            sub_id = "custom"
        node_id = _valid_identifier(raw_member.get("node_id"))
        candidate = by_key.get((sub_id, node_id)) if node_id else None
        if candidate is None:
            node_name = _valid_identifier(raw_member.get("node_name"))
            node_index = raw_member.get("node_index")
            matches = [
                item
                for item in catalog
                if item["sub_id"] == sub_id
                and (
                    (node_name and item["node_name"] == node_name)
                    or (isinstance(node_index, int) and item["node_index"] == node_index)
                )
            ]
            if len(matches) != 1:
                raise NodePoolValidationError("节点池包含不存在或不明确的节点")
            candidate = matches[0]

        key = (candidate["sub_id"], candidate["node_id"])
        if key in seen:
            raise NodePoolValidationError("节点池不能重复添加同一节点")
        seen.add(key)
        normalized.append(
            {
                "sub_id": candidate["sub_id"],
                "node_id": candidate["node_id"],
                "node_index": candidate["node_index"],
                "node_name": candidate["node_name"],
            }
        )
    return normalized


def pool_strategy_config(pool: dict) -> dict:
    """Build the client-facing proxy-group options for one node pool."""
    strategy = _valid_identifier(pool.get("group_strategy")) or "select"
    if strategy not in VALID_NODE_POOL_STRATEGIES:
        strategy = "select"
    group_config = {"type": strategy}
    if strategy in {"url-test", "fallback"}:
        group_config["url"] = pool.get("group_url") or "https://cp.cloudflare.com/generate_204"
        group_config["interval"] = int(pool.get("group_interval") or 300)
    if strategy == "url-test":
        group_config["tolerance"] = int(pool.get("group_tolerance") or 50)
    if strategy == "load-balance":
        lb_strategy = _valid_identifier(pool.get("lb_strategy")) or "round-robin"
        if lb_strategy not in VALID_NODE_POOL_LOAD_BALANCE_STRATEGIES:
            lb_strategy = "round-robin"
        group_config["strategy"] = lb_strategy
    return group_config


def _replace_values(values: object, id_targets: dict[str, str | None], name_targets: dict[str, str | None]) -> object:
    if not isinstance(values, list) or values == ["*"]:
        return values
    updated: list[object] = []
    seen: set[str] = set()
    for value in values:
        target = id_targets.get(value, value)
        if target == value:
            target = name_targets.get(value, value)
        if target is None:
            continue
        if isinstance(target, str):
            if target in seen:
                continue
            seen.add(target)
        updated.append(target)
    return updated


def _replace_subject_group_config(subject: dict, id_targets: dict[str, str | None], name_id_targets: dict[str, str | None]) -> None:
    group_config = subject.get("group_config")
    if not isinstance(group_config, dict):
        return
    for group_name, values in list(group_config.items()):
        group_config[group_name] = _replace_values(values, id_targets, name_id_targets)


def reconcile_node_pool_references(config: dict, previous_config: dict) -> None:
    """Migrate allocations, group selections and listeners after pool edits."""
    old_references = {
        reference.identity_key: reference
        for reference in list_node_pool_virtual_references(previous_config)
    }
    new_references = {
        reference.identity_key: reference
        for reference in list_node_pool_virtual_references(config)
    }
    id_targets: dict[str, str | None] = {}
    name_targets: dict[str, str | None] = {}
    name_id_targets: dict[str, str | None] = {}
    for key, old_reference in old_references.items():
        new_reference = new_references.get(key)
        target_id = new_reference.stable_id if new_reference else None
        id_targets[old_reference.stable_id] = target_id
        id_targets[old_reference.legacy_id] = target_id
        name_targets[old_reference.name] = new_reference.name if new_reference else None
        name_id_targets[old_reference.name] = target_id
    for new_reference in new_references.values():
        id_targets[new_reference.legacy_id] = new_reference.stable_id

    for user in config.get("users", []):
        if not isinstance(user, dict):
            continue
        allocations = user.get("allocations")
        if isinstance(allocations, dict) and NODE_POOL_SOURCE in allocations:
            allocations[NODE_POOL_SOURCE] = _replace_values(
                allocations.get(NODE_POOL_SOURCE), id_targets, name_targets
            )
        _replace_subject_group_config(user, id_targets, name_id_targets)
        user.pop("sub_cache", None)

    for admin_token in config.get("admin_tokens", []):
        if isinstance(admin_token, dict):
            _replace_subject_group_config(admin_token, id_targets, name_id_targets)

    mappings = config.get("port_mappings")
    if isinstance(mappings, dict):
        updated_mappings = {}
        for reference, port in mappings.items():
            target = id_targets.get(reference, reference)
            if target == reference:
                target = name_id_targets.get(reference, reference)
            if target is not None:
                updated_mappings.setdefault(target, port)
        config["port_mappings"] = updated_mappings

    settings = config.get("settings")
    if isinstance(settings, dict):
        proxy_id = settings.get("proxy_node_id")
        if proxy_id in id_targets:
            target = id_targets[proxy_id]
            if target is None:
                settings.pop("proxy_node_id", None)
                settings.pop("proxy_node_name", None)
            else:
                settings["proxy_node_id"] = target
        proxy_name = settings.get("proxy_node_name")
        if proxy_name in name_targets:
            target_name = name_targets[proxy_name]
            if target_name is None:
                settings.pop("proxy_node_id", None)
                settings.pop("proxy_node_name", None)
            else:
                settings["proxy_node_name"] = target_name

    clear_user_subscription_caches(config)


def remove_node_pool_members_for_source(config: dict, source_aliases: set[str]) -> None:
    """Drop members from deleted/removed sources while preserving the pool."""
    for pool in config.get("node_pools", []):
        if not isinstance(pool, dict) or not isinstance(pool.get("nodes"), list):
            continue
        pool["nodes"] = [
            member
            for member in pool["nodes"]
            if not isinstance(member, dict)
            or str(member.get("sub_id") or "") not in source_aliases
        ]


def update_node_pool_members_for_transition(
    config: dict,
    *,
    source_aliases: set[str],
    id_targets: dict[str, str | None],
    name_targets: dict[str, str | None],
    new_id_display_names: dict[str, str],
) -> None:
    """Update pool member IDs when a subscription/custom node is refreshed."""
    for pool in config.get("node_pools", []):
        if not isinstance(pool, dict) or not isinstance(pool.get("nodes"), list):
            continue
        updated_members = []
        seen: set[tuple[str, str]] = set()
        for member in pool["nodes"]:
            if not isinstance(member, dict):
                continue
            source_id = str(member.get("sub_id") or "")
            if source_id not in source_aliases:
                updated_members.append(member)
                continue
            old_id = _valid_identifier(member.get("node_id"))
            target_id = id_targets.get(old_id, old_id)
            if target_id is None:
                continue
            member = dict(member)
            member["node_id"] = target_id
            old_name = _valid_identifier(member.get("node_name"))
            member["node_name"] = new_id_display_names.get(
                target_id,
                name_targets.get(old_name, old_name),
            )
            key = (source_id, target_id)
            if key not in seen:
                updated_members.append(member)
                seen.add(key)
        pool["nodes"] = updated_members
