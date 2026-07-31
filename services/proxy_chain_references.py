"""Stable identities and persisted-reference updates for generated proxy chains."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Iterable

from core.config import AppConfig
from helpers import generate_timestamp_id, load_subscription_yaml
from logger_config import get_logger
from services.name_transformer import NameTransformer
from services.node_identity import proxy_chain_virtual_node_id, virtual_node_id
from services.node_visibility import clear_user_subscription_caches, is_node_enabled
from services.proxy_chain_utils import unique_group_name, unique_name


logger = get_logger(__name__)

CHAIN_NODE_SOURCE = "chain_nodes"
CHAIN_POOL_SOURCE = "chain_pools"


@dataclass(frozen=True)
class ProxyChainVirtualReference:
    """One selectable generated chain node or pool with a stable owner."""

    source_id: str
    chain_id: str
    component_id: str
    name: str
    enabled: bool

    @property
    def stable_id(self) -> str:
        return proxy_chain_virtual_node_id(self.source_id, self.chain_id, self.component_id)

    @property
    def legacy_id(self) -> str:
        return virtual_node_id(self.source_id, self.name)

    @property
    def identity_key(self) -> tuple[str, str, str]:
        return self.source_id, self.chain_id, self.component_id


def _valid_identifier(value: object) -> str:
    return str(value or "").strip()


def ensure_proxy_chain_component_ids(config: dict) -> int:
    """Assign unique row/group IDs required for durable generated references."""
    changed = 0
    used_row_ids: set[str] = set()
    used_group_ids: set[str] = set()

    for chain in config.get("proxy_chains", []):
        if not isinstance(chain, dict):
            continue
        for row in chain.get("rows", []):
            if not isinstance(row, dict):
                continue
            row_id = _valid_identifier(row.get("row_id"))
            if not row_id or row_id in used_row_ids:
                row_id = generate_timestamp_id("row_")
                while row_id in used_row_ids:
                    row_id = generate_timestamp_id("row_")
                row["row_id"] = row_id
                changed += 1
            used_row_ids.add(row_id)

            for node in row.get("nodes", []):
                if not isinstance(node, dict) or node.get("type") != "group":
                    continue
                group_id = _valid_identifier(node.get("group_id"))
                if not group_id or group_id in used_group_ids:
                    group_id = generate_timestamp_id("grp_")
                    while group_id in used_group_ids:
                        group_id = generate_timestamp_id("grp_")
                    node["group_id"] = group_id
                    changed += 1
                used_group_ids.add(group_id)

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
            subscription_yaml = load_subscription_yaml(
                subscription_id,
                AppConfig.YAML_SOURCE_DIR,
                use_cache=True,
            )
        except Exception as exc:
            logger.warning(
                "Failed to load subscription %s while resolving chain names: %s",
                subscription_id,
                type(exc).__name__,
            )
            continue
        for node in subscription_yaml.get("proxies", []) if isinstance(subscription_yaml, dict) else []:
            if not isinstance(node, dict) or not is_node_enabled(node):
                continue
            final_name = NameTransformer.transform_name(
                node,
                subscription.get("name", subscription_id),
            ).get("name")
            if final_name:
                names.add(final_name)

    for node in config.get("custom_nodes", []):
        if not isinstance(node, dict) or not is_node_enabled(node):
            continue
        final_name = NameTransformer.transform_name(node, "Custom").get("name")
        if final_name:
            names.add(final_name)
    return names


def list_proxy_chain_virtual_references(
    config: dict,
    *,
    base_node_names: Iterable[str] | None = None,
    reserved_group_names: Iterable[str] | None = None,
) -> list[ProxyChainVirtualReference]:
    """Resolve generated names while retaining stable row/group ownership.

    Disabled chains reserve their names too. This prevents enabling or disabling
    one chain from silently renaming another chain that happens to collide.
    """
    existing_names = set(base_node_names) if base_node_names is not None else _base_node_names(config)
    existing_group_names = set(reserved_group_names or ())
    # Clash resolves proxies and proxy groups through the same reference field.
    # Reserving template group names prevents a generated chain proxy from
    # shadowing a group with the same display name.
    existing_names.update(existing_group_names)
    references: list[ProxyChainVirtualReference] = []

    for chain_index, chain in enumerate(config.get("proxy_chains", [])):
        if not isinstance(chain, dict):
            continue
        chain_id = _valid_identifier(chain.get("id")) or f"legacy_chain_{chain_index}"
        chain_name = _valid_identifier(chain.get("name")) or "Chain"
        chain_enabled = bool(chain.get("enabled", True))
        rows = chain.get("rows", [])
        if not isinstance(rows, list):
            continue

        for row_index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            nodes = row.get("nodes", [])
            if not isinstance(nodes, list) or len(nodes) < 2:
                continue
            row_id = _valid_identifier(row.get("row_id")) or f"legacy_row_{row_index}"
            row_name = chain_name if len(rows) == 1 else f"{chain_name} #{row_index + 1}"
            terminal_group = False
            transit_group_index = 0

            for node_index, node in enumerate(nodes):
                if not isinstance(node, dict) or node.get("type") != "group":
                    continue
                is_terminal = node_index == len(nodes) - 1
                terminal_group = terminal_group or is_terminal
                if is_terminal:
                    fallback_name = f"{row_name} 落地池"
                else:
                    transit_group_index += 1
                    fallback_name = f"{row_name} 中转池{transit_group_index}"
                group_name = unique_group_name(
                    f"🔀 {_valid_identifier(node.get('group_name')) or fallback_name}",
                    existing_group_names,
                    _valid_identifier(node.get("group_id")) or None,
                )
                group_id = _valid_identifier(node.get("group_id")) or f"legacy_group_{row_index}_{node_index}"
                references.append(ProxyChainVirtualReference(
                    source_id=CHAIN_POOL_SOURCE,
                    chain_id=chain_id,
                    component_id=group_id,
                    name=group_name,
                    enabled=chain_enabled,
                ))

            if not terminal_group:
                final_name = unique_name(f"🔗 {row_name}", existing_names)
                references.append(ProxyChainVirtualReference(
                    source_id=CHAIN_NODE_SOURCE,
                    chain_id=chain_id,
                    component_id=row_id,
                    name=final_name,
                    enabled=chain_enabled,
                ))

    return references


def _replace_values(values: object, id_targets: dict[str, str | None], name_targets: dict[str, str | None]) -> object:
    if not isinstance(values, list):
        return values
    if values == ["*"]:
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


def _replace_group_config_references(
    subject: dict,
    id_targets: dict[str, str | None],
    name_id_targets: dict[str, str | None],
) -> None:
    group_config = subject.get("group_config")
    if not isinstance(group_config, dict):
        return
    for group_name, values in list(group_config.items()):
        group_config[group_name] = _replace_values(values, id_targets, name_id_targets)


def _replace_port_mapping_references(
    config: dict,
    id_targets: dict[str, str | None],
    name_id_targets: dict[str, str | None],
) -> None:
    mappings = config.get("port_mappings")
    if not isinstance(mappings, dict):
        return
    updated_mappings = {}
    for reference, port in mappings.items():
        target = id_targets.get(reference, reference)
        if target == reference:
            target = name_id_targets.get(reference, reference)
        if target is not None:
            updated_mappings.setdefault(target, port)
    config["port_mappings"] = updated_mappings


def reconcile_proxy_chain_references(config: dict, previous_config: dict) -> None:
    """Migrate or remove all references affected by a chain lifecycle change."""
    old_references = {
        reference.identity_key: reference
        for reference in list_proxy_chain_virtual_references(previous_config)
    }
    new_references = {
        reference.identity_key: reference
        for reference in list_proxy_chain_virtual_references(config)
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

    # One-time normalization of still-current legacy name-derived IDs.
    for new_reference in new_references.values():
        id_targets[new_reference.legacy_id] = new_reference.stable_id

    for user in config.get("users", []):
        if not isinstance(user, dict):
            continue
        allocations = user.get("allocations")
        if isinstance(allocations, dict):
            for source_id in (CHAIN_NODE_SOURCE, CHAIN_POOL_SOURCE):
                if source_id in allocations:
                    allocations[source_id] = _replace_values(
                        allocations.get(source_id),
                        id_targets,
                        name_targets,
                    )
        _replace_group_config_references(user, id_targets, name_id_targets)
        user.pop("sub_cache", None)

    for admin_token in config.get("admin_tokens", []):
        if isinstance(admin_token, dict):
            _replace_group_config_references(admin_token, id_targets, name_id_targets)

    _replace_port_mapping_references(config, id_targets, name_id_targets)

    settings = config.get("settings")
    if isinstance(settings, dict):
        current_id = settings.get("proxy_node_id")
        if current_id in id_targets:
            target_id = id_targets[current_id]
            if target_id is None:
                settings.pop("proxy_node_id", None)
                settings.pop("proxy_node_name", None)
            else:
                settings["proxy_node_id"] = target_id
        current_name = settings.get("proxy_node_name")
        if current_name in name_targets:
            target_name = name_targets[current_name]
            if target_name is None:
                settings.pop("proxy_node_id", None)
                settings.pop("proxy_node_name", None)
            else:
                settings["proxy_node_name"] = target_name

    speedtest_results = config.get("speedtest_results")
    if isinstance(speedtest_results, dict):
        for source_id in (CHAIN_NODE_SOURCE, CHAIN_POOL_SOURCE, "chain"):
            source_results = speedtest_results.get(source_id)
            if isinstance(source_results, dict):
                speedtest_results[source_id] = {
                    id_targets.get(reference, reference): measurement
                    for reference, measurement in source_results.items()
                    if id_targets.get(reference, reference) is not None
                }

    clear_user_subscription_caches(config)


def snapshot_with_chain_component_ids(config: dict) -> dict:
    """Return a detached snapshot useful before an in-place chain mutation."""
    return deepcopy(config)
