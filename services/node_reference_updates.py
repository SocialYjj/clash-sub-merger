"""Keep persisted node references consistent when source nodes change."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

import yaml
from fastapi import HTTPException

from core.config import AppConfig
from core.database import update_config
from helpers import YAMLLoader, YAMLDumper, load_subscription_yaml
from services.name_transformer import NameTransformer
from services.node_identity import (
    custom_node_id,
    normalized_node_name,
    subscription_node_ids,
    virtual_node_id,
)
from services.node_visibility import clear_user_subscription_caches
from services.subscription_refresh_lock import subscription_write_slot
from services.subscription_storage import persist_subscription_content_and_record


@dataclass(frozen=True)
class _NodeDescription:
    position: int
    node_id: str
    original_name: str
    display_name: str
    normalized_name: str


@dataclass(frozen=True)
class _ReferenceTransitionPlan:
    source_aliases: frozenset[str]
    allocation_key: str
    id_targets: dict[str, Optional[str]]
    id_display_names: dict[str, str]
    name_id_targets: dict[str, Optional[str]]
    name_targets: dict[str, Optional[str]]
    new_id_display_names: dict[str, str]


_MISSING = object()


def _describe_nodes(
    nodes: Iterable[dict],
    source_name: str,
    identity_builder: Callable[[dict, int], str],
) -> list[_NodeDescription]:
    descriptions: list[_NodeDescription] = []
    for position, node in enumerate(nodes or []):
        if not isinstance(node, dict):
            continue
        original_name = str(node.get("name") or "").strip()
        transformed = NameTransformer.transform_name(node, source_name)
        display_name = str(
            transformed.get("name") if isinstance(transformed, dict) else original_name
        ).strip()
        descriptions.append(
            _NodeDescription(
                position=position,
                node_id=identity_builder(node, position),
                original_name=original_name,
                display_name=display_name or original_name,
                normalized_name=normalized_node_name(original_name),
            )
        )
    return descriptions


def _unique_descriptions(
    descriptions: Iterable[_NodeDescription],
    key_builder: Callable[[_NodeDescription], str],
) -> dict[str, _NodeDescription]:
    grouped: dict[str, list[_NodeDescription]] = {}
    for description in descriptions:
        lookup_key = key_builder(description)
        if lookup_key:
            grouped.setdefault(lookup_key, []).append(description)
    return {
        lookup_key: matches[0]
        for lookup_key, matches in grouped.items()
        if len(matches) == 1
    }


def _single_target_map(associations: dict[str, set]) -> dict:
    return {
        lookup_key: next(iter(targets))
        for lookup_key, targets in associations.items()
        if lookup_key and len(targets) == 1
    }


def _build_transition_plan(
    *,
    source_aliases: set[str],
    allocation_key: str,
    old_nodes: Iterable[dict],
    new_nodes: Iterable[dict],
    old_source_name: str,
    new_source_name: str,
    identity_builder: Callable[[dict, int], str] | None = None,
    old_identity_builder: Callable[[dict, int], str] | None = None,
    new_identity_builder: Callable[[dict, int], str] | None = None,
) -> _ReferenceTransitionPlan:
    old_identity_builder = old_identity_builder or identity_builder
    new_identity_builder = new_identity_builder or identity_builder
    if old_identity_builder is None or new_identity_builder is None:
        raise ValueError("Node identity builder is required")
    old_descriptions = _describe_nodes(old_nodes, old_source_name, old_identity_builder)
    new_descriptions = _describe_nodes(new_nodes, new_source_name, new_identity_builder)

    unique_old_ids = _unique_descriptions(old_descriptions, lambda item: item.node_id)
    unique_new_ids = _unique_descriptions(new_descriptions, lambda item: item.node_id)
    matched_new_positions: set[int] = set()
    matched_nodes: dict[int, _NodeDescription] = {}

    # Exact stable identities are authoritative. A display-name-only edit lands
    # here because display fields are intentionally excluded from subscription IDs.
    for node_id, old_description in unique_old_ids.items():
        new_description = unique_new_ids.get(node_id)
        if new_description is None:
            continue
        matched_nodes[old_description.position] = new_description
        matched_new_positions.add(new_description.position)

    # Providers sometimes rotate credentials or endpoints while retaining the
    # logical node name. Only unique names are accepted as a fallback so a
    # duplicate provider label can never redirect a reference to the wrong node.
    unmatched_old = [
        item for item in old_descriptions if item.position not in matched_nodes
    ]
    unmatched_new = [
        item for item in new_descriptions if item.position not in matched_new_positions
    ]
    unique_old_names = _unique_descriptions(unmatched_old, lambda item: item.normalized_name)
    unique_new_names = _unique_descriptions(unmatched_new, lambda item: item.normalized_name)
    for normalized_name, old_description in unique_old_names.items():
        new_description = unique_new_names.get(normalized_name)
        if new_description is None:
            continue
        matched_nodes[old_description.position] = new_description
        matched_new_positions.add(new_description.position)

    id_associations: dict[str, set[Optional[str]]] = {}
    id_name_associations: dict[str, set[str]] = {}
    name_id_associations: dict[str, set[Optional[str]]] = {}
    name_associations: dict[str, set[Optional[str]]] = {}

    for old_description in old_descriptions:
        new_description = matched_nodes.get(old_description.position)
        target_id = new_description.node_id if new_description else None
        target_name = new_description.display_name if new_description else None

        if old_description.node_id:
            id_associations.setdefault(old_description.node_id, set()).add(target_id)
            if target_name:
                id_name_associations.setdefault(old_description.node_id, set()).add(target_name)

        for old_name in {old_description.original_name, old_description.display_name}:
            if not old_name:
                continue
            name_id_associations.setdefault(old_name, set()).add(target_id)
            name_associations.setdefault(old_name, set()).add(target_name)

    new_id_name_associations: dict[str, set[str]] = {}
    for description in new_descriptions:
        if description.node_id and description.display_name:
            new_id_name_associations.setdefault(description.node_id, set()).add(
                description.display_name
            )

    return _ReferenceTransitionPlan(
        source_aliases=frozenset(source_aliases),
        allocation_key=allocation_key,
        id_targets=_single_target_map(id_associations),
        id_display_names=_single_target_map(id_name_associations),
        name_id_targets=_single_target_map(name_id_associations),
        name_targets=_single_target_map(name_associations),
        new_id_display_names=_single_target_map(new_id_name_associations),
    )


def _replace_allocation_values(values: object, plan: _ReferenceTransitionPlan) -> object:
    if not isinstance(values, list) or values == ["*"]:
        return values

    updated_values = []
    seen_values = set()
    for value in values:
        target = _MISSING
        if isinstance(value, str):
            target = plan.id_targets.get(value, _MISSING)
            if target is _MISSING:
                target = plan.name_id_targets.get(value, _MISSING)

        if target is None:
            continue
        updated_value = value if target is _MISSING else target
        try:
            already_seen = updated_value in seen_values
        except TypeError:
            already_seen = False
        if already_seen:
            continue
        updated_values.append(updated_value)
        try:
            seen_values.add(updated_value)
        except TypeError:
            pass
    return updated_values


def _replace_name_list(values: object, name_targets: dict[str, Optional[str]]) -> object:
    if not isinstance(values, list):
        return values
    updated_names: list = []
    seen_names = set()
    for value in values:
        if not isinstance(value, str):
            updated_names.append(value)
            continue
        target = name_targets.get(value, _MISSING)
        if target is None:
            continue
        updated_value = value if target is _MISSING else target
        if updated_value in seen_names:
            continue
        updated_names.append(updated_value)
        try:
            seen_names.add(updated_value)
        except TypeError:
            pass
    return updated_names


def _replace_subject_group_names(subject: dict, name_targets: dict[str, Optional[str]]) -> None:
    group_config = subject.get("group_config")
    if not isinstance(group_config, dict):
        return
    for group_name, selected_nodes in list(group_config.items()):
        group_config[group_name] = _replace_name_list(selected_nodes, name_targets)


def _replace_port_mapping_names(config: dict, name_targets: dict[str, Optional[str]]) -> None:
    mappings = config.get("port_mappings")
    if isinstance(mappings, dict):
        updated_mappings = {}
        for node_name, port in mappings.items():
            target = name_targets.get(node_name, _MISSING)
            if target is None:
                continue
            updated_name = node_name if target is _MISSING else target
            # Never overwrite another explicit mapping after a rename collision.
            updated_mappings.setdefault(updated_name, port)
        config["port_mappings"] = updated_mappings
        return

    if isinstance(mappings, list):
        updated_mappings = []
        for mapping in mappings:
            if not isinstance(mapping, dict):
                updated_mappings.append(mapping)
                continue
            node_name = mapping.get("final_name")
            target = name_targets.get(node_name, _MISSING)
            if target is None:
                continue
            updated_mapping = dict(mapping)
            if target is not _MISSING:
                updated_mapping["final_name"] = target
            updated_mappings.append(updated_mapping)
        config["port_mappings"] = updated_mappings


def _replace_default_proxy(config: dict, plan: _ReferenceTransitionPlan) -> None:
    settings = config.get("settings")
    if not isinstance(settings, dict):
        return

    current_id = settings.get("proxy_node_id")
    id_target = plan.id_targets.get(current_id, _MISSING)
    if id_target is None:
        settings.pop("proxy_node_id", None)
        settings.pop("proxy_node_name", None)
        return
    if id_target is not _MISSING:
        settings["proxy_node_id"] = id_target
        display_name = plan.new_id_display_names.get(id_target)
        if display_name:
            settings["proxy_node_name"] = display_name
        return

    current_name = settings.get("proxy_node_name")
    name_target = plan.name_targets.get(current_name, _MISSING)
    if name_target is None:
        settings.pop("proxy_node_id", None)
        settings.pop("proxy_node_name", None)
    elif name_target is not _MISSING:
        settings["proxy_node_name"] = name_target


def _replace_speedtest_results(config: dict, plan: _ReferenceTransitionPlan) -> None:
    all_results = config.get("speedtest_results")
    if not isinstance(all_results, dict):
        return
    for source_key in plan.source_aliases | {plan.allocation_key}:
        source_results = all_results.get(source_key)
        if not isinstance(source_results, dict):
            continue
        updated_results = {}
        for stored_reference, measurement in source_results.items():
            target = plan.id_targets.get(stored_reference, _MISSING)
            if target is _MISSING:
                target = plan.name_id_targets.get(stored_reference, _MISSING)
            if target is None:
                continue
            updated_reference = stored_reference if target is _MISSING else target
            updated_results[updated_reference] = measurement
        all_results[source_key] = updated_results


def _replace_node_reference(reference: dict, plan: _ReferenceTransitionPlan) -> Optional[dict]:
    if reference.get("sub_id") not in plan.source_aliases:
        return dict(reference)

    updated_reference = dict(reference)
    stored_id = str(reference.get("node_id") or "").strip()
    stored_name = str(reference.get("node_name") or "").strip()
    target_id = plan.id_targets.get(stored_id, _MISSING) if stored_id else _MISSING
    if target_id is _MISSING and stored_name:
        target_id = plan.name_id_targets.get(stored_name, _MISSING)

    if target_id is None:
        return None
    if target_id is _MISSING:
        name_target = plan.name_targets.get(stored_name, _MISSING)
        if name_target is None:
            return None
        if name_target is not _MISSING:
            updated_reference["node_name"] = name_target
        return updated_reference

    updated_reference["node_id"] = target_id
    updated_reference.pop("node_index", None)
    display_name = plan.new_id_display_names.get(target_id)
    if display_name:
        updated_reference["node_name"] = display_name
    return updated_reference


def _chain_reference_names(chain: dict) -> tuple[set[str], set[str]]:
    names: set[str] = set()
    allocation_ids: set[str] = set()
    rows = chain.get("rows", []) if isinstance(chain, dict) else []
    chain_name = str(chain.get("name") or "") if isinstance(chain, dict) else ""
    for row_index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        display_name = chain_name
        if len(rows) > 1:
            display_name = f"{chain_name} #{row_index + 1}"
        chain_proxy_name = f"🔗 {display_name}" if display_name else ""
        if chain_proxy_name:
            names.add(chain_proxy_name)
            allocation_ids.add(virtual_node_id("chain_nodes", chain_proxy_name))
        for reference in row.get("nodes", []):
            if not isinstance(reference, dict) or reference.get("type") != "group":
                continue
            group_name = str(reference.get("group_name") or "").strip()
            if group_name:
                pool_name = f"🔀 {group_name}"
                names.add(pool_name)
                allocation_ids.add(virtual_node_id("chain_pools", pool_name))
    return names, allocation_ids


def _replace_proxy_chain_references(
    config: dict,
    plan: _ReferenceTransitionPlan,
) -> tuple[set[str], set[str]]:
    retained_chains = []
    invalidated_names: set[str] = set()
    invalidated_allocation_ids: set[str] = set()

    for chain in config.get("proxy_chains", []):
        if not isinstance(chain, dict):
            continue
        retained_rows = []
        removed_row = False
        for row in chain.get("rows", []):
            if not isinstance(row, dict):
                removed_row = True
                continue
            retained_references = []
            row_invalid = False
            for reference in row.get("nodes", []):
                if not isinstance(reference, dict):
                    row_invalid = True
                    break
                if reference.get("type") == "group":
                    retained_members = []
                    for member in reference.get("group_nodes", []) or []:
                        if not isinstance(member, dict):
                            continue
                        updated_member = _replace_node_reference(member, plan)
                        if updated_member is not None:
                            retained_members.append(updated_member)
                    if not retained_members:
                        row_invalid = True
                        break
                    updated_group = dict(reference)
                    updated_group["group_nodes"] = retained_members
                    retained_references.append(updated_group)
                    continue

                updated_reference = _replace_node_reference(reference, plan)
                if updated_reference is None:
                    row_invalid = True
                    break
                retained_references.append(updated_reference)

            if row_invalid or len(retained_references) < 2:
                removed_row = True
                continue
            retained_rows.append({**row, "nodes": retained_references})

        if removed_row:
            chain_names, chain_allocation_ids = _chain_reference_names(chain)
            invalidated_names.update(chain_names)
            invalidated_allocation_ids.update(chain_allocation_ids)
        if retained_rows:
            retained_chains.append({**chain, "rows": retained_rows})

    config["proxy_chains"] = retained_chains
    return invalidated_names, invalidated_allocation_ids


def _apply_transition_plan(config: dict, plan: _ReferenceTransitionPlan) -> None:
    from services.proxy_chain_references import (
        ensure_proxy_chain_component_ids,
        reconcile_proxy_chain_references,
        snapshot_with_chain_component_ids,
    )

    ensure_proxy_chain_component_ids(config)
    previous_chain_config = snapshot_with_chain_component_ids(config)
    invalidated_chain_names, invalidated_chain_ids = _replace_proxy_chain_references(
        config,
        plan,
    )
    reconcile_proxy_chain_references(config, previous_chain_config)

    combined_name_targets = dict(plan.name_targets)
    combined_name_targets.update({name: None for name in invalidated_chain_names})
    for user in config.get("users", []):
        if not isinstance(user, dict):
            continue
        allocations = user.get("allocations")
        if isinstance(allocations, dict):
            if plan.allocation_key in allocations:
                allocations[plan.allocation_key] = _replace_allocation_values(
                    allocations.get(plan.allocation_key),
                    plan,
                )
            for chain_key in ("chain_nodes", "chain_pools"):
                chain_values = allocations.get(chain_key)
                if isinstance(chain_values, list):
                    allocations[chain_key] = [
                        stored_value
                        for stored_value in chain_values
                        if stored_value not in invalidated_chain_ids
                        and stored_value not in invalidated_chain_names
                    ]
        user.pop("sub_cache", None)
        _replace_subject_group_names(user, combined_name_targets)

    for admin_token in config.get("admin_tokens", []):
        if isinstance(admin_token, dict):
            _replace_subject_group_names(admin_token, combined_name_targets)

    _replace_port_mapping_names(config, combined_name_targets)
    _replace_default_proxy(config, plan)
    _replace_speedtest_results(config, plan)


def reconcile_subscription_node_references(
    config: dict,
    subscription_id: str,
    *,
    old_nodes: Iterable[dict],
    new_nodes: Iterable[dict],
    old_subscription_name: str,
    new_subscription_name: str,
) -> None:
    """Replace or remove every persisted reference affected by subscription changes."""
    old_nodes = list(old_nodes or [])
    new_nodes = list(new_nodes or [])
    old_ids = subscription_node_ids(subscription_id, old_nodes)
    new_ids = subscription_node_ids(subscription_id, new_nodes)
    plan = _build_transition_plan(
        source_aliases={subscription_id},
        allocation_key=subscription_id,
        old_nodes=old_nodes,
        new_nodes=new_nodes,
        old_source_name=old_subscription_name,
        new_source_name=new_subscription_name,
        old_identity_builder=lambda _node, index: old_ids[index] if index < len(old_ids) else "",
        new_identity_builder=lambda _node, index: new_ids[index] if index < len(new_ids) else "",
    )
    _apply_transition_plan(config, plan)


def reconcile_custom_node_references(
    config: dict,
    *,
    old_nodes: Iterable[dict],
    new_nodes: Iterable[dict],
) -> None:
    """Replace or remove references affected by custom-node mutations."""
    plan = _build_transition_plan(
        source_aliases={"custom", "custom_nodes"},
        allocation_key="custom_nodes",
        old_nodes=old_nodes,
        new_nodes=new_nodes,
        old_source_name="Custom",
        new_source_name="Custom",
        identity_builder=lambda node, _index: custom_node_id(node),
    )
    _apply_transition_plan(config, plan)


def remove_explicit_source_references(
    config: dict,
    *,
    source_aliases: set[str],
    allocation_key: str,
) -> None:
    """Remove source-qualified references even when its YAML cannot be parsed."""
    stored_ids: set[str] = set()
    stored_names: set[str] = set()
    for chain in config.get("proxy_chains", []):
        if not isinstance(chain, dict):
            continue
        for row in chain.get("rows", []):
            if not isinstance(row, dict):
                continue
            for reference in row.get("nodes", []):
                if not isinstance(reference, dict):
                    continue
                candidates = (
                    reference.get("group_nodes", []) or []
                    if reference.get("type") == "group"
                    else [reference]
                )
                for candidate in candidates:
                    if not isinstance(candidate, dict) or candidate.get("sub_id") not in source_aliases:
                        continue
                    stored_id = str(candidate.get("node_id") or "").strip()
                    stored_name = str(candidate.get("node_name") or "").strip()
                    if stored_id:
                        stored_ids.add(stored_id)
                    if stored_name:
                        stored_names.add(stored_name)

    removal_plan = _ReferenceTransitionPlan(
        source_aliases=frozenset(source_aliases),
        allocation_key=allocation_key,
        id_targets={stored_id: None for stored_id in stored_ids},
        id_display_names={},
        name_id_targets={stored_name: None for stored_name in stored_names},
        name_targets={stored_name: None for stored_name in stored_names},
        new_id_display_names={},
    )
    _apply_transition_plan(config, removal_plan)


def subscription_nodes_from_yaml_content(yaml_content: str) -> list[dict]:
    """Parse the node list from already validated subscription YAML content."""
    try:
        subscription_yaml = yaml.load(yaml_content, Loader=YAMLLoader)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail="Invalid subscription YAML") from exc
    if not isinstance(subscription_yaml, dict):
        raise HTTPException(status_code=400, detail="Invalid subscription YAML")
    nodes = subscription_yaml.get("proxies")
    if not isinstance(nodes, list):
        raise HTTPException(status_code=400, detail="Subscription has no node list")
    return [node for node in nodes if isinstance(node, dict)]


def update_subscription_yaml_with_references(
    subscription_id: str,
    mutator: Callable[[dict], object],
):
    """Persist a node mutation and its config references as one rollback-safe operation."""
    with subscription_write_slot(subscription_id):
        subscription_yaml = load_subscription_yaml(
            subscription_id,
            AppConfig.YAML_SOURCE_DIR,
            use_cache=False,
        )
        if not isinstance(subscription_yaml, dict):
            raise HTTPException(status_code=500, detail="Invalid subscription YAML")

        old_nodes = deepcopy(subscription_yaml.get("proxies", []))
        mutation_response = mutator(subscription_yaml)
        new_nodes = subscription_yaml.get("proxies", [])
        if not isinstance(new_nodes, list):
            raise HTTPException(status_code=500, detail="Invalid subscription node list")

        serialized_yaml = yaml.dump(
            subscription_yaml,
            allow_unicode=True,
            sort_keys=False,
            Dumper=YAMLDumper,
        )

        def update_node_references(config: dict) -> dict:
            subscription = next(
                (
                    candidate
                    for candidate in config.get("subscriptions", [])
                    if candidate.get("id") == subscription_id
                ),
                None,
            )
            if subscription is None:
                raise HTTPException(status_code=404, detail="Subscription not found")
            subscription_name = str(subscription.get("name") or subscription_id)
            reconcile_subscription_node_references(
                config,
                subscription_id,
                old_nodes=old_nodes,
                new_nodes=new_nodes,
                old_subscription_name=subscription_name,
                new_subscription_name=subscription_name,
            )
            subscription["node_count"] = len(new_nodes)
            clear_user_subscription_caches(config)
            return {
                "subscription": dict(subscription),
                "mutation_response": mutation_response,
            }

        persisted_update = persist_subscription_content_and_record(
            subscription_id,
            serialized_yaml,
            AppConfig.YAML_SOURCE_DIR,
            lambda: update_config(update_node_references),
        )
        return persisted_update["mutation_response"]
