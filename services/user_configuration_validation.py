"""Boundary validation for user allocations and editable proxy groups."""

from __future__ import annotations

from collections import defaultdict

from fastapi import HTTPException

from core.config import AppConfig
from helpers import load_subscription_yaml
from logger_config import get_logger
from services.group_config_builder import build_group_config_view
from services.name_transformer import NameTransformer
from services.node_identity import custom_node_id, subscription_node_id
from services.proxy_chain_references import list_proxy_chain_virtual_references


logger = get_logger(__name__)
MAX_ALLOCATION_SOURCES = 500
MAX_NODES_PER_SOURCE = 5000
MAX_EDITABLE_GROUPS = 200
MAX_GROUP_NODES = 5000
MAX_REFERENCE_LENGTH = 500


def _add_alias(
    aliases: dict[str, dict[str, set[str]]],
    source_id: str,
    alias: object,
    stable_id: str,
) -> None:
    value = str(alias or "").strip()
    if value and len(value) <= MAX_REFERENCE_LENGTH:
        aliases[source_id][value].add(stable_id)


def _allocation_aliases(config: dict) -> tuple[set[str], dict[str, dict[str, set[str]]], set[str]]:
    known_sources = {
        str(subscription.get("id"))
        for subscription in config.get("subscriptions", [])
        if isinstance(subscription, dict) and subscription.get("id")
    }
    if any(isinstance(node, dict) for node in config.get("custom_nodes", [])):
        known_sources.add("custom_nodes")
    aliases: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    unavailable_sources: set[str] = set()

    for subscription in config.get("subscriptions", []):
        if not isinstance(subscription, dict) or not subscription.get("id"):
            continue
        subscription_id = str(subscription["id"])
        try:
            subscription_yaml = load_subscription_yaml(
                subscription_id,
                AppConfig.YAML_SOURCE_DIR,
                use_cache=True,
            )
        except Exception as exc:
            unavailable_sources.add(subscription_id)
            logger.warning(
                "Cannot validate allocations for subscription %s: %s",
                subscription_id,
                type(exc).__name__,
            )
            continue
        for node in subscription_yaml.get("proxies", []) if isinstance(subscription_yaml, dict) else []:
            if not isinstance(node, dict):
                continue
            stable_id = subscription_node_id(subscription_id, node)
            final_name = NameTransformer.transform_name(
                node,
                subscription.get("name", subscription_id),
            ).get("name")
            _add_alias(aliases, subscription_id, stable_id, stable_id)
            _add_alias(aliases, subscription_id, final_name, stable_id)
            _add_alias(aliases, subscription_id, node.get("name"), stable_id)

    for node in config.get("custom_nodes", []):
        if not isinstance(node, dict):
            continue
        stable_id = custom_node_id(node)
        final_name = NameTransformer.transform_name(node, "Custom").get("name")
        _add_alias(aliases, "custom_nodes", stable_id, stable_id)
        _add_alias(aliases, "custom_nodes", final_name, stable_id)
        _add_alias(aliases, "custom_nodes", node.get("name"), stable_id)

    for reference in list_proxy_chain_virtual_references(config):
        known_sources.add(reference.source_id)
        _add_alias(aliases, reference.source_id, reference.stable_id, reference.stable_id)
        _add_alias(aliases, reference.source_id, reference.legacy_id, reference.stable_id)
        _add_alias(aliases, reference.source_id, reference.name, reference.stable_id)

    return known_sources, aliases, unavailable_sources


def normalize_user_allocations(
    config: dict,
    submitted_allocations: dict,
    *,
    existing_allocations: dict | None = None,
) -> dict:
    """Reject unknown references and convert unambiguous legacy names to IDs."""
    if len(submitted_allocations) > MAX_ALLOCATION_SOURCES:
        raise HTTPException(status_code=400, detail="Too many allocation sources")

    known_sources, aliases, unavailable_sources = _allocation_aliases(config)
    existing_allocations = existing_allocations if isinstance(existing_allocations, dict) else {}
    normalized_allocations: dict[str, list[str]] = {}

    for source_id, values in submitted_allocations.items():
        if source_id not in known_sources:
            raise HTTPException(status_code=400, detail="Allocation contains an unknown source")
        if not isinstance(values, list):
            raise HTTPException(status_code=400, detail="Allocation values must be lists")
        if len(values) > MAX_NODES_PER_SOURCE:
            raise HTTPException(status_code=400, detail="Allocation contains too many nodes")
        if not values:
            continue
        if "*" in values:
            if values != ["*"]:
                raise HTTPException(status_code=400, detail="Wildcard allocation cannot be combined with node IDs")
            normalized_allocations[source_id] = ["*"]
            continue

        existing_values = {
            value for value in existing_allocations.get(source_id, [])
            if isinstance(value, str)
        }
        normalized_values: list[str] = []
        seen_values: set[str] = set()
        for raw_value in values:
            if not isinstance(raw_value, str):
                raise HTTPException(status_code=400, detail="Allocation reference must be a string")
            value = raw_value.strip()
            if not value or len(value) > MAX_REFERENCE_LENGTH:
                raise HTTPException(status_code=400, detail="Allocation reference is invalid")
            targets = aliases[source_id].get(value, set())
            if len(targets) == 1:
                normalized_value = next(iter(targets))
            elif len(targets) > 1:
                raise HTTPException(status_code=409, detail="Allocation reference is ambiguous")
            elif source_id in unavailable_sources and value in existing_values:
                # A damaged/missing YAML must not prevent saving another source,
                # but it also must not become a way to inject a new arbitrary ID.
                normalized_value = value
            else:
                raise HTTPException(status_code=400, detail="Allocation contains a missing node")
            if normalized_value not in seen_values:
                normalized_values.append(normalized_value)
                seen_values.add(normalized_value)
        if normalized_values:
            normalized_allocations[source_id] = normalized_values

    return normalized_allocations


def normalize_group_config(
    config: dict,
    subject: dict,
    submitted_group_config: dict,
    *,
    allocations: dict | None,
    builtin_template: dict,
) -> dict:
    """Allow only editable template groups and nodes visible to the subject."""
    if len(submitted_group_config) > MAX_EDITABLE_GROUPS:
        raise HTTPException(status_code=400, detail="Too many proxy groups")
    group_view = build_group_config_view(
        config,
        subject,
        allocations=allocations,
        builtin_template=builtin_template,
    )
    editable_groups = {
        group["name"]: set(group.get("available_nodes", []))
        for group in group_view.get("groups", [])
        if group.get("editable")
    }
    chain_reference_ids = group_view.get("chain_reference_ids", {})
    normalized_group_config: dict[str, list[str]] = {}

    for group_name, values in submitted_group_config.items():
        if group_name not in editable_groups:
            raise HTTPException(status_code=400, detail="Group configuration contains an unknown or read-only group")
        if not isinstance(values, list) or len(values) > MAX_GROUP_NODES:
            raise HTTPException(status_code=400, detail="Group configuration contains too many nodes")
        allowed_nodes = editable_groups[group_name]
        normalized_values: list[str] = []
        seen_values: set[str] = set()
        for raw_value in values:
            if not isinstance(raw_value, str):
                raise HTTPException(status_code=400, detail="Group node must be a string")
            value = raw_value.strip()
            if not value or len(value) > MAX_REFERENCE_LENGTH or value not in allowed_nodes:
                raise HTTPException(status_code=400, detail="Group configuration contains an unavailable node")
            stored_reference = chain_reference_ids.get(value, value)
            if stored_reference not in seen_values:
                normalized_values.append(stored_reference)
                seen_values.add(stored_reference)
        if normalized_values:
            normalized_group_config[group_name] = normalized_values

    return normalized_group_config
