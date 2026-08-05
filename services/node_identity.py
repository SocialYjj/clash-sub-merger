"""Stable, non-secret node identities used by allocation and mutation APIs."""

import hashlib
import json
from typing import Optional, Sequence

from core.proxy_compat import normalize_trojan_proxy
from services.name_transformer import NameTransformer


_VOLATILE_NODE_FIELDS = {
    # A display-name edit must not invalidate allocations, proxy chains, or
    # in-flight test result writes. Technical connection fields still define
    # the stable identity; duplicate endpoints receive a UI-only disambiguator.
    "name",
    "last_latency",
    "last_latency_time",
    "last_speed",
    "last_peak_speed",
    "last_speed_time",
    "exit_ip",
    "geoip",
    "region",
    "city",
    "enabled",
    "display_name",
    "index",
}


def _identity_payload(value):
    if isinstance(value, dict):
        return {
            str(key): _identity_payload(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in _VOLATILE_NODE_FIELDS and not str(key).startswith("_")
        }
    if isinstance(value, list):
        return [_identity_payload(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def subscription_node_id(subscription_id: str, node: dict) -> str:
    """Hash a subscription node without exposing its server credentials."""
    identity_node = dict(node or {})
    normalize_trojan_proxy(identity_node)
    canonical = json.dumps(
        {
            "subscription_id": str(subscription_id),
            "node": _identity_payload(identity_node),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"node_{hashlib.sha256(canonical).hexdigest()}"


def subscription_node_ids(subscription_id: str, nodes: Sequence[dict]) -> list[str]:
    """Return unique UI identities while preserving stable IDs for normal nodes.

    Providers sometimes publish several labels for the same technical endpoint.
    The technical identity intentionally ignores display metadata, so those
    entries would otherwise share one ID and every mutation/test request would
    be ambiguous.  Only duplicate technical identities receive a deterministic
    name-based suffix; ordinary nodes keep the long-standing stable ID.
    """
    materialized_nodes = [node if isinstance(node, dict) else {} for node in (nodes or [])]
    base_ids = [subscription_node_id(subscription_id, node) for node in materialized_nodes]

    base_counts: dict[str, int] = {}
    for base_id in base_ids:
        base_counts[base_id] = base_counts.get(base_id, 0) + 1

    duplicate_name_counts: dict[tuple[str, str], int] = {}
    for base_id, node in zip(base_ids, materialized_nodes):
        name_key = normalized_node_name(node.get("name", ""))
        key = (base_id, name_key)
        duplicate_name_counts[key] = duplicate_name_counts.get(key, 0) + 1

    duplicate_occurrences: dict[tuple[str, str], int] = {}
    identities: list[str] = []
    for base_id, node in zip(base_ids, materialized_nodes):
        if base_counts[base_id] == 1:
            identities.append(base_id)
            continue

        name_key = normalized_node_name(node.get("name", ""))
        name_group = (base_id, name_key)
        occurrence = duplicate_occurrences.get(name_group, 0)
        duplicate_occurrences[name_group] = occurrence + 1

        suffix_payload = {
            "base_id": base_id,
            "name": name_key,
        }
        if duplicate_name_counts[name_group] > 1:
            suffix_payload["occurrence"] = occurrence

        suffix = hashlib.sha256(
            json.dumps(
                suffix_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        identities.append(f"{base_id}_duplicate_{suffix}")

    return identities


def custom_node_id(node: dict) -> str:
    """Return the persisted custom-node ID, with a deterministic fallback."""
    persisted_id = str((node or {}).get("id") or "").strip()
    if persisted_id:
        return persisted_id
    return f"custom_{hashlib.sha256(json.dumps(_identity_payload(node or {}), sort_keys=True).encode('utf-8')).hexdigest()}"


def virtual_node_id(source_id: str, name: str) -> str:
    """Return the legacy name-derived ID used before chain components had IDs."""
    canonical = f"{source_id}\0{name}".encode("utf-8")
    return f"virtual_{hashlib.sha256(canonical).hexdigest()}"


def proxy_chain_virtual_node_id(source_id: str, chain_id: str, component_id: str) -> str:
    """Return an ID that survives proxy-chain and generated-name changes."""
    canonical = f"{source_id}\0{chain_id}\0{component_id}".encode("utf-8")
    return f"virtual_{hashlib.sha256(canonical).hexdigest()}"


def normalized_node_name(name: str) -> str:
    return NameTransformer.remove_flags(str(name or "")).strip()


def is_node_allocated(
    node_name: str,
    allocated_nodes: Optional[list[str]],
    node_id: Optional[str] = None,
) -> bool:
    """Match stable IDs first and legacy names only by normalized equality."""
    if not allocated_nodes:
        return False
    if allocated_nodes == ["*"]:
        return True
    if node_id and node_id in allocated_nodes:
        return True
    if not node_name:
        return False

    normalized_name = normalized_node_name(node_name)
    for allocation in allocated_nodes:
        if not isinstance(allocation, str) or not allocation:
            continue
        if allocation == node_name:
            return True
        if normalized_node_name(allocation) == normalized_name:
            return True
    return False


def find_subscription_node_index(nodes: list, subscription_id: str, node_id: str) -> Optional[int]:
    materialized_nodes = [node if isinstance(node, dict) else {} for node in (nodes or [])]
    unique_ids = subscription_node_ids(subscription_id, materialized_nodes)
    unique_matches = [index for index, identity in enumerate(unique_ids) if identity == node_id]
    if len(unique_matches) == 1:
        return unique_matches[0]
    if len(unique_matches) > 1:
        raise ValueError("Node identity is ambiguous")

    # Accept legacy technical IDs for persisted allocations and references.
    legacy_matches = [
        index
        for index, node in enumerate(materialized_nodes)
        if subscription_node_id(subscription_id, node) == node_id
    ]
    if len(legacy_matches) > 1:
        raise ValueError("Node identity is ambiguous")
    return legacy_matches[0] if legacy_matches else None
