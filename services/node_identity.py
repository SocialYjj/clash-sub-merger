"""Stable, non-secret node identities used by allocation and mutation APIs."""

import hashlib
import json
from typing import Optional

from services.name_transformer import NameTransformer


_VOLATILE_NODE_FIELDS = {
    # A display-name edit must not invalidate allocations, proxy chains, or
    # in-flight test result writes. Technical connection fields still define
    # the identity; exact duplicate endpoints are rejected as ambiguous.
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
    canonical = json.dumps(
        {
            "subscription_id": str(subscription_id),
            "node": _identity_payload(node or {}),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"node_{hashlib.sha256(canonical).hexdigest()}"


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
    matches = [
        index
        for index, node in enumerate(nodes)
        if isinstance(node, dict) and subscription_node_id(subscription_id, node) == node_id
    ]
    if len(matches) > 1:
        raise ValueError("Node identity is ambiguous")
    return matches[0] if matches else None
