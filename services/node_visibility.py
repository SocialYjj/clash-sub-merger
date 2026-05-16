"""Node visibility helpers.

The UI can disable individual nodes without deleting them. Disabled nodes
remain visible/manageable in the admin panel, but they must not be exported in
aggregated subscription files or offered as selectable nodes for users/chains.
"""
import hashlib
import json
import re
from typing import Iterable, Optional, Tuple

import yaml

from logger_config import get_logger
from services.name_transformer import NameTransformer

logger = get_logger(__name__)

try:
    from yaml import CSafeLoader as YAMLLoader, CSafeDumper as YAMLDumper
except ImportError:
    from yaml import SafeLoader as YAMLLoader, SafeDumper as YAMLDumper


_SPACE_RE = re.compile(r"\s+")


def is_node_enabled(node: dict) -> bool:
    """Return whether a node should be exported.

    Missing ``enabled`` means enabled for full backward compatibility with
    existing configs. String false values are accepted defensively because
    imported YAML or manual edits may not preserve boolean types.
    """
    if not isinstance(node, dict):
        return False

    raw = node.get("enabled", True)
    if raw is False:
        return False
    if isinstance(raw, (int, float)) and not isinstance(raw, bool) and raw == 0:
        return False
    if isinstance(raw, str):
        return raw.strip().lower() not in {"0", "false", "no", "off", "disabled"}
    return True


def strip_visibility_fields(node: dict) -> dict:
    """Remove admin-only visibility fields before writing final proxy output."""
    if not isinstance(node, dict):
        return node
    cleaned = dict(node)
    cleaned.pop("enabled", None)
    return cleaned


def filter_enabled_nodes(nodes: Iterable[dict], *, strip: bool = False) -> list:
    """Keep enabled nodes and optionally remove visibility metadata."""
    result = []
    for node in nodes or []:
        if not is_node_enabled(node):
            continue
        result.append(strip_visibility_fields(node) if strip else node)
    return result


def clear_user_subscription_caches(config: dict) -> None:
    """Invalidate cached generated user subscriptions after node visibility changes."""
    if not isinstance(config, dict):
        return
    for user in config.get("users", []) or []:
        if isinstance(user, dict):
            user.pop("sub_cache", None)


def _normalize_text(value) -> str:
    return _SPACE_RE.sub(" ", str(value or "").strip())


def _normalize_name(value) -> str:
    return _normalize_text(NameTransformer.remove_flags(str(value or "")))


def _node_identity(node: dict) -> Optional[dict]:
    """Identity for exact visibility inheritance across refreshes."""
    if not isinstance(node, dict):
        return None

    name = _normalize_name(node.get("name"))
    server = _normalize_text(node.get("server")).lower()
    port = str(node.get("port") or "").strip()
    node_type = _normalize_text(node.get("type")).lower()

    if not name or not server or not port:
        return None

    return {
        "name": name,
        "server": server,
        "port": port,
        "type": node_type,
    }


def _endpoint_identity(node: dict) -> Optional[dict]:
    """Endpoint-only identity used for conservative rename fallback."""
    if not isinstance(node, dict):
        return None

    server = _normalize_text(node.get("server")).lower()
    port = str(node.get("port") or "").strip()
    node_type = _normalize_text(node.get("type")).lower()

    if not server or not port:
        return None

    return {
        "server": server,
        "port": port,
        "type": node_type,
    }


def _identity_key(identity: Optional[dict]) -> Optional[str]:
    if not identity:
        return None
    raw = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _build_visibility_index(existing_nodes: Iterable[dict]) -> Tuple[set, dict]:
    """Build exact and endpoint indexes from old nodes.

    Exact match preserves disabled state by name+endpoint. Endpoint fallback is
    only applied when all old nodes sharing the endpoint were disabled; mixed
    enabled/disabled endpoints are intentionally ignored to avoid disabling the
    wrong refreshed node after a provider rename.
    """
    exact_disabled = set()
    endpoints = {}

    for node in existing_nodes or []:
        if not isinstance(node, dict):
            continue

        enabled = is_node_enabled(node)
        exact_key = _identity_key(_node_identity(node))
        if exact_key and not enabled:
            exact_disabled.add(exact_key)

        endpoint_key = _identity_key(_endpoint_identity(node))
        if endpoint_key:
            state = endpoints.setdefault(endpoint_key, {"disabled": 0, "enabled": 0})
            if enabled:
                state["enabled"] += 1
            else:
                state["disabled"] += 1

    return exact_disabled, endpoints


def apply_node_visibility_history(nodes: Iterable[dict], existing_nodes: Iterable[dict] = None) -> int:
    """Carry disabled state from old subscription nodes to refreshed nodes."""
    nodes = list(nodes or [])
    if not nodes:
        return 0

    exact_disabled, endpoints = _build_visibility_index(existing_nodes or [])
    if not exact_disabled and not endpoints:
        return 0

    applied = 0
    for node in nodes:
        if not isinstance(node, dict):
            continue

        # Explicit visibility in incoming content wins.
        if "enabled" in node:
            continue

        exact_key = _identity_key(_node_identity(node))
        if exact_key and exact_key in exact_disabled:
            node["enabled"] = False
            applied += 1
            continue

        endpoint_key = _identity_key(_endpoint_identity(node))
        endpoint_state = endpoints.get(endpoint_key) if endpoint_key else None
        if (
            endpoint_state
            and endpoint_state.get("disabled", 0) > 0
            and endpoint_state.get("enabled", 0) == 0
        ):
            node["enabled"] = False
            applied += 1

    if applied:
        logger.info("Inherited disabled state for %s refreshed node(s)", applied)

    return applied


def apply_node_visibility_to_yaml_content(
    yaml_content: str,
    existing_nodes: Optional[Iterable[dict]] = None,
) -> Tuple[str, int]:
    """Apply disabled-node inheritance to YAML subscription content."""
    try:
        cfg = yaml.load(yaml_content, Loader=YAMLLoader)
    except Exception as exc:
        logger.warning("Failed to parse YAML for node visibility inheritance: %s", exc)
        return yaml_content, 0

    if not isinstance(cfg, dict):
        return yaml_content, 0

    proxies = cfg.get("proxies", [])
    if not isinstance(proxies, list):
        return yaml_content, 0

    inherited = apply_node_visibility_history(proxies, existing_nodes or [])
    if not inherited:
        return yaml_content, inherited

    try:
        return (
            yaml.dump(cfg, allow_unicode=True, sort_keys=False, Dumper=YAMLDumper),
            inherited,
        )
    except Exception as exc:
        logger.warning("Failed to dump YAML after node visibility inheritance: %s", exc)
        return yaml_content, 0
