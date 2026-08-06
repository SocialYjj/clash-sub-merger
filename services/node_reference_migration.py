"""One-time migration from positional node references to persisted/stable IDs."""

from typing import Optional

from core.config import AppConfig
from helpers import generate_timestamp_id, load_subscription_yaml
from services.name_transformer import NameTransformer
from services.node_identity import custom_node_id, subscription_node_ids


def ensure_custom_node_ids(config: dict) -> int:
    added = 0
    reserved_ids = {
        str(node.get("id"))
        for node in config.get("custom_nodes", [])
        if isinstance(node, dict) and node.get("id")
    }
    seen_ids: set[str] = set()
    for node in config.get("custom_nodes", []):
        if not isinstance(node, dict):
            continue
        stored_id = str(node.get("id") or "").strip()
        if stored_id and stored_id not in seen_ids:
            node["id"] = stored_id
            seen_ids.add(stored_id)
            continue
        node_id = generate_timestamp_id("node_")
        while node_id in reserved_ids or node_id in seen_ids:
            node_id = generate_timestamp_id("node_")
        node["id"] = node_id
        reserved_ids.add(node_id)
        seen_ids.add(node_id)
        added += 1
    return added


def _resolve_reference_id(config: dict, reference: dict) -> Optional[str]:
    existing_id = str(reference.get("node_id") or "").strip()
    if existing_id:
        return existing_id
    source_id = reference.get("sub_id")
    node_index = reference.get("node_index")
    node_name = reference.get("node_name")

    if source_id == "custom":
        nodes = config.get("custom_nodes", [])
        if isinstance(node_index, int) and 0 <= node_index < len(nodes):
            return custom_node_id(nodes[node_index])
        for node in nodes:
            transformed_name = NameTransformer.transform_name(node, "Custom").get("name")
            if node_name and transformed_name == node_name:
                return custom_node_id(node)
        return None

    subscription = next(
        (item for item in config.get("subscriptions", []) if item.get("id") == source_id),
        None,
    )
    if not subscription:
        return None
    try:
        subscription_data = load_subscription_yaml(
            source_id,
            AppConfig.YAML_SOURCE_DIR,
            use_cache=False,
        )
    except Exception:
        return None
    nodes = subscription_data.get("proxies", []) if isinstance(subscription_data, dict) else []
    node_ids = subscription_node_ids(source_id, nodes)
    if isinstance(node_index, int) and 0 <= node_index < len(nodes):
        return node_ids[node_index]
    for index, node in enumerate(nodes):
        transformed_name = NameTransformer.transform_name(
            node,
            subscription.get("name", source_id),
        ).get("name")
        if node_name and transformed_name == node_name:
            return node_ids[index]
    return None


def migrate_proxy_chain_node_ids(config: dict) -> int:
    migrated = 0
    for chain in config.get("proxy_chains", []):
        for row in chain.get("rows", []) if isinstance(chain, dict) else []:
            for reference in row.get("nodes", []) if isinstance(row, dict) else []:
                if not isinstance(reference, dict):
                    continue
                if reference.get("type") == "group":
                    nested_references = reference.get("group_nodes") or []
                else:
                    nested_references = [reference]
                for nested_reference in nested_references:
                    if not isinstance(nested_reference, dict) or nested_reference.get("node_id"):
                        continue
                    node_id = _resolve_reference_id(config, nested_reference)
                    if node_id:
                        nested_reference["node_id"] = node_id
                        migrated += 1
    return migrated
