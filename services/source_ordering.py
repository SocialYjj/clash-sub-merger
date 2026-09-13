"""Source ordering and final node-name index over the merged configuration."""

from typing import List

from fastapi import HTTPException

from logger_config import get_logger
from services.name_transformer import NameTransformer
from services.node_visibility import is_node_enabled
from services.vpngate import list_vpngate_nodes

logger = get_logger(__name__)


def update_custom_nodes_yaml():
    """Update custom nodes yaml file"""
    from services.custom_node_storage import rebuild_custom_nodes_yaml

    rebuild_custom_nodes_yaml()


def get_ordered_sources() -> List[dict]:
    """Get all sources in order"""
    import server as srv

    config = srv.load_config()
    subs = config.get("subscriptions", [])
    custom_nodes = config.get("custom_nodes", [])
    order = config.get("source_order", [])

    all_sources = {}
    for s in subs:
        all_sources[s["id"]] = {"type": "subscription", "data": s}
    if custom_nodes:
        all_sources["custom_nodes"] = {
            "type": "custom",
            "data": {"id": "custom_nodes", "name": "Custom Nodes", "nodes": custom_nodes},
        }

    result = []
    for source_id in order:
        if source_id in all_sources:
            result.append(all_sources.pop(source_id))
    for source in all_sources.values():
        result.append(source)

    return result


def get_all_final_node_names() -> set:
    """Get a set of all current final node names (for validation)"""
    import server as srv

    config = srv.load_config()
    names = set()

    # Get subscription nodes
    for sub in config.get("subscriptions", []):
        if sub.get("enabled", True):
            try:
                cfg = srv.load_subscription_yaml(sub["id"], srv.YAML_SOURCE_DIR, use_cache=True)
                for proxy in cfg.get("proxies", []):
                    if not is_node_enabled(proxy):
                        continue
                    transformed = NameTransformer.transform_name(proxy, sub["name"])
                    names.add(transformed.get("name", ""))
            except HTTPException:
                # Subscription file not found, skip
                pass
            except Exception as e:
                logger.error(f"Error getting node names from {sub['id']}: {e}")

    # Get custom nodes
    for node in config.get("custom_nodes", []):
        if not is_node_enabled(node):
            continue
        transformed = NameTransformer.transform_name(node, "Custom")
        names.add(transformed.get("name", ""))

    for node in list_vpngate_nodes():
        transformed = NameTransformer.transform_name(node, "VPN Gate")
        names.add(transformed.get("name", ""))

    return names
