"""
Node Manager Service
Handles node lookup, name transformation, and allocation logic
"""
from typing import Optional, List, Set

from logger_config import get_logger
from core.database import load_config, find_subscription_by_id
from helpers import load_subscription_yaml
from services.name_transformer import NameTransformer
from services.proxy_filter import ProxyFilter
from services.node_visibility import is_node_enabled
from services.node_identity import (
    custom_node_id,
    is_node_allocated,
    subscription_node_id,
)

logger = get_logger(__name__)

# Fields to exclude from proxy config (metadata fields)
NODE_METADATA_FIELDS = {
    'id', 'link', 'last_latency', 'last_latency_time', 'last_speed',
    'last_peak_speed', 'last_speed_time', 'exit_ip', 'geoip', 'region',
    'city', 'display_name', 'index', 'enabled'
}


def strip_metadata(node: dict) -> dict:
    """
    Remove metadata fields from node dict.
    
    Args:
        node: Node dict with potential metadata fields
        
    Returns:
        Clean node dict
    """
    return {k: v for k, v in node.items() if k not in NODE_METADATA_FIELDS}


def find_custom_node(
    custom_nodes: List[dict],
    node_index: int = None,
    node_name: str = None,
    node_id: str = None,
) -> Optional[dict]:
    """
    Find a custom node by index or name.
    
    Args:
        custom_nodes: List of custom nodes
        node_index: Optional node index
        node_name: Optional node name (after transformation)
        
    Returns:
        Transformed node dict or None
    """
    # Stable ID is authoritative. Name/index remain read-only migration fallbacks.
    if node_id:
        for node in custom_nodes:
            if custom_node_id(node) != node_id or not is_node_enabled(node):
                continue
            proxy = ProxyFilter.sanitize_proxy(dict(node))
            transformed = strip_metadata(NameTransformer.transform_name(proxy, 'Custom'))
            transformed['_allocation_id'] = custom_node_id(node)
            return transformed
        return None

    # Search by name
    if node_name:
        for node in custom_nodes:
            if not is_node_enabled(node):
                continue
            proxy = ProxyFilter.sanitize_proxy(dict(node))
            transformed = strip_metadata(NameTransformer.transform_name(proxy, 'Custom'))
            if transformed.get('name') == node_name:
                transformed['_allocation_id'] = custom_node_id(node)
                return transformed
    
    # Search by index
    if node_index is not None and 0 <= node_index < len(custom_nodes):
        node = custom_nodes[node_index]
        if not is_node_enabled(node):
            return None
        proxy = ProxyFilter.sanitize_proxy(dict(node))
        transformed = strip_metadata(NameTransformer.transform_name(proxy, 'Custom'))
        transformed['_allocation_id'] = custom_node_id(node)
        return transformed
    
    return None


def find_subscription_node(
    sub_id: str,
    node_index: int = None,
    node_name: str = None,
    yaml_source_dir: str = None,
    node_id: str = None,
) -> Optional[dict]:
    """
    Find a subscription node by index or name.
    
    Args:
        sub_id: Subscription ID
        node_index: Optional node index
        node_name: Optional node name (after transformation)
        yaml_source_dir: YAML source directory
        
    Returns:
        Transformed node dict or None
    """
    from core.config import AppConfig
    
    if yaml_source_dir is None:
        yaml_source_dir = AppConfig.YAML_SOURCE_DIR
    
    config = load_config()
    sub = find_subscription_by_id(config, sub_id)
    source_name = sub['name'] if sub else sub_id
    
    try:
        cfg = load_subscription_yaml(sub_id, yaml_source_dir, use_cache=True)
        proxies = cfg.get('proxies', []) if cfg else []
        
        if node_id:
            matching_nodes = [
                proxy
                for proxy in proxies
                if isinstance(proxy, dict) and subscription_node_id(sub_id, proxy) == node_id
            ]
            if len(matching_nodes) > 1:
                logger.warning("Ambiguous stable node reference in subscription %s", sub_id)
                return None
            if matching_nodes:
                proxy = matching_nodes[0]
                if not is_node_enabled(proxy) or not ProxyFilter.is_valid_proxy(proxy):
                    return None
                proxy = ProxyFilter.sanitize_proxy(dict(proxy))
                transformed = strip_metadata(NameTransformer.transform_name(proxy, source_name))
                transformed['_allocation_id'] = node_id
                return transformed
            return None

        # Search by name
        if node_name:
            for proxy in proxies:
                raw_proxy = proxy
                if not is_node_enabled(proxy):
                    continue
                if not ProxyFilter.is_valid_proxy(proxy):
                    continue
                proxy = ProxyFilter.sanitize_proxy(dict(proxy))
                transformed = strip_metadata(NameTransformer.transform_name(proxy, source_name))
                if transformed.get('name') == node_name:
                    transformed['_allocation_id'] = subscription_node_id(sub_id, raw_proxy)
                    return transformed
        
        # Search by index
        if node_index is not None and 0 <= node_index < len(proxies):
            proxy = proxies[node_index]
            raw_proxy = proxy
            if not is_node_enabled(proxy):
                return None
            if not ProxyFilter.is_valid_proxy(proxy):
                return None
            proxy = ProxyFilter.sanitize_proxy(dict(proxy))
            transformed = strip_metadata(NameTransformer.transform_name(proxy, source_name))
            transformed['_allocation_id'] = subscription_node_id(sub_id, raw_proxy)
            return transformed
            
    except Exception as e:
        logger.warning("Failed to load node %s[%s]: %s", sub_id, node_index, e)
    
    return None


def find_node_by_reference(
    sub_id: str,
    node_index: int = None,
    node_name: str = None,
    yaml_source_dir: str = None,
    node_id: str = None,
) -> Optional[dict]:
    """
    Get a proxy node by reference (sub_id + node_name/node_index).
    
    Args:
        sub_id: Subscription ID or 'custom'
        node_index: Optional node index
        node_name: Optional node name (after transformation)
        yaml_source_dir: YAML source directory
        
    Returns:
        Transformed node dict or None if not found
    """
    config = load_config()
    
    # Custom nodes
    if sub_id == 'custom':
        custom_nodes = config.get('custom_nodes', [])
        return find_custom_node(custom_nodes, node_index, node_name, node_id)
    
    # Subscription nodes
    return find_subscription_node(sub_id, node_index, node_name, yaml_source_dir, node_id)


def normalize_alloc_name(name: str) -> str:
    """
    Normalize node name for allocation matching (remove flags and trim).
    
    Args:
        name: Node name
        
    Returns:
        Normalized name
    """
    return NameTransformer.remove_flags(name or '').strip()


def is_name_allocated(
    name: str,
    allocated_nodes: List[str] = None,
    node_id: str = None,
) -> bool:
    """
    Check if a node name is in allocation list.
    
    Args:
        name: Node name to check
        allocated_nodes: List of allocated node names or patterns
        
    Returns:
        True if node is allocated
    """
    return is_node_allocated(name, allocated_nodes, node_id)


def get_all_final_node_names(yaml_source_dir: str = None) -> Set[str]:
    """
    Get a set of all current final node names (for validation).
    
    Args:
        yaml_source_dir: YAML source directory
        
    Returns:
        Set of node names
    """
    from core.config import AppConfig
    
    if yaml_source_dir is None:
        yaml_source_dir = AppConfig.YAML_SOURCE_DIR
    
    config = load_config()
    names = set()
    
    # Get subscription nodes
    for sub in config.get('subscriptions', []):
        if sub.get('enabled', True):
            try:
                cfg = load_subscription_yaml(sub['id'], yaml_source_dir, use_cache=True)
                for proxy in cfg.get('proxies', []):
                    if not is_node_enabled(proxy):
                        continue
                    transformed = NameTransformer.transform_name(proxy, sub['name'])
                    names.add(transformed.get('name', ''))
            except Exception as e:
                logger.error(f"Error getting node names from {sub['id']}: {e}")
    
    # Get custom nodes
    for node in config.get('custom_nodes', []):
        if not is_node_enabled(node):
            continue
        transformed = NameTransformer.transform_name(node, 'Custom')
        names.add(transformed.get('name', ''))
    
    return names


def get_proxy_node_by_id(node_id: str, yaml_source_dir: str = None) -> Optional[dict]:
    """
    Get proxy node config by ID.
    
    Args:
        node_id: Node ID (e.g., 'custom_0', 'sub_xxx_0')
        yaml_source_dir: YAML source directory
        
    Returns:
        Node dict or None
    """
    from core.config import AppConfig
    
    if yaml_source_dir is None:
        yaml_source_dir = AppConfig.YAML_SOURCE_DIR
    
    if not node_id:
        return None
    
    config = load_config()
    for node in config.get('custom_nodes', []):
        if custom_node_id(node) == node_id:
            if not is_node_enabled(node):
                return None
            return strip_metadata(ProxyFilter.sanitize_proxy(node))

    for subscription in config.get('subscriptions', []):
        subscription_id = subscription.get('id')
        if not subscription_id:
            continue
        try:
            subscription_data = load_subscription_yaml(subscription_id, yaml_source_dir, use_cache=True)
        except Exception:
            continue
        for node in subscription_data.get('proxies', []):
            if subscription_node_id(subscription_id, node) == node_id:
                if not is_node_enabled(node):
                    return None
                return strip_metadata(ProxyFilter.sanitize_proxy(node))
    return None
