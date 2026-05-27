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

logger = get_logger(__name__)

# Fields to exclude from proxy config (metadata fields)
NODE_METADATA_FIELDS = {
    'id', 'link', 'last_latency', 'last_latency_time', 'last_speed',
    'last_peak_speed', 'last_speed_time', 'geoip', 'enabled'
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
    node_name: str = None
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
    # Search by name
    if node_name:
        for node in custom_nodes:
            if not is_node_enabled(node):
                continue
            proxy = strip_metadata(node)
            proxy = ProxyFilter.sanitize_proxy(proxy)
            transformed = NameTransformer.transform_name(proxy, 'Custom')
            if transformed.get('name') == node_name:
                return transformed
    
    # Search by index
    if node_index is not None and 0 <= node_index < len(custom_nodes):
        node = custom_nodes[node_index]
        if not is_node_enabled(node):
            return None
        proxy = strip_metadata(node)
        proxy = ProxyFilter.sanitize_proxy(proxy)
        return NameTransformer.transform_name(proxy, 'Custom')
    
    return None


def find_subscription_node(
    sub_id: str,
    node_index: int = None,
    node_name: str = None,
    yaml_source_dir: str = None
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
        
        # Search by name
        if node_name:
            for proxy in proxies:
                if not is_node_enabled(proxy):
                    continue
                if not ProxyFilter.is_valid_proxy(proxy):
                    continue
                proxy = ProxyFilter.sanitize_proxy(proxy)
                proxy.pop('enabled', None)
                transformed = NameTransformer.transform_name(proxy, source_name)
                if transformed.get('name') == node_name:
                    return transformed
        
        # Search by index
        if node_index is not None and 0 <= node_index < len(proxies):
            proxy = proxies[node_index]
            if not is_node_enabled(proxy):
                return None
            if not ProxyFilter.is_valid_proxy(proxy):
                return None
            proxy = ProxyFilter.sanitize_proxy(proxy)
            proxy.pop('enabled', None)
            return NameTransformer.transform_name(proxy, source_name)
            
    except Exception as e:
        logger.warning("Failed to load node %s[%s]: %s", sub_id, node_index, e)
    
    return None


def find_node_by_reference(
    sub_id: str,
    node_index: int = None,
    node_name: str = None,
    yaml_source_dir: str = None
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
        return find_custom_node(custom_nodes, node_index, node_name)
    
    # Subscription nodes
    return find_subscription_node(sub_id, node_index, node_name, yaml_source_dir)


def normalize_alloc_name(name: str) -> str:
    """
    Normalize node name for allocation matching (remove flags and trim).
    
    Args:
        name: Node name
        
    Returns:
        Normalized name
    """
    return NameTransformer.remove_flags(name or '').strip()


def is_name_allocated(name: str, allocated_nodes: List[str] = None) -> bool:
    """
    Check if a node name is in allocation list.
    
    Args:
        name: Node name to check
        allocated_nodes: List of allocated node names or patterns
        
    Returns:
        True if node is allocated
    """
    if not allocated_nodes:
        return False
    if allocated_nodes == ['*']:
        return True
    if not name:
        return False
    
    name_clean = normalize_alloc_name(name)
    
    for alloc in allocated_nodes:
        if not alloc:
            continue
        if alloc == name:
            return True
        if alloc in name:
            return True
        
        alloc_clean = normalize_alloc_name(alloc)
        if alloc_clean and (alloc_clean == name_clean or alloc_clean in name_clean):
            return True
    
    return False


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
    
    # Custom nodes
    if node_id.startswith('custom_'):
        config = load_config()
        custom_nodes = config.get('custom_nodes', [])
        try:
            idx = int(node_id.rsplit('_', 1)[1])
            if 0 <= idx < len(custom_nodes):
                node = custom_nodes[idx]
                if not is_node_enabled(node):
                    return None
                node = dict(node)
                node.pop('enabled', None)
                return node
        except (ValueError, IndexError):
            pass
        return None
    
    # Subscription nodes
    if node_id.startswith('sub_'):
        return _get_subscription_node_by_id(node_id, yaml_source_dir)
    
    return None


def _get_subscription_node_by_id(node_id: str, yaml_source_dir: str) -> Optional[dict]:
    """Get subscription node by ID."""
    sub_id = None
    try:
        node_ref, node_idx_text = node_id.rsplit('_', 1)
        if not node_ref or node_ref == 'sub':
            return None
        node_idx = int(node_idx_text)
        
        # Support both sub_<id>_<index> and <id>_<index> formats
        raw_sub_id = node_ref[4:] if node_ref.startswith('sub_') else node_ref
        candidate_sub_ids = []
        for candidate in (raw_sub_id, f"sub_{raw_sub_id}", node_ref):
            if candidate and candidate not in candidate_sub_ids:
                candidate_sub_ids.append(candidate)
        
        for sub_id in candidate_sub_ids:
            import os
            sub_file = os.path.join(yaml_source_dir, f"{sub_id}.yaml")
            if not os.path.exists(sub_file):
                continue
            sub_data = load_subscription_yaml(sub_id, yaml_source_dir, use_cache=True)
            proxies = sub_data.get('proxies', [])
            if 0 <= node_idx < len(proxies):
                proxy = proxies[node_idx]
                if not is_node_enabled(proxy):
                    return None
                proxy = dict(proxy)
                proxy.pop('enabled', None)
                return proxy
            break
    except (ValueError, IndexError):
        pass
    except Exception as e:
        logger.warning("Error getting subscription node %s: %s", node_id, e)
    return None
