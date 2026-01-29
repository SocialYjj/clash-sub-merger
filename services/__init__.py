"""
Services module - Business logic layer
"""
# HTTP Client
from .http_client import http_client, close_http_client

# Backup
from .backup import (
    create_backup,
    cleanup_old_backups,
    list_backups,
    restore_backup,
    delete_backup,
    export_config,
    import_config,
)

# Key Rotation
from .key_rotation import check_key_rotation_needed, log_rotation_reminder

# Node Parser
from .node_parser import (
    decode_base64, parse_node_link, parse_vmess_link, parse_vless_link,
    parse_ss_link, parse_ssr_link, parse_trojan_link, parse_hysteria_link,
    parse_hysteria2_link, parse_tuic_link, parse_socks_link, parse_http_link
)

# Proxy Filter
from .proxy_filter import ProxyFilter

# Name Transformer
from .name_transformer import NameTransformer

# Country Grouper
from .country_grouper import CountryGrouper

# Config Merger
from .config_merger import ConfigMerger, ProxyGroupGenerator

# Subscription Parser
from .subscription import SubscriptionParser

# Country Data
from .country_data import (
    COUNTRY_KEYWORDS, COUNTRY_NAMES, PLACEHOLDER_COUNTRY_MAP,
    detect_country
)

__all__ = [
    # HTTP Client
    'http_client',
    'close_http_client',
    # Backup
    'create_backup',
    'cleanup_old_backups',
    'list_backups',
    'restore_backup',
    'delete_backup',
    'export_config',
    'import_config',
    # Key Rotation
    'check_key_rotation_needed',
    'log_rotation_reminder',
    # Node Parser
    'decode_base64', 'parse_node_link', 'parse_vmess_link', 'parse_vless_link',
    'parse_ss_link', 'parse_ssr_link', 'parse_trojan_link', 'parse_hysteria_link',
    'parse_hysteria2_link', 'parse_tuic_link', 'parse_socks_link', 'parse_http_link',
    # Proxy Filter
    'ProxyFilter',
    # Name Transformer
    'NameTransformer',
    # Country Grouper
    'CountryGrouper',
    # Config Merger
    'ConfigMerger', 'ProxyGroupGenerator',
    # Subscription Parser
    'SubscriptionParser',
    # Country Data
    'COUNTRY_KEYWORDS', 'COUNTRY_NAMES', 'PLACEHOLDER_COUNTRY_MAP',
    'detect_country',
]
