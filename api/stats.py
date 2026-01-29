"""
Stats API
Statistics and analytics endpoints
"""
import os
from fastapi import APIRouter, Depends

from core.dependencies import verify_session
from core.database import load_config
from helpers import handle_api_errors, load_subscription_yaml
from services.name_transformer import NameTransformer
from services.country_data import detect_country, COUNTRY_NAMES
from geoip_service import GeoIPService
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Get YAML_SOURCE_DIR from environment or default
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(BASE_DIR, 'data'))
YAML_SOURCE_DIR = os.path.join(DATA_DIR, 'uploads')


# ==================== Helper Functions ====================

def _is_info_node(name: str) -> bool:
    """Check if node is an info/advertisement node"""
    info_keywords = [
        '剩余流量', '套餐到期', '距离下次重置', '建议', '未到期',
        '剩余', '到期', '重置', '流量', '过期', '订阅', '网址', '公告',
        '群组', 'Telegram', 'TG', '客服', '续费', '购买', '套餐',
        '使用说明', '教程', '更新', '通知', '邀请', '返利',
        '问题', '工单', '咨询', '合作', '会员', '商城', '账号',
        '官网:', '官网：', '免注册'
    ]
    name_lower = name.lower()
    
    # Check basic keywords
    if any(keyword in name or keyword in name_lower for keyword in info_keywords):
        return True
    
    # Check if starts with "官网" but has no region name
    if name.startswith('官网'):
        # Import ISO_TO_COUNTRY from name_transformer
        from services.name_transformer import NameTransformer
        
        # Define region keywords (country names + common abbreviations)
        region_keywords = list(NameTransformer.ISO_TO_COUNTRY.values()) + [
            'HK', 'TW', 'MO', 'JP', 'KR', 'SG', 'US', 'UK', 
            'DE', 'FR', 'CA', 'AU', 'RU', 'IN', 'TH', 'VN', 'MY', 'PH', 'ID',
            'CN', 'GB', 'IT', 'ES', 'PT', 'NL', 'BE', 'CH', 'AT', 'CZ', 'PL',
            'SE', 'NO', 'FI', 'DK', 'IE', 'NZ', 'BR', 'AR', 'CL', 'MX', 'TR',
            'SA', 'AE', 'IL', 'EG', 'ZA', 'NG', 'KE', 'UA', 'BY', 'KZ', 'UZ',
            '海外'
        ]
        # If it contains a region name, it's a valid node
        if any(region in name for region in region_keywords):
            return False
        # Otherwise it's an info node
        return True
    
    return False


def _get_all_nodes_with_country():
    """Get all nodes with country information"""
    config = load_config()
    nodes = []
    
    # Get subscription nodes
    for sub in config.get('subscriptions', []):
        if not sub.get('enabled', True):
            continue
        try:
            sub_data = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=True)
            for i, proxy in enumerate(sub_data.get('proxies', [])):
                # Skip info/advertisement nodes
                node_name = proxy.get('name', '')
                if _is_info_node(node_name):
                    continue
                    
                transformed = NameTransformer.transform_name(proxy, sub['name'])
                country_info = transformed.get('_country', {})
                nodes.append({
                    'name': transformed.get('name', proxy.get('name', 'Unknown')),
                    'type': proxy.get('type', 'unknown'),
                    'server': proxy.get('server', ''),
                    'country_code': country_info.get('country_code', 'XX'),
                    'country': country_info.get('country', 'Unknown'),
                    'flag': country_info.get('flag', '🏳️'),
                    'source': sub['name'],
                    'source_id': sub['id'],
                    'index': i
                })
        except Exception as e:
            logger.warning(f"Failed to load subscription {sub['id']}: {e}")
    
    # Get custom nodes
    for i, node in enumerate(config.get('custom_nodes', [])):
        transformed = NameTransformer.transform_name(node, 'Custom')
        country_info = transformed.get('_country', {})
        nodes.append({
            'name': transformed.get('name', node.get('name', 'Unknown')),
            'type': node.get('type', 'unknown'),
            'server': node.get('server', ''),
            'country_code': country_info.get('country_code', 'XX'),
            'country': country_info.get('country', 'Unknown'),
            'flag': country_info.get('flag', '🏳️'),
            'source': 'Custom',
            'source_id': 'custom',
            'index': i
        })
    
    return nodes


# ==================== API Endpoints ====================

@router.get("/overview")
@handle_api_errors
def get_stats_overview(_: bool = Depends(verify_session)):
    """Get dashboard overview statistics"""
    config = load_config()
    
    # Count subscriptions
    subs = config.get('subscriptions', [])
    enabled_subs = [s for s in subs if s.get('enabled', True)]
    
    # Count nodes and protocols (exclude info nodes)
    total_nodes = 0
    by_protocol = {}
    
    for sub in enabled_subs:
        # Load subscription to count actual nodes (excluding info nodes)
        try:
            sub_data = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=True)
            for proxy in sub_data.get('proxies', []):
                # Skip info/advertisement nodes
                if _is_info_node(proxy.get('name', '')):
                    continue
                    
                total_nodes += 1
                ptype = proxy.get('type', 'unknown')
                by_protocol[ptype] = by_protocol.get(ptype, 0) + 1
        except Exception:
            pass
    
    # Count custom nodes
    custom_nodes_list = config.get('custom_nodes', [])
    for node in custom_nodes_list:
        ptype = node.get('type', 'unknown')
        by_protocol[ptype] = by_protocol.get(ptype, 0) + 1
    
    # Count users
    users = config.get('users', [])
    enabled_users = [u for u in users if u.get('enabled', True)]
    
    # Count templates
    templates = config.get('templates', [])
    
    # Count admin tokens
    admin_tokens = config.get('admin_tokens', [])
    enabled_tokens = [t for t in admin_tokens if t.get('enabled', True)]
    
    return {
        "subscriptions": {
            "total": len(subs),
            "active": len(enabled_subs)
        },
        "nodes": {
            "subscription": total_nodes,
            "custom": len(custom_nodes_list),
            "total": total_nodes + len(custom_nodes_list),
            "by_protocol": by_protocol
        },
        "users": {
            "total": len(users),
            "active": len(enabled_users)
        },
        "templates": {
            "total": len(templates)
        },
        "admin_tokens": {
            "total": len(admin_tokens),
            "enabled": len(enabled_tokens)
        }
    }


@router.get("/countries")
@handle_api_errors
def get_stats_countries(_: bool = Depends(verify_session)):
    """Get node statistics by country"""
    nodes = _get_all_nodes_with_country()
    
    # Group by country (exclude unknown)
    country_stats = {}
    for node in nodes:
        code = node['country_code']
        # Skip unknown countries
        if code == 'XX' or node['country'] == '未知':
            continue
            
        if code not in country_stats:
            country_stats[code] = {
                'country_code': code,
                'country': node['country'],
                'flag': node['flag'],
                'count': 0,
                'types': {}
            }
        country_stats[code]['count'] += 1
        node_type = node['type']
        country_stats[code]['types'][node_type] = country_stats[code]['types'].get(node_type, 0) + 1
    
    # Sort by count descending
    sorted_countries = sorted(country_stats.values(), key=lambda x: x['count'], reverse=True)
    
    return {
        "countries": sorted_countries,
        "total_countries": len(sorted_countries),
        "total_nodes": len(nodes)
    }


@router.get("/nodes-by-country")
@handle_api_errors
def get_all_nodes_by_country(_: bool = Depends(verify_session)):
    """Get all nodes grouped by country"""
    nodes = _get_all_nodes_with_country()
    
    # Group by country (exclude unknown)
    by_country = {}
    for node in nodes:
        code = node['country_code']
        # Skip unknown countries
        if code == 'XX' or node['country'] == '未知':
            continue
            
        if code not in by_country:
            by_country[code] = {
                'code': code,  # Frontend expects 'code' not 'country_code'
                'name': node['country'],  # Frontend expects 'name' not 'country'
                'flag': node['flag'],
                'count': 0,
                'nodes': []
            }
        by_country[code]['count'] += 1
        by_country[code]['nodes'].append(node)
    
    # Sort by count descending
    sorted_countries = sorted(by_country.values(), key=lambda x: x['count'], reverse=True)
    
    return {
        "countries": sorted_countries,
        "total": sum(c['count'] for c in sorted_countries)
    }


@router.get("/nodes-by-country/{country_code}")
@handle_api_errors
def get_nodes_by_country(country_code: str, _: bool = Depends(verify_session)):
    """Get nodes for a specific country"""
    nodes = _get_all_nodes_with_country()
    
    # Filter by country code
    country_code = country_code.upper()
    filtered = [n for n in nodes if n['country_code'] == country_code]
    
    country_name = COUNTRY_NAMES.get(country_code, country_code)
    flag = GeoIPService.iso_to_flag(country_code) if country_code != 'XX' else '🏳️'
    
    return {
        "country_code": country_code,
        "country": country_name,
        "flag": flag,
        "nodes": filtered,
        "count": len(filtered)
    }
