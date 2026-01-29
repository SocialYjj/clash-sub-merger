"""
Name Transformer Service
Unify node name format to: Flag Provider NodeName
"""
import re
from typing import List, Dict, Optional
from functools import lru_cache
from logger_config import get_logger

logger = get_logger(__name__)


class NameTransformer:
    """Node name transformer - unify node name format to: Flag Provider NodeName"""
    
    # Source filename to prefix mapping
    SOURCE_PREFIX_MAP = {
        '宝可梦': '宝可梦',
        '流量光机场': '流量多',
        '淘气兔': '淘气兔',
        '风萧萧公益机场': '风萧萧',
        '魔戒': '魔戒'
    }
    
    # All flag emojis list (for removal)
    FLAG_EMOJIS = [
        '🇭🇰', '🇹🇼', '🇯🇵', '🇺🇸', '🇸🇬', '🇰🇷', '🇬🇧', '🇩🇪', '🇨🇦', '🇦🇺',
        '🇫🇷', '🇷🇺', '🇮🇳', '🇳🇱', '🇹🇷', '🇦🇶', '🇲🇾', '🇪🇸', '🇻🇳', '🇺🇦',
        '🇲🇩', '🇳🇬', '🇧🇷', '🇮🇹', '🇵🇱', '🇨🇭', '🇦🇹', '🇧🇪', '🇸🇪', '🇳🇴',
        '🇩🇰', '🇫🇮', '🇮🇪', '🇵🇹', '🇬🇷', '🇨🇿', '🇭🇺', '🇷🇴', '🇧🇬', '🇭🇷',
        '🇸🇰', '🇸🇮', '🇱🇹', '🇱🇻', '🇪🇪', '🇮🇱', '🇦🇪', '🇸🇦', '🇶🇦', '🇰🇼',
        '🇴🇲', '🇧🇭', '🇯🇴', '🇱🇧', '🇪🇬', '🇿🇦', '🇰🇪', '🇳🇿', '🇵🇭', '🇹🇭',
        '🇮🇩', '🇵🇰', '🇧🇩', '🇱🇰', '🇳🇵', '🇲🇲', '🇰🇭', '🇱🇦', '🇲🇳', '🇰🇿',
        '🇺🇿', '🇦🇿', '🇬🇪', '🇦🇲', '🇨🇾', '🇲🇹', '🇮🇸', '🇱🇺', '🇲🇨', '🇦🇩',
        '🇱🇮', '🇸🇲', '🇻🇦', '🇲🇽', '🇦🇷', '🇨🇱', '🇨🇴', '🇵🇪', '🇻🇪', '🇪🇨',
        '🇧🇴', '🇵🇾', '🇺🇾', '🇨🇷', '🇵🇦', '🇨🇺', '🇩🇴', '🇵🇷', '🇯🇲', '🇭🇹',
        '🔰', '🌏', '🌍', '🌎', '🏳️'
    ]
    
    # Country identification patterns: Flag -> keyword list
    COUNTRY_FLAG_MAP = {
        '🇭🇰': ['HK', 'Hong Kong', '香港', 'Hongkong'],
        '🇹🇼': ['TW', 'Taiwan', '台湾', 'Taipei'],
        '🇯🇵': ['JP', 'Japan', '日本', 'Tokyo', 'Osaka'],
        '🇺🇸': ['US', 'United States', '美国', 'America', 'USA', 'Los Angeles', 'Seattle', 'San Jose'],
        '🇸🇬': ['SG', 'Singapore', '新加坡'],
        '🇰🇷': ['KR', 'Korea', '韩国', 'Seoul'],
        '🇬🇧': ['GB', 'UK', 'United Kingdom', '英国', 'England', 'London'],
        '🇩🇪': ['DE', 'Germany', '德国', 'Frankfurt'],
        '🇨🇦': ['CA', 'Canada', '加拿大', 'Toronto', 'Vancouver'],
        '🇦🇺': ['AU', 'Australia', '澳大利亚', '澳洲', 'Sydney'],
        '🇫🇷': ['FR', 'France', '法国', 'Paris'],
        '🇷🇺': ['RU', 'Russia', '俄罗斯', 'Moscow'],
        '🇮🇳': ['IN', 'India', '印度'],
        '🇳🇱': ['NL', 'Netherlands', '荷兰', 'Amsterdam'],
        '🇹🇷': ['TR', 'Turkey', '土耳其', 'Istanbul'],
        '🇦🇶': ['Antarctica', '南极'],
        '🇲🇾': ['MY', 'Malaysia', '马来西亚'],
        '🇪🇸': ['ES', 'Spain', '西班牙'],
        '🇻🇳': ['VN', 'Vietnam', '越南'],
        '🇺🇦': ['UA', 'Ukraine', '乌克兰'],
        '🇲🇩': ['MD', 'Moldova', '摩尔多瓦'],
        '🇳🇬': ['NG', 'Nigeria', '尼日利亚'],
        '🇧🇷': ['BR', 'Brazil', '巴西'],
        '🇮🇹': ['IT', 'Italy', '意大利'],
        '🇵🇱': ['PL', 'Poland', '波兰'],
        '🇨🇭': ['CH', 'Switzerland', '瑞士'],
        '🇦🇹': ['AT', 'Austria', '奥地利'],
        '🇧🇪': ['BE', 'Belgium', '比利时'],
        '🇸🇪': ['SE', 'Sweden', '瑞典'],
        '🇳🇴': ['NO', 'Norway', '挪威'],
        '🇩🇰': ['DK', 'Denmark', '丹麦'],
        '🇫🇮': ['FI', 'Finland', '芬兰'],
        '🇮🇪': ['IE', 'Ireland', '爱尔兰'],
        '🇵🇹': ['PT', 'Portugal', '葡萄牙'],
        '🇬🇷': ['GR', 'Greece', '希腊'],
        '🇮🇱': ['IL', 'Israel', '以色列'],
        '🇦🇪': ['AE', 'UAE', '阿联酋', 'Dubai'],
        '🇿🇦': ['ZA', 'South Africa', '南非'],
        '🇳🇿': ['NZ', 'New Zealand', '新西兰'],
        '🇵🇭': ['PH', 'Philippines', '菲律宾'],
        '🇹🇭': ['TH', 'Thailand', '泰国'],
        '🇮🇩': ['ID', 'Indonesia', '印尼', '印度尼西亚'],
        '🇵🇰': ['PK', 'Pakistan', '巴基斯坦'],
        '🇲🇽': ['MX', 'Mexico', '墨西哥'],
        '🇦🇷': ['AR', 'Argentina', '阿根廷'],
    }

    # Pre-compiled regex for flag removal (performance optimization)
    _FLAG_PATTERN = None
    
    @staticmethod
    def _get_flag_pattern():
        """Lazy compile flag removal pattern"""
        if NameTransformer._FLAG_PATTERN is None:
            flags_escaped = [re.escape(flag) for flag in NameTransformer.FLAG_EMOJIS]
            NameTransformer._FLAG_PATTERN = re.compile('|'.join(flags_escaped))
        return NameTransformer._FLAG_PATTERN
    
    @staticmethod
    @lru_cache(maxsize=1024)
    def remove_flags(name: str) -> str:
        """Remove all flag emojis from node name (optimized with regex and LRU cache)"""
        pattern = NameTransformer._get_flag_pattern()
        result = pattern.sub('', name)
        result = ' '.join(result.split())
        return result.strip()
    
    # Flag emoji set for fast lookup
    _FLAG_SET = None
    
    @staticmethod
    def _get_flag_set():
        """Lazy create flag set"""
        if NameTransformer._FLAG_SET is None:
            NameTransformer._FLAG_SET = set(NameTransformer.FLAG_EMOJIS) - {'🔰', '🌏', '🌍', '🌎', '🏳️'}
        return NameTransformer._FLAG_SET
    
    @staticmethod
    @lru_cache(maxsize=2048)
    def identify_flag(name: str, server: str = None) -> str:
        """Identify country flag based on node name (with LRU cache)"""
        flag_set = NameTransformer._get_flag_set()
        
        # Priority 1: Check if name STARTS with a country flag emoji
        if len(name) >= 2:
            first_char = name[0]
            if first_char in flag_set:
                return first_char
            first_two = name[:2]
            if first_two in flag_set:
                return first_two
        
        # Priority 2: Check if name contains a country flag emoji anywhere
        for char in name:
            if char in flag_set:
                return char
        
        # Priority 3: Try to identify by keywords
        name_upper = name.upper()
        for flag, patterns in NameTransformer.COUNTRY_FLAG_MAP.items():
            for pattern in patterns:
                has_chinese = any('\u4e00' <= c <= '\u9fff' for c in pattern)
                if has_chinese:
                    if pattern in name:
                        return flag
                elif len(pattern) <= 3:
                    pattern_upper = pattern.upper()
                    if re.search(r'(?<![A-Z])' + re.escape(pattern_upper) + r'(?![A-Z])', name_upper):
                        return flag
                else:
                    if pattern.upper() in name_upper:
                        return flag
        
        return '🔰'
    
    # Flag to ISO code mapping
    FLAG_TO_ISO = {
        '🇭🇰': 'HK', '🇹🇼': 'TW', '🇯🇵': 'JP', '🇺🇸': 'US', '🇸🇬': 'SG',
        '🇰🇷': 'KR', '🇬🇧': 'GB', '🇩🇪': 'DE', '🇨🇦': 'CA', '🇦🇺': 'AU',
        '🇫🇷': 'FR', '🇷🇺': 'RU', '🇮🇳': 'IN', '🇳🇱': 'NL', '🇹🇷': 'TR',
        '🇦🇶': 'AQ', '🇲🇾': 'MY', '🇪🇸': 'ES', '🇻🇳': 'VN', '🇺🇦': 'UA',
        '🇲🇩': 'MD', '🇳🇬': 'NG', '🇧🇷': 'BR', '🇮🇹': 'IT', '🇵🇱': 'PL',
        '🇨🇭': 'CH', '🇦🇹': 'AT', '🇧🇪': 'BE', '🇸🇪': 'SE', '🇳🇴': 'NO',
        '🇩🇰': 'DK', '🇫🇮': 'FI', '🇮🇪': 'IE', '🇵🇹': 'PT', '🇬🇷': 'GR',
        '🇮🇱': 'IL', '🇦🇪': 'AE', '🇿🇦': 'ZA', '🇳🇿': 'NZ', '🇵🇭': 'PH',
        '🇹🇭': 'TH', '🇮🇩': 'ID', '🇵🇰': 'PK', '🇲🇽': 'MX', '🇦🇷': 'AR',
        '🇨🇿': 'CZ', '🇭🇺': 'HU', '🇷🇴': 'RO', '🇧🇬': 'BG', '🇭🇷': 'HR',
        '🇸🇰': 'SK', '🇸🇮': 'SI', '🇱🇹': 'LT', '🇱🇻': 'LV', '🇪🇪': 'EE',
        '🇸🇦': 'SA', '🇶🇦': 'QA', '🇰🇼': 'KW', '🇴🇲': 'OM', '🇧🇭': 'BH',
        '🇯🇴': 'JO', '🇱🇧': 'LB', '🇪🇬': 'EG', '🇰🇪': 'KE', '🇧🇩': 'BD',
        '🇱🇰': 'LK', '🇳🇵': 'NP', '🇲🇲': 'MM', '🇰🇭': 'KH', '🇱🇦': 'LA',
        '🇲🇳': 'MN', '🇰🇿': 'KZ', '🇺🇿': 'UZ', '🇦🇿': 'AZ', '🇬🇪': 'GE',
        '🇦🇲': 'AM', '🇨🇾': 'CY', '🇲🇹': 'MT', '🇮🇸': 'IS', '🇱🇺': 'LU',
        '🇲🇨': 'MC', '🇦🇩': 'AD', '🇱🇮': 'LI', '🇸🇲': 'SM', '🇻🇦': 'VA',
        '🇨🇱': 'CL', '🇨🇴': 'CO', '🇵🇪': 'PE', '🇻🇪': 'VE', '🇪🇨': 'EC',
        '🇧🇴': 'BO', '🇵🇾': 'PY', '🇺🇾': 'UY', '🇨🇷': 'CR', '🇵🇦': 'PA',
        '🇨🇺': 'CU', '🇩🇴': 'DO', '🇵🇷': 'PR', '🇯🇲': 'JM', '🇭🇹': 'HT',
        '🔰': 'XX', '🌏': 'XX', '🌍': 'XX', '🌎': 'XX', '🏳️': 'XX',
    }
    
    # ISO code to country name mapping
    ISO_TO_COUNTRY = {
        'HK': '中国香港', 'TW': '中国台湾', 'MO': '中国澳门', 'JP': '日本', 'US': '美国', 'SG': '新加坡',
        'KR': '韩国', 'GB': '英国', 'DE': '德国', 'CA': '加拿大', 'AU': '澳大利亚',
        'FR': '法国', 'RU': '俄罗斯', 'IN': '印度', 'NL': '荷兰', 'TR': '土耳其',
        'AQ': '南极', 'MY': '马来西亚', 'ES': '西班牙', 'VN': '越南', 'UA': '乌克兰',
        'MD': '摩尔多瓦', 'NG': '尼日利亚', 'BR': '巴西', 'IT': '意大利', 'PL': '波兰',
        'CH': '瑞士', 'AT': '奥地利', 'BE': '比利时', 'SE': '瑞典', 'NO': '挪威',
        'DK': '丹麦', 'FI': '芬兰', 'IE': '爱尔兰', 'PT': '葡萄牙', 'GR': '希腊',
        'IL': '以色列', 'AE': '阿联酋', 'ZA': '南非', 'NZ': '新西兰', 'PH': '菲律宾',
        'TH': '泰国', 'ID': '印尼', 'PK': '巴基斯坦', 'MX': '墨西哥', 'AR': '阿根廷',
        'CZ': '捷克', 'HU': '匈牙利', 'RO': '罗马尼亚', 'BG': '保加利亚', 'HR': '克罗地亚',
        'SK': '斯洛伐克', 'SI': '斯洛文尼亚', 'LT': '立陶宛', 'LV': '拉脱维亚', 'EE': '爱沙尼亚',
        'SA': '沙特', 'QA': '卡塔尔', 'KW': '科威特', 'OM': '阿曼', 'BH': '巴林',
        'JO': '约旦', 'LB': '黎巴嫩', 'EG': '埃及', 'KE': '肯尼亚', 'BD': '孟加拉',
        'LK': '斯里兰卡', 'NP': '尼泊尔', 'MM': '缅甸', 'KH': '柬埔寨', 'LA': '老挝',
        'MN': '蒙古', 'KZ': '哈萨克斯坦', 'UZ': '乌兹别克斯坦', 'AZ': '阿塞拜疆', 'GE': '格鲁吉亚',
        'AM': '亚美尼亚', 'CY': '塞浦路斯', 'MT': '马耳他', 'IS': '冰岛', 'LU': '卢森堡',
        'MC': '摩纳哥', 'AD': '安道尔', 'LI': '列支敦士登', 'SM': '圣马力诺', 'VA': '梵蒂冈',
        'CL': '智利', 'CO': '哥伦比亚', 'PE': '秘鲁', 'VE': '委内瑞拉', 'EC': '厄瓜多尔',
        'BO': '玻利维亚', 'PY': '巴拉圭', 'UY': '乌拉圭', 'CR': '哥斯达黎加', 'PA': '巴拿马',
        'CU': '古巴', 'DO': '多米尼加', 'PR': '波多黎各', 'JM': '牙买加', 'HT': '海地',
        'XX': '未知',
    }

    @staticmethod
    def transform_name(proxy: dict, source_name: str) -> dict:
        """Unify node name format to: Flag Provider NodeName"""
        if not proxy or 'name' not in proxy:
            return proxy
        
        prefix = NameTransformer.SOURCE_PREFIX_MAP.get(source_name, source_name)
        original_name = proxy['name']
        server = proxy.get('server', '')
        
        flag = NameTransformer.identify_flag(original_name, server)
        clean_name = NameTransformer.remove_flags(original_name)
        
        if '[ipv6]' in clean_name:
            clean_name = clean_name.replace('[ipv6]', 'ipv6')
        
        has_prefix = False
        for known_prefix in NameTransformer.SOURCE_PREFIX_MAP.values():
            if clean_name.startswith(known_prefix + ' ') or clean_name.startswith(known_prefix + '-'):
                has_prefix = True
                break
        
        if has_prefix:
            new_name = f"{flag} {clean_name}"
        else:
            new_name = f"{flag} {prefix} {clean_name}"
        
        new_proxy = proxy.copy()
        new_proxy['name'] = new_name
        
        # Add country information
        country_code = NameTransformer.FLAG_TO_ISO.get(flag, 'XX')
        country_name = NameTransformer.ISO_TO_COUNTRY.get(country_code, 'Unknown')
        new_proxy['_country'] = {
            'country_code': country_code,
            'country': country_name,
            'flag': flag
        }
        
        return new_proxy
    
    @staticmethod
    def transform_proxies(proxies: List[dict], source_name: str) -> List[dict]:
        """Batch transform proxy node names"""
        return [NameTransformer.transform_name(p, source_name) for p in proxies]
