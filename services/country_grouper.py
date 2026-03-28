"""
Country Grouper Service
Group proxy nodes by country/region
"""
import re
from typing import List, Dict, Optional
from logger_config import get_logger

logger = get_logger(__name__)


class CountryGrouper:
    """Group proxy nodes by country/region"""
    
    # Pre-compiled patterns cache
    _compiled_patterns = None
    _flag_to_country = None
    _code_to_country = None
    
    # Country identification patterns: Group name -> keyword list
    COUNTRY_PATTERNS = {
        '🇭🇰 中国香港': ['🇭🇰', 'hongkong', 'hong kong', 'hk', '香港', '港'],
        '🇹🇼 中国台湾': ['🇹🇼', 'taiwan', 'tw', '台湾', '台', 'taipei'],
        '🇲🇴 中国澳门': ['🇲🇴', 'macau', 'macao', 'mo', '澳门', '濠江'],
        '🇯🇵 日本': ['🇯🇵', 'japan', 'jp', '日本', '日'],
        '🇰🇷 韩国': ['🇰🇷', 'korea', 'kr', 'kor', '韩国', '韩', '首尔', 'seoul'],
        '🇸🇬 新加坡': ['🇸🇬', 'singapore', 'sg', '新加坡', '狮城', '坡'],
        '🇺🇸 美国': ['🇺🇸', 'usa', 'us', 'united states', 'america', '美国', '美', 'la', 'los angeles', 'seattle', 'san jose', 'dallas', 'chicago', 'miami', 'new york', 'silicon valley', '硅谷', '洛杉矶', '西雅图', '纽约'],
        '🇬🇧 英国': ['🇬🇧', 'uk', 'gb', 'united kingdom', 'britain', 'england', '英国', '英', 'london', '伦敦'],
        '🇩🇪 德国': ['🇩🇪', 'germany', 'de', 'deutsch', '德国', '德', 'frankfurt', '法兰克福'],
        '🇫🇷 法国': ['🇫🇷', 'france', 'fr', '法国', '法', 'paris', '巴黎'],
        '🇳🇱 荷兰': ['🇳🇱', 'netherlands', 'nl', 'holland', '荷兰', '荷', 'amsterdam', '阿姆斯特丹'],
        '🇧🇾 白俄罗斯': ['🇧🇾', 'belarus', 'by', '白俄罗斯', 'minsk', '明斯克'],
        '🇷🇺 俄罗斯': ['🇷🇺', 'russia', 'ru', '俄罗斯', 'moscow', '莫斯科'],
        '🇨🇦 加拿大': ['🇨🇦', 'canada', 'ca', '加拿大', '加', 'toronto', 'vancouver', '多伦多', '温哥华'],
        '🇦🇺 澳大利亚': ['🇦🇺', 'australia', 'au', '澳大利亚', '澳洲', '澳', 'sydney', '悉尼'],
        '🇮🇳 印度': ['🇮🇳', 'india', '印度', 'mumbai', '孟买'],
        '🇹🇷 土耳其': ['🇹🇷', 'turkey', 'tr', '土耳其', 'istanbul', '伊斯坦布尔'],
        '🇲🇾 马来西亚': ['🇲🇾', 'malaysia', 'my', '马来西亚', '马来', '大马', 'kuala lumpur', '吉隆坡'],
        '🇹🇭 泰国': ['🇹🇭', 'thailand', 'th', '泰国', '泰', 'bangkok', '曼谷'],
        '🇻🇳 越南': ['🇻🇳', 'vietnam', 'vn', '越南', '越'],
        '🇮🇩 印尼': ['🇮🇩', 'indonesia', '印尼', '印度尼西亚', 'jakarta', '雅加达'],
        '🇵🇭 菲律宾': ['🇵🇭', 'philippines', 'ph', '菲律宾', '菲', 'manila', '马尼拉'],
        '🇧🇷 巴西': ['🇧🇷', 'brazil', 'br', '巴西', 'sao paulo', '圣保罗'],
        '🇦🇷 阿根廷': ['🇦🇷', 'argentina', 'ar', '阿根廷', 'buenos aires', '布宜诺斯艾利斯'],
        '🇲🇽 墨西哥': ['🇲🇽', 'mexico', 'mx', '墨西哥'],
        '🇿🇦 南非': ['🇿🇦', 'south africa', 'za', '南非', 'johannesburg', '约翰内斯堡'],
        '🇦🇪 阿联酋': ['🇦🇪', 'uae', 'ae', 'dubai', '阿联酋', '迪拜', 'abu dhabi', '阿布扎比'],
        '🇮🇱 以色列': ['🇮🇱', 'israel', 'il', '以色列', 'tel aviv', '特拉维夫'],
        '🇺🇦 乌克兰': ['🇺🇦', 'ukraine', 'ua', '乌克兰', 'kiev', '基辅'],
        '🇵🇱 波兰': ['🇵🇱', 'poland', 'pl', '波兰', 'warsaw', '华沙'],
        '🇨🇭 瑞士': ['🇨🇭', 'switzerland', 'ch', '瑞士', 'zurich', '苏黎世'],
        '🇸🇪 瑞典': ['🇸🇪', 'sweden', 'se', '瑞典', 'stockholm', '斯德哥尔摩'],
        '🇳🇴 挪威': ['🇳🇴', 'norway', 'no', '挪威', 'oslo', '奥斯陆'],
        '🇫🇮 芬兰': ['🇫🇮', 'finland', 'fi', '芬兰', 'helsinki', '赫尔辛基'],
        '🇩🇰 丹麦': ['🇩🇰', 'denmark', 'dk', '丹麦', 'copenhagen', '哥本哈根'],
        '🇮🇹 意大利': ['🇮🇹', 'italy', 'it', '意大利', '意', 'rome', 'milan', '罗马', '米兰'],
        '🇪🇸 西班牙': ['🇪🇸', 'spain', 'es', '西班牙', 'madrid', 'barcelona', '马德里', '巴塞罗那'],
        '🇳🇬 尼日利亚': ['🇳🇬', 'nigeria', 'ng', '尼日利亚'],
        '🇳🇿 新西兰': ['🇳🇿', 'new zealand', 'nz', '新西兰', 'auckland', '奥克兰'],
        '🇲🇩 摩尔多瓦': ['🇲🇩', 'moldova', 'md', '摩尔多瓦'],
        '🇮🇪 爱尔兰': ['🇮🇪', 'ireland', 'ie', '爱尔兰', 'dublin', '都柏林'],
        '🇵🇹 葡萄牙': ['🇵🇹', 'portugal', 'pt', '葡萄牙', 'lisbon', '里斯本'],
        '🇬🇷 希腊': ['🇬🇷', 'greece', 'gr', '希腊', 'athens', '雅典'],
        '🇦🇹 奥地利': ['🇦🇹', 'austria', 'at', '奥地利', 'vienna', '维也纳'],
        '🇨🇿 捷克': ['🇨🇿', 'czech', 'cz', '捷克', 'prague', '布拉格'],
        '🇭🇺 匈牙利': ['🇭🇺', 'hungary', 'hu', '匈牙利', 'budapest', '布达佩斯'],
        '🇷🇴 罗马尼亚': ['🇷🇴', 'romania', 'ro', '罗马尼亚', 'bucharest', '布加勒斯特'],
        '🇧🇬 保加利亚': ['🇧🇬', 'bulgaria', 'bg', '保加利亚', 'sofia', '索非亚'],
        '🇰🇿 哈萨克斯坦': ['🇰🇿', 'kazakhstan', 'kz', '哈萨克斯坦', '哈萨克'],
        '🇪🇬 埃及': ['🇪🇬', 'egypt', 'eg', '埃及', 'cairo', '开罗'],
        '🇦🇶 南极洲': ['🇦🇶', 'antarctica', 'aq', '南极'],
    }

    @staticmethod
    def _init_patterns():
        """Initialize pre-compiled patterns for fast matching"""
        if CountryGrouper._compiled_patterns is not None:
            return
        
        CountryGrouper._compiled_patterns = {}
        CountryGrouper._flag_to_country = {}
        CountryGrouper._code_to_country = {}
        
        for country, patterns in CountryGrouper.COUNTRY_PATTERNS.items():
            flag = patterns[0]
            CountryGrouper._flag_to_country[flag] = country
            from services.name_transformer import NameTransformer
            code = NameTransformer.FLAG_TO_ISO.get(flag)
            if code and code != 'XX':
                CountryGrouper._code_to_country[code] = country
            
            compiled_list = []
            for pattern in patterns[1:]:
                has_chinese = any('\u4e00' <= c <= '\u9fff' for c in pattern)
                if has_chinese:
                    compiled_list.append(('chinese', pattern))
                elif len(pattern) <= 3:
                    regex = re.compile(r'(?<![A-Za-z])' + re.escape(pattern) + r'(?![A-Za-z])', re.IGNORECASE)
                    compiled_list.append(('regex', regex, len(pattern)))
                else:
                    compiled_list.append(('english', pattern.upper(), len(pattern)))
            
            CountryGrouper._compiled_patterns[country] = compiled_list

    @staticmethod
    def _country_from_region(region: dict) -> Optional[str]:
        """Resolve country group directly from saved/tested region info."""
        if not isinstance(region, dict):
            return None
        CountryGrouper._init_patterns()
        code = str(region.get('country_code') or '').upper()
        if code:
            return CountryGrouper._code_to_country.get(code)
        flag = str(region.get('flag') or '').strip()
        if flag:
            return CountryGrouper._flag_to_country.get(flag)
        return None
    
    @staticmethod
    def identify_country(proxy_name: str, proxy_server: str = None) -> str:
        """Identify country/region of proxy node (optimized with pre-compiled patterns)"""
        CountryGrouper._init_patterns()
        
        # Priority 1: Check if name STARTS with a flag emoji
        if len(proxy_name) >= 2:
            first_char = proxy_name[0]
            if first_char in CountryGrouper._flag_to_country:
                return CountryGrouper._flag_to_country[first_char]
            first_two = proxy_name[:2]
            if first_two in CountryGrouper._flag_to_country:
                return CountryGrouper._flag_to_country[first_two]
        
        # Priority 2: Check for any flag emoji in name
        for char in proxy_name:
            if char in CountryGrouper._flag_to_country:
                return CountryGrouper._flag_to_country[char]
        
        # Priority 3: Try keyword matching with LONGEST MATCH principle
        best_match_country = None
        best_match_len = 0
        name_upper = proxy_name.upper()
        
        for country, compiled_list in CountryGrouper._compiled_patterns.items():
            for item in compiled_list:
                matched = False
                pattern_len = 0
                
                if item[0] == 'chinese':
                    pattern = item[1]
                    if pattern in proxy_name:
                        matched = True
                        pattern_len = len(pattern)
                elif item[0] == 'regex':
                    regex, pattern_len = item[1], item[2]
                    if regex.search(proxy_name):
                        matched = True
                else:
                    pattern, pattern_len = item[1], item[2]
                    if pattern in name_upper:
                        matched = True
                
                if matched and pattern_len > best_match_len:
                    best_match_len = pattern_len
                    best_match_country = country
        
        if best_match_country:
            return best_match_country
        
        return '🔰 未知'
    
    @staticmethod
    def group_by_country(proxies: List[dict]) -> Dict[str, List[str]]:
        """Group proxy nodes by country/region, return {country: [node_name_list]}"""
        groups: Dict[str, List[str]] = {}
        
        for proxy in proxies:
            name = proxy.get('name', '')
            server = proxy.get('server', '')
            country = CountryGrouper._country_from_region(proxy.get('region')) or CountryGrouper.identify_country(name, server)
            
            if country not in groups:
                groups[country] = []
            groups[country].append(name)
        
        return groups
    
    @staticmethod
    async def identify_country_async(proxy_name: str, proxy_server: str = None) -> str:
        """Async version: Identify country with GeoIP lookup support"""
        CountryGrouper._init_patterns()
        
        # First try synchronous methods (fast)
        if len(proxy_name) >= 2:
            first_char = proxy_name[0]
            if first_char in CountryGrouper._flag_to_country:
                return CountryGrouper._flag_to_country[first_char]
            first_two = proxy_name[:2]
            if first_two in CountryGrouper._flag_to_country:
                return CountryGrouper._flag_to_country[first_two]
        
        for char in proxy_name:
            if char in CountryGrouper._flag_to_country:
                return CountryGrouper._flag_to_country[char]
        
        # Keyword matching
        best_match_country = None
        best_match_len = 0
        name_upper = proxy_name.upper()
        
        for country, compiled_list in CountryGrouper._compiled_patterns.items():
            for item in compiled_list:
                matched = False
                pattern_len = 0
                
                if item[0] == 'chinese':
                    pattern = item[1]
                    if pattern in proxy_name:
                        matched = True
                        pattern_len = len(pattern)
                elif item[0] == 'regex':
                    regex, pattern_len = item[1], item[2]
                    if regex.search(proxy_name):
                        matched = True
                else:
                    pattern, pattern_len = item[1], item[2]
                    if pattern in name_upper:
                        matched = True
                
                if matched and pattern_len > best_match_len:
                    best_match_len = pattern_len
                    best_match_country = country
        
        if best_match_country:
            return best_match_country
        
        # Try GeoIP lookup (async)
        if proxy_server:
            try:
                from geoip_service import GeoIPService
                geoip = GeoIPService.get_instance()
                country_info = await geoip.lookup_country_async(proxy_server)
                if country_info and country_info.get('country_code'):
                    code = country_info['country_code']
                    for country_group in CountryGrouper.COUNTRY_PATTERNS.keys():
                        if code in country_group or country_info.get('country_name', '') in country_group:
                            return country_group
            except Exception:
                pass
        
        return '🔰 未知'
