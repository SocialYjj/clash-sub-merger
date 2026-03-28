"""
Country Data Service
Contains country keywords, names, and detection utilities
"""
import re
from typing import Dict, List, Optional
from geoip_service import GeoIPService


# Keyword to country code mapping (only need code, flag is generated dynamically)
COUNTRY_KEYWORDS: Dict[str, List[str]] = {
    'HK': ['hongkong', 'hong kong', 'hk', '香港', '港'],
    'TW': ['taiwan', 'tw', '台湾', '台', 'taipei'],
    'JP': ['japan', 'jp', '日本', '日'],
    'KR': ['korea', 'kr', 'kor', '韩国', '韩', '首尔', 'seoul'],
    'SG': ['singapore', 'sg', '新加坡', '狮城', '坡'],
    'US': ['usa', 'us', 'united states', 'america', '美国', '美', 'la', 'los angeles', 'seattle', 'san jose', 'dallas', 'chicago', 'miami', 'new york', 'silicon valley', '硅谷', '洛杉矶', '西雅图', '纽约'],
    'GB': ['uk', 'gb', 'united kingdom', 'britain', 'england', '英国', '英', 'london', '伦敦'],
    'DE': ['germany', 'de', 'deutsch', '德国', '德', 'frankfurt', '法兰克福'],
    'FR': ['france', 'fr', '法国', '法', 'paris', '巴黎'],
    'NL': ['netherlands', 'nl', 'holland', '荷兰', '荷', 'amsterdam', '阿姆斯特丹'],
    'BY': ['belarus', 'by', '白俄罗斯', 'minsk', '明斯克'],
    'RU': ['russia', 'ru', '俄罗斯', 'moscow', '莫斯科'],
    'CA': ['canada', 'ca', '加拿大', '加', 'toronto', 'vancouver', '多伦多', '温哥华'],
    'AU': ['australia', 'au', '澳大利亚', '澳洲', '澳', 'sydney', '悉尼'],
    'IN': ['india', '印度', 'mumbai', '孟买'],
    'TR': ['turkey', 'tr', '土耳其', 'istanbul', '伊斯坦布尔'],
    'MY': ['malaysia', 'my', '马来西亚', '马来', '大马', 'kuala lumpur', '吉隆坡'],
    'TH': ['thailand', 'th', '泰国', '泰', 'bangkok', '曼谷'],
    'VN': ['vietnam', 'vn', '越南', '越'],
    'ID': ['indonesia', '印尼', '印度尼西亚', 'jakarta', '雅加达'],
    'PH': ['philippines', 'ph', '菲律宾', '菲', 'manila', '马尼拉'],
    'BR': ['brazil', 'br', '巴西', 'sao paulo', '圣保罗'],
    'AR': ['argentina', 'ar', '阿根廷', 'buenos aires', '布宜诺斯艾利斯'],
    'MX': ['mexico', 'mx', '墨西哥'],
    'ZA': ['south africa', 'za', '南非', 'johannesburg', '约翰内斯堡'],
    'AE': ['uae', 'ae', 'dubai', '阿联酋', '迪拜', 'abu dhabi', '阿布扎比'],
    'IL': ['israel', 'il', '以色列', 'tel aviv', '特拉维夫'],
    'UA': ['ukraine', 'ua', '乌克兰', 'kiev', '基辅'],
    'PL': ['poland', 'pl', '波兰', 'warsaw', '华沙'],
    'CH': ['switzerland', 'ch', '瑞士', 'zurich', '苏黎世'],
    'SE': ['sweden', 'se', '瑞典', 'stockholm', '斯德哥尔摩'],
    'NO': ['norway', 'no', '挪威', 'oslo', '奥斯陆'],
    'FI': ['finland', 'fi', '芬兰', 'helsinki', '赫尔辛基'],
    'DK': ['denmark', 'dk', '丹麦', 'copenhagen', '哥本哈根'],
    'IT': ['italy', 'it', '意大利', '意', 'rome', 'milan', '罗马', '米兰'],
    'ES': ['spain', 'es', '西班牙', 'madrid', 'barcelona', '马德里', '巴塞罗那'],
    'NG': ['nigeria', 'ng', '尼日利亚'],
    'NZ': ['new zealand', 'nz', '新西兰', 'auckland', '奥克兰'],
    'MD': ['moldova', 'md', '摩尔多瓦'],
    'IE': ['ireland', 'ie', '爱尔兰', 'dublin', '都柏林'],
    'PT': ['portugal', 'pt', '葡萄牙', 'lisbon', '里斯本'],
    'GR': ['greece', 'gr', '希腊', 'athens', '雅典'],
    'AT': ['austria', 'at', '奥地利', 'vienna', '维也纳'],
    'CZ': ['czech', 'cz', '捷克', 'prague', '布拉格'],
    'HU': ['hungary', 'hu', '匈牙利', 'budapest', '布达佩斯'],
    'RO': ['romania', 'ro', '罗马尼亚', 'bucharest', '布加勒斯特'],
    'BG': ['bulgaria', 'bg', '保加利亚', 'sofia', '索非亚'],
    'KZ': ['kazakhstan', 'kz', '哈萨克斯坦', '哈萨克'],
    'EG': ['egypt', 'eg', '埃及', 'cairo', '开罗'],
    'KE': ['kenya', 'ke', '肯尼亚', 'nairobi', '内罗毕'],
    'PK': ['pakistan', 'pk', '巴基斯坦', 'karachi', '卡拉奇'],
    'BD': ['bangladesh', 'bd', '孟加拉', 'dhaka', '达卡'],
    'CL': ['chile', 'cl', '智利', 'santiago', '圣地亚哥'],
    'AQ': ['antarctica', 'aq', '南极'],
}

# Additional less common countries
COUNTRY_KEYWORDS.update({
    'KP': ['north korea', 'kp', 'dprk', '朝鲜', '北朝鲜', '平壤', 'pyongyang'],
    'MN': ['mongolia', 'mn', '蒙古', 'ulaanbaatar', '乌兰巴托'],
    'NP': ['nepal', 'np', '尼泊尔', 'kathmandu', '加德满都'],
    'LK': ['sri lanka', 'lk', '斯里兰卡', 'colombo', '科伦坡'],
    'IR': ['iran', 'ir', '伊朗', 'tehran', '德黑兰'],
    'SA': ['saudi arabia', 'sa', '沙特', '沙特阿拉伯', 'riyadh', '利雅得'],
    'QA': ['qatar', 'qa', '卡塔尔', 'doha', '多哈'],
    'KW': ['kuwait', 'kw', '科威特'],
    'OM': ['oman', 'om', '阿曼', 'muscat', '马斯喀特'],
    'BH': ['bahrain', 'bh', '巴林'],
    'LB': ['lebanon', 'lb', '黎巴嫩', 'beirut', '贝鲁特'],
    'JO': ['jordan', 'jo', '约旦', 'amman', '安曼'],
    'IQ': ['iraq', 'iq', '伊拉克', 'baghdad', '巴格达'],
    'SY': ['syria', 'sy', '叙利亚', 'damascus', '大马士革'],
    'AF': ['afghanistan', 'af', '阿富汗', 'kabul', '喀布尔'],
    'MM': ['myanmar', 'mm', 'burma', '缅甸', 'yangon', '仰光'],
    'KH': ['cambodia', 'kh', '柬埔寨', 'phnom penh', '金边'],
    'LA': ['laos', 'la', '老挝', 'vientiane', '万象'],
    'BN': ['brunei', 'bn', '文莱'],
    'MO': ['macau', 'macao', 'mo', '澳门', '濠江'],
    'IS': ['iceland', 'is', '冰岛', 'reykjavik', '雷克雅未克'],
    'LU': ['luxembourg', 'lu', '卢森堡'],
    'BE': ['belgium', 'be', '比利时', 'brussels', '布鲁塞尔'],
    'SK': ['slovakia', 'sk', '斯洛伐克', 'bratislava', '布拉迪斯拉发'],
    'SI': ['slovenia', 'si', '斯洛文尼亚', 'ljubljana', '卢布尔雅那'],
    'HR': ['croatia', 'hr', '克罗地亚', 'zagreb', '萨格勒布'],
    'RS': ['serbia', 'rs', '塞尔维亚', 'belgrade', '贝尔格莱德'],
    'BA': ['bosnia', 'ba', '波黑', '波斯尼亚'],
    'ME': ['montenegro', 'me', '黑山'],
    'MK': ['macedonia', 'mk', '马其顿', '北马其顿'],
    'AL': ['albania', 'al', '阿尔巴尼亚', 'tirana', '地拉那'],
    'LT': ['lithuania', 'lt', '立陶宛', 'vilnius', '维尔纽斯'],
    'LV': ['latvia', 'lv', '拉脱维亚', 'riga', '里加'],
    'EE': ['estonia', 'ee', '爱沙尼亚', 'tallinn', '塔林'],
    'GE': ['georgia', 'ge', '格鲁吉亚', 'tbilisi', '第比利斯'],
    'AM': ['armenia', 'am', '亚美尼亚', 'yerevan', '埃里温'],
    'AZ': ['azerbaijan', 'az', '阿塞拜疆', 'baku', '巴库'],
    'UZ': ['uzbekistan', 'uz', '乌兹别克斯坦', 'tashkent', '塔什干'],
    'TM': ['turkmenistan', 'tm', '土库曼斯坦'],
    'KG': ['kyrgyzstan', 'kg', '吉尔吉斯斯坦', 'bishkek', '比什凯克'],
    'TJ': ['tajikistan', 'tj', '塔吉克斯坦'],
    'CO': ['colombia', 'co', '哥伦比亚', 'bogota', '波哥大'],
    'PE': ['peru', 'pe', '秘鲁', 'lima', '利马'],
    'VE': ['venezuela', 've', '委内瑞拉', 'caracas', '加拉加斯'],
    'EC': ['ecuador', 'ec', '厄瓜多尔', 'quito', '基多'],
    'UY': ['uruguay', 'uy', '乌拉圭', 'montevideo', '蒙得维的亚'],
    'PY': ['paraguay', 'py', '巴拉圭', 'asuncion', '亚松森'],
    'BO': ['bolivia', 'bo', '玻利维亚', 'la paz', '拉巴斯'],
    'PA': ['panama', 'pa', '巴拿马'],
})

# More countries
COUNTRY_KEYWORDS.update({
    'CR': ['costa rica', 'cr', '哥斯达黎加'],
    'CU': ['cuba', 'cu', '古巴', 'havana', '哈瓦那'],
    'DO': ['dominican', 'do', '多米尼加'],
    'PR': ['puerto rico', 'pr', '波多黎各'],
    'JM': ['jamaica', 'jm', '牙买加'],
    'MA': ['morocco', 'ma', '摩洛哥', 'casablanca', '卡萨布兰卡'],
    'TN': ['tunisia', 'tn', '突尼斯'],
    'DZ': ['algeria', 'dz', '阿尔及利亚'],
    'LY': ['libya', 'ly', '利比亚'],
    'GH': ['ghana', 'gh', '加纳'],
    'SN': ['senegal', 'sn', '塞内加尔'],
    'CI': ['ivory coast', 'ci', '科特迪瓦', '象牙海岸'],
    'CM': ['cameroon', 'cm', '喀麦隆'],
    'TZ': ['tanzania', 'tz', '坦桑尼亚'],
    'UG': ['uganda', 'ug', '乌干达'],
    'RW': ['rwanda', 'rw', '卢旺达'],
    'ET': ['ethiopia', 'et', '埃塞俄比亚'],
    'MU': ['mauritius', 'mu', '毛里求斯'],
    'SC': ['seychelles', 'sc', '塞舌尔'],
    'MV': ['maldives', 'mv', '马尔代夫', 'male', '马累'],
    'GU': ['guam', 'gu', '关岛'],
    'FJ': ['fiji', 'fj', '斐济'],
    'NC': ['new caledonia', 'nc', '新喀里多尼亚'],
    'PF': ['french polynesia', 'pf', '法属波利尼西亚', 'tahiti', '塔希提'],
    'GL': ['greenland', 'gl', '格陵兰'],
    'MT': ['malta', 'mt', '马耳他'],
    'CY': ['cyprus', 'cy', '塞浦路斯'],
})


# Country code to Chinese name mapping (complete 241 countries/regions)
COUNTRY_NAMES: Dict[str, str] = {
    'AD': '安道尔', 'AE': '阿联酋', 'AF': '阿富汗', 'AG': '安提瓜和巴布达',
    'AI': '安圭拉', 'AL': '阿尔巴尼亚', 'AM': '亚美尼亚', 'AO': '安哥拉',
    'AQ': '南极洲', 'AR': '阿根廷', 'AS': '美属萨摩亚', 'AT': '奥地利',
    'AU': '澳大利亚', 'AW': '阿鲁巴', 'AX': '奥兰群岛', 'AZ': '阿塞拜疆',
    'BA': '波黑', 'BB': '巴巴多斯', 'BD': '孟加拉国', 'BE': '比利时',
    'BF': '布基纳法索', 'BG': '保加利亚', 'BH': '巴林', 'BI': '布隆迪',
    'BJ': '贝宁', 'BL': '圣巴泰勒米', 'BM': '百慕大', 'BN': '文莱',
    'BO': '玻利维亚', 'BR': '巴西', 'BS': '巴哈马', 'BT': '不丹',
    'BW': '博茨瓦纳', 'BY': '白俄罗斯', 'BZ': '伯利兹', 'CA': '加拿大',
    'CD': '刚果民主共和国', 'CF': '中非共和国', 'CG': '刚果共和国', 'CH': '瑞士',
    'CI': '科特迪瓦', 'CK': '库克群岛', 'CL': '智利', 'CM': '喀麦隆',
    'CN': '中国大陆', 'CO': '哥伦比亚', 'CR': '哥斯达黎加', 'CU': '古巴',
    'CV': '佛得角', 'CW': '库拉索', 'CY': '塞浦路斯', 'CZ': '捷克',
    'DE': '德国', 'DJ': '吉布提', 'DK': '丹麦', 'DM': '多米尼克',
    'DO': '多米尼加', 'DZ': '阿尔及利亚', 'EC': '厄瓜多尔', 'EE': '爱沙尼亚',
    'EG': '埃及', 'EH': '西撒哈拉', 'ER': '厄立特里亚', 'ES': '西班牙',
    'ET': '埃塞俄比亚', 'FI': '芬兰', 'FJ': '斐济', 'FK': '福克兰群岛',
    'FM': '密克罗尼西亚', 'FO': '法罗群岛', 'FR': '法国', 'GA': '加蓬',
    'GB': '英国', 'GD': '格林纳达', 'GE': '格鲁吉亚', 'GG': '根西岛',
    'GH': '加纳', 'GL': '格陵兰', 'GM': '冈比亚', 'GN': '几内亚',
    'GQ': '赤道几内亚', 'GR': '希腊', 'GS': '南乔治亚和南桑威奇群岛',
    'GT': '危地马拉', 'GU': '关岛', 'GW': '几内亚比绍', 'GY': '圭亚那',
    'HK': '中国香港', 'HM': '赫德岛和麦克唐纳群岛', 'HN': '洪都拉斯',
    'HR': '克罗地亚', 'HT': '海地', 'HU': '匈牙利', 'ID': '印尼',
    'IE': '爱尔兰', 'IL': '以色列', 'IM': '马恩岛', 'IN': '印度',
    'IO': '英属印度洋领地', 'IQ': '伊拉克', 'IR': '伊朗', 'IS': '冰岛',
    'IT': '意大利', 'JE': '泽西岛', 'JM': '牙买加', 'JO': '约旦',
    'JP': '日本', 'KE': '肯尼亚', 'KG': '吉尔吉斯斯坦', 'KH': '柬埔寨',
    'KI': '基里巴斯', 'KM': '科摩罗', 'KN': '圣基茨和尼维斯', 'KP': '朝鲜',
    'KR': '韩国', 'KW': '科威特', 'KY': '开曼群岛', 'KZ': '哈萨克斯坦',
    'LA': '老挝', 'LB': '黎巴嫩', 'LC': '圣卢西亚', 'LI': '列支敦士登',
    'LK': '斯里兰卡', 'LR': '利比里亚', 'LS': '莱索托', 'LT': '立陶宛',
    'LU': '卢森堡', 'LV': '拉脱维亚', 'LY': '利比亚', 'MA': '摩洛哥',
    'MC': '摩纳哥', 'MD': '摩尔多瓦', 'ME': '黑山', 'MF': '法属圣马丁',
    'MG': '马达加斯加', 'MH': '马绍尔群岛', 'MK': '北马其顿', 'ML': '马里',
    'MM': '缅甸', 'MN': '蒙古', 'MO': '中国澳门', 'MP': '北马里亚纳群岛',
    'MR': '毛里塔尼亚', 'MS': '蒙特塞拉特', 'MT': '马耳他', 'MU': '毛里求斯',
    'MV': '马尔代夫', 'MW': '马拉维', 'MX': '墨西哥', 'MY': '马来西亚',
    'MZ': '莫桑比克', 'NA': '纳米比亚', 'NC': '新喀里多尼亚', 'NE': '尼日尔',
    'NF': '诺福克岛', 'NG': '尼日利亚', 'NI': '尼加拉瓜', 'NL': '荷兰',
    'NO': '挪威', 'NP': '尼泊尔', 'NR': '瑙鲁', 'NU': '纽埃',
    'NZ': '新西兰', 'OM': '阿曼', 'PA': '巴拿马', 'PE': '秘鲁',
    'PF': '法属波利尼西亚', 'PG': '巴布亚新几内亚', 'PH': '菲律宾', 'PK': '巴基斯坦',
    'PL': '波兰', 'PM': '圣皮埃尔和密克隆', 'PN': '皮特凯恩群岛', 'PR': '波多黎各',
    'PS': '巴勒斯坦', 'PT': '葡萄牙', 'PW': '帕劳', 'PY': '巴拉圭',
    'QA': '卡塔尔', 'RO': '罗马尼亚', 'RS': '塞尔维亚', 'RU': '俄罗斯',
    'RW': '卢旺达', 'SA': '沙特阿拉伯', 'SB': '所罗门群岛', 'SC': '塞舌尔',
    'SD': '苏丹', 'SE': '瑞典', 'SG': '新加坡', 'SH': '圣赫勒拿',
    'SI': '斯洛文尼亚', 'SK': '斯洛伐克', 'SL': '塞拉利昂', 'SM': '圣马力诺',
    'SN': '塞内加尔', 'SO': '索马里', 'SR': '苏里南', 'SS': '南苏丹',
    'ST': '圣多美和普林西比', 'SV': '萨尔瓦多', 'SX': '荷属圣马丁', 'SY': '叙利亚',
    'SZ': '斯威士兰', 'TC': '特克斯和凯科斯群岛', 'TD': '乍得', 'TF': '法属南部领地',
    'TG': '多哥', 'TH': '泰国', 'TJ': '塔吉克斯坦', 'TL': '东帝汶',
    'TM': '土库曼斯坦', 'TN': '突尼斯', 'TO': '汤加', 'TR': '土耳其',
    'TT': '特立尼达和多巴哥', 'TW': '中国台湾', 'TZ': '坦桑尼亚', 'UA': '乌克兰',
    'UG': '乌干达', 'US': '美国', 'UY': '乌拉圭', 'UZ': '乌兹别克斯坦',
    'VA': '梵蒂冈', 'VC': '圣文森特和格林纳丁斯', 'VE': '委内瑞拉',
    'VG': '英属维尔京群岛', 'VI': '美属维尔京群岛', 'VN': '越南', 'VU': '瓦努阿图',
    'WF': '瓦利斯和富图纳', 'WS': '萨摩亚', 'XK': '科索沃', 'YE': '也门',
    'ZA': '南非', 'ZM': '赞比亚', 'ZW': '津巴布韦'
}


# Placeholder to country code mapping for template processing
PLACEHOLDER_COUNTRY_MAP: Dict[str, str] = {
    '{{HK}}': 'HK', '{{TW}}': 'TW', '{{JP}}': 'JP', '{{KR}}': 'KR', '{{SG}}': 'SG',
    '{{US}}': 'US', '{{GB}}': 'GB', '{{DE}}': 'DE', '{{FR}}': 'FR', '{{NL}}': 'NL',
    '{{RU}}': 'RU', '{{CA}}': 'CA', '{{AU}}': 'AU', '{{IN}}': 'IN', '{{TR}}': 'TR',
    '{{MY}}': 'MY', '{{TH}}': 'TH', '{{VN}}': 'VN', '{{ID}}': 'ID', '{{PH}}': 'PH',
    '{{BR}}': 'BR', '{{AR}}': 'AR', '{{MX}}': 'MX', '{{ZA}}': 'ZA', '{{AE}}': 'AE',
    '{{IL}}': 'IL', '{{UA}}': 'UA', '{{PL}}': 'PL', '{{CH}}': 'CH', '{{SE}}': 'SE',
    '{{NO}}': 'NO', '{{FI}}': 'FI', '{{DK}}': 'DK', '{{IT}}': 'IT', '{{ES}}': 'ES',
}


def detect_country(name: str) -> Optional[Dict[str, str]]:
    """
    Detect country from node name using flag emoji or keywords.
    
    Args:
        name: Node name to analyze
        
    Returns:
        Dict with 'country', 'country_code', 'flag' or None if not detected
    """
    if not name:
        return None
    
    name_lower = name.lower()
    
    # Priority 1: Check for flag emoji at start
    if len(name) >= 2:
        first_two = name[:2]
        code = GeoIPService.flag_to_iso(first_two)
        if code and len(code) == 2:
            return {
                'country': COUNTRY_NAMES.get(code, code),
                'country_code': code,
                'flag': GeoIPService.iso_to_flag(code)
            }
    
    # Priority 2: Check for any flag emoji
    for i in range(len(name) - 1):
        code = GeoIPService.flag_to_iso(name[i:i+2])
        if code and len(code) == 2:
            return {
                'country': COUNTRY_NAMES.get(code, code),
                'country_code': code,
                'flag': GeoIPService.iso_to_flag(code)
            }
    
    # Priority 3: Keyword matching (longest match wins)
    best_match_code = None
    max_len = 0
    
    for code, keywords in COUNTRY_KEYWORDS.items():
        for keyword in keywords:
            keyword_lower = keyword.lower()
            is_short_latin = len(keyword_lower) <= 3 and keyword_lower.isascii() and keyword_lower.isalpha()
            if is_short_latin:
                matched = re.search(r'(?<![a-z])' + re.escape(keyword_lower) + r'(?![a-z])', name_lower)
            else:
                matched = keyword_lower in name_lower
            if matched and len(keyword_lower) > max_len:
                max_len = len(keyword_lower)
                best_match_code = code
    
    if best_match_code:
        return {
            'country': COUNTRY_NAMES.get(best_match_code, best_match_code),
            'country_code': best_match_code,
            'flag': GeoIPService.iso_to_flag(best_match_code)
        }
    
    return None
