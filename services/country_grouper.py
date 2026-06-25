"""
Country Grouper Service
Group proxy nodes by country/region
"""
import re
from typing import List, Dict, Optional
from logger_config import get_logger
from geoip_service import GeoIPService
from services.country_data import detect_country, COUNTRY_NAMES
from services.name_transformer import NameTransformer

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
        '🇯🇵 日本': ['🇯🇵', 'japan', 'jp', '日本', '日', 'tokyo', '东京', 'osaka', '大阪', '横滨', '名古屋', '札幌', '福冈'],
        '🇰🇷 韩国': ['🇰🇷', 'korea', 'kr', 'kor', '韩国', '韩', '首尔', 'seoul'],
        '🇸🇬 新加坡': ['🇸🇬', 'singapore', 'sg', '新加坡', '狮城', '坡'],
        '🇺🇸 美国': ['🇺🇸', 'usa', 'us', 'united states', 'america', '美国', '美', 'la', 'los angeles', 'seattle', 'san jose', 'dallas', 'chicago', 'miami', 'new york', 'silicon valley', '硅谷', '洛杉矶', '西雅图', '纽约'],
        '🇬🇧 英国': ['🇬🇧', 'uk', 'gb', 'united kingdom', 'britain', 'england', '英国', '英', 'london', '伦敦'],
        '🇩🇪 德国': ['🇩🇪', 'germany', 'de', 'deutsch', '德国', '德', 'frankfurt', '法兰克福', 'berlin', '柏林', 'munich', '慕尼黑'],
        '🇫🇷 法国': ['🇫🇷', 'france', 'fr', '法国', '法', 'paris', '巴黎'],
        '🇳🇱 荷兰': ['🇳🇱', 'netherlands', 'nl', 'holland', '荷兰', '荷', 'amsterdam', '阿姆斯特丹'],
        '🇧🇾 白俄罗斯': ['🇧🇾', 'belarus', 'by', '白俄罗斯', 'minsk', '明斯克'],
        '🇷🇺 俄罗斯': ['🇷🇺', 'russia', 'ru', '俄罗斯', 'moscow', '莫斯科'],
        '🇨🇦 加拿大': ['🇨🇦', 'canada', 'ca', '加拿大', '加', 'toronto', 'vancouver', '多伦多', '温哥华'],
        '🇦🇺 澳大利亚': ['🇦🇺', 'australia', 'au', '澳大利亚', '澳洲', '澳', 'sydney', '悉尼'],
        '🇮🇳 印度': ['🇮🇳', 'india', 'in', '印度', 'mumbai', '孟买'],
        '🇹🇷 土耳其': ['🇹🇷', 'turkey', 'tr', '土耳其', 'istanbul', '伊斯坦布尔'],
        '🇲🇾 马来西亚': ['🇲🇾', 'malaysia', 'my', '马来西亚', '马来', '大马', 'kuala lumpur', '吉隆坡'],
        '🇹🇭 泰国': ['🇹🇭', 'thailand', 'th', '泰国', '泰', 'bangkok', '曼谷'],
        '🇻🇳 越南': ['🇻🇳', 'vietnam', 'vn', '越南', '越'],
        '🇮🇩 印尼': ['🇮🇩', 'indonesia', 'id', '印尼', '印度尼西亚', 'jakarta', '雅加达'],
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
        '🇧🇪 比利时': ['🇧🇪', 'belgium', 'be', '比利时', 'brussels', '布鲁塞尔'],
        '🇨🇿 捷克': ['🇨🇿', 'czech', 'cz', '捷克', 'prague', '布拉格'],
        '🇭🇺 匈牙利': ['🇭🇺', 'hungary', 'hu', '匈牙利', 'budapest', '布达佩斯'],
        '🇷🇴 罗马尼亚': ['🇷🇴', 'romania', 'ro', '罗马尼亚', 'bucharest', '布加勒斯特'],
        '🇧🇬 保加利亚': ['🇧🇬', 'bulgaria', 'bg', '保加利亚', 'sofia', '索非亚'],
        '🇭🇷 克罗地亚': ['🇭🇷', 'croatia', 'hr', '克罗地亚', 'zagreb', '萨格勒布'],
        '🇸🇰 斯洛伐克': ['🇸🇰', 'slovakia', 'sk', '斯洛伐克', 'bratislava', '布拉迪斯拉发'],
        '🇸🇮 斯洛文尼亚': ['🇸🇮', 'slovenia', 'si', '斯洛文尼亚', 'ljubljana', '卢布尔雅那'],
        '🇱🇹 立陶宛': ['🇱🇹', 'lithuania', 'lt', '立陶宛', 'vilnius', '维尔纽斯'],
        '🇱🇻 拉脱维亚': ['🇱🇻', 'latvia', 'lv', '拉脱维亚', 'riga', '里加'],
        '🇪🇪 爱沙尼亚': ['🇪🇪', 'estonia', 'ee', '爱沙尼亚', 'tallinn', '塔林'],
        '🇷🇸 塞尔维亚': ['🇷🇸', 'serbia', 'rs', '塞尔维亚', 'belgrade', '贝尔格莱德'],
        '🇧🇦 波黑': ['🇧🇦', 'bosnia', 'ba', '波黑', '波斯尼亚'],
        '🇲🇪 黑山': ['🇲🇪', 'montenegro', 'me', '黑山'],
        '🇲🇰 北马其顿': ['🇲🇰', 'macedonia', 'mk', '马其顿', '北马其顿'],
        '🇦🇱 阿尔巴尼亚': ['🇦🇱', 'albania', 'al', '阿尔巴尼亚', 'tirana', '地拉那'],
        '🇮🇸 冰岛': ['🇮🇸', 'iceland', 'is', '冰岛', 'reykjavik', '雷克雅未克'],
        '🇱🇺 卢森堡': ['🇱🇺', 'luxembourg', 'lu', '卢森堡'],
        '🇲🇨 摩纳哥': ['🇲🇨', 'monaco', 'mc', '摩纳哥'],
        '🇦🇩 安道尔': ['🇦🇩', 'andorra', 'ad', '安道尔'],
        '🇱🇮 列支敦士登': ['🇱🇮', 'liechtenstein', 'li', '列支敦士登'],
        '🇸🇲 圣马力诺': ['🇸🇲', 'san marino', 'sm', '圣马力诺'],
        '🇻🇦 梵蒂冈': ['🇻🇦', 'vatican', 'va', '梵蒂冈'],
        '🇨🇾 塞浦路斯': ['🇨🇾', 'cyprus', 'cy', '塞浦路斯'],
        '🇲🇹 马耳他': ['🇲🇹', 'malta', 'mt', '马耳他'],
        '🇬🇪 格鲁吉亚': ['🇬🇪', 'georgia', 'ge', '格鲁吉亚', 'tbilisi', '第比利斯'],
        '🇦🇲 亚美尼亚': ['🇦🇲', 'armenia', 'am', '亚美尼亚', 'yerevan', '埃里温'],
        '🇦🇿 阿塞拜疆': ['🇦🇿', 'azerbaijan', 'az', '阿塞拜疆', 'baku', '巴库'],
        '🇰🇿 哈萨克斯坦': ['🇰🇿', 'kazakhstan', 'kz', '哈萨克斯坦', '哈萨克'],
        '🇺🇿 乌兹别克斯坦': ['🇺🇿', 'uzbekistan', 'uz', '乌兹别克斯坦', 'tashkent', '塔什干'],
        '🇰🇬 吉尔吉斯斯坦': ['🇰🇬', 'kyrgyzstan', 'kg', '吉尔吉斯斯坦', 'bishkek', '比什凯克'],
        '🇹🇯 塔吉克斯坦': ['🇹🇯', 'tajikistan', 'tj', '塔吉克斯坦'],
        '🇹🇲 土库曼斯坦': ['🇹🇲', 'turkmenistan', 'tm', '土库曼斯坦'],
        '🇲🇳 蒙古': ['🇲🇳', 'mongolia', 'mn', '蒙古', 'ulaanbaatar', '乌兰巴托'],
        '🇰🇵 朝鲜': ['🇰🇵', 'north korea', 'kp', 'dprk', '朝鲜', '北朝鲜', '平壤', 'pyongyang'],
        '🇮🇷 伊朗': ['🇮🇷', 'iran', 'ir', '伊朗', 'tehran', '德黑兰'],
        '🇮🇶 伊拉克': ['🇮🇶', 'iraq', 'iq', '伊拉克', 'baghdad', '巴格达'],
        '🇸🇾 叙利亚': ['🇸🇾', 'syria', 'sy', '叙利亚', 'damascus', '大马士革'],
        '🇦🇫 阿富汗': ['🇦🇫', 'afghanistan', 'af', '阿富汗', 'kabul', '喀布尔'],
        '🇸🇦 沙特阿拉伯': ['🇸🇦', 'saudi arabia', 'sa', '沙特', '沙特阿拉伯', 'riyadh', '利雅得'],
        '🇶🇦 卡塔尔': ['🇶🇦', 'qatar', 'qa', '卡塔尔', 'doha', '多哈'],
        '🇰🇼 科威特': ['🇰🇼', 'kuwait', 'kw', '科威特'],
        '🇴🇲 阿曼': ['🇴🇲', 'oman', 'om', '阿曼', 'muscat', '马斯喀特'],
        '🇧🇭 巴林': ['🇧🇭', 'bahrain', 'bh', '巴林'],
        '🇯🇴 约旦': ['🇯🇴', 'jordan', 'jo', '约旦', 'amman', '安曼'],
        '🇱🇧 黎巴嫩': ['🇱🇧', 'lebanon', 'lb', '黎巴嫩', 'beirut', '贝鲁特'],
        '🇵🇸 巴勒斯坦': ['🇵🇸', 'palestine', 'ps', '巴勒斯坦'],
        '🇪🇬 埃及': ['🇪🇬', 'egypt', 'eg', '埃及', 'cairo', '开罗'],
        '🇲🇦 摩洛哥': ['🇲🇦', 'morocco', 'ma', '摩洛哥', 'casablanca', '卡萨布兰卡'],
        '🇹🇳 突尼斯': ['🇹🇳', 'tunisia', 'tn', '突尼斯'],
        '🇩🇿 阿尔及利亚': ['🇩🇿', 'algeria', 'dz', '阿尔及利亚'],
        '🇱🇾 利比亚': ['🇱🇾', 'libya', 'ly', '利比亚'],
        '🇸🇩 苏丹': ['🇸🇩', 'sudan', 'sd', '苏丹'],
        '🇪🇹 埃塞俄比亚': ['🇪🇹', 'ethiopia', 'et', '埃塞俄比亚'],
        '🇰🇪 肯尼亚': ['🇰🇪', 'kenya', 'ke', '肯尼亚', 'nairobi', '内罗毕'],
        '🇹🇿 坦桑尼亚': ['🇹🇿', 'tanzania', 'tz', '坦桑尼亚'],
        '🇺🇬 乌干达': ['🇺🇬', 'uganda', 'ug', '乌干达'],
        '🇷🇼 卢旺达': ['🇷🇼', 'rwanda', 'rw', '卢旺达'],
        '🇬🇭 加纳': ['🇬🇭', 'ghana', 'gh', '加纳'],
        '🇨🇮 科特迪瓦': ['🇨🇮', 'ivory coast', 'ci', '科特迪瓦', '象牙海岸'],
        '🇸🇳 塞内加尔': ['🇸🇳', 'senegal', 'sn', '塞内加尔'],
        '🇨🇲 喀麦隆': ['🇨🇲', 'cameroon', 'cm', '喀麦隆'],
        '🇲🇿 莫桑比克': ['🇲🇿', 'mozambique', 'mz', '莫桑比克'],
        '🇲🇬 马达加斯加': ['🇲🇬', 'madagascar', 'mg', '马达加斯加'],
        '🇦🇴 安哥拉': ['🇦🇴', 'angola', 'ao', '安哥拉'],
        '🇿🇲 赞比亚': ['🇿🇲', 'zambia', 'zm', '赞比亚'],
        '🇿🇼 津巴布韦': ['🇿🇼', 'zimbabwe', 'zw', '津巴布韦'],
        '🇧🇼 博茨瓦纳': ['🇧🇼', 'botswana', 'bw', '博茨瓦纳'],
        '🇳🇦 纳米比亚': ['🇳🇦', 'namibia', 'na', '纳米比亚'],
        '🇲🇺 毛里求斯': ['🇲🇺', 'mauritius', 'mu', '毛里求斯'],
        '🇸🇨 塞舌尔': ['🇸🇨', 'seychelles', 'sc', '塞舌尔'],
        '🇲🇲 缅甸': ['🇲🇲', 'myanmar', 'mm', 'burma', '缅甸', '仰光', 'yangon'],
        '🇰🇭 柬埔寨': ['🇰🇭', 'cambodia', 'kh', '柬埔寨', '金边', 'phnom penh'],
        '🇱🇦 老挝': ['🇱🇦', 'laos', 'la', '老挝', '万象', 'vientiane'],
        '🇧🇳 文莱': ['🇧🇳', 'brunei', 'bn', '文莱'],
        '🇵🇰 巴基斯坦': ['🇵🇰', 'pakistan', 'pk', '巴基斯坦', 'karachi', '卡拉奇'],
        '🇧🇩 孟加拉': ['🇧🇩', 'bangladesh', 'bd', '孟加拉', 'dhaka', '达卡'],
        '🇱🇰 斯里兰卡': ['🇱🇰', 'sri lanka', 'lk', '斯里兰卡', 'colombo', '科伦坡'],
        '🇳🇵 尼泊尔': ['🇳🇵', 'nepal', 'np', '尼泊尔', 'kathmandu', '加德满都'],
        '🇲🇻 马尔代夫': ['🇲🇻', 'maldives', 'mv', '马尔代夫', 'male', '马累'],
        '🇨🇱 智利': ['🇨🇱', 'chile', 'cl', '智利', 'santiago', '圣地亚哥'],
        '🇨🇴 哥伦比亚': ['🇨🇴', 'colombia', 'co', '哥伦比亚', 'bogota', '波哥大'],
        '🇵🇪 秘鲁': ['🇵🇪', 'peru', 'pe', '秘鲁', 'lima', '利马'],
        '🇻🇪 委内瑞拉': ['🇻🇪', 'venezuela', 've', '委内瑞拉', 'caracas', '加拉加斯'],
        '🇪🇨 厄瓜多尔': ['🇪🇨', 'ecuador', 'ec', '厄瓜多尔', 'quito', '基多'],
        '🇧🇴 玻利维亚': ['🇧🇴', 'bolivia', 'bo', '玻利维亚', 'la paz', '拉巴斯'],
        '🇵🇾 巴拉圭': ['🇵🇾', 'paraguay', 'py', '巴拉圭', 'asuncion', '亚松森'],
        '🇺🇾 乌拉圭': ['🇺🇾', 'uruguay', 'uy', '乌拉圭', 'montevideo', '蒙得维的亚'],
        '🇨🇷 哥斯达黎加': ['🇨🇷', 'costa rica', 'cr', '哥斯达黎加'],
        '🇵🇦 巴拿马': ['🇵🇦', 'panama', 'pa', '巴拿马'],
        '🇨🇺 古巴': ['🇨🇺', 'cuba', 'cu', '古巴', 'havana', '哈瓦那'],
        '🇩🇴 多米尼加': ['🇩🇴', 'dominican', 'do', '多米尼加'],
        '🇵🇷 波多黎各': ['🇵🇷', 'puerto rico', 'pr', '波多黎各'],
        '🇯🇲 牙买加': ['🇯🇲', 'jamaica', 'jm', '牙买加'],
        '🇭🇹 海地': ['🇭🇹', 'haiti', 'ht', '海地'],
        '🇹🇹 特立尼达和多巴哥': ['🇹🇹', 'trinidad', 'tt', '特立尼达和多巴哥'],
        '🇸🇷 苏里南': ['🇸🇷', 'suriname', 'sr', '苏里南'],
        '🇬🇾 圭亚那': ['🇬🇾', 'Guyana', 'gy', '圭亚那'],
        '🇧🇸 巴哈马': ['🇧🇸', 'bahamas', 'bs', '巴哈马'],
        '🇧🇿 伯利兹': ['🇧🇿', 'belize', 'bz', '伯利兹'],
        '🇬🇹 危地马拉': ['🇬🇹', 'guatemala', 'gt', '危地马拉'],
        '🇭🇳 洪都拉斯': ['🇭🇳', 'honduras', 'hn', '洪都拉斯'],
        '🇸🇻 萨尔瓦多': ['🇸🇻', 'el salvador', 'sv', '萨尔瓦多'],
        '🇳🇮 尼加拉瓜': ['🇳🇮', 'nicaragua', 'ni', '尼加拉瓜'],
        '🇦🇶 南极洲': ['🇦🇶', 'antarctica', 'aq', '南极'],
        '🇫🇯 斐济': ['🇫🇯', 'fiji', 'fj', '斐济'],
        '🇳🇨 新喀里多尼亚': ['🇳🇨', 'new caledonia', 'nc', '新喀里多尼亚'],
        '🇵🇫 法属波利尼西亚': ['🇵🇫', 'french polynesia', 'pf', '法属波利尼西亚', 'tahiti', '塔希提'],
        '🇬🇺 关岛': ['🇬🇺', 'guam', 'gu', '关岛'],
        '🇼🇸 萨摩亚': ['🇼🇸', 'samoa', 'ws', '萨摩亚'],
        '🇹🇴 汤加': ['🇹🇴', 'tonga', 'to', '汤加'],
        '🇻🇺 瓦努阿图': ['🇻🇺', 'vanuatu', 'vu', '瓦努阿图'],
        '🇸🇧 所罗门群岛': ['🇸🇧', 'solomon', 'sb', '所罗门群岛'],
        '🇹🇱 东帝汶': ['🇹🇱', 'timor', 'tl', '东帝汶'],
        '🇵🇬 巴布亚新几内亚': ['🇵🇬', 'papua', 'pg', '巴布亚新几内亚'],
        '🇰🇮 基里巴斯': ['🇰🇮', 'kiribati', 'ki', '基里巴斯'],
        '🇹🇻 图瓦卢': ['🇹🇻', 'tuvalu', 'tv', '图瓦卢'],
        '🇳🇷 瑙鲁': ['🇳🇷', 'nauru', 'nr', '瑙鲁'],
        '🇵🇼 帕劳': ['🇵🇼', 'palau', 'pw', '帕劳'],
        '🇫🇲 密克罗尼西亚': ['🇫🇲', 'micronesia', 'fm', '密克罗尼西亚'],
        '🇲🇭 马绍尔群岛': ['🇲🇭', 'marshall', 'mh', '马绍尔群岛'],
        '🇬🇱 格陵兰': ['🇬🇱', 'greenland', 'gl', '格陵兰'],
        # CN placed after HK/TW/MO so "中国香港"/"中国台湾"/"中国澳门" resolve correctly
        '🇨🇳 中国大陆': ['🇨🇳', 'china', 'cn', '中国', '大陆', '上海', 'shanghai', '北京', 'beijing',
                        '广州', 'guangzhou', '深圳', 'shenzhen', '成都', 'chengdu',
                        '杭州', 'hangzhou', '南京', 'nanjing', '武汉', 'wuhan',
                        '重庆', 'chongqing', '青岛', 'qingdao'],
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
    def _format_group_name(country_code: str = '', country_name: str = '', flag: str = '') -> str:
        """Format a standard country group name."""
        code = str(country_code or '').upper().strip()
        if code and code != 'XX':
            flag = flag or GeoIPService.iso_to_flag(code)
            country_name = country_name or COUNTRY_NAMES.get(code) or NameTransformer.ISO_TO_COUNTRY.get(code, code)

        if flag and country_name:
            return f"{flag} {country_name}"

        return '🔰 未知'

    @staticmethod
    def _country_from_detection_result(result: Optional[dict]) -> Optional[str]:
        """Convert a detect_country-style result to a standard group name."""
        if not isinstance(result, dict):
            return None

        country_code = str(result.get('country_code') or '').upper().strip()
        if not country_code or country_code == 'XX':
            return None

        return CountryGrouper._format_group_name(
            country_code=country_code,
            country_name=str(result.get('country') or '').strip(),
            flag=str(result.get('flag') or '').strip(),
        )

    @staticmethod
    def _country_from_region(region: dict) -> Optional[str]:
        """Resolve country group directly from saved/tested region info."""
        if not isinstance(region, dict):
            return None
        code = str(region.get('country_code') or '').upper()
        flag = str(region.get('flag') or '').strip()
        country = str(region.get('country') or '').strip()
        if code and code != 'XX':
            return CountryGrouper._format_group_name(code, country, flag)
        if flag:
            code = NameTransformer.FLAG_TO_ISO.get(flag, '')
            if code and code != 'XX':
                return CountryGrouper._format_group_name(code, country, flag)
        if country:
            detected = detect_country(country)
            if detected:
                return CountryGrouper._country_from_detection_result(detected)
        return None

    @staticmethod
    def _identify_by_patterns(proxy_name: str) -> str:
        """Legacy keyword matcher as a final fallback."""
        CountryGrouper._init_patterns()
        
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
    def identify_country(proxy_name: str, proxy_server: str = None) -> str:
        """Identify country/region of proxy node."""
        detected = detect_country(proxy_name)
        detected_group = CountryGrouper._country_from_detection_result(detected)
        if detected_group:
            return detected_group

        # Keep legacy pattern matcher as a final synchronous fallback.
        legacy_group = CountryGrouper._identify_by_patterns(proxy_name)
        if legacy_group != '🔰 未知':
            return legacy_group

        return '🔰 未知'
    
    @staticmethod
    def group_by_country(proxies: List[dict]) -> Dict[str, List[str]]:
        """Group proxy nodes by country/region, return {country: [node_name_list]}"""
        groups: Dict[str, List[str]] = {}
        
        for proxy in proxies:
            name = proxy.get('name', '')
            if not name:
                continue
            server = proxy.get('server', '')
            country = CountryGrouper._country_from_region(proxy.get('region')) or CountryGrouper.identify_country(name, server)
            
            if country not in groups:
                groups[country] = []
            if name not in groups[country]:
                groups[country].append(name)
        
        return groups
    
    @staticmethod
    async def identify_country_async(proxy_name: str, proxy_server: str = None) -> str:
        """Async version: Identify country with GeoIP lookup support"""
        detected = detect_country(proxy_name)
        detected_group = CountryGrouper._country_from_detection_result(detected)
        if detected_group:
            return detected_group

        legacy_group = CountryGrouper._identify_by_patterns(proxy_name)
        if legacy_group != '🔰 未知':
            return legacy_group
        
        # Try GeoIP lookup (async)
        if proxy_server:
            try:
                geoip = GeoIPService.get_instance()
                country_info = await geoip.lookup_country_async(proxy_server)
                if country_info and country_info.get('country_code'):
                    return CountryGrouper._format_group_name(
                        country_code=country_info['country_code'],
                        country_name=country_info.get('country_name', ''),
                        flag=country_info.get('flag', ''),
                    )
            except Exception:
                pass
        
        return '🔰 未知'
