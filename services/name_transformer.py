"""
Name Transformer Service
Unify node name format to: Flag Provider NodeName
"""
import re
from typing import List, Optional
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
        '🇨🇳', '🇭🇰', '🇹🇼', '🇲🇴', '🇯🇵', '🇺🇸', '🇸🇬', '🇰🇷', '🇬🇧', '🇩🇪',
        '🇨🇦', '🇦🇺', '🇫🇷', '🇷🇺', '🇮🇳', '🇳🇱', '🇹🇷', '🇦🇶', '🇲🇾', '🇪🇸',
        '🇻🇳', '🇺🇦', '🇲🇩', '🇳🇬', '🇧🇷', '🇮🇹', '🇵🇱', '🇨🇭', '🇦🇹', '🇧🇪',
        '🇸🇪', '🇳🇴', '🇩🇰', '🇫🇮', '🇮🇪', '🇵🇹', '🇬🇷', '🇨🇿', '🇭🇺', '🇷🇴',
        '🇧🇬', '🇭🇷', '🇸🇰', '🇸🇮', '🇱🇹', '🇱🇻', '🇪🇪', '🇮🇱', '🇦🇪', '🇸🇦',
        '🇶🇦', '🇰🇼', '🇴🇲', '🇧🇭', '🇯🇴', '🇱🇧', '🇪🇬', '🇰🇪', '🇳🇿', '🇵🇭',
        '🇹🇭', '🇮🇩', '🇵🇰', '🇧🇩', '🇲🇽', '🇦🇷', '🇿🇦', '🇨🇱', '🇨🇴', '🇵🇪',
        '🇻🇪', '🇪🇨', '🇧🇴', '🇵🇾', '🇺🇾', '🇨🇷', '🇵🇦', '🇨🇺', '🇩🇴', '🇵🇷',
        '🇯🇲', '🇭🇹', '🇱🇰', '🇳🇵', '🇲🇲', '🇰🇭', '🇱🇦', '🇲🇳', '🇰🇿', '🇺🇿',
        '🇦🇿', '🇬🇪', '🇦🇲', '🇨🇾', '🇲🇹', '🇮🇸', '🇱🇺', '🇲🇨', '🇦🇩', '🇱🇮',
        '🇸🇲', '🇻🇦', '🇮🇷', '🇮🇶', '🇸🇾', '🇦🇫', '🇧🇳', '🇰🇵', '🇷🇸', '🇧🇦',
        '🇲🇪', '🇲🇰', '🇦🇱', '🇧🇾', '🇰🇬', '🇹🇯', '🇹🇲', '🇬🇭', '🇨🇮', '🇨🇲',
        '🇹🇿', '🇺🇬', '🇷🇼', '🇪🇹', '🇸🇳', '🇲🇦', '🇹🇳', '🇩🇿', '🇱🇾', '🇲🇺',
        '🇸🇨', '🇲🇻', '🇬🇺', '🇫🇯', '🇳🇨', '🇵🇫', '🇬🇱', '🇦🇩', '🇩🇲', '🇰🇳',
        '🇱🇨', '🇻🇨', '🇦🇬', '🇧🇧', '🇹🇹', '🇸🇷', '🇬🇾', '🇧🇸', '🇯🇲', '🇭🇹',
        '🇧🇿', '🇸🇻', '🇭🇳', '🇳🇮', '🇨🇷', '🇵🇦', '🇨🇺', '🇩🇴', '🇵🇷',
        '🇹🇱', '🇸🇧', '🇻🇺', '🇼🇸', '🇹🇴', '🇰🇮', '🇳🇷', '🇵🇼', '🇫🇲', '🇲🇭',
        '🇹🇻', '🇳🇺', '🇨🇰', '🇵🇳', '🇸🇭', '🇫🇰', '🇬🇮', '🇧🇲', '🇰🇾', '🇹🇨',
        '🇻🇬', '🇻🇮', '🇵🇲', '🇬🇫', '🇬🇵', '🇲🇶', '🇷🇪', '🇾🇹', '🇼🇫', '🇵🇫',
        '🇹🇫', '🇪🇭', '🇸🇸', '🇸🇩', '🇨🇫', '🇨🇩', '🇨🇬', '🇬🇶', '🇬🇦', '🇧🇯',
        '🇧🇫', '🇲🇱', '🇳🇪', '🇹🇩', '🇩🇯', '🇸🇴', '🇪🇷', '🇲🇿', '🇲🇬', '🇿🇲',
        '🇿🇼', '🇧🇼', '🇳🇦', '🇱🇸', '🇸🇿', '🇦🇴', '🇨🇻', '🇸🇹', '🇬🇳', '🇬🇼',
        '🇸🇱', '🇱🇷', '🇹🇬', '🇧🇯', '🇰🇲', '🇲🇷', '🇬🇲', '🇨🇨', '🇨🇽',
        '🇭🇲', '🇸🇯', '🇧🇶', '🇸🇽', '🇲🇫', '🇧🇱', '🇦🇮', '🇲🇸', '🇰🇵',
        '🇮🇲', '🇯🇪', '🇬🇬', '🇦🇽', '🇫🇴', '🇸🇲', '🇱🇮', '🇲🇨', '🇦🇩',
        '🏳️', '🔰', '🌏', '🌍', '🌎'
    ]
    
    # Country identification patterns: Flag -> keyword list (complete world coverage)
    COUNTRY_FLAG_MAP = {
        '🇭🇰': ['HK', 'Hong Kong', '香港', 'Hongkong'],
        '🇹🇼': ['TW', 'Taiwan', '台湾', 'Taipei'],
        '🇲🇴': ['MO', 'Macau', 'Macao', '澳门', '濠江'],
        '🇨🇳': ['CN', 'China', '中国', '大陆', '上海', '北京', '广州', '深圳', '成都', '杭州', '南京', '武汉', '重庆', '青岛'],
        '🇯🇵': ['JP', 'Japan', '日本', 'Tokyo', 'Osaka', '东京', '大阪', '横滨', '名古屋', '札幌', '福冈'],
        '🇰🇷': ['KR', 'Korea', '韩国', 'Seoul', '首尔'],
        '🇸🇬': ['SG', 'Singapore', '新加坡', '狮城'],
        '🇺🇸': ['US', 'USA', 'United States', 'America', '美国', '洛杉矶', '西雅图', '纽约', '硅谷', 'Los Angeles', 'Seattle', 'San Jose', 'Dallas', 'Chicago', 'Miami', 'New York'],
        '🇬🇧': ['GB', 'UK', 'United Kingdom', 'Britain', 'England', '英国', '伦敦', 'London'],
        '🇩🇪': ['DE', 'Germany', 'Deutsch', '德国', '法兰克福', '柏林', '慕尼黑', 'Frankfurt', 'Berlin', 'Munich'],
        '🇫🇷': ['FR', 'France', '法国', '巴黎', 'Paris'],
        '🇳🇱': ['NL', 'Netherlands', 'Holland', '荷兰', '阿姆斯特丹', 'Amsterdam'],
        '🇷🇺': ['RU', 'Russia', '俄罗斯', '莫斯科', 'Moscow'],
        '🇧🇾': ['BY', 'Belarus', '白俄罗斯', '明斯克', 'Minsk'],
        '🇨🇦': ['CA', 'Canada', '加拿大', '多伦多', '温哥华', 'Toronto', 'Vancouver'],
        '🇦🇺': ['AU', 'Australia', '澳大利亚', '澳洲', '悉尼', 'Sydney'],
        '🇮🇳': ['IN', 'India', '印度', '孟买', 'Mumbai'],
        '🇹🇷': ['TR', 'Turkey', '土耳其', '伊斯坦布尔', 'Istanbul'],
        '🇲🇾': ['MY', 'Malaysia', '马来西亚', '马来', '大马', '吉隆坡', 'Kuala Lumpur'],
        '🇹🇭': ['TH', 'Thailand', '泰国', '曼谷', 'Bangkok'],
        '🇻🇳': ['VN', 'Vietnam', '越南'],
        '🇮🇩': ['ID', 'Indonesia', '印尼', '印度尼西亚', '雅加达', 'Jakarta'],
        '🇵🇭': ['PH', 'Philippines', '菲律宾', '马尼拉', 'Manila'],
        '🇧🇷': ['BR', 'Brazil', '巴西', '圣保罗', 'Sao Paulo'],
        '🇦🇷': ['AR', 'Argentina', '阿根廷', '布宜诺斯艾利斯', 'Buenos Aires'],
        '🇲🇽': ['MX', 'Mexico', '墨西哥'],
        '🇿🇦': ['ZA', 'South Africa', '南非', '约翰内斯堡', 'Johannesburg'],
        '🇦🇪': ['AE', 'UAE', 'Dubai', '阿联酋', '迪拜', '阿布扎比', 'Abu Dhabi'],
        '🇮🇱': ['IL', 'Israel', '以色列', '特拉维夫', 'Tel Aviv'],
        '🇺🇦': ['UA', 'Ukraine', '乌克兰', '基辅', 'Kiev'],
        '🇵🇱': ['PL', 'Poland', '波兰', '华沙', 'Warsaw'],
        '🇨🇭': ['CH', 'Switzerland', '瑞士', '苏黎世', 'Zurich'],
        '🇸🇪': ['SE', 'Sweden', '瑞典', '斯德哥尔摩', 'Stockholm'],
        '🇳🇴': ['NO', 'Norway', '挪威', '奥斯陆', 'Oslo'],
        '🇫🇮': ['FI', 'Finland', '芬兰', '赫尔辛基', 'Helsinki'],
        '🇩🇰': ['DK', 'Denmark', '丹麦', '哥本哈根', 'Copenhagen'],
        '🇮🇹': ['IT', 'Italy', '意大利', '罗马', '米兰', 'Rome', 'Milan'],
        '🇪🇸': ['ES', 'Spain', '西班牙', '马德里', '巴塞罗那', 'Madrid', 'Barcelona'],
        '🇳🇬': ['NG', 'Nigeria', '尼日利亚'],
        '🇳🇿': ['NZ', 'New Zealand', '新西兰', '奥克兰', 'Auckland'],
        '🇲🇩': ['MD', 'Moldova', '摩尔多瓦'],
        '🇮🇪': ['IE', 'Ireland', '爱尔兰', '都柏林', 'Dublin'],
        '🇵🇹': ['PT', 'Portugal', '葡萄牙', '里斯本', 'Lisbon'],
        '🇬🇷': ['GR', 'Greece', '希腊', '雅典', 'Athens'],
        '🇦🇹': ['AT', 'Austria', '奥地利', '维也纳', 'Vienna'],
        '🇧🇪': ['BE', 'Belgium', '比利时', '布鲁塞尔', 'Brussels'],
        '🇨🇿': ['CZ', 'Czech', '捷克', '布拉格', 'Prague'],
        '🇭🇺': ['HU', 'Hungary', '匈牙利', '布达佩斯', 'Budapest'],
        '🇷🇴': ['RO', 'Romania', '罗马尼亚', '布加勒斯特', 'Bucharest'],
        '🇧🇬': ['BG', 'Bulgaria', '保加利亚', '索非亚', 'Sofia'],
        '🇭🇷': ['HR', 'Croatia', '克罗地亚', '萨格勒布', 'Zagreb'],
        '🇸🇰': ['SK', 'Slovakia', '斯洛伐克', '布拉迪斯拉发', 'Bratislava'],
        '🇸🇮': ['SI', 'Slovenia', '斯洛文尼亚', '卢布尔雅那', 'Ljubljana'],
        '🇱🇹': ['LT', 'Lithuania', '立陶宛', '维尔纽斯', 'Vilnius'],
        '🇱🇻': ['LV', 'Latvia', '拉脱维亚', '里加', 'Riga'],
        '🇪🇪': ['EE', 'Estonia', '爱沙尼亚', '塔林', 'Tallinn'],
        '🇷🇸': ['RS', 'Serbia', '塞尔维亚', '贝尔格莱德', 'Belgrade'],
        '🇧🇦': ['BA', 'Bosnia', '波黑', '波斯尼亚'],
        '🇲🇪': ['ME', 'Montenegro', '黑山'],
        '🇲🇰': ['MK', 'Macedonia', '马其顿', '北马其顿'],
        '🇦🇱': ['AL', 'Albania', '阿尔巴尼亚', '地拉那', 'Tirana'],
        '🇮🇸': ['IS', 'Iceland', '冰岛', '雷克雅未克', 'Reykjavik'],
        '🇱🇺': ['LU', 'Luxembourg', '卢森堡'],
        '🇲🇨': ['MC', 'Monaco', '摩纳哥'],
        '🇦🇩': ['AD', 'Andorra', '安道尔'],
        '🇱🇮': ['LI', 'Liechtenstein', '列支敦士登'],
        '🇸🇲': ['SM', 'San Marino', '圣马力诺'],
        '🇻🇦': ['VA', 'Vatican', '梵蒂冈'],
        '🇨🇾': ['CY', 'Cyprus', '塞浦路斯'],
        '🇲🇹': ['MT', 'Malta', '马耳他'],
        '🇬🇪': ['GE', 'Georgia', '格鲁吉亚', '第比利斯', 'Tbilisi'],
        '🇦🇲': ['AM', 'Armenia', '亚美尼亚', '埃里温', 'Yerevan'],
        '🇦🇿': ['AZ', 'Azerbaijan', '阿塞拜疆', '巴库', 'Baku'],
        '🇰🇿': ['KZ', 'Kazakhstan', '哈萨克斯坦', '哈萨克'],
        '🇺🇿': ['UZ', 'Uzbekistan', '乌兹别克斯坦', '塔什干', 'Tashkent'],
        '🇰🇬': ['KG', 'Kyrgyzstan', '吉尔吉斯斯坦', '比什凯克', 'Bishkek'],
        '🇹🇯': ['TJ', 'Tajikistan', '塔吉克斯坦'],
        '🇹🇲': ['TM', 'Turkmenistan', '土库曼斯坦'],
        '🇲🇳': ['MN', 'Mongolia', '蒙古', '乌兰巴托', 'Ulaanbaatar'],
        '🇰🇵': ['KP', 'North Korea', '朝鲜', '北朝鲜', '平壤', 'Pyongyang'],
        '🇮🇷': ['IR', 'Iran', '伊朗', '德黑兰', 'Tehran'],
        '🇮🇶': ['IQ', 'Iraq', '伊拉克', '巴格达', 'Baghdad'],
        '🇸🇾': ['SY', 'Syria', '叙利亚', '大马士革', 'Damascus'],
        '🇦🇫': ['AF', 'Afghanistan', '阿富汗', '喀布尔', 'Kabul'],
        '🇸🇦': ['SA', 'Saudi Arabia', '沙特', '沙特阿拉伯', '利雅得', 'Riyadh'],
        '🇶🇦': ['QA', 'Qatar', '卡塔尔', '多哈', 'Doha'],
        '🇰🇼': ['KW', 'Kuwait', '科威特'],
        '🇴🇲': ['OM', 'Oman', '阿曼', '马斯喀特', 'Muscat'],
        '🇧🇭': ['BH', 'Bahrain', '巴林'],
        '🇯🇴': ['JO', 'Jordan', '约旦', '安曼', 'Amman'],
        '🇱🇧': ['LB', 'Lebanon', '黎巴嫩', '贝鲁特', 'Beirut'],
        '🇮🇱': ['IL', 'Israel', '以色列', '特拉维夫', 'Tel Aviv'],
        '🇵🇸': ['PS', 'Palestine', '巴勒斯坦'],
        '🇪🇬': ['EG', 'Egypt', '埃及', '开罗', 'Cairo'],
        '🇲🇦': ['MA', 'Morocco', '摩洛哥', '卡萨布兰卡', 'Casablanca'],
        '🇹🇳': ['TN', 'Tunisia', '突尼斯'],
        '🇩🇿': ['DZ', 'Algeria', '阿尔及利亚'],
        '🇱🇾': ['LY', 'Libya', '利比亚'],
        '🇸🇩': ['SD', 'Sudan', '苏丹'],
        '🇪🇹': ['ET', 'Ethiopia', '埃塞俄比亚'],
        '🇰🇪': ['KE', 'Kenya', '肯尼亚', '内罗毕', 'Nairobi'],
        '🇹🇿': ['TZ', 'Tanzania', '坦桑尼亚'],
        '🇺🇬': ['UG', 'Uganda', '乌干达'],
        '🇷🇼': ['RW', 'Rwanda', '卢旺达'],
        '🇬🇭': ['GH', 'Ghana', '加纳'],
        '🇨🇮': ['CI', 'Ivory Coast', '科特迪瓦', '象牙海岸'],
        '🇸🇳': ['SN', 'Senegal', '塞内加尔'],
        '🇨🇲': ['CM', 'Cameroon', '喀麦隆'],
        '🇲🇿': ['MZ', 'Mozambique', '莫桑比克'],
        '🇲🇬': ['MG', 'Madagascar', '马达加斯加'],
        '🇦🇴': ['AO', 'Angola', '安哥拉'],
        '🇿🇲': ['ZM', 'Zambia', '赞比亚'],
        '🇿🇼': ['ZW', 'Zimbabwe', '津巴布韦'],
        '🇧🇼': ['BW', 'Botswana', '博茨瓦纳'],
        '🇳🇦': ['NA', 'Namibia', '纳米比亚'],
        '🇲🇺': ['MU', 'Mauritius', '毛里求斯'],
        '🇸🇨': ['SC', 'Seychelles', '塞舌尔'],
        '🇲🇲': ['MM', 'Myanmar', 'Burma', '缅甸', '仰光', 'Yangon'],
        '🇰🇭': ['KH', 'Cambodia', '柬埔寨', '金边', 'Phnom Penh'],
        '🇱🇦': ['LA', 'Laos', '老挝', '万象', 'Vientiane'],
        '🇧🇳': ['BN', 'Brunei', '文莱'],
        '🇵🇰': ['PK', 'Pakistan', '巴基斯坦', '卡拉奇', 'Karachi'],
        '🇧🇩': ['BD', 'Bangladesh', '孟加拉', '达卡', 'Dhaka'],
        '🇱🇰': ['LK', 'Sri Lanka', '斯里兰卡', '科伦坡', 'Colombo'],
        '🇳🇵': ['NP', 'Nepal', '尼泊尔', '加德满都', 'Kathmandu'],
        '🇲🇻': ['MV', 'Maldives', '马尔代夫', '马累', 'Male'],
        '🇨🇱': ['CL', 'Chile', '智利', '圣地亚哥', 'Santiago'],
        '🇨🇴': ['CO', 'Colombia', '哥伦比亚', '波哥大', 'Bogota'],
        '🇵🇪': ['PE', 'Peru', '秘鲁', '利马', 'Lima'],
        '🇻🇪': ['VE', 'Venezuela', '委内瑞拉', '加拉加斯', 'Caracas'],
        '🇪🇨': ['EC', 'Ecuador', '厄瓜多尔', '基多', 'Quito'],
        '🇧🇴': ['BO', 'Bolivia', '玻利维亚', '拉巴斯', 'La Paz'],
        '🇵🇾': ['PY', 'Paraguay', '巴拉圭', '亚松森', 'Asuncion'],
        '🇺🇾': ['UY', 'Uruguay', '乌拉圭', '蒙得维的亚', 'Montevideo'],
        '🇨🇷': ['CR', 'Costa Rica', '哥斯达黎加'],
        '🇵🇦': ['PA', 'Panama', '巴拿马'],
        '🇨🇺': ['CU', 'Cuba', '古巴', '哈瓦那', 'Havana'],
        '🇩🇴': ['DO', 'Dominican', '多米尼加'],
        '🇵🇷': ['PR', 'Puerto Rico', '波多黎各'],
        '🇯🇲': ['JM', 'Jamaica', '牙买加'],
        '🇭🇹': ['HT', 'Haiti', '海地'],
        '🇹🇹': ['TT', 'Trinidad', '特立尼达和多巴哥'],
        '🇸🇷': ['SR', 'Suriname', '苏里南'],
        '🇬🇾': ['GY', 'Guyana', '圭亚那'],
        '🇧🇸': ['BS', 'Bahamas', '巴哈马'],
        '🇧🇿': ['BZ', 'Belize', '伯利兹'],
        '🇬🇹': ['GT', 'Guatemala', '危地马拉'],
        '🇭🇳': ['HN', 'Honduras', '洪都拉斯'],
        '🇸🇻': ['SV', 'El Salvador', '萨尔瓦多'],
        '🇳🇮': ['NI', 'Nicaragua', '尼加拉瓜'],
        '🇦🇶': ['AQ', 'Antarctica', '南极'],
        '🇫🇯': ['FJ', 'Fiji', '斐济'],
        '🇳🇨': ['NC', 'New Caledonia', '新喀里多尼亚'],
        '🇵🇫': ['PF', 'French Polynesia', '法属波利尼西亚', '塔希提', 'Tahiti'],
        '🇬🇺': ['GU', 'Guam', '关岛'],
        '🇼🇸': ['WS', 'Samoa', '萨摩亚'],
        '🇹🇴': ['TO', 'Tonga', '汤加'],
        '🇻🇺': ['VU', 'Vanuatu', '瓦努阿图'],
        '🇸🇧': ['SB', 'Solomon', '所罗门群岛'],
        '🇹🇱': ['TL', 'Timor', '东帝汶'],
        '🇵🇬': ['PG', 'Papua', '巴布亚新几内亚'],
        '🇰🇮': ['KI', 'Kiribati', '基里巴斯'],
        '🇹🇻': ['TV', 'Tuvalu', '图瓦卢'],
        '🇳🇷': ['NR', 'Nauru', '瑙鲁'],
        '🇵🇼': ['PW', 'Palau', '帕劳'],
        '🇫🇲': ['FM', 'Micronesia', '密克罗尼西亚'],
        '🇲🇭': ['MH', 'Marshall', '马绍尔群岛'],
        '🇬🇱': ['GL', 'Greenland', '格陵兰'],
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
    _ISO_TO_FLAG = None
    
    @staticmethod
    def _get_flag_set():
        """Lazy create flag set"""
        if NameTransformer._FLAG_SET is None:
            NameTransformer._FLAG_SET = set(NameTransformer.FLAG_EMOJIS) - {'🔰', '🌏', '🌍', '🌎', '🏳️'}
        return NameTransformer._FLAG_SET

    @staticmethod
    def _get_iso_to_flag():
        """Lazy create ISO -> flag mapping."""
        if NameTransformer._ISO_TO_FLAG is None:
            NameTransformer._ISO_TO_FLAG = {
                iso: flag for flag, iso in NameTransformer.FLAG_TO_ISO.items()
                if iso and iso != 'XX'
            }
        return NameTransformer._ISO_TO_FLAG

    @staticmethod
    def _resolve_saved_country(proxy: dict) -> Optional[dict]:
        """Prefer saved/tested country info when region metadata exists."""
        if not isinstance(proxy, dict):
            return None

        region = proxy.get('region', {})
        if not isinstance(region, dict):
            return None

        country_code = str(region.get('country_code') or '').upper()
        country = str(region.get('country') or '').strip()
        flag = str(region.get('flag') or '').strip()

        if country_code and country_code != 'XX':
            flag = flag or NameTransformer._get_iso_to_flag().get(country_code, '')
            country = NameTransformer.ISO_TO_COUNTRY.get(country_code, country or country_code)
        elif flag:
            country_code = NameTransformer.FLAG_TO_ISO.get(flag, '')
            if country_code and country_code != 'XX':
                country = NameTransformer.ISO_TO_COUNTRY.get(country_code, country or country_code)

        if not country_code and not flag:
            return None

        return {
            'country_code': country_code or 'XX',
            'country': country or NameTransformer.ISO_TO_COUNTRY.get(country_code or 'XX', '未知'),
            'flag': flag or '🔰'
        }
    
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

        # Priority 4: Fall back to shared country detection for broader ISO/city coverage.
        try:
            from services.country_data import detect_country

            detected = detect_country(name)
            if detected and detected.get('flag'):
                return detected['flag']
        except Exception as e:
            logger.debug("Fallback country detection failed for %s: %s", name, e)
        
        return '🔰'
    
    # Flag to ISO code mapping (complete world coverage)
    FLAG_TO_ISO = {
        '🇦🇩': 'AD', '🇦🇪': 'AE', '🇦🇫': 'AF', '🇦🇬': 'AG', '🇦🇮': 'AI',
        '🇦🇱': 'AL', '🇦🇲': 'AM', '🇦🇴': 'AO', '🇦🇶': 'AQ', '🇦🇷': 'AR',
        '🇦🇸': 'AS', '🇦🇹': 'AT', '🇦🇺': 'AU', '🇦🇼': 'AW', '🇦🇽': 'AX',
        '🇦🇿': 'AZ', '🇧🇦': 'BA', '🇧🇧': 'BB', '🇧🇩': 'BD', '🇧🇪': 'BE',
        '🇧🇫': 'BF', '🇧🇬': 'BG', '🇧🇭': 'BH', '🇧🇮': 'BI', '🇧🇯': 'BJ',
        '🇧🇱': 'BL', '🇧🇲': 'BM', '🇧🇳': 'BN', '🇧🇴': 'BO', '🇧🇶': 'BQ',
        '🇧🇷': 'BR', '🇧🇸': 'BS', '🇧🇹': 'BT', '🇧🇼': 'BW', '🇧🇾': 'BY',
        '🇧🇿': 'BZ', '🇨🇦': 'CA', '🇨🇨': 'CC', '🇨🇩': 'CD', '🇨🇫': 'CF',
        '🇨🇬': 'CG', '🇨🇭': 'CH', '🇨🇮': 'CI', '🇨🇰': 'CK', '🇨🇱': 'CL',
        '🇨🇲': 'CM', '🇨🇳': 'CN', '🇨🇴': 'CO', '🇨🇷': 'CR', '🇨🇺': 'CU',
        '🇨🇻': 'CV', '🇨🇼': 'CW', '🇨🇽': 'CX', '🇨🇾': 'CY', '🇨🇿': 'CZ',
        '🇩🇪': 'DE', '🇩🇯': 'DJ', '🇩🇰': 'DK', '🇩🇲': 'DM', '🇩🇴': 'DO',
        '🇩🇿': 'DZ', '🇪🇨': 'EC', '🇪🇪': 'EE', '🇪🇬': 'EG', '🇪🇭': 'EH',
        '🇪🇷': 'ER', '🇪🇸': 'ES', '🇪🇹': 'ET', '🇫🇮': 'FI', '🇫🇯': 'FJ',
        '🇫🇰': 'FK', '🇫🇲': 'FM', '🇫🇴': 'FO', '🇫🇷': 'FR', '🇬🇦': 'GA',
        '🇬🇧': 'GB', '🇬🇩': 'GD', '🇬🇪': 'GE', '🇬🇫': 'GF', '🇬🇬': 'GG',
        '🇬🇭': 'GH', '🇬🇮': 'GI', '🇬🇱': 'GL', '🇬🇲': 'GM', '🇬🇳': 'GN',
        '🇬🇵': 'GP', '🇬🇶': 'GQ', '🇬🇷': 'GR', '🇬🇸': 'GS', '🇬🇹': 'GT',
        '🇬🇺': 'GU', '🇬🇼': 'GW', '🇬🇾': 'GY', '🇭🇰': 'HK', '🇭🇲': 'HM',
        '🇭🇳': 'HN', '🇭🇷': 'HR', '🇭🇹': 'HT', '🇭🇺': 'HU', '🇮🇩': 'ID',
        '🇮🇪': 'IE', '🇮🇱': 'IL', '🇮🇲': 'IM', '🇮🇳': 'IN', '🇮🇴': 'IO',
        '🇮🇶': 'IQ', '🇮🇷': 'IR', '🇮🇸': 'IS', '🇮🇹': 'IT', '🇯🇪': 'JE',
        '🇯🇲': 'JM', '🇯🇴': 'JO', '🇯🇵': 'JP', '🇰🇪': 'KE', '🇰🇬': 'KG',
        '🇰🇭': 'KH', '🇰🇮': 'KI', '🇰🇲': 'KM', '🇰🇳': 'KN', '🇰🇵': 'KP',
        '🇰🇷': 'KR', '🇰🇼': 'KW', '🇰🇾': 'KY', '🇰🇿': 'KZ', '🇱🇦': 'LA',
        '🇱🇧': 'LB', '🇱🇨': 'LC', '🇱🇮': 'LI', '🇱🇰': 'LK', '🇱🇷': 'LR',
        '🇱🇸': 'LS', '🇱🇹': 'LT', '🇱🇺': 'LU', '🇱🇻': 'LV', '🇱🇾': 'LY',
        '🇲🇦': 'MA', '🇲🇨': 'MC', '🇲🇩': 'MD', '🇲🇪': 'ME', '🇲🇫': 'MF',
        '🇲🇬': 'MG', '🇲🇭': 'MH', '🇲🇰': 'MK', '🇲🇱': 'ML', '🇲🇲': 'MM',
        '🇲🇳': 'MN', '🇲🇴': 'MO', '🇲🇵': 'MP', '🇲🇶': 'MQ', '🇲🇷': 'MR',
        '🇲🇸': 'MS', '🇲🇹': 'MT', '🇲🇺': 'MU', '🇲🇻': 'MV', '🇲🇼': 'MW',
        '🇲🇽': 'MX', '🇲🇾': 'MY', '🇲🇿': 'MZ', '🇳🇦': 'NA', '🇳🇨': 'NC',
        '🇳🇪': 'NE', '🇳🇫': 'NF', '🇳🇬': 'NG', '🇳🇮': 'NI', '🇳🇱': 'NL',
        '🇳🇴': 'NO', '🇳🇵': 'NP', '🇳🇷': 'NR', '🇳🇺': 'NU', '🇳🇿': 'NZ',
        '🇴🇲': 'OM', '🇵🇦': 'PA', '🇵🇪': 'PE', '🇵🇫': 'PF', '🇵🇬': 'PG',
        '🇵🇭': 'PH', '🇵🇰': 'PK', '🇵🇱': 'PL', '🇵🇲': 'PM', '🇵🇳': 'PN',
        '🇵🇷': 'PR', '🇵🇸': 'PS', '🇵🇹': 'PT', '🇵🇼': 'PW', '🇵🇾': 'PY',
        '🇶🇦': 'QA', '🇷🇪': 'RE', '🇷🇴': 'RO', '🇷🇸': 'RS', '🇷🇺': 'RU',
        '🇷🇼': 'RW', '🇸🇦': 'SA', '🇸🇧': 'SB', '🇸🇨': 'SC', '🇸🇩': 'SD',
        '🇸🇪': 'SE', '🇸🇬': 'SG', '🇸🇭': 'SH', '🇸🇮': 'SI', '🇸🇯': 'SJ',
        '🇸🇰': 'SK', '🇸🇱': 'SL', '🇸🇲': 'SM', '🇸🇳': 'SN', '🇸🇴': 'SO',
        '🇸🇷': 'SR', '🇸🇸': 'SS', '🇸🇹': 'ST', '🇸🇻': 'SV', '🇸🇽': 'SX',
        '🇸🇾': 'SY', '🇸🇿': 'SZ', '🇹🇨': 'TC', '🇹🇩': 'TD', '🇹🇫': 'TF',
        '🇹🇬': 'TG', '🇹🇭': 'TH', '🇹🇯': 'TJ', '🇹🇰': 'TK', '🇹🇱': 'TL',
        '🇹🇲': 'TM', '🇹🇳': 'TN', '🇹🇴': 'TO', '🇹🇷': 'TR', '🇹🇹': 'TT',
        '🇹🇻': 'TV', '🇹🇼': 'TW', '🇹🇿': 'TZ', '🇺🇦': 'UA', '🇺🇬': 'UG',
        '🇺🇲': 'UM', '🇺🇸': 'US', '🇺🇾': 'UY', '🇺🇿': 'UZ', '🇻🇦': 'VA',
        '🇻🇨': 'VC', '🇻🇪': 'VE', '🇻🇬': 'VG', '🇻🇮': 'VI', '🇻🇳': 'VN',
        '🇻🇺': 'VU', '🇼🇫': 'WF', '🇼🇸': 'WS', '🇽🇰': 'XK', '🇾🇪': 'YE',
        '🇾🇹': 'YT', '🇿🇦': 'ZA', '🇿🇲': 'ZM', '🇿🇼': 'ZW',
        '🔰': 'XX', '🌏': 'XX', '🌍': 'XX', '🌎': 'XX', '🏳️': 'XX',
    }
    
    # ISO code to country name mapping (complete world coverage)
    ISO_TO_COUNTRY = {
        'AD': '安道尔', 'AE': '阿联酋', 'AF': '阿富汗', 'AG': '安提瓜和巴布达',
        'AI': '安圭拉', 'AL': '阿尔巴尼亚', 'AM': '亚美尼亚', 'AO': '安哥拉',
        'AQ': '南极洲', 'AR': '阿根廷', 'AS': '美属萨摩亚', 'AT': '奥地利',
        'AU': '澳大利亚', 'AW': '阿鲁巴', 'AX': '奥兰群岛', 'AZ': '阿塞拜疆',
        'BA': '波黑', 'BB': '巴巴多斯', 'BD': '孟加拉国', 'BE': '比利时',
        'BF': '布基纳法索', 'BG': '保加利亚', 'BH': '巴林', 'BI': '布隆迪',
        'BJ': '贝宁', 'BL': '圣巴泰勒米', 'BM': '百慕大', 'BN': '文莱',
        'BO': '玻利维亚', 'BQ': '博内尔', 'BR': '巴西', 'BS': '巴哈马',
        'BT': '不丹', 'BW': '博茨瓦纳', 'BY': '白俄罗斯', 'BZ': '伯利兹',
        'CA': '加拿大', 'CC': '科科斯群岛', 'CD': '刚果(金)', 'CF': '中非',
        'CG': '刚果(布)', 'CH': '瑞士', 'CI': '科特迪瓦', 'CK': '库克群岛',
        'CL': '智利', 'CM': '喀麦隆', 'CN': '中国大陆', 'CO': '哥伦比亚',
        'CR': '哥斯达黎加', 'CU': '古巴', 'CV': '佛得角', 'CW': '库拉索',
        'CX': '圣诞岛', 'CY': '塞浦路斯', 'CZ': '捷克',
        'DE': '德国', 'DJ': '吉布提', 'DK': '丹麦', 'DM': '多米尼克',
        'DO': '多米尼加', 'DZ': '阿尔及利亚',
        'EC': '厄瓜多尔', 'EE': '爱沙尼亚', 'EG': '埃及', 'EH': '西撒哈拉',
        'ER': '厄立特里亚', 'ES': '西班牙', 'ET': '埃塞俄比亚',
        'FI': '芬兰', 'FJ': '斐济', 'FK': '福克兰群岛', 'FM': '密克罗尼西亚',
        'FO': '法罗群岛', 'FR': '法国',
        'GA': '加蓬', 'GB': '英国', 'GD': '格林纳达', 'GE': '格鲁吉亚',
        'GF': '法属圭亚那', 'GG': '根西岛', 'GH': '加纳', 'GI': '直布罗陀',
        'GL': '格陵兰', 'GM': '冈比亚', 'GN': '几内亚', 'GP': '瓜德罗普',
        'GQ': '赤道几内亚', 'GR': '希腊', 'GS': '南乔治亚和南桑威奇群岛',
        'GT': '危地马拉', 'GU': '关岛', 'GW': '几内亚比绍', 'GY': '圭亚那',
        'HK': '中国香港', 'HM': '赫德岛和麦克唐纳群岛', 'HN': '洪都拉斯',
        'HR': '克罗地亚', 'HT': '海地', 'HU': '匈牙利',
        'ID': '印尼', 'IE': '爱尔兰', 'IL': '以色列', 'IM': '马恩岛',
        'IN': '印度', 'IO': '英属印度洋领地', 'IQ': '伊拉克', 'IR': '伊朗',
        'IS': '冰岛', 'IT': '意大利',
        'JE': '泽西岛', 'JM': '牙买加', 'JO': '约旦', 'JP': '日本',
        'KE': '肯尼亚', 'KG': '吉尔吉斯斯坦', 'KH': '柬埔寨', 'KI': '基里巴斯',
        'KM': '科摩罗', 'KN': '圣基茨和尼维斯', 'KP': '朝鲜', 'KR': '韩国',
        'KW': '科威特', 'KY': '开曼群岛', 'KZ': '哈萨克斯坦',
        'LA': '老挝', 'LB': '黎巴嫩', 'LC': '圣卢西亚', 'LI': '列支敦士登',
        'LK': '斯里兰卡', 'LR': '利比里亚', 'LS': '莱索托', 'LT': '立陶宛',
        'LU': '卢森堡', 'LV': '拉脱维亚', 'LY': '利比亚',
        'MA': '摩洛哥', 'MC': '摩纳哥', 'MD': '摩尔多瓦', 'ME': '黑山',
        'MF': '法属圣马丁', 'MG': '马达加斯加', 'MH': '马绍尔群岛',
        'MK': '北马其顿', 'ML': '马里', 'MM': '缅甸', 'MN': '蒙古',
        'MO': '中国澳门', 'MP': '北马里亚纳群岛', 'MQ': '马提尼克',
        'MR': '毛里塔尼亚', 'MS': '蒙特塞拉特', 'MT': '马耳他', 'MU': '毛里求斯',
        'MV': '马尔代夫', 'MW': '马拉维', 'MX': '墨西哥', 'MY': '马来西亚',
        'MZ': '莫桑比克',
        'NA': '纳米比亚', 'NC': '新喀里多尼亚', 'NE': '尼日尔', 'NF': '诺福克岛',
        'NG': '尼日利亚', 'NI': '尼加拉瓜', 'NL': '荷兰', 'NO': '挪威',
        'NP': '尼泊尔', 'NR': '瑙鲁', 'NU': '纽埃', 'NZ': '新西兰',
        'OM': '阿曼',
        'PA': '巴拿马', 'PE': '秘鲁', 'PF': '法属波利尼西亚', 'PG': '巴布亚新几内亚',
        'PH': '菲律宾', 'PK': '巴基斯坦', 'PL': '波兰', 'PM': '圣皮埃尔和密克隆',
        'PN': '皮特凯恩群岛', 'PR': '波多黎各', 'PS': '巴勒斯坦', 'PT': '葡萄牙',
        'PW': '帕劳', 'PY': '巴拉圭',
        'QA': '卡塔尔',
        'RE': '留尼汪', 'RO': '罗马尼亚', 'RS': '塞尔维亚', 'RU': '俄罗斯',
        'RW': '卢旺达',
        'SA': '沙特阿拉伯', 'SB': '所罗门群岛', 'SC': '塞舌尔', 'SD': '苏丹',
        'SE': '瑞典', 'SG': '新加坡', 'SH': '圣赫勒拿', 'SI': '斯洛文尼亚',
        'SJ': '斯瓦尔巴和扬马延', 'SK': '斯洛伐克', 'SL': '塞拉利昂',
        'SM': '圣马力诺', 'SN': '塞内加尔', 'SO': '索马里', 'SR': '苏里南',
        'SS': '南苏丹', 'ST': '圣多美和普林西比', 'SV': '萨尔瓦多',
        'SX': '荷属圣马丁', 'SY': '叙利亚', 'SZ': '斯威士兰',
        'TC': '特克斯和凯科斯群岛', 'TD': '乍得', 'TF': '法属南部领地',
        'TG': '多哥', 'TH': '泰国', 'TJ': '塔吉克斯坦', 'TK': '托克劳',
        'TL': '东帝汶', 'TM': '土库曼斯坦', 'TN': '突尼斯', 'TO': '汤加',
        'TR': '土耳其', 'TT': '特立尼达和多巴哥', 'TV': '图瓦卢',
        'TW': '中国台湾', 'TZ': '坦桑尼亚',
        'UA': '乌克兰', 'UG': '乌干达', 'UM': '美国本土外小岛屿',
        'US': '美国', 'UY': '乌拉圭', 'UZ': '乌兹别克斯坦',
        'VA': '梵蒂冈', 'VC': '圣文森特和格林纳丁斯', 'VE': '委内瑞拉',
        'VG': '英属维尔京群岛', 'VI': '美属维尔京群岛', 'VN': '越南',
        'VU': '瓦努阿图',
        'WF': '瓦利斯和富图纳', 'WS': '萨摩亚',
        'XK': '科索沃',
        'YE': '也门', 'YT': '马约特',
        'ZA': '南非', 'ZM': '赞比亚', 'ZW': '津巴布韦',
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
        
        saved_country = NameTransformer._resolve_saved_country(proxy)
        flag = (saved_country or {}).get('flag') or NameTransformer.identify_flag(original_name, server)
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
        country_code = (saved_country or {}).get('country_code') or NameTransformer.FLAG_TO_ISO.get(flag, 'XX')
        country_name = (saved_country or {}).get('country') or NameTransformer.ISO_TO_COUNTRY.get(country_code, 'Unknown')
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
