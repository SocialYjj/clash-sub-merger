"""
GeoIP Service Module
Provides IP geolocation functionality using online APIs.
"""

import os
import re
import time
import json
import unicodedata
import aiohttp
import asyncio
import threading
from typing import Optional, Dict
from functools import lru_cache
from logger_config import get_logger

# Setup logger
logger = get_logger(__name__)

# Persistent cache configuration
GEOIP_CACHE_FILE = os.path.join(os.environ.get('DATA_DIR', 'data'), 'geoip_cache.json')
GEOIP_CACHE_TTL = 7 * 24 * 3600  # 7 days in seconds

# Traditional to Simplified Chinese converter
try:
    from opencc import OpenCC
    _t2s_converter = OpenCC('t2s')  # Traditional to Simplified
    def convert_to_simplified(text: str) -> str:
        """Convert Traditional Chinese to Simplified Chinese"""
        if not text:
            return text
        return _t2s_converter.convert(text)
except ImportError:
    def convert_to_simplified(text: str) -> str:
        """Fallback: return text as-is if opencc not available"""
        return text

# City name translation mapping (English/Romanized/Traditional -> Simplified Chinese)
CITY_TRANSLATIONS = {
    # Hong Kong
    'Tseung Kwan O': '将军澳',
    'Kowloon City': '九龙城',
    'Kwun Tong': '观塘',
    'Sha Tin': '沙田',
    'Tsuen Wan': '荃湾',
    'Yuen Long': '元朗',
    'Tai Po': '大埔',
    'Tuen Mun': '屯门',
    'Sai Kung': '西贡',
    'North': '北区',
    'Central and Western': '中西区',
    'Wan Chai': '湾仔',
    'Eastern': '东区',
    'Southern': '南区',
    'Yau Tsim Mong': '油尖旺',
    'Sham Shui Po': '深水埗',
    'Wong Tai Sin': '黄大仙',
    'Kwai Tsing': '葵青',
    'Islands': '离岛',
    'Ha Kwai Chung': '下葵涌',
    'Hong Kong': '香港',
    'Kowloon': '九龙',
    'New Territories': '新界',
    'Causeway Bay': '铜锣湾',
    'Mong Kok': '旺角',
    'Tsim Sha Tsui': '尖沙咀',
    'Aberdeen': '香港仔',
    'Stanley': '赤柱',
    'Repulse Bay': '浅水湾',
    'Lantau Island': '大屿山',
    'Cheung Chau': '长洲',
    'Lamma Island': '南丫岛',
    # Japan
    'Roppongi': '六本木',
    'Shibuya': '涩谷',
    'Shinjuku': '新宿',
    'Ikebukuro': '池袋',
    'Ginza': '银座',
    'Akihabara': '秋叶原',
    'Ueno': '上野',
    'Asakusa': '浅草',
    'Odaiba': '台场',
    'Shinagawa': '品川',
    'Meguro': '目黑',
    'Minato': '港区',
    'Chiyoda': '千代田',
    'Chuo': '中央区',
    'Taito': '台东',
    'Sumida': '墨田',
    'Koto': '江东',
    'Setagaya': '世田谷',
    'Nakano': '中野',
    'Suginami': '杉并',
    'Toshima': '丰岛',
    'Kita': '北区',
    'Arakawa': '荒川',
    'Itabashi': '板桥',
    'Nerima': '练马',
    'Adachi': '足立',
    'Katsushika': '葛饰',
    'Edogawa': '江户川',
    'Osaka': '大阪',
    'Kyoto': '京都',
    'Yokohama': '横滨',
    'Nagoya': '名古屋',
    'Sapporo': '札幌',
    'Fukuoka': '福冈',
    'Kobe': '神户',
    'Kawasaki': '川崎',
    'Hiroshima': '广岛',
    'Sendai': '仙台',
    'Tokyo': '东京',
    # Japan - More cities
    'Asagaya': '阿佐谷',
    'Asagaya-minami': '阿佐谷南',
    'Togoshi': '户越',
    'Nishi-Shinjuku': '西新宿',
    'Higashi-Shinjuku': '东新宿',
    'Ota': '大田',
    'Bunkyo': '文京',
    'Shibuya-ku': '涩谷区',
    'Shinjuku-ku': '新宿区',
    'Minato-ku': '港区',
    'Chiyoda-ku': '千代田区',
    'Chuo-ku': '中央区',
    'Shinagawa-ku': '品川区',
    'Meguro-ku': '目黑区',
    'Ota-ku': '大田区',
    'Setagaya-ku': '世田谷区',
    'Nakano-ku': '中野区',
    'Suginami-ku': '杉并区',
    'Toshima-ku': '丰岛区',
    'Kita-ku': '北区',
    'Arakawa-ku': '荒川区',
    'Itabashi-ku': '板桥区',
    'Nerima-ku': '练马区',
    'Adachi-ku': '足立区',
    'Katsushika-ku': '葛饰区',
    'Edogawa-ku': '江户川区',
    'Taito-ku': '台东区',
    'Sumida-ku': '墨田区',
    'Koto-ku': '江东区',
    'Bunkyo-ku': '文京区',
    'Naha': '那霸',
    'Okinawa': '冲绳',
    'Chiba': '千叶',
    'Saitama': '埼玉',
    'Niigata': '新潟',
    'Shizuoka': '静冈',
    'Hamamatsu': '滨松',
    'Kanazawa': '金泽',
    'Okayama': '冈山',
    'Kumamoto': '熊本',
    'Kagoshima': '鹿儿岛',
    'Nagasaki': '长崎',
    'Matsuyama': '松山',
    'Takamatsu': '高松',
    'Nara': '奈良',
    'Wakayama': '和歌山',
    'Otsu': '大津',
    'Gifu': '岐阜',
    'Nagano': '长野',
    'Toyama': '富山',
    'Fukui': '福井',
    'Mito': '水户',
    'Utsunomiya': '宇都宫',
    'Maebashi': '前桥',
    'Kofu': '甲府',
    'Tsu': '津',
    'Tokushima': '德岛',
    'Kochi': '高知',
    'Saga': '佐贺',
    'Oita': '大分',
    'Miyazaki': '宫崎',
    'Yamagata': '山形',
    'Morioka': '盛冈',
    'Akita': '秋田',
    'Aomori': '青森',
    'Hakodate': '函馆',
    'Asahikawa': '旭川',
    'Kushiro': '釧路',
    'Obihiro': '带广',
    # Taiwan (Traditional -> Simplified)
    'Taipei': '台北',
    'Kaohsiung': '高雄',
    'Taichung': '台中',
    'Tainan': '台南',
    'Hsinchu': '新竹',
    'Taoyuan': '桃园',
    'Keelung': '基隆',
    '彰化': '彰化',
    '臺北': '台北',
    '臺中': '台中',
    '臺南': '台南',
    '高雄': '高雄',
    '新竹': '新竹',
    '桃園': '桃园',
    '基隆': '基隆',
    'Changhua': '彰化',
    'Zhanghua': '彰化',
    'Hualien': '花莲',
    'Yilan': '宜兰',
    'Pingtung': '屏东',
    'Nantou': '南投',
    'Yunlin': '云林',
    'Chiayi': '嘉义',
    'Miaoli': '苗栗',
    'Toufen': '头份',
    'Toufen Town': '头份',
    'Toufen City': '头份',
    'Zhubei': '竹北',
    'Zhubei City': '竹北',
    'Banqiao': '板桥',
    'Sanchong': '三重',
    'Zhonghe': '中和',
    'Xinzhuang': '新庄',
    'Tucheng': '土城',
    'Luzhou': '芦洲',
    # Singapore
    'Singapore': '新加坡',
    # South Korea
    'Seoul': '首尔',
    'Busan': '釜山',
    'Incheon': '仁川',
    'Daegu': '大邱',
    'Daejeon': '大田',
    'Gwangju': '光州',
    'Ulsan': '蔚山',
    'Suwon': '水原',
    'Guro-gu': '九老区',
    'Gangnam-gu': '江南区',
    'Songpa-gu': '松坡区',
    'Mapo-gu': '麻浦区',
    'Yeongdeungpo-gu': '永登浦区',
    # USA
    'Los Angeles': '洛杉矶',
    'San Francisco': '旧金山',
    'San Jose': '圣何塞',
    'Seattle': '西雅图',
    'New York': '纽约',
    'Chicago': '芝加哥',
    'Dallas': '达拉斯',
    'Miami': '迈阿密',
    'Atlanta': '亚特兰大',
    'Denver': '丹佛',
    'Phoenix': '凤凰城',
    'Las Vegas': '拉斯维加斯',
    'San Diego': '圣迭戈',
    'Portland': '波特兰',
    'Boston': '波士顿',
    'Washington': '华盛顿',
    'Philadelphia': '费城',
    'Houston': '休斯顿',
    'Austin': '奥斯汀',
    'Silicon Valley': '硅谷',
    'Santa Clara': '圣克拉拉',
    'Tukwila': '塔克维拉',
    'La Puente': '拉蓬特',
    'Secaucus': '锡考克斯',
    'Ashburn': '阿什本',
    'Boydton': '博伊德顿',
    'Richmond': '里士满',
    'Norfolk': '诺福克',
    'Virginia Beach': '弗吉尼亚海滩',
    'Arlington': '阿灵顿',
    'Fremont': '弗里蒙特',
    'Palo Alto': '帕洛阿尔托',
    'San Mateo': '圣马特奥',
    'Mountain View': '山景城',
    'Sunnyvale': '桑尼维尔',
    'Cupertino': '库比蒂诺',
    'Redwood City': '红木城',
    'Newark': '纽瓦克',
    'Jersey City': '泽西城',
    'Buffalo': '布法罗',
    'Clifton': '克利夫顿',
    'Piscataway': '皮斯卡塔韦',
    'Draper': '德雷珀',
    'Salt Lake City': '盐湖城',
    'Sacramento': '萨克拉门托',
    'San Antonio': '圣安东尼奥',
    'Orlando': '奥兰多',
    'Tampa': '坦帕',
    'Charlotte': '夏洛特',
    'Raleigh': '罗利',
    'Nashville': '纳什维尔',
    'Indianapolis': '印第安纳波利斯',
    'Columbus': '哥伦布',
    'Detroit': '底特律',
    'Minneapolis': '明尼阿波利斯',
    'Kansas City': '堪萨斯城',
    'St. Louis': '圣路易斯',
    'New Orleans': '新奥尔良',
    'Oklahoma City': '俄克拉荷马城',
    'Albuquerque': '阿尔伯克基',
    'Tucson': '图森',
    'Honolulu': '檀香山',
    'Anchorage': '安克雷奇',
    # UK
    'London': '伦敦',
    'Manchester': '曼彻斯特',
    'Birmingham': '伯明翰',
    'Liverpool': '利物浦',
    'Edinburgh': '爱丁堡',
    'Glasgow': '格拉斯哥',
    'Leeds': '利兹',
    'Sheffield': '谢菲尔德',
    'Bristol': '布里斯托尔',
    'Newcastle': '纽卡斯尔',
    'Nottingham': '诺丁汉',
    'Southampton': '南安普顿',
    'Cambridge': '剑桥',
    'Oxford': '牛津',
    'Cardiff': '加的夫',
    'Belfast': '贝尔法斯特',
    'Abbey Wood': '阿比伍德',
    # Germany
    'Frankfurt': '法兰克福',
    'Berlin': '柏林',
    'Munich': '慕尼黑',
    'Hamburg': '汉堡',
    'Cologne': '科隆',
    'Dusseldorf': '杜塞尔多夫',
    'Frankfurt am Main': '法兰克福',
    'Nuremberg': '纽伦堡',
    'Stuttgart': '斯图加特',
    'Hanover': '汉诺威',
    'Leipzig': '莱比锡',
    'Dresden': '德累斯顿',
    'Bonn': '波恩',
    'Essen': '埃森',
    'Dortmund': '多特蒙德',
    'Bremen': '不来梅',
    # France
    'Paris': '巴黎',
    'Marseille': '马赛',
    'Lyon': '里昂',
    # Netherlands
    'Amsterdam': '阿姆斯特丹',
    'Rotterdam': '鹿特丹',
    # India
    'Mumbai': '孟买',
    'Bengaluru': '班加罗尔',
    'Bangalore': '班加罗尔',
    'Delhi': '德里',
    'New Delhi': '新德里',
    'Chennai': '金奈',
    'Hyderabad': '海得拉巴',
    'Kolkata': '加尔各答',
    'Pune': '浦那',
    'Bashettihalli': '巴谢蒂哈利',
    'Bāshettihalli': '巴谢蒂哈利',
    'Ahmedabad': '艾哈迈达巴德',
    'Jaipur': '斋浦尔',
    'Lucknow': '勒克瑙',
    'Kanpur': '坎普尔',
    'Nagpur': '那格浦尔',
    'Indore': '印多尔',
    'Thane': '塔那',
    'Bhopal': '博帕尔',
    'Visakhapatnam': '维沙卡帕特南',
    'Patna': '巴特那',
    'Vadodara': '瓦多达拉',
    'Ghaziabad': '加济阿巴德',
    'Ludhiana': '卢迪亚纳',
    'Agra': '阿格拉',
    'Nashik': '纳西克',
    'Faridabad': '法里达巴德',
    'Meerut': '密拉特',
    'Rajkot': '拉杰果德',
    'Varanasi': '瓦拉纳西',
    'Srinagar': '斯利那加',
    'Aurangabad': '奥兰加巴德',
    'Dhanbad': '丹巴德',
    'Amritsar': '阿姆利则',
    'Navi Mumbai': '新孟买',
    'Allahabad': '阿拉哈巴德',
    'Ranchi': '兰契',
    'Howrah': '豪拉',
    'Coimbatore': '哥印拜陀',
    'Jabalpur': '贾巴尔普尔',
    'Gwalior': '瓜廖尔',
    'Vijayawada': '维杰亚瓦达',
    'Jodhpur': '焦特布尔',
    'Madurai': '马杜赖',
    'Raipur': '赖布尔',
    'Kota': '科塔',
    'Guwahati': '古瓦哈提',
    'Chandigarh': '昌迪加尔',
    'Solapur': '索拉普尔',
    'Hubli': '胡布利',
    'Tiruchirappalli': '蒂鲁吉拉帕利',
    'Bareilly': '巴雷利',
    'Mysore': '迈索尔',
    'Tiruppur': '蒂鲁普尔',
    'Gurgaon': '古尔冈',
    'Aligarh': '阿里格尔',
    'Jalandhar': '贾朗达尔',
    'Bhubaneswar': '布巴内斯瓦尔',
    'Salem': '塞勒姆',
    'Warangal': '瓦朗加尔',
    'Guntur': '贡土尔',
    'Bhiwandi': '比万迪',
    'Saharanpur': '萨哈兰普尔',
    'Gorakhpur': '戈勒克布尔',
    'Bikaner': '比卡内尔',
    'Amravati': '阿姆拉瓦蒂',
    'Noida': '诺伊达',
    'Jamshedpur': '贾姆谢德布尔',
    'Bhilai': '比莱',
    'Cuttack': '卡塔克',
    'Firozabad': '费罗扎巴德',
    'Kochi': '科钦',
    'Nellore': '内洛尔',
    'Bhavnagar': '巴夫那加尔',
    'Dehradun': '德拉敦',
    'Durgapur': '杜尔加布尔',
    'Asansol': '阿桑索尔',
    'Rourkela': '鲁尔克拉',
    'Nanded': '南德德',
    'Kolhapur': '科尔哈普尔',
    'Ajmer': '阿杰梅尔',
    'Akola': '阿科拉',
    'Gulbarga': '古尔伯加',
    'Jamnagar': '贾姆讷格尔',
    'Ujjain': '乌贾因',
    'Loni': '洛尼',
    'Siliguri': '西里古里',
    'Jhansi': '占西',
    'Ulhasnagar': '乌尔哈斯纳加尔',
    'Jammu': '查谟',
    'Sangli-Miraj & Kupwad': '桑格利',
    'Mangalore': '门格洛尔',
    'Erode': '埃罗德',
    'Belgaum': '贝尔高姆',
    'Ambattur': '安巴图尔',
    'Tirunelveli': '蒂鲁内尔维利',
    'Malegaon': '马莱冈',
    'Gaya': '伽耶',
    'Jalgaon': '贾尔冈',
    'Udaipur': '乌代布尔',
    'Maheshtala': '马赫什塔拉',
    # Other
    'Moscow': '莫斯科',
    'Sydney': '悉尼',
    'Melbourne': '墨尔本',
    'Toronto': '多伦多',
    'Vancouver': '温哥华',
    'Bangkok': '曼谷',
    'Dubai': '迪拜',
    'Istanbul': '伊斯坦布尔',
    'Kuala Lumpur': '吉隆坡',
    'Jakarta': '雅加达',
    'Manila': '马尼拉',
    'Ho Chi Minh City': '胡志明市',
    'Hanoi': '河内',
    # Ukraine
    'Kyiv': '基辅',
    'Kiev': '基辅',
    'Kharkiv': '哈尔科夫',
    'Odessa': '敖德萨',
    'Dnipro': '第聂伯罗',
    'Donetsk': '顿涅茨克',
    'Zaporizhzhia': '扎波罗热',
    'Lviv': '利沃夫',
    'Kryvyi Rih': '克里沃伊罗格',
    'Mykolaiv': '尼古拉耶夫',
    'Mariupol': '马里乌波尔',
    'Luhansk': '卢甘斯克',
    'Vinnytsia': '文尼察',
    'Makiivka': '马基耶夫卡',
    'Simferopol': '辛菲罗波尔',
    'Sevastopol': '塞瓦斯托波尔',
    'Kherson': '赫尔松',
    'Poltava': '波尔塔瓦',
    'Chernihiv': '切尔尼戈夫',
    'Cherkasy': '切尔卡瑟',
    'Sumy': '苏梅',
    'Zhytomyr': '日托米尔',
    'Rivne': '罗夫诺',
    'Ternopil': '捷尔诺波尔',
    'Ivano-Frankivsk': '伊万诺-弗兰科夫斯克',
    'Lutsk': '卢茨克',
    'Uzhhorod': '乌日霍罗德',
    # Spain
    'Madrid': '马德里',
    'Barcelona': '巴塞罗那',
    'Valencia': '瓦伦西亚',
    'Seville': '塞维利亚',
    'Zaragoza': '萨拉戈萨',
    'Malaga': '马拉加',
    'Murcia': '穆尔西亚',
    'Palma': '帕尔马',
    'Las Palmas': '拉斯帕尔马斯',
    'Bilbao': '毕尔巴鄂',
    'Alicante': '阿利坎特',
    'Cordoba': '科尔多瓦',
    'Valladolid': '巴利亚多利德',
    'Vigo': '维戈',
    'Gijon': '希洪',
    'Hospitalet': '奥斯皮塔莱特',
    'Vitoria-Gasteiz': '维多利亚',
    'Granada': '格拉纳达',
    'Elche': '埃尔切',
    'Oviedo': '奥维耶多',
    'Badalona': '巴达洛纳',
    'Cartagena': '卡塔赫纳',
    'Terrassa': '特拉萨',
    'Jerez de la Frontera': '赫雷斯',
    'Sabadell': '萨瓦德尔',
    'Mostoles': '莫斯托莱斯',
    'Santa Cruz de Tenerife': '圣克鲁斯-德特内里费',
    'Pamplona': '潘普洛纳',
    'Almeria': '阿尔梅里亚',
    'Alcobendas': '阿尔科文达斯',
    # Nigeria
    'Lagos': '拉各斯',
    'Kano': '卡诺',
    'Ibadan': '伊巴丹',
    'Abuja': '阿布贾',
    'Port Harcourt': '哈科特港',
    'Benin City': '贝宁城',
    'Maiduguri': '迈杜古里',
    'Zaria': '扎里亚',
    'Aba': '阿巴',
    'Jos': '乔斯',
    'Ilorin': '伊洛林',
    'Oyo': '奥约',
    'Enugu': '埃努古',
    'Abeokuta': '阿贝奥库塔',
    'Onitsha': '奥尼查',
    'Warri': '瓦里',
    'Sokoto': '索科托',
    'Calabar': '卡拉巴尔',
    'Katsina': '卡齐纳',
    'Akure': '阿库雷',
    'Bauchi': '包奇',
    'Ebute Ikorodu': '伊科罗杜',
    'Makurdi': '马库尔迪',
    'Minna': '明纳',
    'Effon-Alaiye': '埃丰阿拉伊耶',
    'Ilesa': '伊莱沙',
    'Owo': '奥沃',
    'Uyo': '乌约',
    'Ado-Ekiti': '阿多埃基蒂',
    'Ikeja': '伊凯贾',
    'Kaduna': '卡杜纳',
    # China cities
    'Shenzhen': '深圳',
    'Shanghai': '上海',
    'Beijing': '北京',
    'Guangzhou': '广州',
    'Chengdu': '成都',
    'Hangzhou': '杭州',
    'Wuhan': '武汉',
    'Xian': '西安',
    "Xi'an": '西安',
    'Nanjing': '南京',
    'Tianjin': '天津',
    'Suzhou': '苏州',
    'Chongqing': '重庆',
    'Dongguan': '东莞',
    'Shenyang': '沈阳',
    'Qingdao': '青岛',
    'Zhengzhou': '郑州',
    'Dalian': '大连',
    'Jinan': '济南',
    'Changsha': '长沙',
    'Kunming': '昆明',
    'Harbin': '哈尔滨',
    'Foshan': '佛山',
    'Xiamen': '厦门',
    'Fuzhou': '福州',
    'Ningbo': '宁波',
    'Wuxi': '无锡',
    'Hefei': '合肥',
    'Nanchang': '南昌',
    'Changchun': '长春',
    'Shijiazhuang': '石家庄',
    'Guiyang': '贵阳',
    'Nanning': '南宁',
    'Taiyuan': '太原',
    'Urumqi': '乌鲁木齐',
    'Lanzhou': '兰州',
    'Haikou': '海口',
    'Yinchuan': '银川',
    'Xining': '西宁',
    'Hohhot': '呼和浩特',
    'Lhasa': '拉萨',
    'Zhuhai': '珠海',
    'Zhongshan': '中山',
    'Huizhou': '惠州',
    'Jiangmen': '江门',
    'Shantou': '汕头',
    'Zhanjiang': '湛江',
    'Maoming': '茂名',
    'Yangjiang': '阳江',
    'Shaoguan': '韶关',
    'Meizhou': '梅州',
    'Qingyuan': '清远',
    'Jieyang': '揭阳',
    'Chaozhou': '潮州',
    'Yunfu': '云浮',
    'Heyuan': '河源',
    'Shanwei': '汕尾',
    # Traditional Chinese -> Simplified Chinese
    '臺': '台',
    '國': '国',
    '區': '区',
    '東': '东',
    '車': '车',
    '門': '门',
    '開': '开',
    '關': '关',
    '電': '电',
    '話': '话',
    '網': '网',
    '絡': '络',
    '機': '机',
    '場': '场',
    '塔克維拉': '塔克维拉',
}

CITY_TRANSLATIONS.update({
    'Hacienda Heights': '哈仙达岗',
    'Nürnberg': '纽伦堡',
    'Nurnberg': '纽伦堡',
    'Gangseo-gu': '江西区',
    'Gangseo Gu': '江西区',
    'Montréal': '蒙特利尔',
    'Montreal': '蒙特利尔',
    'Budapest': '布达佩斯',
    'Bexley': '贝克斯利',
    'Stockholm': '斯德哥尔摩',
    'Kwai Chung': '葵涌',
    'Tung Chung': '东涌',
    'Genève': '日内瓦',
    'Geneve': '日内瓦',
    'Geneva': '日内瓦',
    'Kanda-jinbōchō': '神田神保町',
    'Kanda-jinbocho': '神田神保町',
    'Yuanlin': '员林',
    'Orem': '奥勒姆',
    'Beauharnois': '博阿努瓦',
    'Ebara': '荏原',
    'Lauterbourg': '劳特堡',
    'Bursa': '布尔萨',
    'Calais': '加来',
    'Meppel': '梅珀尔',
    'Riga': '里加',
    'Warsaw': '华沙',
    'Brussels': '布鲁塞尔',
    'Vienna': '维也纳',
})

# Country/Region display names (for avoiding "Hong Kong Hong Kong" style duplicates and normalizing names)
REGION_DISPLAY_NAMES = {
    'HK': '中国香港',
    'MO': '中国澳门',
    'TW': '中国台湾',
    'SG': '新加坡',
}

# Country name normalization (GeoIP database name -> preferred display name)
COUNTRY_NAME_NORMALIZE = {
    '俄罗斯联邦': '俄罗斯',
    '大韩民国': '韩国',
    '朝鲜民主主义人民共和国': '朝鲜',
    '阿拉伯联合酋长国': '阿联酋',
    '美利坚合众国': '美国',
    '大不列颠及北爱尔兰联合王国': '英国',
    '荷兰王国': '荷兰',
}

COUNTRY_NAME_NORMALIZE.update({
    'Russian Federation': '俄罗斯',
    'Republic of Korea': '韩国',
    'Korea, Republic of': '韩国',
    'United States': '美国',
    'United States of America': '美国',
    'United Kingdom': '英国',
    'Kingdom of the Netherlands': '荷兰',
    'Türkiye': '土耳其',
    'Latvia': '拉脱维亚',
    'Lithuania': '立陶宛',
    'Estonia': '爱沙尼亚',
})

# Online GeoIP lookup cache (to avoid repeated requests)
_online_geoip_cache: Dict[str, Dict] = {}
_online_geoip_inflight: Dict[str, asyncio.Task] = {}
_online_geoip_semaphore = asyncio.Semaphore(int(os.environ.get('GEOIP_MAX_CONCURRENCY', '8')))
_online_geoip_cache_lock = threading.RLock()
_online_geoip_inflight_lock = asyncio.Lock()
_online_geoip_save_lock = asyncio.Lock()

def load_geoip_cache_from_disk():
    """Load GeoIP cache from disk on startup"""
    global _online_geoip_cache
    try:
        if os.path.exists(GEOIP_CACHE_FILE):
            with open(GEOIP_CACHE_FILE, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            # Filter out expired entries
            current_time = time.time()
            valid_cache = {}
            expired_count = 0
            
            for key, entry in cache_data.items():
                if not isinstance(entry, dict):
                    expired_count += 1
                    continue
                if 'timestamp' in entry:
                    age = current_time - entry['timestamp']
                    if age < GEOIP_CACHE_TTL:
                        valid_cache[key] = entry
                    else:
                        expired_count += 1
                else:
                    # Old format without timestamp, keep it
                    valid_cache[key] = entry
            
            with _online_geoip_cache_lock:
                _online_geoip_cache = valid_cache
            logger.info(f"Loaded {len(valid_cache)} GeoIP cache entries from disk ({expired_count} expired entries removed)")
    except Exception as e:
        logger.warning(f"Failed to load GeoIP cache from disk: {e}")
        with _online_geoip_cache_lock:
            _online_geoip_cache = {}

async def save_geoip_cache_to_disk():
    """Save GeoIP cache to disk with in-process serialization and atomic replace."""
    async with _online_geoip_save_lock:
        try:
            with _online_geoip_cache_lock:
                cache_snapshot = dict(_online_geoip_cache)

            os.makedirs(os.path.dirname(GEOIP_CACHE_FILE), exist_ok=True)
            tmp_file = f"{GEOIP_CACHE_FILE}.tmp"
            with open(tmp_file, 'w', encoding='utf-8') as f:
                json.dump(cache_snapshot, f, ensure_ascii=False, indent=2)
            os.replace(tmp_file, GEOIP_CACHE_FILE)
            logger.debug(f"Saved {len(cache_snapshot)} GeoIP cache entries to disk")
        except Exception as e:
            logger.error(f"Failed to save GeoIP cache to disk: {e}")

# Load cache on module import
load_geoip_cache_from_disk()

# Built-in API definitions
BUILTIN_GEOIP_APIS = [
    {
        "id": "ip-api.com",
        "name": "ip-api.com",
        "limit": "45次/分钟",
        "description": "免费，支持中文，推荐",
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "ipwhois",
        "name": "ipwhois.app",
        "limit": "10,000次/月",
        "description": "免费，支持中文",
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "ipinfo",
        "name": "ipinfo.io",
        "limit": "50,000次/月",
        "description": "免费额度较高",
        "builtin": True,
        "enabled": True,
        "needs_token": True,
    },
]

# Online API configuration
_online_geoip_config: Dict = {
    "ipinfo_token": "",
    "preferred_api": "ip-api.com",
    "custom_apis": [],  # User-defined custom APIs
    "api_settings": {},  # Per-API settings like enabled/disabled
}

def set_online_geoip_config(ipinfo_token: str = None, preferred_api: str = None, 
                            custom_apis: list = None, api_settings: dict = None):
    """Set online GeoIP API configuration"""
    global _online_geoip_config
    if ipinfo_token is not None:
        _online_geoip_config["ipinfo_token"] = ipinfo_token
    if preferred_api is not None:
        _online_geoip_config["preferred_api"] = preferred_api
    if custom_apis is not None:
        _online_geoip_config["custom_apis"] = custom_apis
    if api_settings is not None:
        _online_geoip_config["api_settings"] = api_settings

def get_online_geoip_config() -> Dict:
    """Get current online GeoIP API configuration"""
    return _online_geoip_config.copy()

def get_all_geoip_apis() -> list:
    """Get all available GeoIP APIs (builtin + custom)"""
    apis = []
    api_settings = _online_geoip_config.get("api_settings", {})
    
    # Add builtin APIs
    for api in BUILTIN_GEOIP_APIS:
        api_copy = api.copy()
        # Apply user settings
        if api["id"] in api_settings:
            api_copy.update(api_settings[api["id"]])
        apis.append(api_copy)
    
    # Add custom APIs
    for api in _online_geoip_config.get("custom_apis", []):
        api_copy = api.copy()
        api_copy["builtin"] = False
        # Mask token for security - only indicate if it exists
        if api_copy.get("token"):
            api_copy["has_token"] = True
            api_copy["token"] = ""  # Don't expose actual token
        apis.append(api_copy)
    
    return apis

def add_custom_geoip_api(api_config: dict) -> dict:
    """Add a custom GeoIP API"""
    global _online_geoip_config
    
    # Validate required fields - only name and url are required now
    required = ["name", "url"]
    for field in required:
        if not api_config.get(field):
            raise ValueError(f"Missing required field: {field}")
    
    # Generate ID
    api_id = f"custom_{int(time.time() * 1000)}"
    
    new_api = {
        "id": api_id,
        "name": api_config["name"],
        "url": api_config["url"],  # URL template with {ip} placeholder
        "token": api_config.get("token", ""),  # Optional token/API key
        "limit": api_config.get("limit", ""),  # Optional usage limit display
        "method": api_config.get("method", "GET"),
        "headers": api_config.get("headers", {}),
        "country_code_path": api_config.get("country_code_path", ""),  # JSON path, auto-detected if empty
        "country_name_path": api_config.get("country_name_path", ""),
        "city_path": api_config.get("city_path", ""),
        "success_check": api_config.get("success_check", ""),  # Optional: path to check for success
        "enabled": True,
        "builtin": False,
    }
    
    if "custom_apis" not in _online_geoip_config:
        _online_geoip_config["custom_apis"] = []
    _online_geoip_config["custom_apis"].append(new_api)
    
    return new_api

def update_custom_geoip_api(api_id: str, api_config: dict) -> dict:
    """Update a custom GeoIP API"""
    global _online_geoip_config
    
    custom_apis = _online_geoip_config.get("custom_apis", [])
    for i, api in enumerate(custom_apis):
        if api["id"] == api_id:
            # Update fields
            for key in ["name", "url", "token", "limit", "method", "headers", "country_code_path", 
                       "country_name_path", "city_path", "success_check", "enabled"]:
                if key in api_config:
                    custom_apis[i][key] = api_config[key]
            return custom_apis[i]
    
    raise ValueError(f"API not found: {api_id}")

def delete_custom_geoip_api(api_id: str) -> bool:
    """Delete a custom GeoIP API"""
    global _online_geoip_config
    
    custom_apis = _online_geoip_config.get("custom_apis", [])
    for i, api in enumerate(custom_apis):
        if api["id"] == api_id:
            custom_apis.pop(i)
            return True
    
    return False

def set_api_enabled(api_id: str, enabled: bool):
    """Enable or disable an API"""
    global _online_geoip_config
    
    if "api_settings" not in _online_geoip_config:
        _online_geoip_config["api_settings"] = {}
    
    if api_id not in _online_geoip_config["api_settings"]:
        _online_geoip_config["api_settings"][api_id] = {}
    
    _online_geoip_config["api_settings"][api_id]["enabled"] = enabled

def _get_json_path(data: dict, path: str):
    """Get value from nested dict using dot notation path"""
    if not path:
        return None
    
    keys = path.split(".")
    value = data
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value

async def _lookup_custom_api(ip: str, api_config: dict, timeout: int = 5) -> Optional[Dict]:
    """Lookup using a custom API configuration"""
    try:
        url = api_config["url"].replace("{ip}", ip)
        # Replace {key} or {token} placeholder if present
        token = api_config.get("token", "")
        if token:
            url = url.replace("{key}", token).replace("{token}", token)
        else:
            # Remove empty placeholders
            url = url.replace("{key}", "").replace("{token}", "")
        
        method = api_config.get("method", "GET").upper()
        headers = api_config.get("headers", {})
        
        async with aiohttp.ClientSession() as session:
            if method == "GET":
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
            else:
                async with session.post(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
            
            # Check success condition if specified
            success_check = api_config.get("success_check", "")
            if success_check:
                # Simple check: "field==value" or just "field" (truthy check)
                if "==" in success_check:
                    field, expected = success_check.split("==", 1)
                    actual = _get_json_path(data, field.strip())
                    if str(actual) != expected.strip():
                        return None
                else:
                    if not _get_json_path(data, success_check):
                        return None
            
            # Get field paths, auto-detect if not specified
            country_code_path = api_config.get("country_code_path", "")
            country_name_path = api_config.get("country_name_path", "")
            city_path = api_config.get("city_path", "")
            
            # Auto-detect paths if not specified
            if not country_code_path:
                detected = _auto_detect_json_paths(data)
                if detected:
                    country_code_path = detected.get("country_code_path", "")
                    country_name_path = detected.get("country_name_path", "") or country_name_path
                    city_path = detected.get("city_path", "") or city_path
            
            country_code = _get_json_path(data, country_code_path) or "" if country_code_path else ""
            country_name = _get_json_path(data, country_name_path) or "" if country_name_path else ""
            city = _get_json_path(data, city_path) or "" if city_path else ""
            
            if not country_code:
                return None
            
            return {
                "countryCode": country_code,
                "country": country_name or COUNTRY_NAMES_FROM_CODE.get(country_code, country_code),
                "city": city
            }
    except Exception as e:
        logger.debug("Custom API lookup error for %s: %s", ip, e)
        return None


def _auto_detect_json_paths(data: dict) -> Optional[Dict]:
    """Auto-detect common JSON field paths for GeoIP data"""
    if not isinstance(data, dict):
        return None
    
    result = {}
    
    # Common field names for country code (2-letter ISO code)
    country_code_fields = [
        "countryCode", "country_code", "country_code2", "countrycode", "cc", 
        "country_iso", "iso_code", "iso", "code", "country_code3"
    ]
    
    # Common field names for country name
    country_name_fields = [
        "country", "country_name", "countryName", "nation"
    ]
    
    # Common field names for city
    city_fields = [
        "city", "cityName", "city_name"
    ]
    
    def find_field(fields, data, prefix="", check_2letter=False):
        """Recursively search for field in data"""
        for field in fields:
            if field in data:
                value = data[field]
                # Country code should be 2 or 3 letter string
                if check_2letter:
                    if isinstance(value, str) and 2 <= len(value) <= 3 and value.isupper():
                        return prefix + field if prefix else field
                else:
                    if isinstance(value, str) and value:
                        return prefix + field if prefix else field
        
        # Check nested objects (skip complex nested like currency, time_zone)
        for key, value in data.items():
            if isinstance(value, dict) and key not in ['currency', 'time_zone', 'dst_start', 'dst_end']:
                new_prefix = f"{prefix}{key}." if prefix else f"{key}."
                found = find_field(fields, value, new_prefix, check_2letter)
                if found:
                    return found
        return None
    
    # Find country code (check for 2-3 letter codes)
    code_path = find_field(country_code_fields, data, check_2letter=True)
    if code_path:
        result["country_code_path"] = code_path
    
    # Find country name
    name_path = find_field(country_name_fields, data)
    if name_path:
        result["country_name_path"] = name_path
    
    # Find city
    city_path = find_field(city_fields, data)
    if city_path:
        result["city_path"] = city_path
    
    return result if result else None


async def _lookup_ip_api_com(ip: str, timeout: int = 5) -> Optional[Dict]:
    """Lookup using ip-api.com (free, 45 req/min, supports Chinese)"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,countryCode,city",
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        return {
                            "countryCode": data.get("countryCode", ""),
                            "country": data.get("country", ""),
                            "city": data.get("city", "")
                        }
    except Exception as e:
        logger.debug("ip-api.com lookup error for %s: %s", ip, e)
    return None

async def _lookup_ipwhois(ip: str, timeout: int = 5) -> Optional[Dict]:
    """Lookup using ipwhois.app (free, 10k/month, supports Chinese)"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://ipwhois.app/json/{ip}?lang=zh-CN",
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("success"):
                        country_name = data.get("country", "")
                        # Normalize "Republic of Korea" -> "South Korea"
                        country_name = COUNTRY_NAME_NORMALIZE.get(country_name, country_name)
                        return {
                            "countryCode": data.get("country_code", ""),
                            "country": country_name,
                            "city": data.get("city", "")
                        }
    except Exception as e:
        logger.debug("ipwhois.app lookup error for %s: %s", ip, e)
    return None

async def _lookup_ipinfo(ip: str, timeout: int = 5) -> Optional[Dict]:
    """Lookup using ipinfo.io (free 50k/month with token)"""
    try:
        token = _online_geoip_config.get("ipinfo_token", "")
        url = f"https://ipinfo.io/{ip}/json"
        if token:
            url += f"?token={token}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    country_code = data.get("country", "")
                    city = data.get("city", "")
                    
                    # ipinfo doesn't return country name in Chinese, need to map it
                    country_name = COUNTRY_NAMES_FROM_CODE.get(country_code, country_code)
                    
                    return {
                        "countryCode": country_code,
                        "country": country_name,
                        "city": city
                    }
    except Exception as e:
        logger.debug("ipinfo.io lookup error for %s: %s", ip, e)
    return None

# Country code to Chinese name mapping for ipinfo.io
COUNTRY_NAMES_FROM_CODE = {
    'HK': '中国香港', 'TW': '中国台湾', 'MO': '中国澳门', 'JP': '日本', 'KR': '韩国', 'SG': '新加坡',
    'US': '美国', 'GB': '英国', 'DE': '德国', 'FR': '法国', 'NL': '荷兰',
    'RU': '俄罗斯', 'CA': '加拿大', 'AU': '澳大利亚', 'IN': '印度', 'TR': '土耳其',
    'MY': '马来西亚', 'TH': '泰国', 'VN': '越南', 'ID': '印尼', 'PH': '菲律宾',
    'BR': '巴西', 'AR': '阿根廷', 'MX': '墨西哥', 'ZA': '南非', 'AE': '阿联酋',
    'CN': '中国', 'CY': '塞浦路斯', 'IT': '意大利', 'ES': '西班牙',
    'PT': '葡萄牙', 'GR': '希腊', 'PL': '波兰', 'CZ': '捷克', 'AT': '奥地利',
    'CH': '瑞士', 'SE': '瑞典', 'NO': '挪威', 'FI': '芬兰', 'DK': '丹麦',
    'IE': '爱尔兰', 'BE': '比利时', 'NZ': '新西兰', 'IL': '以色列', 'UA': '乌克兰',
    'BY': '白俄罗斯', 'MD': '摩尔多瓦', 'NG': '尼日利亚', 'AQ': '南极洲',
    'LV': '拉脱维亚', 'LT': '立陶宛', 'EE': '爱沙尼亚', 'HR': '克罗地亚',
    'SI': '斯洛文尼亚', 'SK': '斯洛伐克', 'RO': '罗马尼亚', 'BG': '保加利亚',
    'RS': '塞尔维亚', 'HU': '匈牙利',
}


@lru_cache(maxsize=4096)
def normalize_location_name(value: str) -> str:
    """Normalize accents, punctuation and spaces for robust location matching."""
    if not value:
        return ""

    text = convert_to_simplified(str(value)).strip()
    text = unicodedata.normalize('NFKD', text)
    text = ''.join(ch for ch in text if not unicodedata.combining(ch))
    text = text.replace('’', "'").replace('`', "'").replace('ʻ', "'")
    text = re.sub(r"(?<=\w)'(?=\w)", "", text)
    text = re.sub(r"[-_/·,()]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.casefold().strip()


@lru_cache(maxsize=1)
def _get_city_translation_index() -> Dict[str, str]:
    return {normalize_location_name(src): dst for src, dst in CITY_TRANSLATIONS.items()}


@lru_cache(maxsize=1)
def _get_country_normalize_index() -> Dict[str, str]:
    return {normalize_location_name(src): dst for src, dst in COUNTRY_NAME_NORMALIZE.items()}


def normalize_country_name(country_name: str, iso_code: str = "") -> str:
    """Normalize country names to preferred Simplified Chinese display names."""
    code = (iso_code or "").upper()
    if code and code in COUNTRY_NAMES_FROM_CODE:
        return REGION_DISPLAY_NAMES.get(code, COUNTRY_NAMES_FROM_CODE[code])

    text = convert_to_simplified(country_name or "").strip()
    if not text:
        return code or ""

    direct = COUNTRY_NAME_NORMALIZE.get(text)
    if direct:
        return direct

    normalized = _get_country_normalize_index().get(normalize_location_name(text))
    return normalized or text


def _normalize_geo_result_fields(iso_code: str, country_name: str, city_name: str) -> Dict[str, Optional[str]]:
    """Apply unified country and city normalization to GeoIP results."""
    code = (iso_code or "").upper()
    display_country = normalize_country_name(country_name, code)
    translated_city = translate_city_name(city_name) if city_name else ""

    if translated_city and translated_city in display_country:
        translated_city = None

    return {
        "iso_code": code,
        "country_name": display_country,
        "city": translated_city or None,
        "flag": GeoIPService.iso_to_flag(code),
    }


def _normalize_cached_geo_entry(entry: Dict) -> Dict:
    """Re-normalize cached entries so new mappings apply without clearing cache."""
    normalized = dict(entry)
    normalized.update(_normalize_geo_result_fields(
        entry.get("iso_code", ""),
        entry.get("country_name") or entry.get("country", ""),
        entry.get("city", "")
    ))
    return normalized

async def lookup_ip_online(ip: str, timeout: int = 5, api_id: str = None) -> Optional[Dict]:
    """
    Lookup IP location using online API (ASYNC)
    Default: ip-api.com (45/min), alternatives: ipwhois (10k/month), ipinfo (needs token), or custom APIs

    Args:
        ip: IP address to lookup
        timeout: Request timeout in seconds
        api_id: Specific API to use (optional, uses preferred_api from config if not specified)

    Returns: {"iso_code": "KR", "country_name": "韩国", "city": "首尔", "flag": "🇰🇷"} or None
    """
    global _online_geoip_cache, _online_geoip_inflight

    cache_key = f"{ip}:{api_id or 'default'}"

    def _get_valid_cache_entry():
        with _online_geoip_cache_lock:
            entry = _online_geoip_cache.get(cache_key)
            if not isinstance(entry, dict):
                return False, None

            ts = entry.get('timestamp')
            if ts and (time.time() - ts) < GEOIP_CACHE_TTL:
                if entry.get('_negative'):
                    return True, None
                normalized_entry = _normalize_cached_geo_entry(entry)
                if normalized_entry != entry:
                    _online_geoip_cache[cache_key] = normalized_entry
                return True, normalized_entry

            _online_geoip_cache.pop(cache_key, None)
            return False, None

    # Fast path before taking the lock.
    cache_hit, cached_result = _get_valid_cache_entry()
    if cache_hit:
        return cached_result

    async def _do_lookup():
        target_api = api_id or _online_geoip_config.get("preferred_api", "ip-api.com")

        builtin_api_map = {
            "ip-api.com": _lookup_ip_api_com,
            "ipwhois": _lookup_ipwhois,
            "ipinfo": _lookup_ipinfo,
        }

        raw_data = None

        async with _online_geoip_semaphore:
            if target_api in builtin_api_map:
                raw_data = await builtin_api_map[target_api](ip, timeout)
            else:
                custom_apis = _online_geoip_config.get("custom_apis", [])
                custom_api = next((a for a in custom_apis if a["id"] == target_api), None)
                if custom_api and custom_api.get("enabled", True):
                    raw_data = await _lookup_custom_api(ip, custom_api, timeout)

            if not raw_data and not api_id:
                for api_name, api_func in builtin_api_map.items():
                    if api_name != target_api:
                        api_settings = _online_geoip_config.get("api_settings", {})
                        if api_settings.get(api_name, {}).get("enabled", True):
                            raw_data = await api_func(ip, timeout)
                            if raw_data:
                                break

        if not raw_data:
            return None

        normalized = _normalize_geo_result_fields(
            raw_data.get("countryCode", ""),
            raw_data.get("country", ""),
            raw_data.get("city", "")
        )

        return {
            **normalized,
            "source": "online",
            "timestamp": time.time()
        }

    async with _online_geoip_inflight_lock:
        # Double-check under the lock so cache expiry and task creation are atomic.
        cache_hit, cached_result = _get_valid_cache_entry()
        if cache_hit:
            return cached_result

        task = _online_geoip_inflight.get(cache_key)
        if task is None:
            task = asyncio.create_task(_do_lookup())
            _online_geoip_inflight[cache_key] = task

    try:
        # Shield the shared task so a cancelled client request does not cancel
        # the lookup that other waiters may still be awaiting.
        result = await asyncio.shield(task)
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.warning("Online GeoIP lookup task failed for %s: %s", cache_key, e)
        return None
    finally:
        if task.done():
            async with _online_geoip_inflight_lock:
                if _online_geoip_inflight.get(cache_key) is task:
                    _online_geoip_inflight.pop(cache_key, None)

    with _online_geoip_cache_lock:
        if not result:
            _online_geoip_cache[cache_key] = {"timestamp": time.time(), "_negative": True}
            return None

        _online_geoip_cache[cache_key] = result
        cache_size = len(_online_geoip_cache)

    if cache_size % 10 == 0:
        await save_geoip_cache_to_disk()

    return result

def get_online_geoip_cache_snapshot() -> Dict[str, Dict]:
    """Return a shallow snapshot of the online GeoIP cache for safe iteration."""
    with _online_geoip_cache_lock:
        return dict(_online_geoip_cache)


def get_online_geoip_cache_stats() -> dict:
    """Return positive/negative cache counts without exposing the live dict."""
    snapshot = get_online_geoip_cache_snapshot()
    positive = 0
    negative = 0
    for entry in snapshot.values():
        if isinstance(entry, dict) and entry.get('_negative'):
            negative += 1
        else:
            positive += 1
    return {
        "cache_size": len(snapshot),
        "positive": positive,
        "negative": negative,
    }


async def clear_online_geoip_cache():
    """Clear the online GeoIP lookup cache (both memory and disk)"""
    global _online_geoip_cache, _online_geoip_inflight
    with _online_geoip_cache_lock:
        _online_geoip_cache = {}
    async with _online_geoip_inflight_lock:
        for task in _online_geoip_inflight.values():
            if not task.done():
                task.cancel()
        _online_geoip_inflight = {}
    try:
        if os.path.exists(GEOIP_CACHE_FILE):
            os.remove(GEOIP_CACHE_FILE)
        logger.info("GeoIP cache cleared")
    except Exception as e:
        logger.error(f"Failed to clear GeoIP cache file: {e}")

def translate_city_name(city_name: str) -> str:
    """Translate city name to Simplified Chinese if available"""
    if not city_name:
        return city_name

    text = str(city_name).strip()

    # Direct translation lookup (exact match)
    if text in CITY_TRANSLATIONS:
        return CITY_TRANSLATIONS[text]

    # Normalized lookup handles accents, case and punctuation variants.
    normalized = _get_city_translation_index().get(normalize_location_name(text))
    if normalized:
        return normalized

    # Try character-by-character Traditional -> Simplified conversion for remaining chars
    result = text
    for trad, simp in CITY_TRANSLATIONS.items():
        if len(trad) == 1 and trad in result:
            result = result.replace(trad, simp)

    # Convert any remaining Traditional Chinese to Simplified
    result = convert_to_simplified(result)

    return result.strip()

def format_location_display(country_code: str, country_name: str, city_name: str) -> str:
    """
    Format location for display, avoiding duplicates like "香港 香港"
    Returns: "国家/地区 城市" or just "国家/地区" if city is same as country or empty
    """
    # Use special display name for certain regions
    display_country = REGION_DISPLAY_NAMES.get(country_code, country_name)
    
    if not city_name:
        return display_country
    
    # Translate city name
    translated_city = translate_city_name(city_name)
    
    # Avoid duplicates: if city name is same as country/region name, just show country
    # e.g., "Hong Kong" city in "Hong Kong" -> just "China Hong Kong"
    # e.g., "Singapore" city in "Singapore" -> just "Singapore"
    if translated_city == country_name or translated_city in display_country:
        return display_country
    
    return f"{display_country} {translated_city}"


class GeoIPService:
    """Static utility class for GeoIP-related functions (flag conversion, etc.)"""
    
    @staticmethod
    def iso_to_flag(iso_code: str) -> str:
        """
        Convert ISO 3166-1 alpha-2 country code to flag emoji
        Example: "US" -> "🇺🇸", "CN" -> "🇨🇳"
        
        Uses Unicode Regional Indicator Symbols:
        - 'A' (U+0041) maps to 🇦 (U+1F1E6)
        - 'Z' (U+005A) maps to 🇿 (U+1F1FF)
        """
        if not iso_code or len(iso_code) != 2:
            return "🌐"
        
        try:
            # Convert each letter to regional indicator symbol
            # Regional indicators start at U+1F1E6 for 'A'
            flag = ""
            for char in iso_code.upper():
                if 'A' <= char <= 'Z':
                    # Calculate offset from 'A' and add to base regional indicator
                    flag += chr(0x1F1E6 + ord(char) - ord('A'))
                else:
                    return "🌐"
            return flag
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid ISO code for flag conversion: {iso_code}, error: {e}")
            return "🌐"
        except Exception as e:
            logger.error(f"Error converting ISO to flag: {e}")
            return "🌐"
    
    @staticmethod
    def flag_to_iso(flag: str) -> Optional[str]:
        """
        Convert flag emoji back to ISO country code
        Example: "🇺🇸" -> "US"
        """
        if not flag or len(flag) < 1:
            return None
        
        try:
            # Each flag emoji is 2 regional indicator symbols
            # Regional indicator 🇦 (U+1F1E6) to 🇿 (U+1F1FF)
            iso = ""
            for char in flag:
                cp = ord(char)
                if 0x1F1E6 <= cp <= 0x1F1FF:
                    iso += chr(ord('A') + cp - 0x1F1E6)
            
            if len(iso) == 2:
                return iso
            return None
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid flag emoji for ISO conversion: {flag}, error: {e}")
            return None
        except Exception as e:
            logger.error(f"Error converting flag to ISO: {e}")
            return None
