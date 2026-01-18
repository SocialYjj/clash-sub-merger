import os
import requests
import yaml
import json
import time
import secrets
import re
import hashlib
import httpx
import subprocess
import sys
import atexit
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote, quote
from typing import Optional, Tuple, Dict, List
from collections import OrderedDict
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Header, BackgroundTasks
from fastapi.responses import FileResponse, PlainTextResponse   
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from merge_config import ConfigMerger, NameTransformer, CountryGrouper
from geoip_service import GeoIPService, lookup_ip_online
from scheduler_service import get_scheduler, init_scheduler, CRON_PRESETS, get_cron_description
from speedtest_service import (
    get_speedtest_service, SpeedTestConfig, SpeedTestResult,
    get_latency_color, get_speed_color, format_speed, format_latency
)

app = FastAPI(title="Clash Config Merger")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('DATA_DIR', BASE_DIR)
YAML_SOURCE_DIR = os.path.join(DATA_DIR, 'uploads')
OUTPUT_FILE = os.path.join(DATA_DIR, 'myconfig.yaml')
CONFIG_FILE = os.path.join(DATA_DIR, 'config.json')  # Unified config file

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(YAML_SOURCE_DIR, exist_ok=True)

# ==================== Stats Cache ====================
# Cache stats data to improve dashboard performance
STATS_CACHE = {
    'overview': None,
    'countries': None,
    'last_update': 0,
    'cache_duration': 60  # Cache for 60 seconds
}

def invalidate_stats_cache():
    """Invalidate stats cache when data changes"""
    STATS_CACHE['overview'] = None
    STATS_CACHE['countries'] = None
    STATS_CACHE['last_update'] = 0

# ==================== Go Speedtest Service Management ====================

GO_SPEEDTEST_PROCESS = None

def start_go_speedtest_service():
    """Start the Go speedtest service as a subprocess"""
    global GO_SPEEDTEST_PROCESS
    
    # Check if already running
    if GO_SPEEDTEST_PROCESS is not None and GO_SPEEDTEST_PROCESS.poll() is None:
        print("Go speedtest service already running")
        return True
    
    # Find the speedtest executable
    speedtest_dir = os.path.join(BASE_DIR, 'speedtest')
    if sys.platform == 'win32':
        speedtest_exe = os.path.join(speedtest_dir, 'speedtest.exe')
    else:
        speedtest_exe = os.path.join(speedtest_dir, 'speedtest')
    
    if not os.path.exists(speedtest_exe):
        print(f"Go speedtest executable not found at {speedtest_exe}")
        return False
    
    try:
        # Start the Go service
        GO_SPEEDTEST_PROCESS = subprocess.Popen(
            [speedtest_exe],
            cwd=speedtest_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
        print(f"Go speedtest service started (PID: {GO_SPEEDTEST_PROCESS.pid})")
        return True
    except Exception as e:
        print(f"Failed to start Go speedtest service: {e}")
        return False

def stop_go_speedtest_service():
    """Stop the Go speedtest service"""
    global GO_SPEEDTEST_PROCESS
    
    if GO_SPEEDTEST_PROCESS is not None:
        try:
            GO_SPEEDTEST_PROCESS.terminate()
            GO_SPEEDTEST_PROCESS.wait(timeout=5)
            print("Go speedtest service stopped")
        except Exception as e:
            print(f"Error stopping Go speedtest service: {e}")
            try:
                GO_SPEEDTEST_PROCESS.kill()
            except:
                pass
        GO_SPEEDTEST_PROCESS = None

# Register cleanup on exit
atexit.register(stop_go_speedtest_service)

# Also handle signals for proper cleanup
import signal

def signal_handler(signum, frame):
    """Handle termination signals to ensure Go service is stopped"""
    print(f"\nReceived signal {signum}, stopping Go speedtest service...")
    stop_go_speedtest_service()
    sys.exit(0)

# Register signal handlers (Windows only supports SIGINT and SIGTERM)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ==================== Config Management ====================

def load_config() -> dict:
    """Load unified config"""
    default = {
        'auth': {},
        'subscriptions': [],
        'custom_nodes': [],
        'source_order': [],
        'users': [],  # User management
        'templates': [],  # Multi-template management
        'admin_tokens': []  # Admin multi-token management
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
            # Ensure all required keys exist
            for key in default:
                if key not in config:
                    config[key] = default[key]
            return config
        except:
            pass
    return default

def save_config(config: dict):
    """Save unified config"""
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

def migrate_old_config():
    """Migrate old config files to unified config"""
    if os.path.exists(CONFIG_FILE):
        return  # Already migrated
    
    config = {'auth': {}, 'subscriptions': [], 'custom_nodes': [], 'source_order': []}
    
    # Migrate auth.json
    auth_file = os.path.join(DATA_DIR, 'auth.json')
    if os.path.exists(auth_file):
        with open(auth_file, 'r', encoding='utf-8') as f:
            config['auth'] = json.load(f)
    
    # Migrate subscriptions.json
    subs_file = os.path.join(DATA_DIR, 'subscriptions.json')
    if os.path.exists(subs_file):
        with open(subs_file, 'r', encoding='utf-8') as f:
            config['subscriptions'] = json.load(f)
    
    # Migrate custom_nodes.json
    nodes_file = os.path.join(DATA_DIR, 'custom_nodes.json')
    if os.path.exists(nodes_file):
        with open(nodes_file, 'r', encoding='utf-8') as f:
            config['custom_nodes'] = json.load(f)
    
    # Migrate source_order.json
    order_file = os.path.join(DATA_DIR, 'source_order.json')
    if os.path.exists(order_file):
        with open(order_file, 'r', encoding='utf-8') as f:
            config['source_order'] = json.load(f)
    
    save_config(config)
    print("Config migration completed")

def migrate_legacy_sub_token():
    """Migrate legacy auth.sub_token to admin_tokens if not already migrated"""
    config = load_config()
    auth = config.get('auth', {})
    admin_tokens = config.get('admin_tokens', [])
    
    # Check if legacy sub_token exists
    legacy_token = auth.get('sub_token')
    if not legacy_token:
        return  # No legacy token to migrate
    
    # Check if already migrated (token value exists in admin_tokens)
    already_migrated = any(t.get('token') == legacy_token for t in admin_tokens)
    if already_migrated:
        return  # Already migrated
    
    # Create new admin token from legacy settings
    migrated_token = {
        'id': f"tpl_{int(time.time() * 1000)}",
        'name': auth.get('sub_name', '默认'),  # Use original config name
        'token': legacy_token,  # Keep the same token value for backward compatibility
        'template_id': 'builtin',
        'sub_filename': auth.get('sub_filename', ''),
        'sub_name': auth.get('sub_name', ''),
        'enabled': True,
        'created_at': int(time.time())
    }
    
    if 'admin_tokens' not in config:
        config['admin_tokens'] = []
    config['admin_tokens'].insert(0, migrated_token)  # Add at beginning
    
    # Remove legacy fields after migration
    if 'sub_token' in config['auth']:
        del config['auth']['sub_token']
    if 'sub_filename' in config['auth']:
        del config['auth']['sub_filename']
    if 'sub_name' in config['auth']:
        del config['auth']['sub_name']
    
    save_config(config)
    print(f"Legacy sub_token migrated to admin_tokens: {legacy_token[:8]}...")

# Run migration on startup
migrate_old_config()
migrate_legacy_sub_token()

# ==================== Country Detection from Node Name ====================

from geoip_service import GeoIPService

# Keyword to country code mapping (only need code, flag is generated dynamically)
COUNTRY_KEYWORDS = {
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
    'BY': ['belarus', 'by', '白俄罗斯', 'minsk', '明斯克'],  # MUST be before RU!
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
    # Additional less common countries
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
}

# Country code to Chinese name mapping
# Complete mapping of all 241 countries/regions from world.json (236 unique ISO codes)
COUNTRY_NAMES = {
    'AD': '安道尔',
    'AE': '阿联酋',
    'AF': '阿富汗',
    'AG': '安提瓜和巴布达',
    'AI': '安圭拉',
    'AL': '阿尔巴尼亚',
    'AM': '亚美尼亚',
    'AO': '安哥拉',
    'AQ': '南极洲',
    'AR': '阿根廷',
    'AS': '美属萨摩亚',
    'AT': '奥地利',
    'AU': '澳大利亚',
    'AW': '阿鲁巴',
    'AX': '奥兰群岛',
    'AZ': '阿塞拜疆',
    'BA': '波黑',
    'BB': '巴巴多斯',
    'BD': '孟加拉国',
    'BE': '比利时',
    'BF': '布基纳法索',
    'BG': '保加利亚',
    'BH': '巴林',
    'BI': '布隆迪',
    'BJ': '贝宁',
    'BL': '圣巴泰勒米',
    'BM': '百慕大',
    'BN': '文莱',
    'BO': '玻利维亚',
    'BR': '巴西',
    'BS': '巴哈马',
    'BT': '不丹',
    'BW': '博茨瓦纳',
    'BY': '白俄罗斯',
    'BZ': '伯利兹',
    'CA': '加拿大',
    'CD': '刚果民主共和国',
    'CF': '中非共和国',
    'CG': '刚果共和国',
    'CH': '瑞士',
    'CI': '科特迪瓦',
    'CK': '库克群岛',
    'CL': '智利',
    'CM': '喀麦隆',
    'CN': '中国大陆',
    'CO': '哥伦比亚',
    'CR': '哥斯达黎加',
    'CU': '古巴',
    'CV': '佛得角',
    'CW': '库拉索',
    'CY': '塞浦路斯',
    'CZ': '捷克',
    'DE': '德国',
    'DJ': '吉布提',
    'DK': '丹麦',
    'DM': '多米尼克',
    'DO': '多米尼加',
    'DZ': '阿尔及利亚',
    'EC': '厄瓜多尔',
    'EE': '爱沙尼亚',
    'EG': '埃及',
    'EH': '西撒哈拉',
    'ER': '厄立特里亚',
    'ES': '西班牙',
    'ET': '埃塞俄比亚',
    'FI': '芬兰',
    'FJ': '斐济',
    'FK': '福克兰群岛',
    'FM': '密克罗尼西亚',
    'FO': '法罗群岛',
    'FR': '法国',
    'GA': '加蓬',
    'GB': '英国',
    'GD': '格林纳达',
    'GE': '格鲁吉亚',
    'GG': '根西岛',
    'GH': '加纳',
    'GL': '格陵兰',
    'GM': '冈比亚',
    'GN': '几内亚',
    'GQ': '赤道几内亚',
    'GR': '希腊',
    'GS': '南乔治亚和南桑威奇群岛',
    'GT': '危地马拉',
    'GU': '关岛',
    'GW': '几内亚比绍',
    'GY': '圭亚那',
    'HK': '中国香港',
    'HM': '赫德岛和麦克唐纳群岛',
    'HN': '洪都拉斯',
    'HR': '克罗地亚',
    'HT': '海地',
    'HU': '匈牙利',
    'ID': '印尼',
    'IE': '爱尔兰',
    'IL': '以色列',
    'IM': '马恩岛',
    'IN': '印度',
    'IO': '英属印度洋领地',
    'IQ': '伊拉克',
    'IR': '伊朗',
    'IS': '冰岛',
    'IT': '意大利',
    'JE': '泽西岛',
    'JM': '牙买加',
    'JO': '约旦',
    'JP': '日本',
    'KE': '肯尼亚',
    'KG': '吉尔吉斯斯坦',
    'KH': '柬埔寨',
    'KI': '基里巴斯',
    'KM': '科摩罗',
    'KN': '圣基茨和尼维斯',
    'KP': '朝鲜',
    'KR': '韩国',
    'KW': '科威特',
    'KY': '开曼群岛',
    'KZ': '哈萨克斯坦',
    'LA': '老挝',
    'LB': '黎巴嫩',
    'LC': '圣卢西亚',
    'LI': '列支敦士登',
    'LK': '斯里兰卡',
    'LR': '利比里亚',
    'LS': '莱索托',
    'LT': '立陶宛',
    'LU': '卢森堡',
    'LV': '拉脱维亚',
    'LY': '利比亚',
    'MA': '摩洛哥',
    'MC': '摩纳哥',
    'MD': '摩尔多瓦',
    'ME': '黑山',
    'MF': '法属圣马丁',
    'MG': '马达加斯加',
    'MH': '马绍尔群岛',
    'MK': '北马其顿',
    'ML': '马里',
    'MM': '缅甸',
    'MN': '蒙古',
    'MO': '中国澳门',
    'MP': '北马里亚纳群岛',
    'MR': '毛里塔尼亚',
    'MS': '蒙特塞拉特',
    'MT': '马耳他',
    'MU': '毛里求斯',
    'MV': '马尔代夫',
    'MW': '马拉维',
    'MX': '墨西哥',
    'MY': '马来西亚',
    'MZ': '莫桑比克',
    'NA': '纳米比亚',
    'NC': '新喀里多尼亚',
    'NE': '尼日尔',
    'NF': '诺福克岛',
    'NG': '尼日利亚',
    'NI': '尼加拉瓜',
    'NL': '荷兰',
    'NO': '挪威',
    'NP': '尼泊尔',
    'NR': '瑙鲁',
    'NU': '纽埃',
    'NZ': '新西兰',
    'OM': '阿曼',
    'PA': '巴拿马',
    'PE': '秘鲁',
    'PF': '法属波利尼西亚',
    'PG': '巴布亚新几内亚',
    'PH': '菲律宾',
    'PK': '巴基斯坦',
    'PL': '波兰',
    'PM': '圣皮埃尔和密克隆',
    'PN': '皮特凯恩群岛',
    'PR': '波多黎各',
    'PS': '巴勒斯坦',
    'PT': '葡萄牙',
    'PW': '帕劳',
    'PY': '巴拉圭',
    'QA': '卡塔尔',
    'RO': '罗马尼亚',
    'RS': '塞尔维亚',
    'RU': '俄罗斯',
    'RW': '卢旺达',
    'SA': '沙特阿拉伯',
    'SB': '所罗门群岛',
    'SC': '塞舌尔',
    'SD': '苏丹',
    'SE': '瑞典',
    'SG': '新加坡',
    'SH': '圣赫勒拿',
    'SI': '斯洛文尼亚',
    'SK': '斯洛伐克',
    'SL': '塞拉利昂',
    'SM': '圣马力诺',
    'SN': '塞内加尔',
    'SO': '索马里',
    'SR': '苏里南',
    'SS': '南苏丹',
    'ST': '圣多美和普林西比',
    'SV': '萨尔瓦多',
    'SX': '荷属圣马丁',
    'SY': '叙利亚',
    'SZ': '斯威士兰',
    'TC': '特克斯和凯科斯群岛',
    'TD': '乍得',
    'TF': '法属南部领地',
    'TG': '多哥',
    'TH': '泰国',
    'TJ': '塔吉克斯坦',
    'TL': '东帝汶',
    'TM': '土库曼斯坦',
    'TN': '突尼斯',
    'TO': '汤加',
    'TR': '土耳其',
    'TT': '特立尼达和多巴哥',
    'TW': '中国台湾',
    'TZ': '坦桑尼亚',
    'UA': '乌克兰',
    'UG': '乌干达',
    'US': '美国',
    'UY': '乌拉圭',
    'UZ': '乌兹别克斯坦',
    'VA': '梵蒂冈',
    'VC': '圣文森特和格林纳丁斯',
    'VE': '委内瑞拉',
    'VG': '英属维尔京群岛',
    'VI': '美属维尔京群岛',
    'VN': '越南',
    'VU': '瓦努阿图',
    'WF': '瓦利斯和富图纳',
    'WS': '萨摩亚',
    'XK': '科索沃',
    'YE': '也门',
    'ZA': '南非',
    'ZM': '赞比亚',
    'ZW': '津巴布韦'
}

# Placeholder to country code mapping for template processing
PLACEHOLDER_COUNTRY_MAP = {
    '{{HK}}': 'HK', '{{TW}}': 'TW', '{{JP}}': 'JP', '{{KR}}': 'KR', '{{SG}}': 'SG',
    '{{US}}': 'US', '{{GB}}': 'GB', '{{DE}}': 'DE', '{{FR}}': 'FR', '{{NL}}': 'NL',
    '{{RU}}': 'RU', '{{CA}}': 'CA', '{{AU}}': 'AU', '{{IN}}': 'IN', '{{TR}}': 'TR',
    '{{MY}}': 'MY', '{{TH}}': 'TH', '{{VN}}': 'VN', '{{ID}}': 'ID', '{{PH}}': 'PH',
    '{{BR}}': 'BR', '{{AR}}': 'AR', '{{MX}}': 'MX', '{{ZA}}': 'ZA', '{{AE}}': 'AE',
    '{{IL}}': 'IL', '{{UA}}': 'UA', '{{PL}}': 'PL', '{{CH}}': 'CH', '{{SE}}': 'SE',
    '{{NO}}': 'NO', '{{FI}}': 'FI', '{{DK}}': 'DK', '{{IT}}': 'IT', '{{ES}}': 'ES',
}

def filter_underscore_fields(data: dict) -> dict:
    """
    Filter out fields starting with underscore from a dictionary.
    Used to remove internal fields like _editable, _icon, _description from template output.
    
    Args:
        data: Dictionary that may contain underscore-prefixed fields
    
    Returns:
        New dictionary with underscore fields removed
    """
    return {k: v for k, v in data.items() if not k.startswith('_')}

def process_template_proxy_groups(template_groups: List[dict], all_proxies: List[str], 
                                   country_groups: Dict[str, List[str]], 
                                   sorted_country_names: List[str]) -> List[dict]:
    """
    Process template proxy-groups by replacing placeholders with actual values.
    
    Placeholders:
    - {{ALL_PROXIES}}: All proxy node names
    - {{COUNTRY_GROUPS}}: All country group names (e.g., ['🇭🇰 香港', '🇺🇸 美国', ...])
    - {{XX}}: Proxies from specific country (e.g., {{US}} for US proxies, {{HK}} for HK proxies)
    """
    processed_groups = []
    
    for group in template_groups:
        if not isinstance(group, dict):
            continue
        
        new_group = dict(group)
        proxies = group.get('proxies', [])
        
        if not isinstance(proxies, list):
            processed_groups.append(new_group)
            continue
        
        new_proxies = []
        for item in proxies:
            if not isinstance(item, str):
                new_proxies.append(item)
                continue
            
            if item == '{{ALL_PROXIES}}':
                # Replace with all proxy names
                new_proxies.extend(all_proxies)
            elif item == '{{COUNTRY_GROUPS}}':
                # Replace with all country group names
                new_proxies.extend(sorted_country_names)
            elif item in PLACEHOLDER_COUNTRY_MAP:
                # Replace with proxies from specific country
                country_code = PLACEHOLDER_COUNTRY_MAP[item]
                # Find the country group name that matches this code
                for country_name in sorted_country_names:
                    # Country name format: "flag + name" - need to check if code matches
                    if country_code in country_name or COUNTRY_NAMES.get(country_code, '') in country_name:
                        if country_name in country_groups:
                            new_proxies.extend(country_groups[country_name])
                        break
            else:
                # Keep as-is (DIRECT, REJECT, group references, etc.)
                new_proxies.append(item)
        
        new_group['proxies'] = new_proxies
        # Filter out underscore-prefixed fields before adding to output
        filtered_group = filter_underscore_fields(new_group)
        processed_groups.append(filtered_group)
    
    return processed_groups

def extract_country_from_name(node_name: str, server: str = None) -> Optional[Dict]:
    """
    Extract country info from node name using flag emoji or keywords.
    Priority: 1. Flag emoji  2. Keywords  3. None
    Returns: {'country': str, 'country_code': str, 'flag': str} or None
    """
    if not node_name:
        return None
    
    # 1. Check for flag emoji first (decode from name)
    for char in node_name:
        # Check if it's a regional indicator symbol (flag emoji)
        if len(char) == 2 or ord(char) >= 0x1F1E6:
            # Try to convert flag back to country code
            code = GeoIPService.flag_to_iso(char)
            if code and len(code) == 2:
                return {
                    'country': COUNTRY_NAMES.get(code, code),
                    'country_code': code,
                    'flag': GeoIPService.iso_to_flag(code)
                }
    
    # Also check for two-char flag sequences
    for i in range(len(node_name) - 1):
        potential_flag = node_name[i:i+2]
        code = GeoIPService.flag_to_iso(potential_flag)
        if code and len(code) == 2:
            return {
                'country': COUNTRY_NAMES.get(code, code),
                'country_code': code,
                'flag': GeoIPService.iso_to_flag(code)
            }
    
    # 2. Check for keywords (case-insensitive)
    # Find the longest matching keyword to prioritize specific names (e.g. 'Antarctica' > 'CA')
    name_lower = node_name.lower()
    best_match_code = None
    max_len = 0
    
    for code, keywords in COUNTRY_KEYWORDS.items():
        for keyword in keywords:
            if keyword in name_lower:
                if len(keyword) > max_len:
                    max_len = len(keyword)
                    best_match_code = code
    
    if best_match_code:
        return {
            'country': COUNTRY_NAMES.get(best_match_code, best_match_code),
            'country_code': best_match_code,
            'flag': GeoIPService.iso_to_flag(best_match_code)
        }
    
    return None

# ==================== Authentication ====================

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token() -> str:
    return secrets.token_urlsafe(24)

def verify_session(authorization: Optional[str] = Header(None)) -> bool:
    config = load_config()
    auth = config.get('auth', {})
    
    if not auth.get('password_hash'):
        return True
    
    if not authorization:
        raise HTTPException(status_code=401, detail="Not logged in")
    
    sessions = auth.get('sessions', {})
    if authorization in sessions:
        if sessions[authorization] > time.time():
            return True
        del sessions[authorization]
        config['auth']['sessions'] = sessions
        save_config(config)
    
    raise HTTPException(status_code=401, detail="Session expired")

# ==================== Data Models ====================

class SetPassword(BaseModel):
    password: str

class Login(BaseModel):
    password: str

class AddSubscription(BaseModel):
    name: str
    url: str

class AddLocalSubscription(BaseModel):
    name: str
    content: str  # YAML or Base64 encoded content

class UpdateSubscription(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None

class UpdateLocalSubscription(BaseModel):
    name: Optional[str] = None
    content: Optional[str] = None  # YAML or Base64 encoded content

class ReorderSubscriptions(BaseModel):
    order: List[str]

class TemplateContent(BaseModel):
    content: str
    file_aliases: Optional[Dict[str, str]] = None

class FinalContent(BaseModel):
    content: str
    save_path: Optional[str] = None

class CustomNode(BaseModel):
    link: str
    name: Optional[str] = None

class UpdateNodeName(BaseModel):
    name: str

class UpdateNodeFull(BaseModel):
    node: dict

class UpdateSubNode(BaseModel):
    name: str

class UpdateSubNodeFull(BaseModel):
    node: dict

# User management models
class CreateUser(BaseModel):
    name: str
    expire_time: Optional[int] = 0  # 0 = never expire, timestamp for expiry

class UpdateUser(BaseModel):
    name: Optional[str] = None
    expire_time: Optional[int] = None
    enabled: Optional[bool] = None
    template_id: Optional[str] = None  # Template to use for this user
    sub_name: Optional[str] = None  # Subscription config name
    sub_filename: Optional[str] = None  # Subscription filename

class UserNodeAllocation(BaseModel):
    subscriptions: Dict[str, List[str]]  # {sub_id: [node_names] or ["*"] for all}

class UpdateUserGroupConfig(BaseModel):
    group_config: Dict[str, List[str]]  # {group_name: [node_names]}

# Port mapping models
class PortMappingCreate(BaseModel):
    final_name: str  # The final transformed node name
    port: int  # Port number to map (e.g., 52001)

class PortMappingUpdate(BaseModel):
    port: int  # New port number

# Proxy chain models
class ProxyChainNode(BaseModel):
    sub_id: str           # Subscription ID or "custom" for custom nodes
    node_index: int       # Index of node in subscription
    node_name: str        # Display name of the node

class ProxyChainRow(BaseModel):
    nodes: List[ProxyChainNode]  # Ordered list of nodes in this chain row

class CreateProxyChain(BaseModel):
    name: str
    rows: List[ProxyChainRow]

class UpdateProxyChain(BaseModel):
    name: Optional[str] = None
    rows: Optional[List[ProxyChainRow]] = None
    enabled: Optional[bool] = None

# ==================== Auth API ====================

@app.get("/api/auth/status")
def get_auth_status():
    config = load_config()
    auth = config.get('auth', {})
    return {
        "has_password": bool(auth.get('password_hash')),
        "sub_token": auth.get('sub_token', ''),
        "sub_filename": auth.get('sub_filename', 'config.yaml'),
        "sub_name": auth.get('sub_name', 'Aggregated')
    }

@app.post("/api/auth/setup")
def setup_password(data: SetPassword):
    config = load_config()
    if config['auth'].get('password_hash'):
        raise HTTPException(status_code=400, detail="Password already set, use change password")
    
    session_token = generate_token()
    config['auth'] = {
        'password_hash': hash_password(data.password),
        'sub_token': generate_token(),
        'sessions': {session_token: time.time() + 86400}
    }
    save_config(config)
    return {"status": "success", "session": session_token, "sub_token": config['auth']['sub_token']}

@app.post("/api/auth/login")
def login(data: Login):
    config = load_config()
    auth = config.get('auth', {})
    
    if not auth.get('password_hash'):
        raise HTTPException(status_code=400, detail="Please set password first")
    
    if hash_password(data.password) != auth['password_hash']:
        raise HTTPException(status_code=401, detail="Wrong password")
    
    session_token = generate_token()
    if 'sessions' not in config['auth']:
        config['auth']['sessions'] = {}
    config['auth']['sessions'][session_token] = time.time() + 86400
    save_config(config)
    return {"status": "success", "session": session_token}

@app.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization:
        config = load_config()
        sessions = config['auth'].get('sessions', {})
        if authorization in sessions:
            del sessions[authorization]
            config['auth']['sessions'] = sessions
            save_config(config)
    return {"status": "success"}

@app.post("/api/auth/change-password")
def change_password(data: SetPassword, _: bool = Depends(verify_session)):
    config = load_config()
    session_token = generate_token()
    # Keep sub_token, only update password and sessions
    sub_token = config['auth'].get('sub_token', generate_token())
    config['auth'] = {
        'password_hash': hash_password(data.password),
        'sub_token': sub_token,
        'sessions': {session_token: time.time() + 86400}
    }
    save_config(config)
    return {"status": "success", "session": session_token}

@app.post("/api/auth/regenerate-token")
def regenerate_sub_token(_: bool = Depends(verify_session)):
    config = load_config()
    config['auth']['sub_token'] = generate_token()
    save_config(config)
    return {"status": "success", "sub_token": config['auth']['sub_token']}

class UpdateSubFilename(BaseModel):
    filename: str

@app.post("/api/auth/sub-filename")
def update_sub_filename(data: UpdateSubFilename, _: bool = Depends(verify_session)):
    """Update subscription filename"""
    filename = data.filename.strip()
    # Ensure filename is safe
    if not filename:
        filename = 'config.yaml'
    # Remove unsafe characters
    filename = ''.join(c for c in filename if c.isalnum() or c in '._-')
    if not filename.endswith('.yaml') and not filename.endswith('.yml'):
        filename += '.yaml'
    
    config = load_config()
    config['auth']['sub_filename'] = filename
    save_config(config)
    return {"status": "success", "sub_filename": filename}

class UpdateSubName(BaseModel):
    name: str

@app.post("/api/auth/sub-name")
def update_sub_name(data: UpdateSubName, _: bool = Depends(verify_session)):
    """Update subscription config name (displayed in client)"""
    name = data.name.strip()
    if not name:
        name = 'Aggregated'
    
    config = load_config()
    config['auth']['sub_name'] = name
    save_config(config)
    return {"status": "success", "sub_name": name}

@app.get("/api/auth/sub-token")
def get_sub_token(_: bool = Depends(verify_session)):
    config = load_config()
    return {"sub_token": config['auth'].get('sub_token', '')}

# ==================== Node Parsing ====================

import base64

def decode_base64(content: str) -> str:
    """Safely decode Base64"""
    content = content.strip().replace('-', '+').replace('_', '/')
    missing_padding = len(content) % 4
    if missing_padding:
        content += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(content).decode('utf-8')
    except:
        return ""

def parse_vless_link(link: str) -> dict:
    """Parse vless:// link to Clash format"""
    link = link.strip()
    if not link.startswith('vless://'):
        return None
    
    name = "VLESS Node"
    if '#' in link:
        link, name = link.rsplit('#', 1)
        name = unquote(name)
    
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    
    proxy = {
        'name': name,
        'type': 'vless',
        'server': parsed.hostname,
        'port': parsed.port,
        'uuid': parsed.username,
        'udp': True,
    }
    
    security = params.get('security', [''])[0]
    if security == 'tls':
        proxy['tls'] = True
        if 'sni' in params:
            proxy['servername'] = params['sni'][0]
        if 'fp' in params:
            proxy['client-fingerprint'] = params['fp'][0]
        if 'alpn' in params:
            proxy['alpn'] = params['alpn'][0].split(',')
    elif security == 'reality':
        proxy['tls'] = True
        proxy['reality-opts'] = {}
        if 'pbk' in params:
            proxy['reality-opts']['public-key'] = params['pbk'][0]
        if 'sid' in params:
            proxy['reality-opts']['short-id'] = params['sid'][0]
        if 'sni' in params:
            proxy['servername'] = params['sni'][0]
        if 'fp' in params:
            proxy['client-fingerprint'] = params['fp'][0]
    
    network = params.get('type', [''])[0]
    if network:
        proxy['network'] = network
        if network == 'ws':
            proxy['ws-opts'] = {}
            if 'path' in params:
                proxy['ws-opts']['path'] = params['path'][0]
            if 'host' in params:
                proxy['ws-opts']['headers'] = {'Host': params['host'][0]}
        elif network == 'grpc':
            proxy['grpc-opts'] = {}
            if 'serviceName' in params:
                proxy['grpc-opts']['grpc-service-name'] = params['serviceName'][0]
        elif network == 'h2':
            proxy['h2-opts'] = {}
            if 'path' in params:
                proxy['h2-opts']['path'] = params['path'][0]
            if 'host' in params:
                proxy['h2-opts']['host'] = [params['host'][0]]
    
    if 'flow' in params:
        proxy['flow'] = params['flow'][0]
    
    return proxy

def parse_vmess_link(link: str) -> dict:
    """Parse vmess:// link to Clash format"""
    link = link.strip()
    if not link.startswith('vmess://'):
        return None
    
    try:
        b64 = link[8:]
        json_str = decode_base64(b64)
        if not json_str:
            return None
        v = json.loads(json_str)
        
        proxy = {
            'name': v.get('ps', 'VMess Node'),
            'type': 'vmess',
            'server': v.get('add'),
            'port': int(v.get('port')),
            'uuid': v.get('id'),
            'alterId': int(v.get('aid', 0)),
            'cipher': v.get('scy', 'auto'),
            'udp': True,
        }
        
        net = v.get('net', 'tcp')
        if net and net != 'tcp':
            proxy['network'] = net
            if net == 'ws':
                proxy['ws-opts'] = {'path': v.get('path', '/')}
                if v.get('host'):
                    proxy['ws-opts']['headers'] = {'Host': v.get('host')}
            elif net == 'grpc':
                proxy['grpc-opts'] = {}
                if v.get('path'):
                    proxy['grpc-opts']['grpc-service-name'] = v.get('path')
            elif net == 'h2':
                proxy['h2-opts'] = {'path': v.get('path', '/')}
                if v.get('host'):
                    proxy['h2-opts']['host'] = [v.get('host')]
        
        if v.get('tls') == 'tls':
            proxy['tls'] = True
            if v.get('sni'):
                proxy['servername'] = v.get('sni')
            if v.get('alpn'):
                proxy['alpn'] = v.get('alpn').split(',') if isinstance(v.get('alpn'), str) else v.get('alpn')
            if v.get('fp'):
                proxy['client-fingerprint'] = v.get('fp')
        
        return proxy
    except Exception:
        return None

def parse_ss_link(link: str) -> dict:
    """Parse ss:// link to Clash format"""
    link = link.strip()
    if not link.startswith('ss://'):
        return None
    
    try:
        name = "SS Node"
        if '#' in link:
            main, name = link[5:].split('#', 1)
            name = unquote(name)
        else:
            main = link[5:]
        
        # Handle SIP002 format: ss://base64(method:password)@host:port
        # Or old format: ss://base64(method:password@host:port)
        if '@' in main:
            user_pass_b64, host_port = main.split('@', 1)
            user_pass = decode_base64(user_pass_b64)
            if ':' not in user_pass:
                return None
            method, password = user_pass.split(':', 1)
            
            # Handle possible query parameters
            if '?' in host_port:
                host_port = host_port.split('?')[0]
            if ':' not in host_port:
                return None
            server, port = host_port.rsplit(':', 1)
        else:
            decoded = decode_base64(main.split('?')[0] if '?' in main else main)
            if '@' not in decoded:
                return None
            user_pass, host_port = decoded.rsplit('@', 1)
            if ':' not in user_pass:
                return None
            method, password = user_pass.split(':', 1)
            if ':' not in host_port:
                return None
            server, port = host_port.rsplit(':', 1)
        
        proxy = {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password,
            'udp': True,
        }
        
        return proxy
    except Exception:
        return None

def parse_trojan_link(link: str) -> dict:
    """Parse trojan:// link to Clash format"""
    link = link.strip()
    if not link.startswith('trojan://'):
        return None
    
    try:
        name = "Trojan Node"
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        
        proxy = {
            'name': name,
            'type': 'trojan',
            'server': parsed.hostname,
            'port': parsed.port,
            'password': unquote(parsed.username) if parsed.username else '',
            'udp': True,
        }
        
        # SNI
        if 'sni' in params:
            proxy['sni'] = params['sni'][0]
        elif 'peer' in params:
            proxy['sni'] = params['peer'][0]
        
        # ALPN
        if 'alpn' in params:
            proxy['alpn'] = params['alpn'][0].split(',')
        
        # Fingerprint
        if 'fp' in params:
            proxy['client-fingerprint'] = params['fp'][0]
        
        # Skip cert verify
        if params.get('allowInsecure', ['0'])[0] == '1':
            proxy['skip-cert-verify'] = True
        
        # Transport
        transport = params.get('type', ['tcp'])[0]
        if transport == 'ws':
            proxy['network'] = 'ws'
            proxy['ws-opts'] = {}
            if 'path' in params:
                proxy['ws-opts']['path'] = params['path'][0]
            if 'host' in params:
                proxy['ws-opts']['headers'] = {'Host': params['host'][0]}
        elif transport == 'grpc':
            proxy['network'] = 'grpc'
            proxy['grpc-opts'] = {}
            if 'serviceName' in params:
                proxy['grpc-opts']['grpc-service-name'] = params['serviceName'][0]
        
        return proxy
    except Exception:
        return None

def parse_hysteria2_link(link: str) -> dict:
    """Parse hysteria2:// or hy2:// link to Clash format"""
    link = link.strip()
    if not link.startswith('hysteria2://') and not link.startswith('hy2://'):
        return None
    
    try:
        name = "Hysteria2 Node"
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        
        proxy = {
            'name': name,
            'type': 'hysteria2',
            'server': parsed.hostname,
            'port': parsed.port,
            'password': unquote(parsed.username) if parsed.username else '',
            'udp': True,
        }
        
        # SNI
        if 'sni' in params:
            proxy['sni'] = params['sni'][0]
        
        # Skip cert verify
        if params.get('insecure', ['0'])[0] == '1':
            proxy['skip-cert-verify'] = True
        
        # Obfuscation
        if 'obfs' in params:
            proxy['obfs'] = params['obfs'][0]
            if 'obfs-password' in params:
                proxy['obfs-password'] = params['obfs-password'][0]
        
        # Fingerprint
        if 'fp' in params:
            proxy['client-fingerprint'] = params['fp'][0]
        
        # ALPN
        if 'alpn' in params:
            proxy['alpn'] = params['alpn'][0].split(',')
        
        return proxy
    except Exception:
        return None

def parse_tuic_link(link: str) -> dict:
    """Parse tuic:// link to Clash format"""
    link = link.strip()
    if not link.startswith('tuic://'):
        return None
    
    try:
        name = "TUIC Node"
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        
        # tuic://uuid:password@host:port
        proxy = {
            'name': name,
            'type': 'tuic',
            'server': parsed.hostname,
            'port': parsed.port,
            'uuid': parsed.username,
            'password': parsed.password if parsed.password else '',
            'udp': True,
        }
        
        # SNI
        if 'sni' in params:
            proxy['sni'] = params['sni'][0]
        
        # Skip cert verify
        if params.get('allow_insecure', ['0'])[0] == '1' or params.get('insecure', ['0'])[0] == '1':
            proxy['skip-cert-verify'] = True
        
        # Congestion control
        if 'congestion_control' in params:
            proxy['congestion-controller'] = params['congestion_control'][0]
        
        # ALPN
        if 'alpn' in params:
            proxy['alpn'] = params['alpn'][0].split(',')
        
        # UDP relay mode
        if 'udp_relay_mode' in params:
            proxy['udp-relay-mode'] = params['udp_relay_mode'][0]
        
        return proxy
    except Exception:
        return None

def parse_ssr_link(link: str) -> dict:
    """Parse ssr:// link to Clash format"""
    link = link.strip()
    if not link.startswith('ssr://'):
        return None
    
    try:
        decoded = decode_base64(link[6:])
        if not decoded:
            return None
        
        # ssr://base64(server:port:protocol:method:obfs:base64(password)/?params)
        main_part = decoded.split('/?')[0] if '/?' in decoded else decoded
        parts = main_part.split(':')
        if len(parts) < 6:
            return None
        
        server = parts[0]
        port = int(parts[1])
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password = decode_base64(parts[5])
        
        # Parse params
        name = "SSR Node"
        obfs_param = ""
        protocol_param = ""
        
        if '/?' in decoded:
            param_str = decoded.split('/?')[1]
            params = {}
            for p in param_str.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    params[k] = decode_base64(v) if v else ''
            
            name = params.get('remarks', name)
            obfs_param = params.get('obfsparam', '')
            protocol_param = params.get('protoparam', '')
        
        proxy = {
            'name': name,
            'type': 'ssr',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'protocol': protocol,
            'obfs': obfs,
            'udp': True,
        }
        
        if protocol_param:
            proxy['protocol-param'] = protocol_param
        if obfs_param:
            proxy['obfs-param'] = obfs_param
        
        return proxy
    except Exception:
        return None

def parse_hysteria_link(link: str) -> dict:
    """Parse hysteria:// or hy:// link to Clash format (Hysteria v1)"""
    link = link.strip()
    if not link.startswith('hysteria://') and not link.startswith('hy://'):
        return None
    
    try:
        name = "Hysteria Node"
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        # Remove protocol prefix
        if link.startswith('hysteria://'):
            link = link[11:]
        else:
            link = link[5:]
        
        # Parse server:port?params
        if '?' in link:
            server_part, query = link.split('?', 1)
        else:
            server_part, query = link, ''
        
        # Parse server and port
        if ':' in server_part:
            server, port_str = server_part.rsplit(':', 1)
            port = int(port_str) if port_str.isdigit() else 443
        else:
            server = server_part
            port = 443
        
        proxy = {
            'name': name,
            'type': 'hysteria',
            'server': server,
            'port': port,
            'protocol': 'udp',
        }
        
        # Parse params
        params = parse_qs(query)
        
        if 'auth' in params:
            proxy['auth-str'] = params['auth'][0]
        if 'peer' in params:
            proxy['sni'] = params['peer'][0]
        if 'sni' in params:
            proxy['sni'] = params['sni'][0]
        if 'alpn' in params:
            proxy['alpn'] = params['alpn'][0].split(',')
        if 'upmbps' in params:
            proxy['up'] = params['upmbps'][0]
        if 'downmbps' in params:
            proxy['down'] = params['downmbps'][0]
        if 'obfs' in params and params['obfs'][0] != 'none':
            proxy['_obfs'] = params['obfs'][0]
        if 'obfsParam' in params:
            proxy['obfs'] = params['obfsParam'][0]
        if 'insecure' in params and params['insecure'][0] == '1':
            proxy['skip-cert-verify'] = True
        if 'mport' in params:
            proxy['ports'] = params['mport'][0]
        if 'protocol' in params:
            proxy['protocol'] = params['protocol'][0]
        
        return proxy
    except Exception:
        return None

def parse_anytls_link(link: str) -> dict:
    """Parse anytls:// link to Clash format"""
    link = link.strip()
    if not link.startswith('anytls://'):
        return None
    
    try:
        name = "AnyTLS Node"
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        
        password = unquote(parsed.username) if parsed.username else ''
        port = parsed.port if parsed.port else 443
        
        proxy = {
            'name': name,
            'type': 'anytls',
            'server': parsed.hostname,
            'port': port,
            'password': password,
        }
        
        # SNI
        if 'sni' in params:
            proxy['sni'] = params['sni'][0]
        
        # Skip cert verify
        if params.get('insecure', ['0'])[0] == '1':
            proxy['skip-cert-verify'] = True
        
        # ALPN
        if 'alpn' in params:
            proxy['alpn'] = params['alpn'][0].split(',')
        
        # Fingerprint
        if 'fp' in params:
            proxy['client-fingerprint'] = params['fp'][0]
        
        # UDP
        if 'udp' in params and params['udp'][0] == '1':
            proxy['udp'] = True
        
        return proxy
    except Exception:
        return None

def parse_wireguard_link(link: str) -> dict:
    """Parse wireguard:// or wg:// link to Clash format"""
    link = link.strip()
    if not link.startswith('wireguard://') and not link.startswith('wg://'):
        return None
    
    try:
        name = "WireGuard Node"
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        
        private_key = unquote(parsed.username) if parsed.username else ''
        port = parsed.port if parsed.port else 51820
        
        proxy = {
            'name': name,
            'type': 'wireguard',
            'server': parsed.hostname,
            'port': port,
            'private-key': private_key,
            'udp': True,
        }
        
        # Public key
        if 'publickey' in params:
            proxy['public-key'] = params['publickey'][0]
        elif 'public-key' in params:
            proxy['public-key'] = params['public-key'][0]
        
        # Private key (if in params)
        if 'privatekey' in params:
            proxy['private-key'] = params['privatekey'][0]
        elif 'private-key' in params:
            proxy['private-key'] = params['private-key'][0]
        
        # IP address
        if 'address' in params or 'ip' in params:
            addr = params.get('address', params.get('ip', ['']))[0]
            for ip in addr.split(','):
                ip = ip.strip().split('/')[0].strip('[]')
                if '.' in ip:  # IPv4
                    proxy['ip'] = ip
                elif ':' in ip:  # IPv6
                    proxy['ipv6'] = ip
        
        # Reserved
        if 'reserved' in params:
            reserved = params['reserved'][0].split(',')
            if len(reserved) == 3:
                proxy['reserved'] = [int(r.strip()) for r in reserved]
        
        # MTU
        if 'mtu' in params:
            proxy['mtu'] = int(params['mtu'][0])
        
        return proxy
    except Exception:
        return None

def parse_socks_link(link: str) -> dict:
    """Parse socks5://, socks5+tls://, socks:// link to Clash format"""
    link = link.strip()
    if not link.startswith('socks5://') and not link.startswith('socks5+tls://') and not link.startswith('socks://'):
        return None
    
    try:
        name = "SOCKS5 Node"
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        # Check if TLS
        tls = '+tls' in link or link.startswith('socks5+tls://')
        
        parsed = urlparse(link)
        port = parsed.port if parsed.port else (443 if tls else 1080)
        
        proxy = {
            'name': name,
            'type': 'socks5',
            'server': parsed.hostname,
            'port': port,
            'tls': tls,
        }
        
        # Username and password
        if parsed.username:
            proxy['username'] = unquote(parsed.username)
        if parsed.password:
            proxy['password'] = unquote(parsed.password)
        
        return proxy
    except Exception:
        return None

def parse_http_link(link: str) -> dict:
    """Parse http://, https:// proxylink to Clash format"""
    link = link.strip()
    if not link.startswith('http://') and not link.startswith('https://'):
        return None
    
    try:
        name = "HTTPproxy"
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        tls = link.startswith('https://')
        
        parsed = urlparse(link)
        port = parsed.port if parsed.port else (443 if tls else 80)
        
        proxy = {
            'name': name,
            'type': 'http',
            'server': parsed.hostname,
            'port': port,
            'tls': tls,
        }
        
        # Username and password
        if parsed.username:
            proxy['username'] = unquote(parsed.username)
        if parsed.password:
            proxy['password'] = unquote(parsed.password)
        
        return proxy
    except Exception:
        return None

def parse_snell_link(link: str) -> dict:
    """Parse snell:// link to Clash format"""
    link = link.strip()
    if not link.startswith('snell://'):
        return None
    
    try:
        name = "Snell Node"
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        
        psk = unquote(parsed.username) if parsed.username else ''
        port = parsed.port if parsed.port else 443
        
        proxy = {
            'name': name,
            'type': 'snell',
            'server': parsed.hostname,
            'port': port,
            'psk': psk,
        }
        
        # Version
        if 'version' in params:
            proxy['version'] = int(params['version'][0])
        
        # Obfuscation
        if 'obfs' in params:
            proxy['obfs-opts'] = {'mode': params['obfs'][0]}
            if 'obfs-host' in params:
                proxy['obfs-opts']['host'] = params['obfs-host'][0]
        
        return proxy
    except Exception:
        return None

def parse_node_link(link: str) -> dict:
    """Parse node link, supports multiple protocols"""
    link = link.strip()
    
    if link.startswith('vless://'):
        return parse_vless_link(link)
    elif link.startswith('vmess://'):
        return parse_vmess_link(link)
    elif link.startswith('ss://'):
        return parse_ss_link(link)
    elif link.startswith('trojan://'):
        return parse_trojan_link(link)
    elif link.startswith('hysteria2://') or link.startswith('hy2://'):
        return parse_hysteria2_link(link)
    elif link.startswith('hysteria://') or link.startswith('hy://'):
        return parse_hysteria_link(link)
    elif link.startswith('tuic://'):
        return parse_tuic_link(link)
    elif link.startswith('ssr://'):
        return parse_ssr_link(link)
    elif link.startswith('anytls://'):
        return parse_anytls_link(link)
    elif link.startswith('wireguard://') or link.startswith('wg://'):
        return parse_wireguard_link(link)
    elif link.startswith('socks5://') or link.startswith('socks5+tls://') or link.startswith('socks://'):
        return parse_socks_link(link)
    elif link.startswith('http://') or link.startswith('https://'):
        return parse_http_link(link)
    elif link.startswith('snell://'):
        return parse_snell_link(link)
    
    return None

# ==================== Subscription Helper Functions ====================

def parse_subscription_info(headers: dict) -> dict:
    info = {'upload': 0, 'download': 0, 'total': 0, 'expire': 0}
    userinfo = headers.get('subscription-userinfo', '') or headers.get('Subscription-Userinfo', '')
    if userinfo:
        for part in userinfo.split(';'):
            if '=' in part:
                key, val = part.split('=', 1)
                try:
                    info[key.strip().lower()] = int(val.strip())
                except:
                    pass
    return info

def fetch_subscription(url: str) -> Tuple[str, dict, int]:
    headers = {'User-Agent': 'FlClash/v0.8.91 clash-verge Platform/windows', 'Accept': '*/*'}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    
    sub_info = parse_subscription_info(dict(response.headers))
    
    # Use response.content (bytes) instead of response.text to avoid encoding issues
    # Some subscriptions contain emoji or special characters that cause decoding problems
    try:
        content = response.content.decode('utf-8', errors='ignore').strip()
    except:
        content = response.text.strip()
    
    # Try to parse as YAML first
    node_count = 0
    try:
        cfg = yaml.safe_load(content)
        if cfg and isinstance(cfg, dict) and 'proxies' in cfg:
            node_count = len(cfg.get('proxies', []))
            return content, sub_info, node_count
    except:
        pass
    
    # If not YAML, try Base64 decode
    try:
        # Try to decode as Base64
        padded = content + '=' * (4 - len(content) % 4)
        decoded = base64.b64decode(padded).decode('utf-8', errors='ignore').strip()
        
        # Check if decoded content is YAML
        try:
            cfg = yaml.safe_load(decoded)
            if cfg and isinstance(cfg, dict) and 'proxies' in cfg:
                node_count = len(cfg.get('proxies', []))
                return decoded, sub_info, node_count
        except:
            pass
        
        # If not YAML, parse as URI list (ss://, vmess://, vless://, etc.)
        proxies = []
        lines = decoded.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse node link
            proxy = parse_node_link(line)
            if proxy:
                proxies.append(proxy)
        
        if proxies:
            # Convert to YAML format
            yaml_content = yaml.dump({'proxies': proxies}, allow_unicode=True, sort_keys=False)
            node_count = len(proxies)
            return yaml_content, sub_info, node_count
    except Exception as e:
        # Base64 decode failed, might be plain URI list
        pass
    
    # Try parsing as plain URI list (not Base64 encoded)
    proxies = []
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        proxy = parse_node_link(line)
        if proxy:
            proxies.append(proxy)
    
    if proxies:
        yaml_content = yaml.dump({'proxies': proxies}, allow_unicode=True, sort_keys=False)
        node_count = len(proxies)
        return yaml_content, sub_info, node_count
    
    # If all parsing failed, return original content
    return content, sub_info, 0

import base64

def parse_local_subscription(content: str) -> Tuple[str, List[dict], int]:
    """
    Parse local subscription content.
    Supports: YAML (with proxies), Base64 encoded content, URI list (ss://, vmess://, etc.)
    
    Returns: (yaml_content, proxies_list, node_count)
    """
    original_content = content.strip()
    decoded_content = original_content
    
    # Try Base64 decode
    try:
        # Remove possible padding issues
        padded = original_content + '=' * (4 - len(original_content) % 4)
        decoded = base64.b64decode(padded).decode('utf-8')
        decoded_content = decoded.strip()
    except:
        pass  # Not Base64, use original
    
    proxies = []
    
    # Check if it's YAML with proxies section
    try:
        cfg = yaml.safe_load(decoded_content)
        if isinstance(cfg, dict) and 'proxies' in cfg:
            proxies = cfg.get('proxies', [])
            yaml_content = decoded_content
            return yaml_content, proxies, len(proxies)
    except:
        pass
    
    # Try parsing as URI list (one link per line)
    lines = decoded_content.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Parse various URI formats
        proxy = parse_node_link(line)
        if proxy:
            proxies.append(proxy)
    
    if proxies:
        # Convert to YAML format
        yaml_content = yaml.dump({'proxies': proxies}, allow_unicode=True, sort_keys=False)
        return yaml_content, proxies, len(proxies)
    
    raise ValueError("无法识别订阅内容格式，请检查是否为有效的 YAML、Base64 或节点链接")

def update_custom_nodes_yaml():
    """Update custom nodes yaml file"""
    config = load_config()
    nodes = config.get('custom_nodes', [])
    proxies = []
    
    for node in nodes:
        proxy = parse_node_link(node['link'])
        if proxy:
            proxy['name'] = node['name']
            proxies.append(proxy)
    
    filepath = os.path.join(YAML_SOURCE_DIR, 'custom_nodes.yaml')
    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.dump({'proxies': proxies}, f, allow_unicode=True, sort_keys=False)

def get_ordered_sources() -> List[dict]:
    """Get all sources in order"""
    config = load_config()
    subs = config.get('subscriptions', [])
    custom_nodes = config.get('custom_nodes', [])
    order = config.get('source_order', [])
    
    all_sources = {}
    for s in subs:
        all_sources[s['id']] = {'type': 'subscription', 'data': s}
    if custom_nodes:
        all_sources['custom_nodes'] = {'type': 'custom', 'data': {'id': 'custom_nodes', 'name': 'Custom Nodes', 'nodes': custom_nodes}}
    
    result = []
    for source_id in order:
        if source_id in all_sources:
            result.append(all_sources.pop(source_id))
    for source in all_sources.values():
        result.append(source)
    
    return result

# ==================== Subscription API ====================

@app.get("/api/subscriptions")
def list_subscriptions(_: bool = Depends(verify_session)):
    config = load_config()
    return {"subscriptions": config.get('subscriptions', [])}

@app.post("/api/subscriptions")
def add_subscription(data: AddSubscription, _: bool = Depends(verify_session)):
    config = load_config()
    sub_id = f"sub_{int(time.time() * 1000)}"
    
    try:
        content, sub_info, node_count = fetch_subscription(data.url)
        new_sub = {
            'id': sub_id, 'name': data.name, 'url': data.url, 'enabled': True,
            'type': 'url',  # Mark as URL subscription
            'upload': sub_info.get('upload', 0), 'download': sub_info.get('download', 0),
            'total': sub_info.get('total', 0), 'expire': sub_info.get('expire', 0),
            'node_count': node_count, 'last_update': int(time.time())
        }
        
        with open(os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml"), 'w', encoding='utf-8') as f:
            f.write(content)
        
        config['subscriptions'].append(new_sub)
        save_config(config)
        invalidate_stats_cache()  # Clear stats cache
        return {"status": "success", "subscription": new_sub}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch subscription: {str(e)}")

@app.post("/api/subscriptions/local")
def add_local_subscription(data: AddLocalSubscription, _: bool = Depends(verify_session)):
    """Add a local subscription by pasting content directly"""
    config = load_config()
    sub_id = f"sub_{int(time.time() * 1000)}"
    
    try:
        yaml_content, proxies, node_count = parse_local_subscription(data.content)
        
        new_sub = {
            'id': sub_id, 'name': data.name, 'enabled': True,
            'type': 'local',  # Mark as local subscription
            'node_count': node_count, 'last_update': int(time.time())
        }
        
        with open(os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml"), 'w', encoding='utf-8') as f:
            f.write(yaml_content)
        
        config['subscriptions'].append(new_sub)
        save_config(config)
        return {"status": "success", "subscription": new_sub}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse content: {str(e)}")

@app.put("/api/subscriptions/{sub_id}/local")
def update_local_subscription(sub_id: str, data: UpdateLocalSubscription, _: bool = Depends(verify_session)):
    """Update a local subscription"""
    config = load_config()
    sub = next((s for s in config['subscriptions'] if s['id'] == sub_id), None)
    
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    if sub.get('type') != 'local':
        raise HTTPException(status_code=400, detail="Not a local subscription")
    
    if data.name:
        sub['name'] = data.name
    
    if data.content:
        try:
            yaml_content, proxies, node_count = parse_local_subscription(data.content)
            sub['node_count'] = node_count
            sub['last_update'] = int(time.time())
            
            with open(os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml"), 'w', encoding='utf-8') as f:
                f.write(yaml_content)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    save_config(config)
    return {"status": "success", "subscription": sub}

@app.post("/api/subscriptions/parse-preview")
def parse_subscription_preview(data: AddLocalSubscription, _: bool = Depends(verify_session)):
    """Preview parsing result without saving"""
    try:
        yaml_content, proxies, node_count = parse_local_subscription(data.content)
        return {
            "status": "success",
            "node_count": node_count,
            "preview": [p.get('name', 'Unknown') for p in proxies[:10]]  # First 10 node names
        }
    except ValueError as e:
        return {"status": "error", "error": str(e), "node_count": 0}
    except Exception as e:
        return {"status": "error", "error": str(e), "node_count": 0}

@app.delete("/api/subscriptions/{sub_id}")
def delete_subscription(sub_id: str, _: bool = Depends(verify_session)):
    config = load_config()
    config['subscriptions'] = [s for s in config['subscriptions'] if s['id'] != sub_id]
    save_config(config)
    invalidate_stats_cache()  # Clear stats cache
    
    filepath = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
    if os.path.exists(filepath):
        os.remove(filepath)
    return {"status": "success"}

@app.put("/api/subscriptions/{sub_id}/toggle")
def toggle_subscription(sub_id: str, _: bool = Depends(verify_session)):
    config = load_config()
    for s in config['subscriptions']:
        if s['id'] == sub_id:
            s['enabled'] = not s['enabled']
            break
    save_config(config)
    invalidate_stats_cache()  # Clear stats cache
    return {"status": "success"}

@app.put("/api/subscriptions/reorder")
def reorder_subscriptions(data: ReorderSubscriptions, _: bool = Depends(verify_session)):
    config = load_config()
    config['source_order'] = data.order
    
    sub_map = {s['id']: s for s in config['subscriptions']}
    new_subs = []
    for source_id in data.order:
        if source_id in sub_map:
            new_subs.append(sub_map.pop(source_id))
    new_subs.extend(sub_map.values())
    config['subscriptions'] = new_subs
    
    save_config(config)
    return {"status": "success"}

@app.put("/api/subscriptions/{sub_id}")
def update_subscription(sub_id: str, data: UpdateSubscription, _: bool = Depends(verify_session)):
    config = load_config()
    for s in config['subscriptions']:
        if s['id'] == sub_id:
            if data.name:
                s['name'] = data.name
            if data.url and data.url != s['url']:
                try:
                    content, sub_info, node_count = fetch_subscription(data.url)
                    s['url'] = data.url
                    s.update({
                        'upload': sub_info.get('upload', 0), 'download': sub_info.get('download', 0),
                        'total': sub_info.get('total', 0), 'expire': sub_info.get('expire', 0),
                        'node_count': node_count, 'last_update': int(time.time())
                    })
                    with open(os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml"), 'w', encoding='utf-8') as f:
                        f.write(content)
                except Exception as e:
                    raise HTTPException(status_code=400, detail=f"Failed to fetch subscription: {str(e)}")
            save_config(config)
            return {"status": "success", "subscription": s}
    raise HTTPException(status_code=404, detail="Subscription not found")

@app.post("/api/subscriptions/{sub_id}/refresh")
def refresh_subscription(sub_id: str, _: bool = Depends(verify_session)):
    config = load_config()
    for s in config['subscriptions']:
        if s['id'] == sub_id:
            try:
                content, sub_info, node_count = fetch_subscription(s['url'])
                s.update({
                    'upload': sub_info.get('upload', 0), 'download': sub_info.get('download', 0),
                    'total': sub_info.get('total', 0), 'expire': sub_info.get('expire', 0),
                    'node_count': node_count, 'last_update': int(time.time())
                })
                with open(os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml"), 'w', encoding='utf-8') as f:
                    f.write(content)
                # Invalidate all user caches when subscription is refreshed
                for user in config.get('users', []):
                    if 'sub_cache' in user:
                        del user['sub_cache']
                save_config(config)
                invalidate_stats_cache()
                return {"status": "success", "subscription": s}
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Refresh failed: {str(e)}")
    raise HTTPException(status_code=404, detail="Subscription not found")

@app.post("/api/subscriptions/refresh-all")
def refresh_all_subscriptions(_: bool = Depends(verify_session)):
    config = load_config()
    updated = 0
    for s in config['subscriptions']:
        if s['enabled']:
            try:
                content, sub_info, node_count = fetch_subscription(s['url'])
                s.update({
                    'upload': sub_info.get('upload', 0), 'download': sub_info.get('download', 0),
                    'total': sub_info.get('total', 0), 'expire': sub_info.get('expire', 0),
                    'node_count': node_count, 'last_update': int(time.time())
                })
                with open(os.path.join(YAML_SOURCE_DIR, f"{s['id']}.yaml"), 'w', encoding='utf-8') as f:
                    f.write(content)
                updated += 1
            except:
                pass
    # Invalidate all user caches when subscriptions are refreshed
    for user in config.get('users', []):
        if 'sub_cache' in user:
            del user['sub_cache']
    save_config(config)
    invalidate_stats_cache()
    return {"status": "success", "updated": updated}

@app.get("/api/source-order")
def get_source_order(_: bool = Depends(verify_session)):
    config = load_config()
    return {"order": config.get('source_order', [])}

# ==================== Subscription Node API ====================

@app.get("/api/subscriptions/{sub_id}/nodes")
def get_subscription_nodes(sub_id: str, _: bool = Depends(verify_session)):
    filepath = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Subscription file not found")
    
    # Get subscription name for NameTransformer
    config = load_config()
    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    source_name = sub['name'] if sub else 'Unknown'
    port_mappings = config.get('port_mappings', {})  # {final_name: port}
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        proxies = cfg.get('proxies', []) if cfg else []
        
        # Enhance each node with final_name and region
        enhanced_nodes = []
        for proxy in proxies:
            node_data = dict(proxy)  # Copy original data
            server = proxy.get('server', '')
            original_name = proxy.get('name', '')
            
            # Generate final name using NameTransformer
            transformed = NameTransformer.transform_name(proxy, source_name)
            final_name = transformed.get('name', original_name)
            node_data['final_name'] = final_name
            
            # Generate display name (clean name without flag for UI display)
            display_name = NameTransformer.remove_flags(original_name)
            node_data['display_name'] = display_name
            
            # Get region info - STRICT priority:
            # 1. Flag emoji in ORIGINAL name (provider's flag) - most reliable
            # 2. Keywords in original name
            # 3. Saved geoip cache (from region testing)  
            # 4. GeoIP lookup (fallback)
            
            # First, check for flag in original name only (no server GeoIP)
            flag_from_name = NameTransformer.identify_flag(original_name, None)  # Don't use server for GeoIP
            
            if flag_from_name and flag_from_name != '🔰':
                # Found flag/keyword in original name - use it!
                code = GeoIPService.flag_to_iso(flag_from_name)
                if code:
                    node_data['region'] = {
                        'country': COUNTRY_NAMES.get(code, code),
                        'country_code': code,
                        'flag': flag_from_name
                    }
            else:
                # No flag in name, check geoip cache (from region testing)
                saved_geoip = proxy.get('geoip')
                if saved_geoip and saved_geoip.get('country_code'):
                    node_data['region'] = {
                        'country': saved_geoip.get('country', saved_geoip['country_code']),
                        'country_code': saved_geoip['country_code'],
                        'flag': saved_geoip.get('flag', '')
                    }
                    node_data['detected_region'] = True  # Mark as detected (not from name)
            
            # Always include city and exit_ip from saved geoip (regardless of flag source)
            saved_geoip = proxy.get('geoip')
            if saved_geoip:
                if saved_geoip.get('city'):
                    node_data['city'] = saved_geoip['city']
                if saved_geoip.get('exit_ip'):
                    node_data['exit_ip'] = saved_geoip['exit_ip']
            
            # Add port mapping info if exists
            if final_name in port_mappings:
                node_data['mapped_port'] = port_mappings[final_name]
            
            # Add saved latency and speed
            if 'last_latency' in proxy:
                node_data['last_latency'] = proxy['last_latency']
            if 'last_speed' in proxy:
                node_data['last_speed'] = proxy['last_speed']
            if 'last_peak_speed' in proxy:
                node_data['last_peak_speed'] = proxy['last_peak_speed']
            
            enhanced_nodes.append(node_data)
        
        return {"nodes": enhanced_nodes, "count": len(enhanced_nodes)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/subscriptions/{sub_id}/nodes/{node_index}")
def update_subscription_node(sub_id: str, node_index: int, data: UpdateSubNode, _: bool = Depends(verify_session)):
    filepath = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Subscription file not found")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        
        proxies = cfg.get('proxies', [])
        if node_index < 0 or node_index >= len(proxies):
            raise HTTPException(status_code=404, detail="Node not found")
        
        proxies[node_index]['name'] = data.name
        cfg['proxies'] = proxies
        
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)
        
        return {"status": "success", "node": proxies[node_index]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/subscriptions/{sub_id}/nodes/{node_index}/full")
def update_subscription_node_full(sub_id: str, node_index: int, data: UpdateSubNodeFull, _: bool = Depends(verify_session)):
    filepath = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Subscription file not found")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        
        proxies = cfg.get('proxies', [])
        if node_index < 0 or node_index >= len(proxies):
            raise HTTPException(status_code=404, detail="Node not found")
        
        node = data.node
        if not all(node.get(k) for k in ['name', 'type', 'server', 'port']):
            raise HTTPException(status_code=400, detail="Missing required fields: name, type, server, port")
        
        proxies[node_index] = node
        cfg['proxies'] = proxies
        
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)
        
        return {"status": "success", "node": node}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/subscriptions/{sub_id}/nodes/{node_index}")
def delete_subscription_node(sub_id: str, node_index: int, _: bool = Depends(verify_session)):
    filepath = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Subscription file not found")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        
        proxies = cfg.get('proxies', [])
        if node_index < 0 or node_index >= len(proxies):
            raise HTTPException(status_code=404, detail="Node not found")
        
        deleted_node = proxies.pop(node_index)
        cfg['proxies'] = proxies
        
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)
        
        config = load_config()
        for s in config['subscriptions']:
            if s['id'] == sub_id:
                s['node_count'] = len(proxies)
                break
        save_config(config)
        
        return {"status": "success", "deleted": deleted_node['name'], "remaining": len(proxies)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class ReorderSubNodes(BaseModel):
    order: List  # List of node indices in new order (accept any type, convert to int)

# Subscription node reorder API removed - only custom nodes support reordering

# ==================== Custom Node API ====================

@app.get("/api/custom-nodes")
def get_custom_nodes(_: bool = Depends(verify_session)):
    config = load_config()
    nodes = config.get('custom_nodes', [])
    port_mappings = config.get('port_mappings', {})  # {final_name: port}
    
    # Enhance each node with final_name and region
    enhanced_nodes = []
    for node in nodes:
        node_data = dict(node)  # Copy original data
        server = node.get('server', '')
        original_name = node.get('name', '')
        
        # Generate final name using NameTransformer (use 'Custom' as source)
        transformed = NameTransformer.transform_name(node, 'Custom')
        final_name = transformed.get('name', original_name)
        node_data['final_name'] = final_name
        
        # Generate display name (clean name without flag for UI display)
        display_name = NameTransformer.remove_flags(original_name)
        node_data['display_name'] = display_name
        
        # Get region info - STRICT priority:
        # 1. Flag emoji in ORIGINAL name - most reliable
        # 2. Keywords in original name
        # 3. Saved geoip cache (from region testing)
        
        # First, check for flag in original name only (no server GeoIP)
        flag_from_name = NameTransformer.identify_flag(original_name, None)
        
        if flag_from_name and flag_from_name != '🔰':
            # Found flag/keyword in original name - use it!
            code = GeoIPService.flag_to_iso(flag_from_name)
            if code:
                node_data['region'] = {
                    'country': COUNTRY_NAMES.get(code, code),
                    'country_code': code,
                    'flag': flag_from_name
                }
        else:
            # No flag in name, check geoip cache
            saved_geoip = node.get('geoip')
            if saved_geoip and saved_geoip.get('country_code'):
                node_data['region'] = {
                    'country': saved_geoip.get('country', saved_geoip['country_code']),
                    'country_code': saved_geoip['country_code'],
                    'flag': saved_geoip.get('flag', '')
                }
                node_data['detected_region'] = True
        
        # Add port mapping info if exists
        if final_name in port_mappings:
            node_data['mapped_port'] = port_mappings[final_name]
        
        # Add saved test results (city, exit_ip, latency, speed)
        saved_geoip = node.get('geoip', {})
        if saved_geoip:
            node_data['city'] = saved_geoip.get('city')
            node_data['exit_ip'] = saved_geoip.get('exit_ip')
        
        # Add saved latency and speed
        if 'last_latency' in node:
            node_data['last_latency'] = node['last_latency']
        if 'last_speed' in node:
            node_data['last_speed'] = node['last_speed']
        if 'last_peak_speed' in node:
            node_data['last_peak_speed'] = node['last_peak_speed']
        
        enhanced_nodes.append(node_data)
    
    return {"nodes": enhanced_nodes, "count": len(enhanced_nodes)}

@app.post("/api/custom-nodes")
def add_custom_node(data: CustomNode, _: bool = Depends(verify_session)):
    proxy = parse_node_link(data.link)
    if not proxy:
        raise HTTPException(status_code=400, detail="Cannot parse node link, supported: vless://, vmess://, ss://, ssr://, trojan://, hysteria://, hy://, hysteria2://, hy2://, tuic://, anytls://, wireguard://, wg://, socks5://, socks5+tls://, http://, https://, snell://")
    
    if data.name:
        proxy['name'] = data.name
    
    # Store full proxy config, not just basic fields
    node = {
        'id': f"node_{int(time.time() * 1000)}",
        'link': data.link,
        **proxy  # Include all parsed proxy fields (name, type, server, port, uuid, password, etc.)
    }
    
    config = load_config()
    config['custom_nodes'].append(node)
    save_config(config)
    update_custom_nodes_yaml()
    
    return {"status": "success", "node": node}

@app.delete("/api/custom-nodes/{node_id}")
def delete_custom_node(node_id: str, _: bool = Depends(verify_session)):
    config = load_config()
    config['custom_nodes'] = [n for n in config['custom_nodes'] if n['id'] != node_id]
    save_config(config)
    update_custom_nodes_yaml()
    return {"status": "success"}

class ReorderNodes(BaseModel):
    order: List[str]  # List of node IDs in new order

@app.put("/api/custom-nodes/reorder")
def reorder_custom_nodes(data: ReorderNodes, _: bool = Depends(verify_session)):
    """Reorder custom nodes"""
    config = load_config()
    nodes = config.get('custom_nodes', [])
    
    # Create a map of id -> node
    node_map = {n['id']: n for n in nodes}
    
    # Reorder based on the provided order
    new_nodes = []
    for node_id in data.order:
        if node_id in node_map:
            new_nodes.append(node_map[node_id])
    
    # Add any nodes not in the order list at the end
    for node in nodes:
        if node['id'] not in data.order:
            new_nodes.append(node)
    
    config['custom_nodes'] = new_nodes
    save_config(config)
    update_custom_nodes_yaml()
    return {"status": "success"}

@app.post("/api/custom-nodes/reparse")
def reparse_all_custom_nodes(_: bool = Depends(verify_session)):
    """Re-parse all custom nodes from their original links to update full config"""
    config = load_config()
    updated_count = 0
    
    for node in config.get('custom_nodes', []):
        if 'link' in node:
            proxy = parse_node_link(node['link'])
            if proxy:
                # Keep id and link, update everything else
                node_id = node['id']
                link = node['link']
                node.clear()
                node['id'] = node_id
                node['link'] = link
                node.update(proxy)
                updated_count += 1
    
    save_config(config)
    update_custom_nodes_yaml()
    return {"status": "success", "updated": updated_count}

@app.post("/api/custom-nodes/{node_id}/reparse")
def reparse_custom_node(node_id: str, _: bool = Depends(verify_session)):
    """Re-parse a single custom node from its original link"""
    config = load_config()
    
    for node in config.get('custom_nodes', []):
        if node['id'] == node_id and 'link' in node:
            proxy = parse_node_link(node['link'])
            if proxy:
                link = node['link']
                node.clear()
                node['id'] = node_id
                node['link'] = link
                node.update(proxy)
                save_config(config)
                update_custom_nodes_yaml()
                return {"status": "success", "node": node}
            else:
                raise HTTPException(status_code=400, detail="Failed to parse node link")
    
    raise HTTPException(status_code=404, detail="Node not found")

@app.put("/api/custom-nodes/{node_id}")
def update_custom_node(node_id: str, data: UpdateNodeName, _: bool = Depends(verify_session)):
    config = load_config()
    for node in config['custom_nodes']:
        if node['id'] == node_id:
            node['name'] = data.name
            save_config(config)
            update_custom_nodes_yaml()
            return {"status": "success", "node": node}
    raise HTTPException(status_code=404, detail="Node not found")

@app.put("/api/custom-nodes/{node_id}/full")
def update_custom_node_full(node_id: str, data: UpdateNodeFull, _: bool = Depends(verify_session)):
    config = load_config()
    for i, node in enumerate(config['custom_nodes']):
        if node['id'] == node_id:
            new_node = data.node
            
            # Update all fields from the new node data
            # Keep id and link (link will be regenerated)
            node_id_val = node['id']
            
            # Clear old proxy fields and update with new ones
            keys_to_keep = ['id', 'geoip']  # Keep id and cached geoip
            old_geoip = node.get('geoip')
            
            # Update node with all new proxy fields
            node.clear()
            node['id'] = node_id_val
            if old_geoip:
                node['geoip'] = old_geoip
            
            # Copy all fields from new_node
            for key, value in new_node.items():
                node[key] = value
            
            # Convert the updated proxy config back to link format and save it
            # This ensures edits persist even after refresh
            new_link = proxy_to_link(new_node)
            if new_link:
                node['link'] = new_link
            
            save_config(config)
            
            # Update yaml
            nodes = config['custom_nodes']
            proxies = []
            for j, n in enumerate(nodes):
                if j == i:
                    proxies.append(new_node)
                else:
                    proxy = parse_node_link(n.get('link', ''))
                    if proxy:
                        proxy['name'] = n.get('name', proxy.get('name', ''))
                        proxies.append(proxy)
                    else:
                        # Fallback: use stored node data
                        proxies.append({k: v for k, v in n.items() if k not in ['id', 'link', 'geoip']})
            
            with open(os.path.join(YAML_SOURCE_DIR, 'custom_nodes.yaml'), 'w', encoding='utf-8') as f:
                yaml.dump({'proxies': proxies}, f, allow_unicode=True, sort_keys=False)
            
            return {"status": "success", "node": node}
    raise HTTPException(status_code=404, detail="Node not found")

# ==================== Port Mapping API ====================

def get_all_final_node_names() -> set:
    """Get a set of all current final node names (for validation)"""
    config = load_config()
    names = set()
    
    # Get subscription nodes
    for sub in config.get('subscriptions', []):
        if sub.get('enabled', True):
            filepath = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        cfg = yaml.safe_load(f)
                    for proxy in cfg.get('proxies', []) if cfg else []:
                        transformed = NameTransformer.transform_name(proxy, sub['name'])
                        names.add(transformed.get('name', ''))
                except:
                    pass
    
    # Get custom nodes
    for node in config.get('custom_nodes', []):
        transformed = NameTransformer.transform_name(node, 'Custom')
        names.add(transformed.get('name', ''))
    
    return names

@app.get("/api/port-mappings")
def get_port_mappings(_: bool = Depends(verify_session)):
    """Get all port mappings with status (active/orphan)"""
    config = load_config()
    mappings = config.get('port_mappings', {})  # {final_name: port}
    
    # Get current valid node names
    valid_names = get_all_final_node_names()
    
    result = []
    for final_name, port in mappings.items():
        result.append({
            "final_name": final_name,
            "port": port,
            "active": final_name in valid_names  # True if node still exists
        })
    
    # Sort by port
    result.sort(key=lambda x: x['port'])
    return {"mappings": result}

@app.post("/api/port-mappings")
def create_port_mapping(data: PortMappingCreate, _: bool = Depends(verify_session)):
    """Create or update a port mapping. Implements 'takeover' logic for orphan ports."""
    config = load_config()
    if 'port_mappings' not in config:
        config['port_mappings'] = {}
    
    mappings = config['port_mappings']
    valid_names = get_all_final_node_names()
    
    # Validate port range
    if data.port < 1024 or data.port > 65535:
        raise HTTPException(status_code=400, detail="Port must be between 1024 and 65535")
    
    # Check if port is already used
    existing_name = None
    for name, port in mappings.items():
        if port == data.port:
            existing_name = name
            break
    
    if existing_name:
        # Port is already mapped
        if existing_name == data.final_name:
            # Same mapping, no change needed
            return {"status": "success", "message": "Mapping already exists", "final_name": data.final_name, "port": data.port}
        elif existing_name not in valid_names:
            # Old node doesn't exist anymore - takeover allowed
            del mappings[existing_name]
        else:
            # Old node still exists - reject
            raise HTTPException(status_code=409, detail=f"Port {data.port} is already mapped to '{existing_name}'")
    
    # Check if this node already has a mapping (update case)
    if data.final_name in mappings:
        old_port = mappings[data.final_name]
        mappings[data.final_name] = data.port
        save_config(config)
        return {"status": "success", "message": f"Updated port from {old_port} to {data.port}", "final_name": data.final_name, "port": data.port}
    
    # Create new mapping
    mappings[data.final_name] = data.port
    save_config(config)
    return {"status": "success", "message": "Mapping created", "final_name": data.final_name, "port": data.port}

@app.delete("/api/port-mappings/{port}")
def delete_port_mapping_by_port(port: int, _: bool = Depends(verify_session)):
    """Delete a port mapping by port number"""
    config = load_config()
    mappings = config.get('port_mappings', {})
    
    # Find and delete
    for final_name, p in list(mappings.items()):
        if p == port:
            del mappings[final_name]
            save_config(config)
            return {"status": "success", "deleted_name": final_name, "deleted_port": port}
    
    raise HTTPException(status_code=404, detail=f"No mapping found for port {port}")

@app.delete("/api/port-mappings/by-name/{final_name:path}")
def delete_port_mapping_by_name(final_name: str, _: bool = Depends(verify_session)):
    """Delete a port mapping by node name"""
    config = load_config()
    mappings = config.get('port_mappings', {})
    
    if final_name in mappings:
        port = mappings[final_name]
        del mappings[final_name]
        save_config(config)
        return {"status": "success", "deleted_name": final_name, "deleted_port": port}
    
    raise HTTPException(status_code=404, detail=f"No mapping found for node '{final_name}'")

# ==================== Proxy Chain API ====================

def get_all_available_nodes() -> List[dict]:
    """Get all available nodes from subscriptions and custom nodes for chain selection"""
    config = load_config()
    nodes = []
    
    # Info node keywords to filter out
    info_keywords = [
        '剩余流量', '套餐到期', '距离下次重置', '建议', '官网', '未到期',
        '剩余', '到期', '重置', '流量', '过期', '订阅', '网址', '公告',
        '群组', 'Telegram', 'TG', '客服', '续费', '购买', '套餐',
        '使用说明', '教程', '更新', '通知', '邀请', '返利'
    ]
    
    def is_info_node(name: str) -> bool:
        if not name:
            return True
        return any(kw in name for kw in info_keywords)
    
    # Get custom nodes FIRST (they should appear at the top)
    for idx, node in enumerate(config.get('custom_nodes', [])):
        original_name = node.get('name', f'Custom Node {idx}')
        if is_info_node(original_name):
            continue
        # Transform name to get final name with flag
        transformed = NameTransformer.transform_name(node, 'Custom')
        final_name = transformed.get('name', original_name)
        nodes.append({
            'sub_id': 'custom',
            'sub_name': '自建节点',
            'node_index': idx,
            'node_name': final_name,  # Use transformed name with flag
            'node_type': node.get('type', 'unknown'),
            'server': node.get('server', '')
        })
    
    # Get nodes from subscriptions
    for sub in config.get('subscriptions', []):
        if not sub.get('enabled', True):
            continue
        filepath = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    cfg = yaml.safe_load(f)
                proxies = cfg.get('proxies', []) if cfg else []
                for idx, proxy in enumerate(proxies):
                    original_name = proxy.get('name', f'Node {idx}')
                    if is_info_node(original_name):
                        continue
                    # Transform name to get final name with flag
                    transformed = NameTransformer.transform_name(proxy, sub['name'])
                    final_name = transformed.get('name', original_name)
                    nodes.append({
                        'sub_id': sub['id'],
                        'sub_name': sub['name'],
                        'node_index': idx,
                        'node_name': final_name,  # Use transformed name with flag
                        'node_type': proxy.get('type', 'unknown'),
                        'server': proxy.get('server', '')
                    })
            except:
                pass
    
    return nodes

def find_node_by_reference(sub_id: str, node_index: int) -> Optional[dict]:
    """Find a node by subscription ID and index"""
    config = load_config()
    
    if sub_id == 'custom':
        custom_nodes = config.get('custom_nodes', [])
        if 0 <= node_index < len(custom_nodes):
            return custom_nodes[node_index]
    else:
        filepath = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    cfg = yaml.safe_load(f)
                proxies = cfg.get('proxies', []) if cfg else []
                if 0 <= node_index < len(proxies):
                    return proxies[node_index]
            except:
                pass
    return None

@app.get("/api/proxy-chains")
def list_proxy_chains(_: bool = Depends(verify_session)):
    """List all proxy chains"""
    config = load_config()
    chains = config.get('proxy_chains', [])
    return {"chains": chains, "count": len(chains)}

@app.get("/api/proxy-chains/available-nodes")
def get_available_nodes_for_chain(_: bool = Depends(verify_session)):
    """Get all available nodes for chain selection"""
    nodes = get_all_available_nodes()
    return {"nodes": nodes, "count": len(nodes)}

@app.post("/api/proxy-chains")
def create_proxy_chain(data: CreateProxyChain, _: bool = Depends(verify_session)):
    """Create a new proxy chain"""
    config = load_config()
    
    # Validate chain has at least one row with at least 2 nodes
    if not data.rows or len(data.rows) == 0:
        raise HTTPException(status_code=400, detail="Chain must have at least one row")
    
    for row in data.rows:
        if not row.nodes or len(row.nodes) < 2:
            raise HTTPException(status_code=400, detail="Each row must have at least 2 nodes")
    
    # Create chain object
    chain = {
        'id': f"chain_{int(time.time() * 1000)}",
        'name': data.name.strip(),
        'rows': [{'nodes': [n.dict() for n in row.nodes]} for row in data.rows],
        'enabled': True,
        'created_at': int(time.time())
    }
    
    if 'proxy_chains' not in config:
        config['proxy_chains'] = []
    config['proxy_chains'].append(chain)
    save_config(config)
    
    return {"status": "success", "chain": chain}

@app.get("/api/proxy-chains/{chain_id}")
def get_proxy_chain(chain_id: str, _: bool = Depends(verify_session)):
    """Get a specific proxy chain"""
    config = load_config()
    for chain in config.get('proxy_chains', []):
        if chain['id'] == chain_id:
            return {"chain": chain}
    raise HTTPException(status_code=404, detail="Proxy chain not found")

@app.put("/api/proxy-chains/{chain_id}")
def update_proxy_chain(chain_id: str, data: UpdateProxyChain, _: bool = Depends(verify_session)):
    """Update a proxy chain"""
    config = load_config()
    
    for chain in config.get('proxy_chains', []):
        if chain['id'] == chain_id:
            if data.name is not None:
                chain['name'] = data.name.strip()
            if data.rows is not None:
                # Validate rows
                for row in data.rows:
                    if not row.nodes or len(row.nodes) < 2:
                        raise HTTPException(status_code=400, detail="Each row must have at least 2 nodes")
                chain['rows'] = [{'nodes': [n.dict() for n in row.nodes]} for row in data.rows]
            if data.enabled is not None:
                chain['enabled'] = data.enabled
            
            save_config(config)
            return {"status": "success", "chain": chain}
    
    raise HTTPException(status_code=404, detail="Proxy chain not found")

@app.put("/api/proxy-chains/{chain_id}/toggle")
def toggle_proxy_chain(chain_id: str, _: bool = Depends(verify_session)):
    """Toggle proxy chain enabled status"""
    config = load_config()
    
    for chain in config.get('proxy_chains', []):
        if chain['id'] == chain_id:
            chain['enabled'] = not chain.get('enabled', True)
            save_config(config)
            return {"status": "success", "enabled": chain['enabled']}
    
    raise HTTPException(status_code=404, detail="Proxy chain not found")

@app.delete("/api/proxy-chains/{chain_id}")
def delete_proxy_chain(chain_id: str, _: bool = Depends(verify_session)):
    """Delete a proxy chain"""
    config = load_config()
    chains = config.get('proxy_chains', [])
    
    original_count = len(chains)
    config['proxy_chains'] = [c for c in chains if c['id'] != chain_id]
    
    if len(config['proxy_chains']) == original_count:
        raise HTTPException(status_code=404, detail="Proxy chain not found")
    
    save_config(config)
    return {"status": "success"}

class ReorderProxyChains(BaseModel):
    order: List[str]

@app.put("/api/proxy-chains/reorder")
def reorder_proxy_chains(data: ReorderProxyChains, _: bool = Depends(verify_session)):
    """Reorder proxy chains"""
    config = load_config()
    chains = config.get('proxy_chains', [])
    
    # Create a map of id -> chain
    chain_map = {c['id']: c for c in chains}
    
    # Reorder based on provided order
    new_chains = []
    for chain_id in data.order:
        if chain_id in chain_map:
            new_chains.append(chain_map[chain_id])
    
    # Add any chains not in the order list at the end
    for chain in chains:
        if chain['id'] not in data.order:
            new_chains.append(chain)
    
    config['proxy_chains'] = new_chains
    save_config(config)
    return {"status": "success"}

# ==================== User Management API ====================

@app.get("/api/users")
def list_users(_: bool = Depends(verify_session)):
    """List all users"""
    config = load_config()
    users = config.get('users', [])
    # Don't expose tokens in list view
    return {"users": [{**u, 'token': u['token'][:8] + '...'} for u in users]}

@app.get("/api/users/{user_id}")
def get_user(user_id: str, _: bool = Depends(verify_session)):
    """Get user details including full token"""
    config = load_config()
    for user in config.get('users', []):
        if user['id'] == user_id:
            return {"user": user}
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/api/users")
def create_user(data: CreateUser, _: bool = Depends(verify_session)):
    """Create a new user"""
    config = load_config()
    
    user_id = f"user_{int(time.time() * 1000)}"
    user = {
        'id': user_id,
        'name': data.name,
        'token': generate_token(),
        'enabled': True,
        'expire_time': data.expire_time,  # 0 = never expire
        'created_at': int(time.time()),
        'allocations': {},  # {sub_id: [node_names] or ["*"] for all}
        'template_id': 'builtin',  # Default to built-in template
        'group_config': {}  # User's custom node configuration for editable groups
    }
    
    if 'users' not in config:
        config['users'] = []
    config['users'].append(user)
    save_config(config)
    
    return {"status": "success", "user": user}

@app.put("/api/users/{user_id}")
def update_user(user_id: str, data: UpdateUser, _: bool = Depends(verify_session)):
    """Update user info"""
    config = load_config()
    for user in config.get('users', []):
        if user['id'] == user_id:
            if data.name is not None:
                user['name'] = data.name
            if data.expire_time is not None:
                user['expire_time'] = data.expire_time
            if data.enabled is not None:
                user['enabled'] = data.enabled
            if data.template_id is not None:
                # Validate template exists
                if data.template_id != 'builtin':
                    templates = config.get('templates', [])
                    if not any(t['id'] == data.template_id for t in templates):
                        raise HTTPException(status_code=400, detail="Template not found")
                user['template_id'] = data.template_id
            if data.sub_name is not None:
                user['sub_name'] = data.sub_name
            if data.sub_filename is not None:
                user['sub_filename'] = data.sub_filename
            # Invalidate cache when settings change
            if 'sub_cache' in user:
                del user['sub_cache']
            save_config(config)
            return {"status": "success", "user": user}
    raise HTTPException(status_code=404, detail="User not found")

@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, _: bool = Depends(verify_session)):
    """Delete a user"""
    config = load_config()
    users = config.get('users', [])
    config['users'] = [u for u in users if u['id'] != user_id]
    save_config(config)
    return {"status": "success"}

class RegenerateTokenRequest(BaseModel):
    custom_token: Optional[str] = None

@app.post("/api/users/{user_id}/regenerate-token")
def regenerate_user_token(user_id: str, data: RegenerateTokenRequest = None, _: bool = Depends(verify_session)):
    """Regenerate user's subscription token, optionally with a custom token"""
    config = load_config()
    for user in config.get('users', []):
        if user['id'] == user_id:
            if data and data.custom_token and len(data.custom_token.strip()) >= 8:
                user['token'] = data.custom_token.strip()
            else:
                user['token'] = generate_token()
            save_config(config)
            return {"status": "success", "token": user['token']}
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/api/users/{user_id}/reset-group-config")
def reset_user_group_config(user_id: str, _: bool = Depends(verify_session)):
    """Reset user's group configuration (clear all saved settings)"""
    config = load_config()
    for user in config.get('users', []):
        if user['id'] == user_id:
            # Clear group_config
            user['group_config'] = {}
            # Invalidate subscription cache
            if 'sub_cache' in user:
                del user['sub_cache']
            save_config(config)
            return {"status": "success", "message": "组配置已重置"}
    raise HTTPException(status_code=404, detail="User not found")

@app.get("/api/users/{user_id}/group-config")
def get_user_group_config(user_id: str, _: bool = Depends(verify_session)):
    """Get user's group configuration for visual editor
    
    Returns:
        - template_id: User's template ID
        - template_name: Template name
        - groups: List of proxy groups with editable flag and available nodes
    """
    config = load_config()
    
    # Find user
    user = next((u for u in config.get('users', []) if u['id'] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get template
    template_id = user.get('template_id', 'builtin')
    if template_id == 'builtin':
        template = get_builtin_template()
    else:
        template = next((t for t in config.get('templates', []) if t['id'] == template_id), None)
        if not template:
            # Fallback to builtin
            template = get_builtin_template()
            template_id = 'builtin'
    
    # Auto-migrate: Add _editable: true to all groups if not present
    template_proxy_groups = template.get('proxy_groups', [])
    if template_proxy_groups and isinstance(template_proxy_groups, list):
        needs_migration = False
        for group in template_proxy_groups:
            if isinstance(group, dict) and '_editable' not in group:
                group['_editable'] = True
                needs_migration = True
        
        # Save the migration if needed (only for custom templates)
        if needs_migration and template_id != 'builtin':
            template['proxy_groups'] = template_proxy_groups
            save_config(config)
    
    # Get user's available nodes (based on allocations)
    available_nodes = []
    user_allocations = user.get('allocations', {})
    
    # 1. Load nodes from subscriptions
    for sub in config.get('subscriptions', []):
        if not sub.get('enabled', True):
            continue
        
        sub_id = sub['id']
        allocation = user_allocations.get(sub_id, [])
        
        # Skip if user has no allocation for this subscription
        if not allocation:
            continue
        
        # Load subscription nodes
        sub_file = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
        if os.path.exists(sub_file):
            try:
                with open(sub_file, 'r', encoding='utf-8') as f:
                    sub_data = yaml.safe_load(f)
                    proxies = sub_data.get('proxies', [])
                    
                    for proxy in proxies:
                        node_name = proxy.get('name', '')
                        if not node_name:
                            continue
                        
                        # Use NameTransformer to get the final transformed name (same as in subscription generation)
                        from merge_config import NameTransformer
                        transformed = NameTransformer.transform_name(proxy, sub['name'])
                        final_name = transformed.get('name', node_name)
                        
                        # Check if user has access to this node (check against original name)
                        if allocation == ["*"] or node_name in allocation or final_name in allocation:
                            available_nodes.append(final_name)
            except:
                pass
    
    # 2. Load custom nodes if allocated
    custom_allocation = user_allocations.get('custom_nodes', [])
    if custom_allocation:
        custom_nodes = config.get('custom_nodes', [])
        for custom_node in custom_nodes:
            node_name = custom_node.get('name', '')
            if not node_name:
                continue
            
            # Use NameTransformer to get the final transformed name (same as in subscription generation)
            from merge_config import NameTransformer
            transformed = NameTransformer.transform_name(custom_node, 'Custom')
            final_name = transformed.get('name', node_name)
            
            # Check if user has access to this custom node
            if custom_allocation == ["*"] or node_name in custom_allocation:
                available_nodes.append(final_name)
    
    # 3. Add DIRECT and REJECT as special nodes (always available)
    special_nodes = ["DIRECT", "REJECT"]
    all_available_nodes = special_nodes + available_nodes
    
    # Get user's current group config
    group_config = user.get('group_config', {})
    
    # Build groups list
    groups = []
    # Get proxy-groups from template's proxy_groups field (not from header)
    template_proxy_groups = template.get('proxy_groups', [])
    if template_proxy_groups and isinstance(template_proxy_groups, list):
        for group in template_proxy_groups:
            if not isinstance(group, dict):
                continue
            
            group_name = group.get('name', '')
            group_type = group.get('type', 'select')
            # All groups are editable by default (unless explicitly marked as false)
            editable = group.get('_editable', True)
            icon = group.get('_icon', '')
            description = group.get('_description', '')
            
            # Get current nodes for this group
            if group_name in group_config:
                # User has configured this group - use their selection
                current_nodes = group_config[group_name]
            else:
                # User hasn't configured this group yet
                # Default: only actual proxy nodes (not DIRECT/REJECT)
                # DIRECT and REJECT should be explicitly selected by user
                current_nodes = available_nodes.copy() if editable else []
            
            groups.append({
                'name': group_name,
                'type': group_type,
                'editable': editable,
                'icon': icon,
                'description': description,
                'current_nodes': current_nodes,
                'available_nodes': all_available_nodes if editable else []
            })
    
    return {
        'template_id': template_id,
        'template_name': template.get('name', 'Built-in Template'),
        'groups': groups
    }

@app.put("/api/users/{user_id}/group-config")
def update_user_group_config(user_id: str, data: UpdateUserGroupConfig, _: bool = Depends(verify_session)):
    """Update user's group configuration"""
    config = load_config()
    
    for user in config.get('users', []):
        if user['id'] == user_id:
            user['group_config'] = data.group_config
            # Invalidate user's subscription cache when config changes
            if 'sub_cache' in user:
                del user['sub_cache']
            save_config(config)
            return {"status": "success", "message": "配置已保存"}
    
    raise HTTPException(status_code=404, detail="User not found")

@app.get("/api/users/{user_id}/preview-yaml")
def preview_user_yaml(user_id: str, _: bool = Depends(verify_session)):
    """Preview YAML configuration for user based on their group config"""
    config = load_config()
    
    # Find user
    user = next((u for u in config.get('users', []) if u['id'] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get template
    template_id = user.get('template_id', 'builtin')
    if template_id == 'builtin':
        template = get_builtin_template()
    else:
        template = next((t for t in config.get('templates', []) if t['id'] == template_id), None)
        if not template:
            template = get_builtin_template()
    
    # Get user's group config
    group_config = user.get('group_config', {})
    
    # Get user's available nodes (for preview)
    available_nodes = []
    user_allocations = user.get('allocations', {})
    
    # 1. Load nodes from subscriptions
    for sub in config.get('subscriptions', []):
        if not sub.get('enabled', True):
            continue
        sub_id = sub['id']
        allocation = user_allocations.get(sub_id, [])
        
        # Skip if user has no allocation for this subscription
        if not allocation:
            continue
        
        sub_file = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
        if os.path.exists(sub_file):
            try:
                with open(sub_file, 'r', encoding='utf-8') as f:
                    sub_data = yaml.safe_load(f)
                    proxies = sub_data.get('proxies', [])
                    for proxy in proxies:
                        node_name = proxy.get('name', '')
                        if not node_name:
                            continue
                        prefix = sub.get('prefix', '')
                        final_name = f"{prefix}{node_name}" if prefix else node_name
                        if allocation == ["*"] or node_name in allocation or final_name in allocation:
                            available_nodes.append(final_name)
            except:
                pass
    
    # 2. Load custom nodes if allocated
    custom_allocation = user_allocations.get('custom_nodes', [])
    if custom_allocation:
        custom_nodes = config.get('custom_nodes', [])
        for custom_node in custom_nodes:
            node_name = custom_node.get('name', '')
            if not node_name:
                continue
            
            # Check if user has access to this custom node
            if custom_allocation == ["*"] or node_name in custom_allocation:
                available_nodes.append(node_name)
    
    # Get proxy-groups from template's proxy_groups field (not from header)
    try:
        template_proxy_groups = template.get('proxy_groups', [])
        if not template_proxy_groups or not isinstance(template_proxy_groups, list):
            return {"yaml": "# No proxy-groups found in template"}
        
        # Apply user's group config
        proxy_groups = []
        for group in template_proxy_groups:
            if not isinstance(group, dict):
                continue
            
            # Create a copy to avoid modifying the template
            group_copy = dict(group)
            group_name = group_copy.get('name', '')
            
            # If user configured this group, use user's selection
            if group_name in group_config and group_config[group_name]:
                # User has configured this group - use their selection
                # Their selection may include DIRECT/REJECT if they chose them
                group_copy['proxies'] = group_config[group_name]
            else:
                # No user config - default to only actual proxy nodes (not DIRECT/REJECT)
                # DIRECT and REJECT should be explicitly selected by user
                group_copy['proxies'] = available_nodes
            
            # Remove underscore fields for preview
            group_copy.pop('_editable', None)
            group_copy.pop('_icon', None)
            group_copy.pop('_description', None)
            
            proxy_groups.append(group_copy)
        
        # Generate YAML preview (only proxy-groups section)
        preview_data = {'proxy-groups': proxy_groups}
        yaml_preview = yaml.dump(preview_data, allow_unicode=True, sort_keys=False, default_flow_style=False)
        
        return {"yaml": yaml_preview}
    except Exception as e:
        return {"yaml": f"# Error generating preview: {str(e)}"}


@app.put("/api/users/{user_id}/allocations")
def update_user_allocations(user_id: str, data: UserNodeAllocation, _: bool = Depends(verify_session)):
    """Update user's node allocations
    
    data.subscriptions format:
    {
        "sub_id_1": ["*"],  # All nodes from this subscription
        "sub_id_2": ["node_name_1", "node_name_2"],  # Specific nodes
        "custom_nodes": ["node_name_3"]  # Custom nodes
    }
    """
    config = load_config()
    for user in config.get('users', []):
        if user['id'] == user_id:
            user['allocations'] = data.subscriptions
            # Invalidate user's subscription cache when allocations change
            if 'sub_cache' in user:
                del user['sub_cache']
            save_config(config)
            return {"status": "success", "allocations": user['allocations']}
    raise HTTPException(status_code=404, detail="User not found")

@app.get("/api/users/{user_id}/allocations")
def get_user_allocations(user_id: str, _: bool = Depends(verify_session)):
    """Get user's current node allocations"""
    config = load_config()
    for user in config.get('users', []):
        if user['id'] == user_id:
            return {"allocations": user.get('allocations', {})}
    raise HTTPException(status_code=404, detail="User not found")

@app.get("/api/available-nodes")
def get_available_nodes(_: bool = Depends(verify_session)):
    """Get all available nodes grouped by subscription for allocation UI"""
    config = load_config()
    result = {}
    
    # Get nodes from each subscription
    for sub in config.get('subscriptions', []):
        if sub.get('enabled'):
            filepath = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                    nodes = data.get('proxies', []) if data else []
                    result[sub['id']] = {
                        'name': sub['name'],
                        'nodes': [n.get('name', f"node_{i}") for i, n in enumerate(nodes)]
                    }
                except:
                    result[sub['id']] = {'name': sub['name'], 'nodes': []}
    
    # Get custom nodes
    custom_nodes = config.get('custom_nodes', [])
    if custom_nodes:
        result['custom_nodes'] = {
            'name': '自定义节点',
            'nodes': [n['name'] for n in custom_nodes]
        }
    
    return {"sources": result}

# ==================== Admin Token Management API ====================

class CreateAdminToken(BaseModel):
    name: str
    template_id: Optional[str] = 'builtin'
    custom_token: Optional[str] = None  # If provided, use this; otherwise generate random
    sub_filename: Optional[str] = None  # Custom filename for this token
    sub_name: Optional[str] = None  # Custom config name for this token

@app.get("/api/admin-tokens")
def list_admin_tokens(_: bool = Depends(verify_session)):
    """List all admin subscription tokens"""
    config = load_config()
    tokens = config.get('admin_tokens', [])
    # Mask token values for list view
    return {"tokens": [{**t, 'token': t['token'][:8] + '...' if len(t['token']) > 8 else t['token']} for t in tokens]}

@app.get("/api/admin-tokens/{token_id}")
def get_admin_token(token_id: str, _: bool = Depends(verify_session)):
    """Get admin token details including full token"""
    config = load_config()
    for t in config.get('admin_tokens', []):
        if t['id'] == token_id:
            return {"token": t}
    raise HTTPException(status_code=404, detail="Token not found")

@app.post("/api/admin-tokens")
def create_admin_token(data: CreateAdminToken, _: bool = Depends(verify_session)):
    """Create a new admin subscription token"""
    config = load_config()
    
    # Validate template
    if data.template_id and data.template_id != 'builtin':
        templates = config.get('templates', [])
        if not any(t['id'] == data.template_id for t in templates):
            raise HTTPException(status_code=400, detail="Template not found")
    
    # Generate or use custom token
    if data.custom_token and len(data.custom_token.strip()) >= 8:
        token_value = data.custom_token.strip()
    else:
        token_value = generate_token()
    
    token_id = f"atok_{int(time.time() * 1000)}"
    admin_token = {
        'id': token_id,
        'name': data.name,
        'token': token_value,
        'template_id': data.template_id or 'builtin',
        'sub_filename': data.sub_filename or '',
        'sub_name': data.sub_name or '',
        'enabled': True,
        'created_at': int(time.time())
    }
    
    if 'admin_tokens' not in config:
        config['admin_tokens'] = []
    config['admin_tokens'].append(admin_token)
    save_config(config)
    
    return {"status": "success", "token": admin_token}

class UpdateAdminToken(BaseModel):
    name: Optional[str] = None
    template_id: Optional[str] = None
    enabled: Optional[bool] = None
    sub_filename: Optional[str] = None
    sub_name: Optional[str] = None

@app.put("/api/admin-tokens/{token_id}")
def update_admin_token(token_id: str, data: UpdateAdminToken, _: bool = Depends(verify_session)):
    """Update admin token"""
    config = load_config()
    for t in config.get('admin_tokens', []):
        if t['id'] == token_id:
            if data.name is not None:
                t['name'] = data.name
            if data.template_id is not None:
                # Validate template
                if data.template_id != 'builtin':
                    templates = config.get('templates', [])
                    if not any(tpl['id'] == data.template_id for tpl in templates):
                        raise HTTPException(status_code=400, detail="Template not found")
                t['template_id'] = data.template_id
            if data.enabled is not None:
                t['enabled'] = data.enabled
            if data.sub_filename is not None:
                t['sub_filename'] = data.sub_filename
            if data.sub_name is not None:
                t['sub_name'] = data.sub_name
            save_config(config)
            return {"status": "success", "token": t}
    raise HTTPException(status_code=404, detail="Token not found")

@app.delete("/api/admin-tokens/{token_id}")
def delete_admin_token(token_id: str, _: bool = Depends(verify_session)):
    """Delete admin token"""
    config = load_config()
    tokens = config.get('admin_tokens', [])
    config['admin_tokens'] = [t for t in tokens if t['id'] != token_id]
    save_config(config)
    return {"status": "success"}

@app.get("/api/admin-tokens/{token_id}/group-config")
def get_admin_token_group_config(token_id: str, _: bool = Depends(verify_session)):
    """Get admin token's group configuration for visual editor (reuse user logic)"""
    config = load_config()
    
    # Find admin token
    token = next((t for t in config.get('admin_tokens', []) if t['id'] == token_id), None)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    
    # Create a fake user object to reuse get_user_group_config logic
    fake_user = {
        'id': token_id,
        'template_id': token.get('template_id', 'builtin'),
        'allocations': {},  # Admin tokens have access to all nodes
        'group_config': token.get('group_config', {})
    }
    
    # Get template
    template_id = fake_user.get('template_id', 'builtin')
    if template_id == 'builtin':
        template = get_builtin_template()
    else:
        template = next((t for t in config.get('templates', []) if t['id'] == template_id), None)
        if not template:
            template = get_builtin_template()
            template_id = 'builtin'
    
    # Auto-migrate: Add _editable: true to all groups if not present
    template_proxy_groups = template.get('proxy_groups', [])
    if template_proxy_groups and isinstance(template_proxy_groups, list):
        needs_migration = False
        for group in template_proxy_groups:
            if isinstance(group, dict) and '_editable' not in group:
                group['_editable'] = True
                needs_migration = True
        
        if needs_migration and template_id != 'builtin':
            template['proxy_groups'] = template_proxy_groups
            save_config(config)
    
    # Get all available nodes (admin tokens have access to all)
    available_nodes = []
    
    # Load all subscription nodes
    for sub in config.get('subscriptions', []):
        if not sub.get('enabled', True):
            continue
        
        sub_file = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
        if os.path.exists(sub_file):
            try:
                with open(sub_file, 'r', encoding='utf-8') as f:
                    sub_data = yaml.safe_load(f)
                    proxies = sub_data.get('proxies', [])
                    
                    for proxy in proxies:
                        node_name = proxy.get('name', '')
                        if not node_name:
                            continue
                        
                        from merge_config import NameTransformer
                        transformed = NameTransformer.transform_name(proxy, sub['name'])
                        final_name = transformed.get('name', node_name)
                        available_nodes.append(final_name)
            except:
                pass
    
    # Load all custom nodes
    custom_nodes = config.get('custom_nodes', [])
    for custom_node in custom_nodes:
        node_name = custom_node.get('name', '')
        if not node_name:
            continue
        
        from merge_config import NameTransformer
        transformed = NameTransformer.transform_name(custom_node, 'Custom')
        final_name = transformed.get('name', node_name)
        available_nodes.append(final_name)
    
    # Add DIRECT and REJECT
    special_nodes = ["DIRECT", "REJECT"]
    all_available_nodes = special_nodes + available_nodes
    
    # Get token's current group config
    group_config = fake_user.get('group_config', {})
    
    # Build groups list
    groups = []
    if template_proxy_groups and isinstance(template_proxy_groups, list):
        for group in template_proxy_groups:
            if not isinstance(group, dict):
                continue
            
            group_name = group.get('name', '')
            group_type = group.get('type', 'select')
            editable = group.get('_editable', True)
            icon = group.get('_icon', '')
            description = group.get('_description', '')
            
            # Get current nodes for this group
            if group_name in group_config:
                current_nodes = group_config[group_name]
            else:
                # Default: only actual proxy nodes (not DIRECT/REJECT)
                current_nodes = available_nodes.copy() if editable else []
            
            groups.append({
                'name': group_name,
                'type': group_type,
                'editable': editable,
                'icon': icon,
                'description': description,
                'current_nodes': current_nodes,
                'available_nodes': all_available_nodes if editable else []
            })
    
    return {
        'template_id': template_id,
        'template_name': template.get('name', '内置模版'),
        'groups': groups
    }

@app.put("/api/admin-tokens/{token_id}/group-config")
def update_admin_token_group_config(token_id: str, data: UpdateUserGroupConfig, _: bool = Depends(verify_session)):
    """Update admin token's group configuration"""
    config = load_config()
    
    for token in config.get('admin_tokens', []):
        if token['id'] == token_id:
            token['group_config'] = data.group_config
            save_config(config)
            return {"status": "success", "message": "配置已保存"}
    
    raise HTTPException(status_code=404, detail="Token not found")

@app.post("/api/admin-tokens/{token_id}/reset-group-config")
def reset_admin_token_group_config(token_id: str, _: bool = Depends(verify_session)):
    """Reset admin token's group configuration (clear all saved settings)"""
    config = load_config()
    
    for token in config.get('admin_tokens', []):
        if token['id'] == token_id:
            # Clear group_config
            token['group_config'] = {}
            save_config(config)
            return {"status": "success", "message": "组配置已重置"}
    
    raise HTTPException(status_code=404, detail="Token not found")

@app.get("/api/admin-tokens/{token_id}/preview-yaml")
def preview_admin_token_yaml(token_id: str, _: bool = Depends(verify_session)):
    """Preview YAML configuration for admin token based on their group config"""
    config = load_config()
    
    # Find token
    token = next((t for t in config.get('admin_tokens', []) if t['id'] == token_id), None)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    
    # Get template
    template_id = token.get('template_id', 'builtin')
    if template_id == 'builtin':
        template = get_builtin_template()
    else:
        template = next((t for t in config.get('templates', []) if t['id'] == template_id), None)
        if not template:
            template = get_builtin_template()
    
    # Get token's group config
    group_config = token.get('group_config', {})
    
    # Get all available nodes (admin has access to all)
    available_nodes = []
    
    for sub in config.get('subscriptions', []):
        if not sub.get('enabled', True):
            continue
        sub_id = sub['id']
        
        sub_file = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
        if os.path.exists(sub_file):
            try:
                with open(sub_file, 'r', encoding='utf-8') as f:
                    sub_data = yaml.safe_load(f)
                    proxies = sub_data.get('proxies', [])
                    for proxy in proxies:
                        node_name = proxy.get('name', '')
                        if not node_name:
                            continue
                        prefix = sub.get('prefix', '')
                        final_name = f"{prefix}{node_name}" if prefix else node_name
                        available_nodes.append(final_name)
            except:
                pass
    
    custom_nodes = config.get('custom_nodes', [])
    for custom_node in custom_nodes:
        node_name = custom_node.get('name', '')
        if not node_name:
            continue
        available_nodes.append(node_name)
    
    # Get proxy-groups from template
    try:
        template_proxy_groups = template.get('proxy_groups', [])
        if not template_proxy_groups or not isinstance(template_proxy_groups, list):
            return {"yaml": "# No proxy-groups found in template"}
        
        # Apply token's group config
        proxy_groups = []
        for group in template_proxy_groups:
            if not isinstance(group, dict):
                continue
            
            group_copy = dict(group)
            group_name = group_copy.get('name', '')
            
            # If token configured this group, use token's selection
            if group_name in group_config and group_config[group_name]:
                group_copy['proxies'] = group_config[group_name]
            else:
                # No config - default to only actual proxy nodes
                group_copy['proxies'] = available_nodes
            
            # Remove underscore fields for preview
            group_copy.pop('_editable', None)
            group_copy.pop('_icon', None)
            group_copy.pop('_description', None)
            
            proxy_groups.append(group_copy)
        
        # Generate YAML preview
        preview_data = {'proxy-groups': proxy_groups}
        yaml_preview = yaml.dump(preview_data, allow_unicode=True, sort_keys=False, default_flow_style=False)
        
        return {"yaml": yaml_preview}
    except Exception as e:
        return {"yaml": f"# Error generating preview: {str(e)}"}

class RegenerateAdminTokenRequest(BaseModel):
    custom_token: Optional[str] = None

@app.post("/api/admin-tokens/{token_id}/regenerate")
def regenerate_admin_token(token_id: str, data: RegenerateAdminTokenRequest = None, _: bool = Depends(verify_session)):
    """Regenerate admin token value"""
    config = load_config()
    for t in config.get('admin_tokens', []):
        if t['id'] == token_id:
            if data and data.custom_token and len(data.custom_token.strip()) >= 8:
                t['token'] = data.custom_token.strip()
            else:
                t['token'] = generate_token()
            save_config(config)
            return {"status": "success", "token": t['token']}
    raise HTTPException(status_code=404, detail="Token not found")

# ==================== Subscription Output API ====================

# ==================== Node to Link Conversion ====================

def proxy_to_link(proxy: dict) -> str:
    """Convert Clash proxy config to node link"""
    proxy_type = proxy.get('type', '')
    name = proxy.get('name', '')
    server = proxy.get('server', '')
    port = proxy.get('port', '')
    
    try:
        if proxy_type == 'vmess':
            # vmess://base64(json)
            vmess_obj = {
                'v': '2',
                'ps': name,
                'add': server,
                'port': str(port),
                'id': proxy.get('uuid', ''),
                'aid': str(proxy.get('alterId', 0)),
                'scy': proxy.get('cipher', 'auto'),
                'net': proxy.get('network', 'tcp'),
                'type': 'none',
            }
            if proxy.get('tls'):
                vmess_obj['tls'] = 'tls'
                if proxy.get('servername'):
                    vmess_obj['sni'] = proxy.get('servername')
            if proxy.get('network') == 'ws':
                ws_opts = proxy.get('ws-opts', {})
                vmess_obj['path'] = ws_opts.get('path', '/')
                if ws_opts.get('headers', {}).get('Host'):
                    vmess_obj['host'] = ws_opts['headers']['Host']
            elif proxy.get('network') == 'grpc':
                grpc_opts = proxy.get('grpc-opts', {})
                vmess_obj['path'] = grpc_opts.get('grpc-service-name', '')
            return 'vmess://' + base64.b64encode(json.dumps(vmess_obj).encode()).decode()
        
        elif proxy_type == 'vless':
            # vless://uuid@server:port?params#name
            params = []
            if proxy.get('network'):
                params.append(f"type={proxy['network']}")
            if proxy.get('tls'):
                if proxy.get('reality-opts'):
                    params.append('security=reality')
                    if proxy['reality-opts'].get('public-key'):
                        params.append(f"pbk={proxy['reality-opts']['public-key']}")
                    if proxy['reality-opts'].get('short-id'):
                        params.append(f"sid={proxy['reality-opts']['short-id']}")
                else:
                    params.append('security=tls')
            if proxy.get('servername'):
                params.append(f"sni={proxy['servername']}")
            if proxy.get('client-fingerprint'):
                params.append(f"fp={proxy['client-fingerprint']}")
            if proxy.get('flow'):
                params.append(f"flow={proxy['flow']}")
            if proxy.get('network') == 'ws':
                ws_opts = proxy.get('ws-opts', {})
                if ws_opts.get('path'):
                    params.append(f"path={quote(ws_opts['path'])}")
                if ws_opts.get('headers', {}).get('Host'):
                    params.append(f"host={ws_opts['headers']['Host']}")
            elif proxy.get('network') == 'grpc':
                grpc_opts = proxy.get('grpc-opts', {})
                if grpc_opts.get('grpc-service-name'):
                    params.append(f"serviceName={grpc_opts['grpc-service-name']}")
            query = '&'.join(params) if params else ''
            return f"vless://{proxy.get('uuid', '')}@{server}:{port}{'?' + query if query else ''}#{quote(name)}"
        
        elif proxy_type == 'ss':
            # ss://base64(method:password)@server:port#name
            method = proxy.get('cipher', '')
            password = proxy.get('password', '')
            userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
            return f"ss://{userinfo}@{server}:{port}#{quote(name)}"
        
        elif proxy_type == 'ssr':
            # ssr://base64(server:port:protocol:method:obfs:base64(password)/?params)
            password_b64 = base64.b64encode(proxy.get('password', '').encode()).decode()
            main = f"{server}:{port}:{proxy.get('protocol', 'origin')}:{proxy.get('cipher', '')}:{proxy.get('obfs', 'plain')}:{password_b64}"
            params = []
            if name:
                params.append(f"remarks={base64.b64encode(name.encode()).decode()}")
            if proxy.get('obfs-param'):
                params.append(f"obfsparam={base64.b64encode(proxy['obfs-param'].encode()).decode()}")
            if proxy.get('protocol-param'):
                params.append(f"protoparam={base64.b64encode(proxy['protocol-param'].encode()).decode()}")
            full = main + ('/?' + '&'.join(params) if params else '')
            return 'ssr://' + base64.b64encode(full.encode()).decode()
        
        elif proxy_type == 'trojan':
            # trojan://password@server:port?params#name
            params = []
            if proxy.get('sni'):
                params.append(f"sni={proxy['sni']}")
            if proxy.get('network') == 'ws':
                params.append('type=ws')
                ws_opts = proxy.get('ws-opts', {})
                if ws_opts.get('path'):
                    params.append(f"path={quote(ws_opts['path'])}")
            elif proxy.get('network') == 'grpc':
                params.append('type=grpc')
            query = '&'.join(params) if params else ''
            return f"trojan://{quote(proxy.get('password', ''))}@{server}:{port}{'?' + query if query else ''}#{quote(name)}"
        
        elif proxy_type == 'hysteria2':
            # hysteria2://password@server:port?params#name
            params = []
            if proxy.get('sni'):
                params.append(f"sni={proxy['sni']}")
            if proxy.get('obfs'):
                params.append(f"obfs={proxy['obfs']}")
                if proxy.get('obfs-password'):
                    params.append(f"obfs-password={proxy['obfs-password']}")
            query = '&'.join(params) if params else ''
            return f"hysteria2://{quote(proxy.get('password', ''))}@{server}:{port}{'?' + query if query else ''}#{quote(name)}"
        
        elif proxy_type == 'tuic':
            # tuic://uuid:password@server:port?params#name
            params = []
            if proxy.get('sni'):
                params.append(f"sni={proxy['sni']}")
            if proxy.get('congestion-controller'):
                params.append(f"congestion_control={proxy['congestion-controller']}")
            query = '&'.join(params) if params else ''
            return f"tuic://{proxy.get('uuid', '')}:{proxy.get('password', '')}@{server}:{port}{'?' + query if query else ''}#{quote(name)}"
        
        elif proxy_type == 'hysteria':
            # hysteria://server:port?params#name
            params = []
            if proxy.get('auth-str'):
                params.append(f"auth={proxy['auth-str']}")
            if proxy.get('sni'):
                params.append(f"peer={proxy['sni']}")
            if proxy.get('up'):
                params.append(f"upmbps={proxy['up']}")
            if proxy.get('down'):
                params.append(f"downmbps={proxy['down']}")
            query = '&'.join(params) if params else ''
            return f"hysteria://{server}:{port}{'?' + query if query else ''}#{quote(name)}"
        
        elif proxy_type == 'socks5':
            # socks5://user:pass@server:port#name
            auth = ''
            if proxy.get('username'):
                auth = f"{quote(proxy['username'])}:{quote(proxy.get('password', ''))}@"
            prefix = 'socks5+tls://' if proxy.get('tls') else 'socks5://'
            return f"{prefix}{auth}{server}:{port}#{quote(name)}"
        
        elif proxy_type == 'http':
            # http://user:pass@server:port#name
            auth = ''
            if proxy.get('username'):
                auth = f"{quote(proxy['username'])}:{quote(proxy.get('password', ''))}@"
            prefix = 'https://' if proxy.get('tls') else 'http://'
            return f"{prefix}{auth}{server}:{port}#{quote(name)}"
        
        else:
            # Unsupported type, return empty
            return ''
    except Exception:
        return ''

@app.get("/sub")
def get_merged_subscription(
    token: Optional[str] = None, 
    format: Optional[str] = None,
    user_agent: Optional[str] = Header(None, alias="User-Agent")
):
    config = load_config()
    auth = config.get('auth', {})
    
    # Check if token is admin token or user token
    is_admin = False
    user_info = None
    user_allocations = None
    template_id = 'builtin'  # Default template
    admin_token_info = None  # Store matched admin token for its settings
    
    # 1. Check legacy admin token (backward compatibility)
    if auth.get('sub_token') and token == auth['sub_token']:
        is_admin = True
        # Legacy admin uses current saved template (if any)
        if 'template' in config:
            template_id = 'legacy'  # Special marker for legacy template
    else:
        # 2. Check new admin tokens
        for admin_token in config.get('admin_tokens', []):
            if admin_token.get('token') == token:
                if not admin_token.get('enabled', True):
                    raise HTTPException(status_code=403, detail="Token is disabled")
                is_admin = True
                template_id = admin_token.get('template_id', 'builtin')
                admin_token_info = admin_token  # Save for later use
                break
        
        # 3. Check user tokens
        if not is_admin:
            for user in config.get('users', []):
                if user.get('token') == token:
                    # Check if user is enabled
                    if not user.get('enabled', True):
                        raise HTTPException(status_code=403, detail="User account is disabled")
                    # Check if user is expired
                    expire_time = user.get('expire_time', 0)
                    if expire_time > 0 and expire_time < time.time():
                        raise HTTPException(status_code=403, detail="Subscription expired")
                    user_info = user
                    user_allocations = user.get('allocations', {})
                    template_id = user.get('template_id', 'builtin')
                    break
        
        if not is_admin and not user_info:
            raise HTTPException(status_code=401, detail="Invalid subscription token")
    
    # Check cache for user subscriptions (admin subscriptions are not cached as they may change frequently)
    if user_info and not format:  # Only cache YAML format
        cache = user_info.get('sub_cache', {})
        cache_time = cache.get('timestamp', 0)
        cache_content = cache.get('content', '')
        cache_headers = cache.get('headers', {})
        
        # Cache is valid for 5 minutes (300 seconds)
        if cache_content and (time.time() - cache_time) < 300:
            print(f"Using cached subscription for user {user_info['name']}")
            return PlainTextResponse(
                cache_content,
                media_type='text/yaml',
                headers=cache_headers
            )
    
    subs = config.get('subscriptions', [])
    enabled_subs = [s for s in subs if s['enabled']]
    custom_nodes = config.get('custom_nodes', [])
    
    # Filter subscriptions based on user allocations
    if user_allocations is not None:
        # User mode: only show allocated subscriptions
        allocated_sub_ids = set(user_allocations.keys()) - {'custom_nodes'}
        enabled_subs = [s for s in enabled_subs if s['id'] in allocated_sub_ids]
        
        # Filter custom nodes if allocated
        if 'custom_nodes' in user_allocations:
            allocated_custom = user_allocations['custom_nodes']
            if allocated_custom != ['*']:
                custom_nodes = [n for n in custom_nodes if n['name'] in allocated_custom]
        else:
            custom_nodes = []  # No custom nodes allocated
    
    if not enabled_subs and not custom_nodes:
        raise HTTPException(status_code=404, detail="No enabled subscriptions or custom nodes")
    
    # Check and auto-refresh missing subscription files
    # This prevents slow first-time access by ensuring files exist
    missing_subs = []
    for sub in enabled_subs:
        filepath = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
        if not os.path.exists(filepath):
            missing_subs.append(sub)
    
    # If there are missing subscription files, fetch them now
    if missing_subs:
        print(f"Auto-refreshing {len(missing_subs)} missing subscription(s)...")
        for sub in missing_subs:
            try:
                content, sub_info, node_count = fetch_subscription(sub['url'])
                sub.update({
                    'upload': sub_info.get('upload', 0),
                    'download': sub_info.get('download', 0),
                    'total': sub_info.get('total', 0),
                    'expire': sub_info.get('expire', 0),
                    'node_count': node_count,
                    'last_update': int(time.time()),
                    'update_status': 'success'
                })
                with open(os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml"), 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"  ✓ Refreshed: {sub['name']}")
            except Exception as e:
                print(f"  ✗ Failed to refresh {sub['name']}: {e}")
                sub['update_status'] = f'error: {str(e)}'
        # Save updated subscription info
        save_config(config)
    
    # Smart format detection: auto-select based on User-Agent
    # Clash clients → YAML, others → Base64
    if format is None and user_agent:
        ua_lower = user_agent.lower()
        # Clash client keywords
        clash_keywords = ['clash', 'stash', 'shadowrocket', 'quantumult', 'surge', 'loon']
        # If Clash client, use YAML; otherwise use Base64
        is_clash = any(kw in ua_lower for kw in clash_keywords)
        if not is_clash:
            # V2RayN, V2RayNG, Nekoray etc use Base64
            format = 'base64'
    
    # Get template based on template_id
    template_proxy_groups = None  # Will store template's proxy-groups if available
    
    if template_id == 'legacy':
        # Use legacy saved template
        tpl = config.get('template', {})
        header = tpl.get('header', ConfigMerger.TEMPLATES['header'])
        suffix = tpl.get('suffix', ConfigMerger.TEMPLATES['suffix'])
    elif template_id == 'builtin':
        # Check for user customization of builtin template
        override = config.get('builtin_template_override')
        if override:
            header = override.get('header', ConfigMerger.TEMPLATES['header'])
            suffix = override.get('suffix', ConfigMerger.TEMPLATES['suffix'])
            template_proxy_groups = override.get('proxy_groups', [])
        else:
            header = ConfigMerger.TEMPLATES['header']
            suffix = ConfigMerger.TEMPLATES['suffix']
    else:
        # Find template by ID
        template = next((t for t in config.get('templates', []) if t['id'] == template_id), None)
        if template:
            # Check if template needs migration (only if both header and suffix are missing)
            needs_migration = ('header' not in template or 'suffix' not in template) and 'content' in template
            
            if needs_migration:
                # Auto-migrate old format templates
                try:
                    parsed = yaml.safe_load(template['content'])
                    if isinstance(parsed, dict):
                        # Split the content
                        header, suffix = split_template(template['content'])
                        template['header'] = header
                        template['suffix'] = suffix
                        if 'proxy_groups' not in template:
                            template['proxy_groups'] = parsed.get('proxy-groups', [])
                        # Remove old content field
                        del template['content']
                        # Save migrated template (only once)
                        save_config(config)
                        print(f"Template {template_id} migrated successfully")
                except Exception as e:
                    print(f"Template migration failed: {e}")
                    # If migration fails, use fallback
                    header = ConfigMerger.TEMPLATES['header']
                    suffix = ConfigMerger.TEMPLATES['suffix']
                    template_proxy_groups = None
            
            # Use template data (either already migrated or just migrated)
            if not needs_migration or ('header' in template and 'suffix' in template):
                header = template.get('header', ConfigMerger.TEMPLATES['header'])
                suffix = template.get('suffix', ConfigMerger.TEMPLATES['suffix'])
                template_proxy_groups = template.get('proxy_groups')
        else:
            # Fallback to built-in
            header = ConfigMerger.TEMPLATES['header']
            suffix = ConfigMerger.TEMPLATES['suffix']
    
    # Build file_aliases based on filtered subscriptions (not all sources)
    file_aliases = OrderedDict()
    
    # Get order from source_order config
    config_order = config.get('source_order', [])
    
    # Add custom nodes first if allocated
    if custom_nodes:
        if 'custom_nodes' in config_order:
            # Will be added in order below
            pass
        else:
            file_aliases['custom_nodes.yaml'] = 'Custom'
    
    # Add sources in order
    for source_id in config_order:
        if source_id == 'custom_nodes' and custom_nodes:
            file_aliases['custom_nodes.yaml'] = 'Custom'
        else:
            # Check if this subscription is in enabled_subs (already filtered for user)
            for sub in enabled_subs:
                if sub['id'] == source_id:
                    file_aliases[f"{sub['id']}.yaml"] = sub['name']
                    break
    
    # Add any remaining enabled_subs not in order
    for sub in enabled_subs:
        filename = f"{sub['id']}.yaml"
        if filename not in file_aliases:
            file_aliases[filename] = sub['name']
    
    merger = ConfigMerger(
        yaml_dir=YAML_SOURCE_DIR, output_file=OUTPUT_FILE,
        custom_header=header, custom_suffix=suffix, file_aliases=file_aliases
    )
    
    try:
        cfg = merger.merge_and_generate()
        proxies = cfg.get('proxies', [])
        proxy_groups = cfg.get('proxy-groups', [])
        
        # Filter proxies based on user allocations (specific nodes)
        if user_allocations is not None:
            # Import NameTransformer for flag removal
            from merge_config import NameTransformer
            
            filtered_proxies = []
            for proxy in proxies:
                proxy_name = proxy.get('name', '')
                # Determine which subscription this proxy belongs to
                # The proxy name format is: "Flag Provider NodeName"
                # We need to check against allocations
                included = False
                
                for sub_id, allocated_nodes in user_allocations.items():
                    if sub_id == 'custom_nodes':
                        continue  # Custom nodes handled separately
                    
                    # Find the subscription name
                    sub_name_match = None
                    for s in config.get('subscriptions', []):
                        if s['id'] == sub_id:
                            sub_name_match = s['name']
                            break
                    
                    if sub_name_match and sub_name_match in proxy_name:
                        if allocated_nodes == ['*']:
                            # All nodes from this subscription
                            included = True
                            break
                        else:
                            # Check if this specific node is allocated
                            # Original node name might have flags, e.g., "🇭🇰HK@xxx"
                            # Transformed name is "flag + name + code@info"
                            # We need to match the core part (without flags)
                            for alloc_node in allocated_nodes:
                                # Remove flags from allocated node name for matching
                                alloc_node_clean = NameTransformer.remove_flags(alloc_node)
                                if alloc_node_clean and alloc_node_clean in proxy_name:
                                    included = True
                                    break
                                # Also try direct match (in case no transformation)
                                if alloc_node in proxy_name:
                                    included = True
                                    break
                        if included:
                            break
                
                # Check custom nodes - need to verify it's actually a custom node
                # Custom nodes have "Custom" in their name after transformation (e.g., "🇸🇬 Custom SG")
                if not included and 'custom_nodes' in user_allocations:
                    # Only check if this is actually a custom node (contains "Custom" provider name)
                    if 'Custom' in proxy_name:
                        allocated_custom = user_allocations['custom_nodes']
                        # Get the list of custom node names from config
                        all_custom_node_names = [cn['name'] for cn in config.get('custom_nodes', [])]
                        
                        # Find which custom node this proxy matches
                        # Sort by length descending to match longer names first (e.g., "SG-azure" before "SG")
                        matching_custom_name = None
                        for cn_name in sorted(all_custom_node_names, key=len, reverse=True):
                            # Proxy name format: "🇸🇬 Custom SG" where "SG" is the custom node name
                            # Use exact end match to avoid "SG" matching "SG-azure"
                            expected_suffix = f"Custom {cn_name}"
                            if proxy_name.endswith(expected_suffix):
                                matching_custom_name = cn_name
                                break
                        
                        if matching_custom_name:
                            if allocated_custom == ['*']:
                                included = True
                            elif matching_custom_name in allocated_custom:
                                included = True
                
                if included:
                    filtered_proxies.append(proxy)
            
            proxies = filtered_proxies
            
            # Regenerate proxy groups based on filtered proxies
            from merge_config import CountryGrouper, ProxyGroupGenerator
            country_groups = CountryGrouper.group_by_country(proxies)
            proxy_groups = ProxyGroupGenerator.generate_groups(proxies, country_groups)
        
        # If using custom template with proxy-groups, process user config
        if template_proxy_groups and isinstance(template_proxy_groups, list) and len(template_proxy_groups) > 0:
            # Get all proxy names
            all_proxy_names = [p['name'] for p in proxies]
            
            # Identify primary selection groups (groups that contain actual proxy nodes)
            # These are typically "manual select" or "auto select" type groups
            primary_groups = []
            for g in template_proxy_groups:
                g_name = g.get('name', '')
                g_type = g.get('type', '')
                # Primary groups are usually select or url-test types that will contain actual nodes
                # Common patterns: "节点选择", "自动选择", "手动选择", etc.
                if g_type in ['select', 'url-test', 'fallback', 'load-balance']:
                    # Check if this looks like a primary selection group (not a policy group)
                    # Policy groups typically have names like "广告拦截", "国内服务", etc.
                    is_policy = any(keyword in g_name for keyword in ['广告', '拦截', '国内', '服务', '私有', '网络', '漏网', 'Ad', 'Block', 'Domestic', 'Private', 'Catch'])
                    if not is_policy:
                        primary_groups.append(g_name)
            
            # Process each group
            custom_groups = []
            for group in template_proxy_groups:
                new_group = dict(group)
                group_name = new_group.get('name', '')
                group_type = new_group.get('type', '')
                
                # Remove underscore fields
                new_group = filter_underscore_fields(new_group)
                
                # Build fixed options based on group type
                # Base options that are always safe
                base_options = ["DIRECT", "REJECT"]
                
                # For policy groups (like ad-block, domestic, etc.), add primary selection groups
                # For primary selection groups, don't add other groups to avoid loops
                is_policy = any(keyword in group_name for keyword in ['广告', '拦截', '国内', '服务', '私有', '网络', '漏网', 'Ad', 'Block', 'Domestic', 'Private', 'Catch'])
                
                if is_policy:
                    # Policy groups can reference primary selection groups
                    fixed_options = base_options + primary_groups
                else:
                    # Primary selection groups only get DIRECT/REJECT
                    fixed_options = base_options
                
                # Apply user's group_config if exists
                if user_info and user_info.get('group_config'):
                    group_config = user_info['group_config']
                    
                    # If user configured this group, use user's selection
                    if group_name in group_config and group_config[group_name]:
                        # Extract group references from original template (for other groups, not DIRECT/REJECT)
                        original_proxies = group.get('proxies', [])
                        group_refs = []
                        
                        for item in original_proxies:
                            # Only keep group references (not DIRECT/REJECT, those come from user config)
                            if item not in ['DIRECT', 'REJECT'] and item in [g.get('name') for g in template_proxy_groups]:
                                group_refs.append(item)
                        
                        # Filter user's selected nodes
                        user_selected_nodes = group_config[group_name]
                        valid_nodes = []
                        
                        # Debug logging
                        print(f"[DEBUG] Group '{group_name}': user selected {len(user_selected_nodes)} nodes")
                        print(f"[DEBUG] Available proxy names: {len(all_proxy_names)} nodes")
                        if len(all_proxy_names) > 0:
                            print(f"[DEBUG] Sample proxy names: {all_proxy_names[:3]}")
                        if len(user_selected_nodes) > 0:
                            print(f"[DEBUG] Sample user selected: {user_selected_nodes[:5]}")
                        
                        for node in user_selected_nodes:
                            # Keep DIRECT and REJECT
                            if node in ['DIRECT', 'REJECT']:
                                valid_nodes.append(node)
                            # Keep actual proxy nodes that exist
                            elif node in all_proxy_names:
                                valid_nodes.append(node)
                            else:
                                # Debug: node not found
                                print(f"[DEBUG] Node '{node}' not found in all_proxy_names")
                        
                        print(f"[DEBUG] Valid nodes after filtering: {len(valid_nodes)} nodes")
                        
                        # Combine: group refs + user selected nodes (including DIRECT/REJECT)
                        if valid_nodes:
                            new_group['proxies'] = group_refs + valid_nodes
                        else:
                            # If no valid nodes, use group refs + all available nodes
                            new_group['proxies'] = group_refs + ["DIRECT", "REJECT"] + all_proxy_names
                    else:
                        # No user config for this group - keep original template structure
                        # but replace actual proxy nodes with user's available nodes
                        original_proxies = group.get('proxies', [])
                        new_proxies = []
                        
                        # Keep group references and special keywords (DIRECT, REJECT)
                        for item in original_proxies:
                            if item in ['DIRECT', 'REJECT'] or item in [g.get('name') for g in template_proxy_groups]:
                                # Keep DIRECT, REJECT, and group references
                                new_proxies.append(item)
                        
                        # Add user's available proxy nodes
                        new_proxies.extend(all_proxy_names)
                        
                        # Remove duplicates while preserving order
                        seen = set()
                        new_group['proxies'] = [x for x in new_proxies if not (x in seen or seen.add(x))]
                else:
                    # No user config at all - keep original template structure
                    # but replace actual proxy nodes with user's available nodes
                    original_proxies = group.get('proxies', [])
                    new_proxies = []
                    
                    # Keep group references and special keywords (DIRECT, REJECT)
                    for item in original_proxies:
                        if item in ['DIRECT', 'REJECT'] or item in [g.get('name') for g in template_proxy_groups]:
                            # Keep DIRECT, REJECT, and group references
                            new_proxies.append(item)
                    
                    # Add user's available proxy nodes
                    new_proxies.extend(all_proxy_names)
                    
                    # Remove duplicates while preserving order
                    seen = set()
                    new_group['proxies'] = [x for x in new_proxies if not (x in seen or seen.add(x))]
                
                custom_groups.append(new_group)
            
            proxy_groups = custom_groups
        # Get custom config name
        # Priority: user's sub_name > admin_token's sub_name > global sub_name
        if user_info:
            # User subscription - use user's sub_name if set
            if user_info.get('sub_name'):
                sub_name = f"{user_info['sub_name']} - {user_info['name']}"
            else:
                # Fallback to global sub_name
                sub_name = f"{auth.get('sub_name', 'Aggregated')} - {user_info['name']}"
        else:
            # Admin token subscription - use admin token's sub_name or global sub_name
            if admin_token_info and admin_token_info.get('sub_name'):
                sub_name = admin_token_info['sub_name']
            else:
                sub_name = auth.get('sub_name', 'Aggregated')
        
        # Generate traffic info nodes for each subscription
        def format_bytes(b):
            if not b or b == 0:
                return '0B'
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if b < 1024:
                    return f'{b:.1f}{unit}' if b != int(b) else f'{int(b)}{unit}'
                b /= 1024
            return f'{b:.1f}PB'
        
        def format_expire(ts):
            if not ts or ts == 0:
                return '永久'
            from datetime import datetime
            return datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
        
        traffic_info_nodes = []
        traffic_info_names = []
        
        # Calculate aggregated total first
        agg_used = sum((s.get('upload', 0) or 0) + (s.get('download', 0) or 0) for s in enabled_subs)
        agg_total = sum(s.get('total', 0) or 0 for s in enabled_subs)
        
        # Add aggregated total node first (only traffic, no time)
        if agg_total > 0:
            agg_name = f"📊 总计 | {format_bytes(agg_used)}/{format_bytes(agg_total)}"
            traffic_info_names.append(agg_name)
            traffic_info_nodes.append({
                'name': agg_name,
                'type': 'http',
                'server': '1.0.0.1',
                'port': 65535
            })
        
        # Add individual subscription traffic info
        for sub in enabled_subs:
            used = (sub.get('upload', 0) or 0) + (sub.get('download', 0) or 0)
            total = sub.get('total', 0) or 0
            expire = sub.get('expire', 0) or 0
            
            # Create info node name: "sub_name | used/total | expire_date"
            if total > 0:
                info_name = f"📊 {sub['name']} | {format_bytes(used)}/{format_bytes(total)} | {format_expire(expire)}"
            else:
                info_name = f"📊 {sub['name']} | {format_expire(expire)}"
            
            traffic_info_names.append(info_name)
            # Create a dummy HTTP node (looks valid but won't work, just for display)
            traffic_info_nodes.append({
                'name': info_name,
                'type': 'http',
                'server': '1.0.0.1',
                'port': 65535
            })
        
        # Prepend traffic info nodes to proxies
        proxies = traffic_info_nodes + proxies
        
        # Process proxy chains - add chain proxies with dialer-proxy
        proxy_chains = config.get('proxy_chains', [])
        chain_proxies = []
        chain_proxy_names = []
        
        for chain in proxy_chains:
            if not chain.get('enabled', True):
                continue
            
            for row_idx, row in enumerate(chain.get('rows', [])):
                nodes = row.get('nodes', [])
                if len(nodes) < 2:
                    continue
                
                # Build the chain by setting dialer-proxy on each node
                # For chain [A, B, C]: B.dialer-proxy = A, C.dialer-proxy = B
                # We create a new proxy entry based on the last node with dialer-proxy set
                
                # Find all nodes in the chain
                chain_node_proxies = []
                for node_ref in nodes:
                    node_proxy = find_node_by_reference(node_ref['sub_id'], node_ref['node_index'])
                    if node_proxy:
                        chain_node_proxies.append(dict(node_proxy))
                
                if len(chain_node_proxies) < 2:
                    continue
                
                # Create chain proxy entry based on the last node
                last_node = chain_node_proxies[-1]
                chain_proxy = dict(last_node)
                
                # Extract country info from the last node (exit node) for grouping
                last_node_name = last_node.get('name', '')
                last_node_server = last_node.get('server', '')
                chain_country_info = extract_country_from_name(last_node_name, last_node_server)
                
                # Set chain name
                chain_name = chain['name']
                if len(chain.get('rows', [])) > 1:
                    chain_name = f"{chain_name} #{row_idx + 1}"
                chain_proxy['name'] = f"🔗 {chain_name}"
                
                # Store country info for later grouping
                if chain_country_info:
                    chain_proxy['_country_info'] = chain_country_info
                
                # Set dialer-proxy to the second-to-last node
                # For longer chains, we need intermediate proxies
                if len(chain_node_proxies) == 2:
                    # Simple 2-node chain: last node uses first as dialer-proxy
                    chain_proxy['dialer-proxy'] = chain_node_proxies[0]['name']
                else:
                    # Multi-node chain: create intermediate proxies
                    # For [A, B, C]: create B' with dialer-proxy=A, then C' with dialer-proxy=B'
                    prev_proxy_name = chain_node_proxies[0]['name']
                    
                    for i in range(1, len(chain_node_proxies) - 1):
                        intermediate = dict(chain_node_proxies[i])
                        intermediate_name = f"🔗 {chain_name} (via {i})"
                        intermediate['name'] = intermediate_name
                        intermediate['dialer-proxy'] = prev_proxy_name
                        chain_proxies.append(intermediate)
                        chain_proxy_names.append(intermediate_name)
                        prev_proxy_name = intermediate_name
                    
                    chain_proxy['dialer-proxy'] = prev_proxy_name
                
                chain_proxies.append(chain_proxy)
                chain_proxy_names.append(chain_proxy['name'])
        
        # Add chain proxies to the proxies list
        # Position: after custom nodes, before subscription nodes
        # Order: traffic_info -> custom_nodes -> chain_proxies -> subscription_nodes
        if chain_proxies:
            # Find the position after custom nodes
            # Custom nodes have "Custom" in their name (from file_aliases)
            custom_node_end_idx = 0
            for i, proxy in enumerate(proxies):
                proxy_name = proxy.get('name', '')
                # Traffic info nodes start with 📊, skip them
                if proxy_name.startswith('📊'):
                    custom_node_end_idx = i + 1
                    continue
                # Custom nodes have "Custom" as provider name
                if 'Custom' in proxy_name:
                    custom_node_end_idx = i + 1
                else:
                    # First non-custom, non-traffic node found
                    break
            
            # Insert chain proxies after custom nodes
            proxies = proxies[:custom_node_end_idx] + chain_proxies + proxies[custom_node_end_idx:]
            
            # Add chain proxies to corresponding country groups
            for chain_proxy in chain_proxies:
                chain_proxy_name = chain_proxy.get('name', '')
                # Use stored country info from exit node
                country_info = chain_proxy.get('_country_info')
                if country_info:
                    country_group_name = f"{country_info['flag']} {country_info['country']}"
                    # Find and update the country group
                    for group in proxy_groups:
                        if group.get('name') == country_group_name:
                            if chain_proxy_name not in group.get('proxies', []):
                                group['proxies'].insert(0, chain_proxy_name)  # Add at beginning
                            break
                    # Clean up temporary field before output
                    del chain_proxy['_country_info']
        
        # Add traffic info nodes and chain proxies to manual select group
        if traffic_info_names or chain_proxy_names:
            for group in proxy_groups:
                if group.get('name') == '🚀 手动选择':
                    # Insert traffic info at the beginning, chain proxies after traffic info
                    current_proxies = group.get('proxies', [])
                    group['proxies'] = traffic_info_names + chain_proxy_names + current_proxies
                    break
        
        # Calculate total traffic info from all subscriptions
        total_upload = sum(s.get('upload', 0) or 0 for s in enabled_subs)
        total_download = sum(s.get('download', 0) or 0 for s in enabled_subs)
        total_traffic = sum(s.get('total', 0) or 0 for s in enabled_subs)
        # Use the earliest expire time (ignore 0 which means permanent/unknown)
        expire_times = [s.get('expire', 0) or 0 for s in enabled_subs if (s.get('expire', 0) or 0) > 0]
        total_expire = min(expire_times) if expire_times else 0
        
        # Base64 format output
        if format == 'base64':
            links = []
            for proxy in proxies:
                link = proxy_to_link(proxy)
                if link:
                    links.append(link)
            content = base64.b64encode('\n'.join(links).encode()).decode()
            
            # Get custom config name
            from urllib.parse import quote
            encoded_name = quote(sub_name)
            
            return PlainTextResponse(
                content,
                media_type='text/plain; charset=utf-8',
                headers={
                    "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}",
                    "profile-title": encoded_name,
                    "profile-update-interval": "24",
                    "subscription-userinfo": f"upload={total_upload}; download={total_download}; total={total_traffic}; expire={total_expire}",
                }
            )
        
        # Clash YAML format output (default)
        output_parts = [f'name: {sub_name}\n' + header.rstrip()]
        
        # Generate listeners based on port mappings
        port_mappings = config.get('port_mappings', {})
        if port_mappings:
            # Get current proxy names for validation
            proxy_names = {p.get('name', '') for p in proxies}
            
            # Build listeners for valid mappings only
            listeners = []
            for node_name, port in sorted(port_mappings.items(), key=lambda x: x[1]):
                if node_name in proxy_names:
                    listener = {
                        'name': f'mixed-{port}',
                        'type': 'mixed',
                        'port': port,
                        'proxy': node_name
                    }
                    listeners.append(listener)
            
            if listeners:
                output_parts.append('\nlisteners:')
                for listener in listeners:
                    output_parts.append(f'  - {json.dumps(listener, ensure_ascii=False, separators=(",",":"))}')
        
        output_parts.append('\nproxies:')
        for proxy in proxies:
            output_parts.append(f'  - {json.dumps(proxy, ensure_ascii=False, separators=(",",":"))}')
        output_parts.append('\nproxy-groups:')
        for group in proxy_groups:
            output_parts.append(f'  - {json.dumps(group, ensure_ascii=False, separators=(",",":"))}')
        
        if suffix:
            output_parts.append('\n' + suffix)
        
        # Get custom filename and config name
        # Priority: user's sub_filename > admin_token's sub_filename > global sub_filename
        if user_info and user_info.get('sub_filename'):
            filename = user_info['sub_filename']
        elif admin_token_info and admin_token_info.get('sub_filename'):
            filename = admin_token_info['sub_filename']
        else:
            filename = auth.get('sub_filename', 'config.yaml')
        
        # Use URL encoding for names
        from urllib.parse import quote
        encoded_name = quote(sub_name)
        # Filename also uses config name (remove unsafe chars, keep Chinese)
        safe_name = ''.join(c for c in sub_name if c.isalnum() or c in ' _-' or '\u4e00' <= c <= '\u9fff')
        if not safe_name:
            safe_name = filename.replace('.yaml', '').replace('.yml', '')
        
        yaml_content = "\n".join(output_parts)
        response_headers = {
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(safe_name)}",
            "profile-title": encoded_name,
            "profile-update-interval": "24",
            "subscription-userinfo": f"upload={total_upload}; download={total_download}; total={total_traffic}; expire={total_expire}",
        }
        
        # Cache the generated YAML for user subscriptions
        if user_info:
            # Update cache in user object
            user_info['sub_cache'] = {
                'content': yaml_content,
                'headers': response_headers,
                'timestamp': time.time()
            }
            # Save config with updated cache
            save_config(config)
            print(f"Cached subscription for user {user_info['name']}")
        
        return PlainTextResponse(
            yaml_content, 
            media_type='text/yaml',
            headers=response_headers
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==================== Multi-Template Management API ====================

def get_builtin_template():
    """Get the built-in default template (with user overrides if any)"""
    config = load_config()
    override = config.get('builtin_template_override')
    
    if override:
        # User has customized the builtin template
        header = override.get('header', ConfigMerger.TEMPLATES['header'])
        suffix = override.get('suffix', ConfigMerger.TEMPLATES['suffix'])
        proxy_groups = override.get('proxy_groups', [])
        is_modified = True
    else:
        # Use default builtin template
        header = ConfigMerger.TEMPLATES['header']
        suffix = ConfigMerger.TEMPLATES['suffix']
        proxy_groups = []
        is_modified = False
    
    return {
        'id': 'builtin',
        'name': '内置模版',
        'header': header,
        'suffix': suffix,
        'proxy_groups': proxy_groups,
        'is_builtin': True,
        'is_modified': is_modified,  # Indicates if user has customized it
        'created_at': 0
    }

def get_all_templates_list():
    """Get all templates including built-in"""
    config = load_config()
    templates = [get_builtin_template()]
    
    # Add custom templates from config
    for t in config.get('templates', []):
        t['is_builtin'] = False
        templates.append(t)
    
    return templates

@app.get("/api/templates")
def list_templates(_: bool = Depends(verify_session)):
    """List all templates including built-in"""
    templates = get_all_templates_list()
    # Return summary without full content for list view
    result = []
    for t in templates:
        result.append({
            'id': t['id'],
            'name': t['name'],
            'is_builtin': t.get('is_builtin', False),
            'is_modified': t.get('is_modified', False),
            'created_at': t.get('created_at', 0)
        })
    return {"templates": result, "count": len(result)}

class CreateTemplateRequest(BaseModel):
    name: str
    content: str  # Full template YAML content

@app.post("/api/templates")
def create_template(data: CreateTemplateRequest, _: bool = Depends(verify_session)):
    """Create a new template"""
    config = load_config()
    
    # Parse and validate content
    try:
        parsed = yaml.safe_load(data.content)
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="Invalid template format")
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)[:100]}")
    
    # Extract proxy-groups structure for visual editor (before clearing)
    template_proxy_groups = parsed.get('proxy-groups', [])
    
    # Add _editable: true to all groups by default (for visual editor)
    if template_proxy_groups and isinstance(template_proxy_groups, list):
        for group in template_proxy_groups:
            if isinstance(group, dict) and '_editable' not in group:
                group['_editable'] = True
    
    # Split the original content to get header and suffix
    # This removes proxies and proxy-groups sections
    header, suffix = split_template(data.content)
    
    template_id = f"tpl_{int(time.time() * 1000)}"
    template = {
        'id': template_id,
        'name': data.name,
        'header': header,  # Header without proxies/proxy-groups
        'suffix': suffix,  # Rules and other sections
        'proxy_groups': template_proxy_groups,  # Save original proxy-groups structure for visual editor
        'created_at': int(time.time())
    }
    
    if 'templates' not in config:
        config['templates'] = []
    config['templates'].append(template)
    save_config(config)
    
    return {"status": "success", "template": {
        'id': template_id,
        'name': data.name,
        'is_builtin': False,
        'created_at': template['created_at']
    }}

@app.get("/api/templates/{template_id}")
def get_template(template_id: str, _: bool = Depends(verify_session)):
    """Get a specific template with full content"""
    if template_id == 'builtin':
        t = get_builtin_template()
    else:
        config = load_config()
        t = next((t for t in config.get('templates', []) if t['id'] == template_id), None)
        if not t:
            raise HTTPException(status_code=404, detail="Template not found")
        t['is_builtin'] = False
        
        # Auto-migrate old format templates to new format
        if 'header' not in t or 'suffix' not in t:
            if 'content' in t:
                # Parse content to extract proxy-groups
                try:
                    parsed = yaml.safe_load(t['content'])
                    if isinstance(parsed, dict):
                        # Split the content
                        header, suffix = split_template(t['content'])
                        t['header'] = header
                        t['suffix'] = suffix
                        if 'proxy_groups' not in t:
                            t['proxy_groups'] = parsed.get('proxy-groups', [])
                        # Remove old content field
                        del t['content']
                        # Save migrated template
                        save_config(config)
                except:
                    pass  # If migration fails, keep old format
    
    # Check if template has old format (content field) or new format (header/suffix)
    if 'header' not in t or 'suffix' not in t:
        # Old format or incomplete migration - use content field if available
        if 'content' in t:
            content = t['content']
        else:
            # Fallback to empty template
            content = "proxies: []\n\nproxy-groups: []"
    else:
        # New format - reconstruct from components
        proxy_groups = t.get('proxy_groups', [])
        
        # Build proxy-groups section manually to ensure clean format
        if proxy_groups and isinstance(proxy_groups, list) and len(proxy_groups) > 0:
            proxy_groups_lines = ["proxy-groups:"]
            for group in proxy_groups:
                # Convert each group to YAML and indent properly
                group_yaml = yaml.dump([group], allow_unicode=True, sort_keys=False, default_flow_style=False)
                # Remove the leading "- " and indent each line
                for line in group_yaml.strip().split('\n'):
                    if line.startswith('- '):
                        proxy_groups_lines.append('  ' + line)
                    else:
                        proxy_groups_lines.append('    ' + line)
            proxy_groups_section = '\n'.join(proxy_groups_lines)
        else:
            proxy_groups_section = "proxy-groups: []"
        
        content = t['header'].strip() + "\n\nproxies: []\n\n" + proxy_groups_section + "\n\n" + t['suffix'].strip()
    
    return {
        "id": t['id'],
        "name": t['name'],
        "content": content,
        "is_builtin": t.get('is_builtin', False),
        "is_modified": t.get('is_modified', False),
        "created_at": t.get('created_at', 0)
    }

class UpdateTemplateRequest(BaseModel):
    name: Optional[str] = None
    content: Optional[str] = None

@app.put("/api/templates/{template_id}")
def update_template(template_id: str, data: UpdateTemplateRequest, _: bool = Depends(verify_session)):
    """Update a template"""
    config = load_config()
    
    # Handle builtin template specially - save to override
    if template_id == 'builtin':
        if not data.content:
            raise HTTPException(status_code=400, detail="Content is required")
        
        try:
            parsed = yaml.safe_load(data.content)
            if not isinstance(parsed, dict):
                raise HTTPException(status_code=400, detail="Invalid template format")
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)[:100]}")
        
        proxy_groups = parsed.get('proxy-groups', [])
        header, suffix = split_template(data.content)
        
        # Save as override
        config['builtin_template_override'] = {
            'header': header,
            'suffix': suffix,
            'proxy_groups': proxy_groups
        }
        save_config(config)
        return {"status": "success", "message": "Built-in template customized"}
    
    # Regular template update
    template = next((t for t in config.get('templates', []) if t['id'] == template_id), None)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    
    if data.name:
        template['name'] = data.name
    
    if data.content:
        try:
            parsed = yaml.safe_load(data.content)
            if not isinstance(parsed, dict):
                raise HTTPException(status_code=400, detail="Invalid template format")
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)[:100]}")
        
        # Split and save
        header, suffix = split_template(data.content)
        template['header'] = header
        template['suffix'] = suffix
        template['proxy_groups'] = parsed.get('proxy-groups', [])
    
    save_config(config)
    return {"status": "success", "message": "Template updated"}

@app.delete("/api/templates/{template_id}")
def delete_template(template_id: str, _: bool = Depends(verify_session)):
    """Delete a template"""
    if template_id == 'builtin':
        raise HTTPException(status_code=400, detail="Cannot delete built-in template")
    
    config = load_config()
    templates = config.get('templates', [])
    idx = next((i for i, t in enumerate(templates) if t['id'] == template_id), None)
    
    if idx is None:
        raise HTTPException(status_code=404, detail="Template not found")
    
    # Check if any user is using this template
    for user in config.get('users', []):
        if user.get('template_id') == template_id:
            raise HTTPException(status_code=400, detail=f"Template is in use by user: {user['name']}")
    
    # Check if any admin token is using this template
    for token in config.get('admin_tokens', []):
        if token.get('template_id') == template_id:
            raise HTTPException(status_code=400, detail=f"Template is in use by admin token: {token['name']}")
    
    templates.pop(idx)
    save_config(config)
    return {"status": "success", "message": "Template deleted"}

@app.post("/api/templates/builtin/reset")
def reset_builtin_template(_: bool = Depends(verify_session)):
    """Reset built-in template to default (remove user customizations)"""
    config = load_config()
    
    if 'builtin_template_override' in config:
        del config['builtin_template_override']
        save_config(config)
        return {"status": "success", "message": "Built-in template reset to default"}
    else:
        return {"status": "success", "message": "Built-in template is already at default"}

# ==================== Template API (Legacy - single template) ====================

def split_template(full_content: str) -> Tuple[str, str]:
    """
    Split template into header (config before proxies) and suffix (rules after proxy-groups).
    Removes proxies: and proxy-groups: sections completely.
    """
    lines = full_content.splitlines(keepends=True)
    header_lines, suffix_lines = [], []
    state = 0  # 0=header, 1=skip(proxies/groups), 2=suffix
    
    for line in lines:
        stripped = line.strip()
        
        if state == 0:
            # In header section
            if stripped.startswith('proxies:') or stripped.startswith('proxy-groups:'):
                # Start skipping proxies/proxy-groups sections
                state = 1
                continue
            header_lines.append(line)
            
        elif state == 1:
            # Skipping proxies/proxy-groups sections
            # Check if we've reached the suffix (rules, etc.)
            if any(stripped.startswith(k) for k in ['rules:', 'rule-providers:', 'script:', 'url-rewrite:']):
                state = 2
                suffix_lines.append(line)
            # Otherwise, skip this line (it's part of proxies/proxy-groups)
            
        elif state == 2:
            # In suffix section
            suffix_lines.append(line)
    
    return "".join(header_lines).strip(), "".join(suffix_lines).strip()

@app.get("/api/template")
def get_saved_template(_: bool = Depends(verify_session)):
    """Get saved template or default if none saved"""
    config = load_config()
    if 'template' in config:
        template = config['template']
        header = template.get('header', ConfigMerger.TEMPLATES['header'])
        suffix = template.get('suffix', ConfigMerger.TEMPLATES['suffix'])
    else:
        header = ConfigMerger.TEMPLATES['header']
        suffix = ConfigMerger.TEMPLATES['suffix']
    return {"content": header.strip() + "\n\nproxies: []\n\nproxy-groups: []\n\n" + suffix.strip()}

@app.get("/api/template/default")
def get_default_template(_: bool = Depends(verify_session)):
    header = ConfigMerger.TEMPLATES['header']
    suffix = ConfigMerger.TEMPLATES['suffix']
    return {"content": header.strip() + "\n\nproxies: []\n\nproxy-groups: []\n\n" + suffix.strip()}

@app.post("/api/template/parse")
async def parse_template_file(file: UploadFile = File(...), current_template: str = Form(default=""), _: bool = Depends(verify_session)):
    try:
        content = (await file.read()).decode('utf-8')
        try:
            uploaded_config = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)[:100]}")
        
        if not isinstance(uploaded_config, dict):
            raise HTTPException(status_code=400, detail="Invalid file format")
        
        if current_template:
            try:
                base_config = yaml.safe_load(current_template)
            except:
                base_config = {}
        else:
            header = ConfigMerger.TEMPLATES['header']
            suffix = ConfigMerger.TEMPLATES['suffix']
            try:
                base_config = yaml.safe_load(header + "\nproxies: []\nproxy-groups: []\n" + suffix)
            except:
                base_config = {}
        
        if not isinstance(base_config, dict):
            base_config = {}
        
        merged = {}
        for key in base_config:
            if key == 'proxies':
                merged[key] = []
            elif key == 'proxy-groups':
                # Preserve from uploaded config if exists
                continue
            elif key in uploaded_config:
                merged[key] = uploaded_config[key]
            else:
                merged[key] = base_config[key]
        
        for key in uploaded_config:
            if key not in merged:
                if key == 'proxies':
                    merged[key] = []
                elif key == 'proxy-groups':
                    # Process proxy-groups: keep structure, clean proxy nodes
                    pass
                else:
                    merged[key] = uploaded_config[key]
        
        merged['proxies'] = []
        
        # Process proxy-groups: keep structure, clean proxy node names
        uploaded_groups = uploaded_config.get('proxy-groups', [])
        if uploaded_groups and isinstance(uploaded_groups, list):
            # Get all group names defined in the config
            group_names = set()
            for group in uploaded_groups:
                if isinstance(group, dict) and group.get('name'):
                    group_names.add(group['name'])
            
            # Special entries to preserve
            preserved_entries = {'DIRECT', 'REJECT', 'GLOBAL', 'PASS'}
            preserved_entries.update(group_names)
            
            cleaned_groups = []
            for group in uploaded_groups:
                if not isinstance(group, dict):
                    continue
                cleaned_group = dict(group)
                proxies = group.get('proxies', [])
                if isinstance(proxies, list):
                    # Keep only DIRECT, REJECT, and other group references
                    cleaned_proxies = [p for p in proxies if p in preserved_entries]
                    cleaned_group['proxies'] = cleaned_proxies
                cleaned_groups.append(cleaned_group)
            
            merged['proxy-groups'] = cleaned_groups
        else:
            merged['proxy-groups'] = []
        
        new_content = yaml.dump(merged, allow_unicode=True, sort_keys=False, default_flow_style=False, width=float("inf"))
        section_keys = ['dns:', 'sniffer:', 'tun:', 'proxies:', 'proxy-groups:', 'rules:', 'rule-providers:', 'script:', 'url-rewrite:']
        lines = new_content.split('\n')
        result_lines = []
        for line in lines:
            stripped = line.strip()
            if any(stripped.startswith(key) for key in section_keys):
                if not line.startswith(' ') and not line.startswith('\t'):
                    if result_lines and result_lines[-1].strip() != '':
                        result_lines.append('')
            result_lines.append(line)
        return {"content": '\n'.join(result_lines).strip()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class TemplateSaveRequest(BaseModel):
    content: str

@app.post("/api/template/save")
def save_template(data: TemplateSaveRequest, _: bool = Depends(verify_session)):
    """Save template content to config"""
    try:
        content = data.content.strip()
        # Parse to validate YAML
        try:
            parsed = yaml.safe_load(content)
            if not isinstance(parsed, dict):
                raise HTTPException(status_code=400, detail="Invalid template format")
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)[:100]}")
        
        # Split into header and suffix
        header, suffix = split_template(content)
        
        # Update ConfigMerger templates
        ConfigMerger.TEMPLATES['header'] = header
        ConfigMerger.TEMPLATES['suffix'] = suffix
        
        # Save to config.json
        config = load_config()
        config['template'] = {
            'header': header,
            'suffix': suffix
        }
        save_config(config)
        
        return {"success": True, "message": "Template saved"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/preview")
def generate_preview(template: TemplateContent, _: bool = Depends(verify_session)):
    header, suffix = split_template(template.content)
    
    config = load_config()
    subs = config.get('subscriptions', [])
    custom_nodes = config.get('custom_nodes', [])
    
    file_aliases = OrderedDict(template.file_aliases or {})
    
    if custom_nodes and 'custom_nodes.yaml' not in file_aliases:
        new_aliases = OrderedDict()
        new_aliases['custom_nodes.yaml'] = 'Custom'
        new_aliases.update(file_aliases)
        file_aliases = new_aliases
    
    for s in subs:
        if s['enabled']:
            filename = f"{s['id']}.yaml"
            if filename not in file_aliases:
                file_aliases[filename] = s['name']
    
    merger = ConfigMerger(
        yaml_dir=YAML_SOURCE_DIR, output_file=OUTPUT_FILE,
        custom_header=header, custom_suffix=suffix, file_aliases=file_aliases
    )
    
    try:
        cfg = merger.merge_and_generate()
        proxies = cfg.get('proxies', [])
        proxy_groups = cfg.get('proxy-groups', [])
        
        output_parts = [header.rstrip(), '\nproxies:']
        for proxy in proxies:
            output_parts.append(f'  - {json.dumps(proxy, ensure_ascii=False, separators=(",",":"))}')
        output_parts.append('\nproxy-groups:')
        for group in proxy_groups:
            output_parts.append(f'  - {json.dumps(group, ensure_ascii=False, separators=(",",":"))}')
        
        if suffix:
            output_parts.append('\n' + suffix)
        return {"content": "\n".join(output_parts)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/save_content")
def save_final_content(data: FinalContent, _: bool = Depends(verify_session)):
    target = data.save_path if data.save_path else OUTPUT_FILE
    try:
        with open(target, 'w', encoding='utf-8') as f:
            f.write(data.content)
        return {"status": "success", "output_file": target}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/download_result")
def download_result(_: bool = Depends(verify_session)):
    if os.path.exists(OUTPUT_FILE):
        return FileResponse(OUTPUT_FILE, media_type='application/yaml', filename='myconfig.yaml')
    raise HTTPException(status_code=404, detail="Config not generated yet")

# ==================== GeoIP API ====================

# Initialize scheduler on startup
scheduler = get_scheduler()

# ==================== Online GeoIP API Settings ====================

from geoip_service import (
    set_online_geoip_config, get_online_geoip_config, clear_online_geoip_cache,
    get_all_geoip_apis, add_custom_geoip_api, update_custom_geoip_api, 
    delete_custom_geoip_api, set_api_enabled, BUILTIN_GEOIP_APIS
)

class OnlineGeoIPConfigRequest(BaseModel):
    preferred_api: Optional[str] = None  # "ip-api.com", "ipwhois", "ipinfo", or custom id
    ipinfo_token: Optional[str] = None

class CustomGeoIPAPIRequest(BaseModel):
    name: str
    url: str  # URL template with {ip} placeholder
    token: Optional[str] = ""  # Optional token/API key
    limit: Optional[str] = ""  # Optional usage limit display (e.g. "1000次/天")
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, str]] = None
    country_code_path: Optional[str] = ""  # JSON path like "countryCode" or "data.country.code"
    country_name_path: Optional[str] = ""
    city_path: Optional[str] = ""
    success_check: Optional[str] = ""  # e.g. "status==success"

class UpdateCustomGeoIPAPIRequest(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    token: Optional[str] = None
    limit: Optional[str] = None
    method: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    country_code_path: Optional[str] = None
    country_name_path: Optional[str] = None
    city_path: Optional[str] = None
    success_check: Optional[str] = None
    enabled: Optional[bool] = None

class TestCustomGeoIPAPIRequest(BaseModel):
    url: str
    token: Optional[str] = ""
    country_code_path: Optional[str] = ""
    country_name_path: Optional[str] = ""
    city_path: Optional[str] = ""
    success_check: Optional[str] = ""
    test_ip: Optional[str] = "8.8.8.8"

class APIEnabledRequest(BaseModel):
    enabled: bool

@app.get("/api/geoip/online-config")
def get_online_geoip_api_config(_: bool = Depends(verify_session)):
    """Get online GeoIP API configuration"""
    config = load_config()
    saved_config = config.get('online_geoip_config', {})
    
    # Merge with current runtime config
    runtime_config = get_online_geoip_config()
    
    return {
        "preferred_api": saved_config.get('preferred_api', runtime_config.get('preferred_api', 'ip-api.com')),
        "ipinfo_token": saved_config.get('ipinfo_token', ''),
        "apis": get_all_geoip_apis()
    }

@app.post("/api/geoip/online-config")
def set_online_geoip_api_config(data: OnlineGeoIPConfigRequest, _: bool = Depends(verify_session)):
    """Set online GeoIP API configuration"""
    config = load_config()
    
    if 'online_geoip_config' not in config:
        config['online_geoip_config'] = {}
    
    if data.preferred_api is not None:
        config['online_geoip_config']['preferred_api'] = data.preferred_api
        set_online_geoip_config(preferred_api=data.preferred_api)
    
    if data.ipinfo_token is not None:
        config['online_geoip_config']['ipinfo_token'] = data.ipinfo_token
        set_online_geoip_config(ipinfo_token=data.ipinfo_token)
    
    # Clear cache when config changes
    clear_online_geoip_cache()
    
    save_config(config)
    return {"success": True, "config": config['online_geoip_config']}

@app.get("/api/geoip/apis")
def get_geoip_apis(_: bool = Depends(verify_session)):
    """Get all available GeoIP APIs (builtin + custom)"""
    return {"apis": get_all_geoip_apis()}

@app.post("/api/geoip/apis")
def create_custom_geoip_api(data: CustomGeoIPAPIRequest, _: bool = Depends(verify_session)):
    """Create a custom GeoIP API"""
    try:
        new_api = add_custom_geoip_api({
            "name": data.name,
            "url": data.url,
            "token": data.token or "",
            "limit": data.limit or "",
            "method": data.method or "GET",
            "headers": data.headers or {},
            "country_code_path": data.country_code_path,
            "country_name_path": data.country_name_path or "",
            "city_path": data.city_path or "",
            "success_check": data.success_check or "",
        })
        
        # Save to config
        config = load_config()
        if 'online_geoip_config' not in config:
            config['online_geoip_config'] = {}
        config['online_geoip_config']['custom_apis'] = get_online_geoip_config().get('custom_apis', [])
        save_config(config)
        
        return {"success": True, "api": new_api}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.put("/api/geoip/apis/{api_id}")
def update_geoip_api(api_id: str, data: UpdateCustomGeoIPAPIRequest, _: bool = Depends(verify_session)):
    """Update a custom GeoIP API"""
    try:
        update_data = {k: v for k, v in data.dict().items() if v is not None}
        updated_api = update_custom_geoip_api(api_id, update_data)
        
        # Save to config
        config = load_config()
        if 'online_geoip_config' not in config:
            config['online_geoip_config'] = {}
        config['online_geoip_config']['custom_apis'] = get_online_geoip_config().get('custom_apis', [])
        save_config(config)
        
        return {"success": True, "api": updated_api}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.delete("/api/geoip/apis/{api_id}")
def delete_geoip_api(api_id: str, _: bool = Depends(verify_session)):
    """Delete a custom GeoIP API"""
    # Check if it's a builtin API
    if any(api["id"] == api_id for api in BUILTIN_GEOIP_APIS):
        raise HTTPException(status_code=400, detail="Cannot delete builtin API")
    
    if delete_custom_geoip_api(api_id):
        # Save to config
        config = load_config()
        if 'online_geoip_config' not in config:
            config['online_geoip_config'] = {}
        config['online_geoip_config']['custom_apis'] = get_online_geoip_config().get('custom_apis', [])
        save_config(config)
        
        return {"success": True}
    else:
        raise HTTPException(status_code=404, detail="API not found")

@app.post("/api/geoip/apis/{api_id}/toggle")
def toggle_geoip_api(api_id: str, data: APIEnabledRequest, _: bool = Depends(verify_session)):
    """Enable or disable a GeoIP API"""
    set_api_enabled(api_id, data.enabled)
    
    # Save to config
    config = load_config()
    if 'online_geoip_config' not in config:
        config['online_geoip_config'] = {}
    config['online_geoip_config']['api_settings'] = get_online_geoip_config().get('api_settings', {})
    save_config(config)
    
    return {"success": True, "enabled": data.enabled}

class TestBuiltinGeoIPAPIRequest(BaseModel):
    test_ip: Optional[str] = "8.8.8.8"

@app.post("/api/geoip/apis/{api_id}/test")
def test_geoip_api(api_id: str, data: TestBuiltinGeoIPAPIRequest = None, _: bool = Depends(verify_session)):
    """Test a GeoIP API with a sample IP"""
    from geoip_service import lookup_ip_online, _lookup_ip_api_com, _lookup_ipwhois, _lookup_ipinfo, _lookup_custom_api, get_online_geoip_config as get_geoip_config
    import requests
    
    test_ip = data.test_ip if data else "8.8.8.8"
    
    # Find the API
    all_apis = get_all_geoip_apis()
    api = next((a for a in all_apis if a["id"] == api_id), None)
    
    if not api:
        raise HTTPException(status_code=404, detail="API not found")
    
    raw_response = None
    
    try:
        result = None
        # Get raw response for builtin APIs
        if api_id == "ip-api.com":
            resp = requests.get(f"http://ip-api.com/json/{test_ip}?lang=zh-CN", timeout=10)
            if resp.status_code == 200:
                raw_response = resp.json()
            result = _lookup_ip_api_com(test_ip)
        elif api_id == "ipwhois":
            resp = requests.get(f"https://ipwhois.app/json/{test_ip}?lang=zh-CN", timeout=10)
            if resp.status_code == 200:
                raw_response = resp.json()
            result = _lookup_ipwhois(test_ip)
        elif api_id == "ipinfo":
            config = load_config()
            token = config.get('online_geoip_config', {}).get('ipinfo_token', '')
            url = f"https://ipinfo.io/{test_ip}/json"
            if token:
                url += f"?token={token}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                raw_response = resp.json()
            result = _lookup_ipinfo(test_ip)
        elif not api.get("builtin"):
            # For custom APIs, get the full config with token from runtime config
            geoip_config = get_geoip_config()
            custom_apis = geoip_config.get("custom_apis", [])
            full_api = next((a for a in custom_apis if a["id"] == api_id), None)
            if full_api:
                # Make test request to get raw response
                url = full_api["url"].replace("{ip}", test_ip)
                token = full_api.get("token", "")
                if token:
                    url = url.replace("{key}", token).replace("{token}", token)
                else:
                    url = url.replace("{key}", "").replace("{token}", "")
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    raw_response = resp.json()
                result = _lookup_custom_api(test_ip, full_api)
            else:
                result = None
        
        if result:
            return {
                "success": True,
                "test_ip": test_ip,
                "result": result,
                "raw_response": raw_response
            }
        else:
            return {
                "success": False,
                "test_ip": test_ip,
                "error": "No result returned",
                "raw_response": raw_response
            }
    except Exception as e:
        return {
            "success": False,
            "test_ip": test_ip,
            "error": str(e),
            "raw_response": raw_response
        }

@app.post("/api/geoip/test-custom-api")
def test_custom_geoip_api(data: TestCustomGeoIPAPIRequest, _: bool = Depends(verify_session)):
    """Test a custom GeoIP API configuration before saving"""
    from geoip_service import _lookup_custom_api, _auto_detect_json_paths
    import requests
    
    test_ip = data.test_ip or "8.8.8.8"
    token = data.token or ""
    
    # Build API config for testing
    api_config = {
        "url": data.url,
        "token": token,
        "country_code_path": data.country_code_path or "",
        "country_name_path": data.country_name_path or "",
        "city_path": data.city_path or "",
        "success_check": data.success_check or ""
    }
    
    raw_response = None
    
    try:
        # Make a test request
        url = api_config["url"].replace("{ip}", test_ip).replace("{key}", token).replace("{token}", token)
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        raw_response = resp.json()
        
        # If no field paths specified, try auto-detection
        if not api_config["country_code_path"]:
            detected = _auto_detect_json_paths(raw_response)
            if detected:
                api_config.update(detected)
        
        result = _lookup_custom_api(test_ip, api_config)
        
        if result:
            return {
                "success": True,
                "test_ip": test_ip,
                "result": result,
                "raw_response": raw_response,
                "detected_paths": {
                    "country_code_path": api_config.get("country_code_path", ""),
                    "country_name_path": api_config.get("country_name_path", ""),
                    "city_path": api_config.get("city_path", "")
                }
            }
        else:
            return {
                "success": False,
                "test_ip": test_ip,
                "error": "No result returned - check field paths",
                "raw_response": raw_response
            }
    except Exception as e:
        return {
            "success": False,
            "test_ip": test_ip,
            "error": str(e),
            "raw_response": raw_response
        }

@app.post("/api/geoip/clear-online-cache")
def clear_online_geoip_api_cache(_: bool = Depends(verify_session)):
    """Clear online GeoIP lookup cache"""
    clear_online_geoip_cache()
    return {"success": True, "message": "Cache cleared"}

# ==================== Scheduler API ====================

@app.on_event("startup")
async def startup_event():
    """Initialize scheduler and load scheduled tasks on startup"""
    # Start Go speedtest service
    start_go_speedtest_service()
    
    # Load saved template from config
    config = load_config()
    if 'template' in config:
        template = config['template']
        if 'header' in template:
            ConfigMerger.TEMPLATES['header'] = template['header']
        if 'suffix' in template:
            ConfigMerger.TEMPLATES['suffix'] = template['suffix']
        print("Custom template loaded from config")
    
    # Load online GeoIP API config
    online_geoip_cfg = config.get('online_geoip_config', {})
    if online_geoip_cfg:
        set_online_geoip_config(
            preferred_api=online_geoip_cfg.get('preferred_api'),
            ipinfo_token=online_geoip_cfg.get('ipinfo_token'),
            custom_apis=online_geoip_cfg.get('custom_apis'),
            api_settings=online_geoip_cfg.get('api_settings')
        )
        print(f"Online GeoIP API config loaded: {online_geoip_cfg.get('preferred_api', 'ip-api.com')}")
    
    scheduler.start()
    load_scheduled_subscriptions()
    
    print("Scheduler initialized and tasks loaded")

@app.on_event("shutdown")
async def shutdown_event():
    """Stop scheduler and Go service on shutdown"""
    scheduler.stop()
    stop_go_speedtest_service()

def load_scheduled_subscriptions():
    """Load all subscriptions with cron expressions into scheduler"""
    config = load_config()
    subs = config.get('subscriptions', [])
    
    for sub in subs:
        cron_expr = sub.get('cron_expr')
        if cron_expr and sub.get('enabled', True):
            scheduler.add_job(
                f"sub_{sub['id']}",
                cron_expr,
                scheduled_subscription_update,
                sub['id']
            )

async def scheduled_subscription_update(sub_id: str):
    """Called by scheduler to update a subscription"""
    print(f"Scheduled update for subscription: {sub_id}")
    try:
        config = load_config()
        subs = config.get('subscriptions', [])
        sub = next((s for s in subs if s['id'] == sub_id), None)
        
        if not sub:
            print(f"Subscription {sub_id} not found")
            return
        
        # Fetch and update subscription
        response = requests.get(sub['url'], timeout=30)
        response.raise_for_status()
        
        # Parse subscription content
        content = response.text
        nodes = parse_subscription_content(content)
        
        # Update subscription data
        sub['nodes'] = nodes
        sub['node_count'] = len(nodes)
        sub['last_update'] = int(time.time())
        sub['update_status'] = 'success'
        
        # Parse traffic info from headers
        traffic_info = parse_subscription_headers(response.headers)
        if traffic_info:
            sub.update(traffic_info)
        
        # Calculate next update time
        if sub.get('cron_expr'):
            next_run = scheduler.get_next_run_time(sub['cron_expr'])
            sub['next_update'] = next_run.strftime("%Y-%m-%d %H:%M:%S") if next_run else None
        
        # Save subscription file
        sub_file = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
        with open(sub_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        save_config(config)
        print(f"Subscription {sub_id} updated successfully, {len(nodes)} nodes")
        
    except Exception as e:
        print(f"Failed to update subscription {sub_id}: {e}")
        # Update status to failed
        config = load_config()
        subs = config.get('subscriptions', [])
        sub = next((s for s in subs if s['id'] == sub_id), None)
        if sub:
            sub['update_status'] = 'failed'
            sub['last_update'] = int(time.time())
            save_config(config)

def parse_subscription_headers(headers) -> dict:
    """
    Parse subscription traffic info from response headers.
    
    Common headers:
    - subscription-userinfo: upload=xxx; download=xxx; total=xxx; expire=xxx
    - Subscription-Userinfo: same as above
    """
    result = {}
    
    # Try different header names
    userinfo = headers.get('subscription-userinfo') or headers.get('Subscription-Userinfo')
    
    if userinfo:
        # Parse format: upload=xxx; download=xxx; total=xxx; expire=xxx
        for part in userinfo.split(';'):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'upload':
                    result['traffic_upload'] = int(value)
                elif key == 'download':
                    result['traffic_download'] = int(value)
                elif key == 'total':
                    result['traffic_total'] = int(value)
                elif key == 'expire':
                    # Convert timestamp to datetime string
                    try:
                        expire_ts = int(value)
                        result['traffic_expire'] = datetime.fromtimestamp(expire_ts).strftime("%Y-%m-%d")
                    except:
                        result['traffic_expire'] = value
    
    return result

def parse_subscription_content(content: str) -> list:
    """
    Parse subscription content to extract nodes.
    Supports: YAML format, Base64 encoded links, plain text links
    """
    nodes = []
    
    # Try YAML format first
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'proxies' in data:
            return data['proxies']
    except:
        pass
    
    # Try Base64 decode
    try:
        decoded = decode_base64(content)
        if decoded:
            content = decoded
    except:
        pass
    
    # Parse line by line for proxy links
    for line in content.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        
        node = None
        if line.startswith('vmess://'):
            node = parse_vmess_link(line)
        elif line.startswith('vless://'):
            node = parse_vless_link(line)
        elif line.startswith('ss://'):
            node = parse_ss_link(line)
        elif line.startswith('ssr://'):
            node = parse_ssr_link(line)
        elif line.startswith('trojan://'):
            node = parse_trojan_link(line)
        elif line.startswith('hysteria2://') or line.startswith('hy2://'):
            node = parse_hysteria2_link(line)
        elif line.startswith('hysteria://') or line.startswith('hy://'):
            node = parse_hysteria_link(line)
        elif line.startswith('tuic://'):
            node = parse_tuic_link(line)
        
        if node:
            nodes.append(node)
    
    return nodes

@app.get("/api/scheduler/status")
def get_scheduler_status(_: bool = Depends(verify_session)):
    """Get scheduler status"""
    return {
        "running": scheduler.is_running(),
        "jobs": scheduler.list_jobs()
    }

@app.get("/api/scheduler/presets")
def get_cron_presets(_: bool = Depends(verify_session)):
    """Get common cron presets"""
    return {
        "presets": [
            {"value": v, "label": get_cron_description(v), "name": k}
            for k, v in CRON_PRESETS.items()
        ]
    }

class ValidateCronRequest(BaseModel):
    cron_expr: str

@app.post("/api/scheduler/validate-cron")
def validate_cron_expression(data: ValidateCronRequest):
    """Validate cron expression and get next run time (no auth required for real-time preview)"""
    if not data.cron_expr or not data.cron_expr.strip():
        return {"valid": False, "error": "Cron expression is empty", "next_run": None}
    
    is_valid, error = scheduler.validate_cron_expression(data.cron_expr)
    if not is_valid:
        return {"valid": False, "error": error, "next_run": None}
    
    next_run = scheduler.get_next_run_time(data.cron_expr)
    return {
        "valid": True,
        "error": None,
        "next_run": next_run.strftime("%Y-%m-%d %H:%M:%S") if next_run else None,
        "description": get_cron_description(data.cron_expr)
    }

class SetSubscriptionSchedule(BaseModel):
    cron_expr: Optional[str] = None
    enabled: Optional[bool] = True

@app.put("/api/subscriptions/{sub_id}/schedule")
def set_subscription_schedule(sub_id: str, data: SetSubscriptionSchedule, _: bool = Depends(verify_session)):
    """Set or update subscription auto-update schedule"""
    config = load_config()
    subs = config.get('subscriptions', [])
    sub = next((s for s in subs if s['id'] == sub_id), None)
    
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    # Validate cron expression
    if data.cron_expr:
        is_valid, error = scheduler.validate_cron_expression(data.cron_expr)
        if not is_valid:
            raise HTTPException(status_code=400, detail=f"Invalid cron expression: {error}")
    
    # Update subscription
    sub['cron_expr'] = data.cron_expr
    
    # Update scheduler
    if data.cron_expr and data.enabled:
        scheduler.add_job(
            f"sub_{sub_id}",
            data.cron_expr,
            scheduled_subscription_update,
            sub_id
        )
        next_run = scheduler.get_next_run_time(data.cron_expr)
        sub['next_update'] = next_run.strftime("%Y-%m-%d %H:%M:%S") if next_run else None
    else:
        scheduler.remove_job(f"sub_{sub_id}")
        sub['next_update'] = None
    
    save_config(config)
    
    return {
        "status": "success",
        "cron_expr": sub.get('cron_expr'),
        "next_update": sub.get('next_update'),
        "description": get_cron_description(data.cron_expr) if data.cron_expr else None
    }

@app.post("/api/subscriptions/{sub_id}/update")
async def manual_subscription_update(sub_id: str, _: bool = Depends(verify_session)):
    """Manually trigger subscription update"""
    config = load_config()
    subs = config.get('subscriptions', [])
    sub = next((s for s in subs if s['id'] == sub_id), None)
    
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    try:
        # Fetch subscription
        response = requests.get(sub['url'], timeout=30)
        response.raise_for_status()
        
        content = response.text
        nodes = parse_subscription_content(content)
        
        # Update subscription data
        sub['nodes'] = nodes
        sub['node_count'] = len(nodes)
        sub['last_update'] = int(time.time())
        sub['update_status'] = 'success'
        
        # Parse traffic info
        traffic_info = parse_subscription_headers(response.headers)
        if traffic_info:
            sub.update(traffic_info)
        
        # Save subscription file
        sub_file = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
        with open(sub_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        save_config(config)
        
        return {
            "status": "success",
            "node_count": len(nodes),
            "last_update": sub['last_update'],
            "traffic": traffic_info
        }
        
    except requests.exceptions.RequestException as e:
        sub['update_status'] = 'failed'
        sub['last_update'] = int(time.time())
        save_config(config)
        raise HTTPException(status_code=500, detail=f"Failed to fetch subscription: {str(e)}")

# ==================== Speed Test API ====================

speedtest_service = get_speedtest_service()

class SpeedTestRequest(BaseModel):
    test_latency: Optional[bool] = True
    test_region: Optional[bool] = False
    test_speed: Optional[bool] = False
    timeout: Optional[int] = 5000  # milliseconds
    geoip_api: Optional[str] = None  # API to use for region detection

@app.post("/api/nodes/{sub_id}/{node_idx}/test")
async def test_subscription_node(sub_id: str, node_idx: int, data: SpeedTestRequest = None, _: bool = Depends(verify_session)):
    """Test a node from subscription by index - real proxy latency/speed test via Go service"""
    import socket
    import asyncio
    import httpx
    
    data = data or SpeedTestRequest()
    
    config = load_config()
    timeout_sec = (data.timeout or 5000) / 1000.0
    
    # Find node and track location for saving
    node = None
    node_location = None  # ('subscription', sub_id, node_idx) or ('custom', node_idx) or ('chain', chain_id)
    yaml_nodes = None  # For subscription nodes, keep reference to the full list
    chain_obj = None  # For chain nodes
    chain_nodes = []  # For chain proxy testing, list of all nodes in the chain
    
    if sub_id == 'custom':
        custom_nodes = config.get('custom_nodes', [])
        if 0 <= node_idx < len(custom_nodes):
            node = custom_nodes[node_idx]
            node_location = ('custom', node_idx)
    elif sub_id == 'chain':
        # Chain proxy - build the full chain for testing
        chains = config.get('proxy_chains', [])
        if 0 <= node_idx < len(chains):
            chain_obj = chains[node_idx]
            node_location = ('chain', node_idx)
            # Build the full chain of nodes for testing
            chain_nodes = []
            if chain_obj.get('rows') and len(chain_obj['rows']) > 0:
                first_row = chain_obj['rows'][0]
                if first_row.get('nodes') and len(first_row['nodes']) > 0:
                    for node_ref in first_row['nodes']:
                        chain_node = find_node_by_reference(node_ref['sub_id'], node_ref['node_index'])
                        if chain_node:
                            chain_nodes.append(chain_node)
                    # Use the last node as the "node" for result display
                    if chain_nodes:
                        node = chain_nodes[-1]
    else:
        # Subscription nodes are stored in YAML files, not in config.json
        # Check if subscription exists first
        sub_exists = any(sub.get('id') == sub_id for sub in config.get('subscriptions', []))
        if sub_exists:
            filepath = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        cfg = yaml.safe_load(f)
                    yaml_nodes = cfg.get('proxies', []) if cfg else []
                    if 0 <= node_idx < len(yaml_nodes):
                        node = yaml_nodes[node_idx]
                        node_location = ('subscription', sub_id, node_idx)
                except Exception:
                    pass
    
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    result = {
        "node_name": node.get('name', ''),
        "server": node.get('server', ''),
        "port": node.get('port', 443),
        "latency": None,
        "region": None,
        "city": None,
        "exit_ip": None,
        "speed": None,
        "peak_speed": None,
        "error": None
    }
    
    server = node.get('server', '')
    port = node.get('port', 443)
    need_save = False
    
    # Go speedtest service URL
    GO_SPEEDTEST_URL = os.environ.get('GO_SPEEDTEST_URL', 'http://localhost:9876')
    
    # Prepare node config for Go service (remove non-serializable fields)
    node_config = {k: v for k, v in node.items() if k not in ['geoip', 'last_latency', 'last_latency_time', 'last_speed', 'last_speed_time']}
    
    # Prepare chain config if this is a chain proxy test
    chain_config = None
    if node_location and node_location[0] == 'chain' and chain_nodes:
        chain_config = [
            {k: v for k, v in n.items() if k not in ['geoip', 'last_latency', 'last_latency_time', 'last_speed', 'last_speed_time']}
            for n in chain_nodes
        ]
    
    # Test latency using Go service (real proxy test)
    if data.test_latency and server:
        try:
            async with httpx.AsyncClient(timeout=timeout_sec + 5) as client:
                # Use chain config for chain proxies, otherwise use single node
                request_data = {
                    "url": "http://cp.cloudflare.com/generate_204",
                    "timeout": data.timeout or 5000
                }
                if chain_config:
                    request_data["chain"] = chain_config
                else:
                    request_data["node"] = node_config
                
                resp = await client.post(
                    f"{GO_SPEEDTEST_URL}/api/delay",
                    json=request_data
                )
                resp_data = resp.json()
                
                if resp_data.get('success'):
                    latency = resp_data.get('latency', -1)
                    result["latency"] = latency
                    node['last_latency'] = latency
                    node['last_latency_time'] = int(time.time())
                    need_save = True
                else:
                    result["latency"] = -1
                    result["error"] = resp_data.get('error', 'Unknown error')
                    node['last_latency'] = -1
                    node['last_latency_time'] = int(time.time())
                    need_save = True
        except httpx.TimeoutException:
            result["latency"] = -1
            result["error"] = "Timeout"
            node['last_latency'] = -1
            node['last_latency_time'] = int(time.time())
            need_save = True
        except Exception as e:
            # Fallback to TCP test if Go service unavailable
            try:
                ip = socket.gethostbyname(server)
                start_time = asyncio.get_event_loop().time()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout_sec
                )
                latency = int((asyncio.get_event_loop().time() - start_time) * 1000)
                writer.close()
                await writer.wait_closed()
                result["latency"] = latency
                node['last_latency'] = latency
                node['last_latency_time'] = int(time.time())
                need_save = True
            except Exception as tcp_e:
                result["latency"] = -2
                result["error"] = f"Go service error: {e}, TCP fallback error: {tcp_e}"
                node['last_latency'] = -2
                node['last_latency_time'] = int(time.time())
                need_save = True
    
    # Test region - Priority: 1. Exit IP via Go service -> GeoIP (country+city), 2. Node name (flag/keyword)
    if data.test_region and server:
        region_info = None
        exit_ip = None
        city = None
        
        # 1. Try to get exit IP via Go service and lookup GeoIP
        try:
            async with httpx.AsyncClient(timeout=timeout_sec + 5) as client:
                # Use chain config for chain proxies
                request_data = {"timeout": data.timeout or 5000}
                if chain_config:
                    request_data["chain"] = chain_config
                else:
                    request_data["node"] = node_config
                
                resp = await client.post(
                    f"{GO_SPEEDTEST_URL}/api/ip",
                    json=request_data
                )
                resp_data = resp.json()
                
                if resp_data.get('success') and resp_data.get('ip'):
                    exit_ip = resp_data.get('ip')
                    result["exit_ip"] = exit_ip
                    
                    # Lookup GeoIP using online API
                    from geoip_service import lookup_ip_online
                    geoip_api_id = data.geoip_api if data else None
                    geo_data = lookup_ip_online(exit_ip, api_id=geoip_api_id)
                    
                    if geo_data:
                        region_info = {
                            "country": geo_data.get('country_name', ''),
                            "country_code": geo_data.get('iso_code', ''),
                            "flag": geo_data.get('flag', ''),
                        }
                        city = geo_data.get('city')
                        if city:
                            result["city"] = city
        except Exception:
            pass
        
        # 2. Fallback to node name extraction if GeoIP failed
        if not region_info:
            node_name = node.get('name', '')
            name_country = extract_country_from_name(node_name)
            if name_country:
                region_info = {
                    "country": name_country['country'],
                    "country_code": name_country['country_code'],
                    "flag": name_country['flag'],
                }
        
        if region_info:
            result["region"] = region_info
            
            # Save region info to node for caching
            node['geoip'] = {
                'country': region_info['country'],
                'country_code': region_info['country_code'],
                'flag': region_info['flag'],
                'city': city,
                'exit_ip': exit_ip,
                'updated_at': int(time.time())
            }
            need_save = True
        else:
            result["region"] = None
    
    # Test speed using Go service
    if data.test_speed and server:
        try:
            speedtest_config = config.get('speedtest', {})
            speed_timeout = speedtest_config.get('timeout', 10)
            
            async with httpx.AsyncClient(timeout=speed_timeout + 10) as client:
                # Use chain config for chain proxies
                request_data = {
                    "url": "https://speed.cloudflare.com/__down?bytes=10000000",
                    "timeout": speed_timeout,
                    "mode": "peak",
                    "peakSampleInterval": 100
                }
                if chain_config:
                    request_data["chain"] = chain_config
                else:
                    request_data["node"] = node_config
                
                resp = await client.post(
                    f"{GO_SPEEDTEST_URL}/api/speed",
                    json=request_data
                )
                resp_data = resp.json()
                
                if resp_data.get('success'):
                    result["speed"] = round(resp_data.get('speed', 0), 2)
                    result["peak_speed"] = round(resp_data.get('peakSpeed', 0), 2)
                    
                    # Save speed to node
                    node['last_speed'] = result["speed"]
                    node['last_peak_speed'] = result["peak_speed"]
                    node['last_speed_time'] = int(time.time())
                    need_save = True
                else:
                    result["error"] = resp_data.get('error', 'Speed test failed')
        except Exception as e:
            result["error"] = f"Speed test error: {e}"
    
    # Save config if any changes were made
    if need_save:
        if node_location and node_location[0] == 'subscription':
            # Save to YAML file for subscription nodes
            sub_id_to_save = node_location[1]
            filepath = os.path.join(YAML_SOURCE_DIR, f"{sub_id_to_save}.yaml")
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    cfg = yaml.safe_load(f)
                if cfg and 'proxies' in cfg and 0 <= node_idx < len(cfg['proxies']):
                    # Update specific fields in the existing node instead of replacing entire node
                    existing_node = cfg['proxies'][node_idx]
                    if 'geoip' in node:
                        existing_node['geoip'] = node['geoip']
                    if 'last_latency' in node:
                        existing_node['last_latency'] = node['last_latency']
                    if 'last_latency_time' in node:
                        existing_node['last_latency_time'] = node['last_latency_time']
                    if 'last_speed' in node:
                        existing_node['last_speed'] = node['last_speed']
                    if 'last_peak_speed' in node:
                        existing_node['last_peak_speed'] = node['last_peak_speed']
                    if 'last_speed_time' in node:
                        existing_node['last_speed_time'] = node['last_speed_time']
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
            except Exception:
                pass  # Silently fail saving to YAML
        elif node_location and node_location[0] == 'chain':
            # Save latency to chain object in config
            chain_idx = node_location[1]
            chains = config.get('proxy_chains', [])
            if 0 <= chain_idx < len(chains):
                if 'last_latency' in node:
                    chains[chain_idx]['last_latency'] = node['last_latency']
                if 'last_latency_time' in node:
                    chains[chain_idx]['last_latency_time'] = node['last_latency_time']
                if 'last_speed' in node:
                    chains[chain_idx]['last_speed'] = node['last_speed']
                if 'last_speed_time' in node:
                    chains[chain_idx]['last_speed_time'] = node['last_speed_time']
                save_config(config)
        elif node_location and node_location[0] == 'custom':
            # Save to config.json for custom nodes
            custom_idx = node_location[1]
            custom_nodes = config.get('custom_nodes', [])
            if 0 <= custom_idx < len(custom_nodes):
                if 'geoip' in node:
                    custom_nodes[custom_idx]['geoip'] = node['geoip']
                if 'last_latency' in node:
                    custom_nodes[custom_idx]['last_latency'] = node['last_latency']
                if 'last_latency_time' in node:
                    custom_nodes[custom_idx]['last_latency_time'] = node['last_latency_time']
                if 'last_speed' in node:
                    custom_nodes[custom_idx]['last_speed'] = node['last_speed']
                if 'last_peak_speed' in node:
                    custom_nodes[custom_idx]['last_peak_speed'] = node['last_peak_speed']
                if 'last_speed_time' in node:
                    custom_nodes[custom_idx]['last_speed_time'] = node['last_speed_time']
                save_config(config)
    
    return result

class NodeTestRequest(BaseModel):
    test_speed: Optional[bool] = False
    timeout: Optional[int] = 10

@app.post("/api/nodes/{node_id}/test")
async def test_single_node(node_id: str, data: SpeedTestRequest = None, _: bool = Depends(verify_session)):
    """Test a single node's latency and optionally speed"""
    data = data or SpeedTestRequest()
    config = load_config()
    
    # Find node in subscriptions or custom nodes
    node = None
    for sub in config.get('subscriptions', []):
        for n in sub.get('nodes', []):
            if n.get('id') == node_id or n.get('name') == node_id:
                node = n
                break
        if node:
            break
    
    if not node:
        for n in config.get('custom_nodes', []):
            if n.get('id') == node_id or n.get('name') == node_id:
                node = n
                break
    
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    # For now, we need a proxy URL - this would typically come from a running proxy
    # In a real implementation, you'd need to start a proxy for this node
    # For testing, we'll return a placeholder
    return {
        "status": "info",
        "message": "Direct node testing requires proxy integration. Use batch test with running proxy.",
        "node": node.get('name')
    }

class BatchTestRequest(BaseModel):
    node_ids: Optional[List[str]] = None  # None = test all
    timeout: Optional[int] = 10
    concurrency: Optional[int] = 10

@app.post("/api/nodes/test-batch")
async def test_batch_nodes(data: BatchTestRequest, _: bool = Depends(verify_session)):
    """Test multiple nodes (placeholder - requires proxy integration)"""
    return {
        "status": "info",
        "message": "Batch testing requires proxy integration. This feature will be available when proxy management is implemented.",
        "config": {
            "node_ids": data.node_ids,
            "timeout": data.timeout,
            "concurrency": data.concurrency
        }
    }

@app.get("/api/speedtest/config")
def get_speedtest_config(_: bool = Depends(verify_session)):
    """Get current speed test configuration"""
    config = load_config()
    speedtest_config = config.get('speedtest', {})
    
    return {
        "latency_url": speedtest_config.get('latency_url', 'http://www.gstatic.com/generate_204'),
        "speed_url": speedtest_config.get('speed_url', 'http://cachefly.cachefly.net/10mb.test'),
        "timeout": speedtest_config.get('timeout', 10),
        "concurrency": speedtest_config.get('concurrency', 10),
        "test_speed_by_default": speedtest_config.get('test_speed_by_default', False)
    }

class UpdateSpeedTestConfig(BaseModel):
    latency_url: Optional[str] = None
    speed_url: Optional[str] = None
    timeout: Optional[int] = None
    concurrency: Optional[int] = None
    test_speed_by_default: Optional[bool] = None

@app.put("/api/speedtest/config")
def update_speedtest_config(data: UpdateSpeedTestConfig, _: bool = Depends(verify_session)):
    """Update speed test configuration"""
    config = load_config()
    
    if 'speedtest' not in config:
        config['speedtest'] = {}
    
    if data.latency_url is not None:
        config['speedtest']['latency_url'] = data.latency_url
    if data.speed_url is not None:
        config['speedtest']['speed_url'] = data.speed_url
    if data.timeout is not None:
        config['speedtest']['timeout'] = data.timeout
    if data.concurrency is not None:
        config['speedtest']['concurrency'] = data.concurrency
    if data.test_speed_by_default is not None:
        config['speedtest']['test_speed_by_default'] = data.test_speed_by_default
    
    save_config(config)
    return {"status": "success", "config": config['speedtest']}

@app.get("/api/speedtest/colors")
def get_color_thresholds():
    """Get color threshold info for latency and speed"""
    return {
        "latency": {
            "green": {"max": 200, "label": "< 200ms"},
            "yellow": {"min": 200, "max": 500, "label": "200-500ms"},
            "red": {"min": 500, "label": "> 500ms"},
            "gray": {"label": "超时/失败"}
        },
        "speed": {
            "green": {"min": 1.0, "label": "> 1 MB/s"},
            "yellow": {"min": 0.5, "max": 1.0, "label": "0.5-1 MB/s"},
            "red": {"max": 0.5, "label": "< 0.5 MB/s"},
            "gray": {"label": "未测试"}
        }
    }

# ==================== Stats API ====================

@app.get("/api/stats/overview")
def get_stats_overview(_: bool = Depends(verify_session)):
    """Get dashboard statistics with caching"""
    import time
    
    # Check cache
    current_time = time.time()
    if (STATS_CACHE['overview'] is not None and 
        current_time - STATS_CACHE['last_update'] < STATS_CACHE['cache_duration']):
        return STATS_CACHE['overview']
    
    config = load_config()
    subs = config.get('subscriptions', [])
    custom_nodes = config.get('custom_nodes', [])
    users = config.get('users', [])
    
    # Count nodes and protocols
    total_nodes = 0
    protocol_counts = {}
    
    # Filter keywords for info nodes
    info_keywords = [
        '剩余流量', '套餐到期', '距离下次重置', '建议', '官网', '未到期',
        '剩余', '到期', '重置', '流量', '过期', '订阅', '网址', '公告',
        '群组', 'Telegram', 'TG', '客服', '续费', '购买', '套餐',
        '使用说明', '教程', '更新', '通知', '邀请', '返利', '📊'
    ]
    
    # Helper to process proxies
    best_node = None
    best_latency = float('inf')
    
    def process_proxies(proxies, source_name=''):
        nonlocal total_nodes, best_node, best_latency
        if not proxies: return 0
        count = 0
        for p in proxies:
            if any(kw in p.get('name', '') for kw in info_keywords):
                continue
            count += 1
            ptype = p.get('type', 'unknown').lower()
            protocol_counts[ptype] = protocol_counts.get(ptype, 0) + 1
            
            # Track best latency
            latency = p.get('last_latency')
            if latency is not None and latency > 0 and latency < best_latency:
                best_latency = latency
                best_node = {
                    'name': p.get('name', 'Unknown'),
                    'latency': latency,
                    'source': source_name
                }
        return count

    # Subscriptions
    for sub in subs:
        if sub.get('enabled') != False:
            # Try to read from YAML
            filepath = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
            proxies = []
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                    proxies = data.get('proxies', []) if data else []
                except:
                    pass
            
            # If no YAML, check config (fallback)
            if not proxies:
                proxies = sub.get('nodes', [])
            
            total_nodes += process_proxies(proxies, sub.get('name', ''))

    # Custom nodes
    total_nodes += process_proxies(custom_nodes, '自建节点')
    
    active_subs = sum(1 for s in subs if s.get('enabled') != False)
    active_users = sum(1 for u in users if u.get('enabled') != False)
    
    # Sort protocols
    sorted_protocols = dict(sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True))
    
    result = {
        "subscriptions": {
            "total": len(subs),
            "active": active_subs
        },
        "nodes": {
            "total": total_nodes,
            "custom": len(custom_nodes),
            "by_protocol": sorted_protocols
        },
        "users": {
            "total": len(users),
            "active": active_users
        },
        "best_node": best_node
    }
    
    # Update cache
    STATS_CACHE['overview'] = result
    STATS_CACHE['last_update'] = current_time
    
    return result

@app.get("/api/stats/nodes-by-country")
def get_nodes_by_country(_: bool = Depends(verify_session)):
    """Get node distribution by country with caching"""
    import time
    
    # Check cache
    current_time = time.time()
    if (STATS_CACHE['countries'] is not None and 
        current_time - STATS_CACHE['last_update'] < STATS_CACHE['cache_duration']):
        return STATS_CACHE['countries']
    
    config = load_config()
    subs = config.get('subscriptions', [])
    custom_nodes = config.get('custom_nodes', [])
    
    # Keywords to filter out info nodes (not real proxy nodes)
    info_keywords = [
        '剩余流量', '套餐到期', '距离下次重置', '建议', '官网', '未到期',
        '剩余', '到期', '重置', '流量', '过期', '订阅', '网址', '公告',
        '群组', 'Telegram', 'TG', '客服', '续费', '购买', '套餐',
        '使用说明', '教程', '更新', '通知', '邀请', '返利', '📊'
    ]
    
    country_counts = {}
    
    # Process all nodes from subscriptions (use cached geoip if available)
    all_nodes = []
    for sub in subs:
        if sub.get('enabled', True):
            # First check nodes stored in config (with cached geoip)
            config_nodes = sub.get('nodes', [])
            for node in config_nodes:
                name = node.get('name', '')
                if not any(kw in name for kw in info_keywords):
                    node['_source'] = sub['name']
                    all_nodes.append(node)
            
            # If no nodes in config, try loading from file
            if not config_nodes:
                filepath = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            cfg = yaml.safe_load(f)
                        nodes = cfg.get('proxies', []) if cfg else []
                        for node in nodes:
                            name = node.get('name', '')
                            if not any(kw in name for kw in info_keywords):
                                node['_source'] = sub['name']
                                all_nodes.append(node)
                    except:
                        pass
    
    # Add custom nodes
    for node in custom_nodes:
        node_copy = dict(node)
        node_copy['_source'] = '自建节点'
        all_nodes.append(node_copy)
    
    # Use CountryGrouper logic
    grouped_nodes = CountryGrouper.group_by_country(all_nodes)
    
    processed_stats = []
    
    for group_name, nodes in grouped_nodes.items():
        if not nodes:
            continue
            
        # Parse flag and name from group_name (e.g., "🇭🇰 香港")
        parts = group_name.split(' ', 1)
        if len(parts) == 2:
            flag, name = parts
        else:
            flag, name = '🇺🇳', group_name
            
        count = len(nodes)
        
        # Try to find code in COUNTRY_NAMES for chart usage
        # Priority: 1. Exact match  2. Longest partial match (to avoid "俄罗斯" matching "白俄罗斯")
        code = 'XX'
        best_match_len = 0
        
        for c, n in COUNTRY_NAMES.items():
            # Exact match - highest priority
            if n == name:
                code = c
                break
            # Partial match - prefer longer matches to avoid substring issues
            # e.g., "白俄罗斯" should match "白俄罗斯" not "俄罗斯"
            if name in n or n in name:
                # Use the longer of the two as match length
                match_len = len(n)
                if match_len > best_match_len:
                    best_match_len = match_len
                    code = c
        
        processed_stats.append({
            'name': name,
            'flag': flag,
            'code': code,
            'count': count
        })
    
    # Sort by count desc
    processed_stats.sort(key=lambda x: x['count'], reverse=True)
    
    result = {"countries": processed_stats, "total": len(all_nodes)}
    
    # Update cache
    STATS_CACHE['countries'] = result
    if STATS_CACHE['overview'] is None:
        STATS_CACHE['last_update'] = current_time
    
    return result

@app.get("/api/stats/nodes-by-country/{country_code}")
def get_nodes_by_country_code(country_code: str, _: bool = Depends(verify_session)):
    """Get nodes for a specific country"""
    config = load_config()
    subs = config.get('subscriptions', [])
    custom_nodes = config.get('custom_nodes', [])
    
    # Keywords to filter out info nodes (not real proxy nodes)
    info_keywords = [
        '剩余流量', '套餐到期', '距离下次重置', '建议', '官网', '未到期',
        '剩余', '到期', '重置', '流量', '过期', '订阅', '网址', '公告',
        '群组', 'Telegram', 'TG', '客服', '续费', '购买', '套餐',
        '使用说明', '教程', '更新', '通知', '邀请', '返利', '📊'
    ]
    
    # Collect all nodes
    all_nodes = []
    for sub in subs:
        if sub.get('enabled', True):
            # First check nodes stored in config (with cached geoip)
            config_nodes = sub.get('nodes', [])
            for node in config_nodes:
                name = node.get('name', '')
                if not any(kw in name for kw in info_keywords):
                    node['_source'] = sub['name']
                    all_nodes.append(node)
            
            # If no nodes in config, try loading from file
            if not config_nodes:
                filepath = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            cfg = yaml.safe_load(f)
                        nodes_list = cfg.get('proxies', []) if cfg else []
                        for node in nodes_list:
                            name = node.get('name', '')
                            if not any(kw in name for kw in info_keywords):
                                node['_source'] = sub['name']
                                all_nodes.append(node)
                    except:
                        pass
    
    # Add custom nodes
    for node in custom_nodes:
        node_copy = dict(node)
        node_copy['_source'] = '自建节点'
        all_nodes.append(node_copy)
    
    # Use CountryGrouper to group nodes
    grouped_nodes = CountryGrouper.group_by_country(all_nodes)
    
    # Find the matching country group
    result_nodes = []
    for group_name, nodes_in_group in grouped_nodes.items():
        # Check if this group matches the country code
        # group_name format: "🇺🇸 美国" or "🇹🇼 台湾"
        # We need to match against country_code like "US" or "TW"
        
        # Extract the country name from group_name (remove emoji)
        parts = group_name.split(' ', 1)
        group_country_name = parts[1] if len(parts) == 2 else group_name
        
        # Try to find matching code
        # Priority: 1. Exact match  2. Longest partial match (to avoid "俄罗斯" matching "白俄罗斯")
        group_code = None
        best_match_len = 0
        
        for code, name in COUNTRY_NAMES.items():
            # Exact match - highest priority
            if group_country_name == name:
                group_code = code
                break
            # Partial match - prefer longer matches to avoid substring issues
            if group_country_name in name or name in group_country_name:
                match_len = len(name)
                if match_len > best_match_len:
                    best_match_len = match_len
                    group_code = code
        
        if group_code == country_code:
            # nodes_in_group is a list of node names (strings), not node dicts
            # We need to find the actual node objects from all_nodes
            for node_name in nodes_in_group:
                # Find the node dict in all_nodes by name
                node_dict = next((n for n in all_nodes if n.get('name') == node_name), None)
                if node_dict:
                    result_nodes.append({
                        "name": node_dict.get('name', ''),
                        "type": node_dict.get('type', ''),
                        "server": node_dict.get('server', ''),
                        "source": node_dict.get('_source', ''),
                        "latency": node_dict.get('last_latency'),
                    })
            break
    
    return {"nodes": result_nodes}

# ==================== Speed Test Profiles API ====================

class SpeedTestProfile(BaseModel):
    name: str
    description: Optional[str] = ""
    subscription_ids: Optional[List[str]] = None  # None = all
    test_speed: Optional[bool] = False
    timeout: Optional[int] = 10
    concurrency: Optional[int] = 10

@app.get("/api/speedtest/profiles")
def get_speedtest_profiles(_: bool = Depends(verify_session)):
    """Get all speed test profiles"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    return {"profiles": profiles}

@app.post("/api/speedtest/profiles")
def create_speedtest_profile(data: SpeedTestProfile, _: bool = Depends(verify_session)):
    """Create a new speed test profile"""
    config = load_config()
    if 'speedtest_profiles' not in config:
        config['speedtest_profiles'] = []
    
    profile = {
        "id": secrets.token_urlsafe(8),
        "name": data.name,
        "description": data.description,
        "subscription_ids": data.subscription_ids,
        "test_speed": data.test_speed,
        "timeout": data.timeout,
        "concurrency": data.concurrency,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_run": None
    }
    
    config['speedtest_profiles'].append(profile)
    save_config(config)
    return {"status": "success", "profile": profile}

@app.get("/api/speedtest/profiles/{profile_id}")
def get_speedtest_profile(profile_id: str, _: bool = Depends(verify_session)):
    """Get a specific speed test profile"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    profile = next((p for p in profiles if p['id'] == profile_id), None)
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    return {"profile": profile}

@app.put("/api/speedtest/profiles/{profile_id}")
def update_speedtest_profile(profile_id: str, data: SpeedTestProfile, _: bool = Depends(verify_session)):
    """Update a speed test profile"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    profile = next((p for p in profiles if p['id'] == profile_id), None)
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    profile['name'] = data.name
    profile['description'] = data.description
    profile['subscription_ids'] = data.subscription_ids
    profile['test_speed'] = data.test_speed
    profile['timeout'] = data.timeout
    profile['concurrency'] = data.concurrency
    
    save_config(config)
    return {"status": "success", "profile": profile}

@app.delete("/api/speedtest/profiles/{profile_id}")
def delete_speedtest_profile(profile_id: str, _: bool = Depends(verify_session)):
    """Delete a speed test profile"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    
    config['speedtest_profiles'] = [p for p in profiles if p['id'] != profile_id]
    save_config(config)
    return {"status": "success"}

@app.post("/api/speedtest/profiles/{profile_id}/run")
async def run_speedtest_profile(profile_id: str, _: bool = Depends(verify_session)):
    """Run a speed test profile (placeholder - requires proxy integration)"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    profile = next((p for p in profiles if p['id'] == profile_id), None)
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    # Update last run time
    profile['last_run'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_config(config)
    
    return {
        "status": "info",
        "message": "Speed test execution requires proxy integration. This feature will be available when proxy management is implemented.",
        "profile": profile
    }

# ==================== Static Files ====================

frontend_dist = os.path.join(BASE_DIR, 'submerger', 'dist')
if os.path.exists(frontend_dist):
    # 1. Mount assets for performance
    assets_path = os.path.join(frontend_dist, 'assets')
    if os.path.exists(assets_path):
        app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

    # 2. Serve root requests
    @app.get("/")
    async def serve_index():
        return FileResponse(os.path.join(frontend_dist, "index.html"))

    # 3. Catch-all for SPA routes (e.g. /settings, /nodes)
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # API 404s should return JSON, not HTML
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")
            
        # Try to serve static file if it exists (e.g. favicon.ico)
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
            
        # Fallback to index.html for React Router
        return FileResponse(os.path.join(frontend_dist, "index.html"))

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get('PORT', 8666))
    uvicorn.run(app, host="0.0.0.0", port=port)
