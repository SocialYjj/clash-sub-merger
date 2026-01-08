import os
import requests
import yaml
import json
import time
import secrets
import re
import hashlib
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
from geoip_service import get_geoip_service, download_geoip_database, init_geoip_service, get_latest_version_info, get_local_version_info, check_update_available
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
    'KR': ['korea', 'kr', 'kor', '韩国', '韩'],
    'SG': ['singapore', 'sg', '新加坡', '狮城', '坡'],
    'US': ['usa', 'us', 'united states', 'america', '美国', '美', 'la', 'los angeles', 'seattle', 'san jose'],
    'GB': ['uk', 'gb', 'united kingdom', 'britain', 'england', '英国', '英'],
    'DE': ['germany', 'de', 'deutsch', '德国', '德'],
    'FR': ['france', 'fr', '法国', '法'],
    'NL': ['netherlands', 'nl', 'holland', '荷兰', '荷'],
    'RU': ['russia', 'ru', '俄罗斯', '俄'],
    'CA': ['canada', 'ca', '加拿大', '加'],
    'AU': ['australia', 'au', '澳大利亚', '澳洲', '澳'],
    'IN': ['india', '印度'],
    'TR': ['turkey', 'tr', '土耳其'],
    'MY': ['malaysia', 'my', '马来西亚', '马来', '大马'],
    'TH': ['thailand', 'th', '泰国', '泰'],
    'VN': ['vietnam', 'vn', '越南', '越'],
    'ID': ['indonesia', '印尼', '印度尼西亚'],
    'PH': ['philippines', 'ph', '菲律宾', '菲'],
    'BR': ['brazil', 'br', '巴西'],
    'AR': ['argentina', 'ar', '阿根廷'],
    'MX': ['mexico', 'mx', '墨西哥'],
    'ZA': ['south africa', 'za', '南非'],
    'AE': ['uae', 'ae', 'dubai', '阿联酋', '迪拜'],
    'IL': ['israel', 'il', '以色列'],
    'UA': ['ukraine', 'ua', '乌克兰'],
    'PL': ['poland', 'pl', '波兰'],
    'CH': ['switzerland', 'ch', '瑞士'],
    'SE': ['sweden', 'se', '瑞典'],
    'NO': ['norway', 'no', '挪威'],
    'FI': ['finland', 'fi', '芬兰'],
    'DK': ['denmark', 'dk', '丹麦'],
    'IT': ['italy', 'it', '意大利', '意'],
    'ES': ['spain', 'es', '西班牙'],
    'NG': ['nigeria', 'ng', '尼日利亚'],
    'NZ': ['new zealand', 'nz', '新西兰'],
    'MD': ['moldova', 'md', '摩尔多瓦'],
    'IE': ['ireland', 'ie', '爱尔兰'],
    'PT': ['portugal', 'pt', '葡萄牙'],
    'GR': ['greece', 'gr', '希腊'],
    'AT': ['austria', 'at', '奥地利'],
    'CZ': ['czech', 'cz', '捷克'],
    'HU': ['hungary', 'hu', '匈牙利'],
    'RO': ['romania', 'ro', '罗马尼亚'],
    'BG': ['bulgaria', 'bg', '保加利亚'],
    'KZ': ['kazakhstan', 'kz', '哈萨克斯坦'],
    'EG': ['egypt', 'eg', '埃及'],
    'KE': ['kenya', 'ke', '肯尼亚'],
    'PK': ['pakistan', 'pk', '巴基斯坦'],
    'BD': ['bangladesh', 'bd', '孟加拉'],
    'CL': ['chile', 'cl', '智利'],
    'AQ': ['antarctica', 'aq', '南极'],
}

# Country code to Chinese name mapping
COUNTRY_NAMES = {
    'HK': '香港', 'TW': '台湾', 'JP': '日本', 'KR': '韩国', 'SG': '新加坡',
    'US': '美国', 'GB': '英国', 'DE': '德国', 'FR': '法国', 'NL': '荷兰',
    'RU': '俄罗斯', 'CA': '加拿大', 'AU': '澳大利亚', 'IN': '印度', 'TR': '土耳其',
    'MY': '马来西亚', 'TH': '泰国', 'VN': '越南', 'ID': '印尼', 'PH': '菲律宾',
    'BR': '巴西', 'AR': '阿根廷', 'MX': '墨西哥', 'ZA': '南非', 'AE': '阿联酋',
    'IL': '以色列', 'UA': '乌克兰', 'PL': '波兰', 'CH': '瑞士', 'SE': '瑞典',
    'NO': '挪威', 'FI': '芬兰', 'DK': '丹麦', 'IT': '意大利', 'ES': '西班牙',
    'NG': '尼日利亚', 'NZ': '新西兰', 'MD': '摩尔多瓦', 'IE': '爱尔兰', 'PT': '葡萄牙',
    'GR': '希腊', 'AT': '奥地利', 'CZ': '捷克', 'HU': '匈牙利', 'RO': '罗马尼亚',
    'BG': '保加利亚', 'KZ': '哈萨克斯坦', 'EG': '埃及', 'KE': '肯尼亚',
    'PK': '巴基斯坦', 'BD': '孟加拉', 'CL': '智利', 'AQ': '南极洲', 'CN': '中国'
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
                    # Country name format: "🇺🇸 美国" - need to check if code matches
                    if country_code in country_name or COUNTRY_NAMES.get(country_code, '') in country_name:
                        if country_name in country_groups:
                            new_proxies.extend(country_groups[country_name])
                        break
            else:
                # Keep as-is (DIRECT, REJECT, group references, etc.)
                new_proxies.append(item)
        
        new_group['proxies'] = new_proxies
        processed_groups.append(new_group)
    
    return processed_groups

def extract_country_from_name(node_name: str, server: str = None) -> Optional[Dict]:
    """
    Extract country info from node name using flag emoji, keywords, or GeoIP.
    Priority: 1. Flag emoji  2. Keywords  3. GeoIP lookup  4. None
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
    
    # 3. GeoIP lookup as fallback (if server address provided)
    if server:
        geoip = get_geoip_service()
        if geoip and geoip.is_available():
            result = geoip.get_country(server)
            if result and result.get('iso_code'):
                code = result['iso_code']
                return {
                    'country': COUNTRY_NAMES.get(code, result.get('country_name', code)),
                    'country_code': code,
                    'flag': result.get('flag', GeoIPService.iso_to_flag(code))
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

class UpdateSubscription(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None

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

class UserNodeAllocation(BaseModel):
    subscriptions: Dict[str, List[str]]  # {sub_id: [node_names] or ["*"] for all}

# Port mapping models
class PortMappingCreate(BaseModel):
    final_name: str  # The final transformed node name
    port: int  # Port number to map (e.g., 52001)

class PortMappingUpdate(BaseModel):
    port: int  # New port number

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
    content = response.text
    
    node_count = 0
    try:
        cfg = yaml.safe_load(content)
        if cfg and 'proxies' in cfg:
            node_count = len(cfg.get('proxies', []))
    except:
        pass
    
    return content, sub_info, node_count

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
            'upload': sub_info.get('upload', 0), 'download': sub_info.get('download', 0),
            'total': sub_info.get('total', 0), 'expire': sub_info.get('expire', 0),
            'node_count': node_count, 'last_update': int(time.time())
        }
        
        with open(os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml"), 'w', encoding='utf-8') as f:
            f.write(content)
        
        config['subscriptions'].append(new_sub)
        save_config(config)
        return {"status": "success", "subscription": new_sub}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch subscription: {str(e)}")

@app.delete("/api/subscriptions/{sub_id}")
def delete_subscription(sub_id: str, _: bool = Depends(verify_session)):
    config = load_config()
    config['subscriptions'] = [s for s in config['subscriptions'] if s['id'] != sub_id]
    save_config(config)
    
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
                save_config(config)
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
    save_config(config)
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
            # 1. Flag emoji in ORIGINAL name (机场提供的旗帜标识) - most reliable
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
            
            # Add port mapping info if exists
            if final_name in port_mappings:
                node_data['mapped_port'] = port_mappings[final_name]
            
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
            node['name'] = new_node.get('name', node['name'])
            node['type'] = new_node.get('type', node.get('type', 'vless'))
            node['server'] = new_node.get('server', node.get('server', ''))
            node['port'] = new_node.get('port', node.get('port', 443))
            
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
                    proxy = parse_node_link(n['link'])
                    if proxy:
                        proxy['name'] = n['name']
                        proxies.append(proxy)
            
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
        'template_id': 'builtin'  # Default to built-in template
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
            header = template['header']
            suffix = template['suffix']
            # Check if template has custom proxy-groups
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
                            # Transformed name is "🇭🇰 风萧萧 HK@xxx"
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
        
        # If using custom template with proxy-groups, process placeholders
        if template_proxy_groups and isinstance(template_proxy_groups, list) and len(template_proxy_groups) > 0:
            # Generate country groups for placeholder replacement
            from merge_config import CountryGrouper
            if 'country_groups' not in dir():
                country_groups = CountryGrouper.group_by_country(proxies)
            
            # Get all proxy names
            all_proxy_names = [p['name'] for p in proxies]
            
            # Get sorted country group names
            sorted_country_names = sorted(
                [c for c in country_groups.keys() if country_groups[c]],
                key=lambda c: len(country_groups[c]),
                reverse=True
            )
            
            # Process template proxy-groups (replace placeholders)
            custom_groups = process_template_proxy_groups(
                template_proxy_groups, 
                all_proxy_names, 
                country_groups, 
                sorted_country_names
            )
            
            # Add country groups after custom groups
            for country_name in sorted_country_names:
                if country_name in country_groups and country_groups[country_name]:
                    country_group = {
                        'name': country_name,
                        'type': 'select',
                        'proxies': country_groups[country_name]
                    }
                    custom_groups.append(country_group)
            
            proxy_groups = custom_groups
        # Get custom config name
        # Priority: admin_token_info's sub_name > global sub_name
        if admin_token_info and admin_token_info.get('sub_name'):
            sub_name = admin_token_info['sub_name']
        else:
            sub_name = auth.get('sub_name', 'Aggregated')
        
        if user_info:
            sub_name = f"{sub_name} - {user_info['name']}"
        
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
            
            # Create info node name: "机场名 | 已用/总量 | 到期时间"
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
        
        # Add traffic info nodes to manual select group (🚀 手动选择)
        if traffic_info_names:
            for group in proxy_groups:
                if group.get('name') == '🚀 手动选择':
                    # Insert traffic info at the beginning of proxies list
                    group['proxies'] = traffic_info_names + group.get('proxies', [])
                    break
        
        # Calculate total traffic info from all subscriptions
        total_upload = sum(s.get('upload', 0) or 0 for s in enabled_subs)
        total_download = sum(s.get('download', 0) or 0 for s in enabled_subs)
        total_traffic = sum(s.get('total', 0) or 0 for s in enabled_subs)
        # Use the earliest expire time (or 0 if any is permanent)
        expire_times = [s.get('expire', 0) or 0 for s in enabled_subs]
        total_expire = min(expire_times) if expire_times and all(t > 0 for t in expire_times) else 0
        
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
        # Remove trailing empty lines from header and add name field at the beginning
        header_clean = header.rstrip()
        output_parts = [f'name: {sub_name}\n' + header_clean]
        
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
        output_parts.append('\n' + suffix)
        
        # Get custom filename and config name
        filename = auth.get('sub_filename', 'config.yaml')
        
        # Use URL encoding for names
        from urllib.parse import quote
        encoded_name = quote(sub_name)
        # Filename also uses config name (remove unsafe chars, keep Chinese)
        safe_name = ''.join(c for c in sub_name if c.isalnum() or c in ' _-' or '\u4e00' <= c <= '\u9fff')
        if not safe_name:
            safe_name = filename.replace('.yaml', '').replace('.yml', '')
        
        return PlainTextResponse(
            "\n".join(output_parts), 
            media_type='text/yaml',
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(safe_name)}",
                "profile-title": encoded_name,
                "profile-update-interval": "24",
                "subscription-userinfo": f"upload={total_upload}; download={total_download}; total={total_traffic}; expire={total_expire}",
            }
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
    
    # Extract proxy-groups for placeholder processing
    template_proxy_groups = parsed.get('proxy-groups', [])
    
    # Split into header and suffix
    header, suffix = split_template(data.content)
    
    template_id = f"tpl_{int(time.time() * 1000)}"
    template = {
        'id': template_id,
        'name': data.name,
        'header': header,
        'suffix': suffix,
        'proxy_groups': template_proxy_groups,  # Save proxy-groups for placeholder processing
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
    
    # Reconstruct full content including proxy-groups
    proxy_groups = t.get('proxy_groups', [])
    if proxy_groups and isinstance(proxy_groups, list) and len(proxy_groups) > 0:
        # Include saved proxy-groups in content
        proxy_groups_yaml = yaml.dump({'proxy-groups': proxy_groups}, allow_unicode=True, sort_keys=False, default_flow_style=False)
        proxy_groups_section = proxy_groups_yaml.strip()
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
        
        header, suffix = split_template(data.content)
        proxy_groups = parsed.get('proxy-groups', [])
        
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
        
        # Extract proxy-groups for placeholder processing
        template['proxy_groups'] = parsed.get('proxy-groups', [])
        
        header, suffix = split_template(data.content)
        template['header'] = header
        template['suffix'] = suffix
    
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
    lines = full_content.splitlines(keepends=True)
    header_lines, suffix_lines = [], []
    state = 0
    for line in lines:
        stripped = line.strip()
        if state == 0:
            if stripped.startswith('proxies:') or stripped.startswith('proxy-groups:'):
                state = 1
                continue
            header_lines.append(line)
        elif state == 1:
            if any(stripped.startswith(k) for k in ['rules:', 'rule-providers:', 'script:', 'url-rewrite:']):
                state = 2
                suffix_lines.append(line)
        elif state == 2:
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
        
        output_parts = [header, '\nproxies:']
        for proxy in proxies:
            output_parts.append(f'  - {json.dumps(proxy, ensure_ascii=False, separators=(",",":"))}')
        output_parts.append('\nproxy-groups:')
        for group in proxy_groups:
            output_parts.append(f'  - {json.dumps(group, ensure_ascii=False, separators=(",",":"))}')
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

# Initialize GeoIP service on startup
geoip_service = get_geoip_service()

# Initialize scheduler on startup
scheduler = get_scheduler()

@app.get("/api/geoip/status")
def get_geoip_status(_: bool = Depends(verify_session)):
    """Get GeoIP database status"""
    return geoip_service.get_db_info()

@app.get("/api/geoip/lookup/{ip}")
def lookup_ip(ip: str, _: bool = Depends(verify_session)):
    """Lookup IP geolocation"""
    if not geoip_service.is_available():
        raise HTTPException(status_code=503, detail="GeoIP database not available")
    
    result = geoip_service.get_country(ip)
    if result is None:
        raise HTTPException(status_code=404, detail=f"No location data for IP: {ip}")
    
    return result

class GeoIPUpdateRequest(BaseModel):
    url: Optional[str] = None
    use_proxy: Optional[bool] = False

@app.post("/api/geoip/update")
def update_geoip_database(
    data: GeoIPUpdateRequest,
    background_tasks: BackgroundTasks,
    _: bool = Depends(verify_session)
):
    """Download/update GeoIP database"""
    result = download_geoip_database(
        url=data.url,
        use_proxy=data.use_proxy
    )
    
    if result["success"]:
        # Reload the database after download
        geoip_service.reload()
    
    return result

@app.get("/api/geoip/test")
def test_geoip(_: bool = Depends(verify_session)):
    """Test GeoIP with sample IPs"""
    test_ips = [
        ("8.8.8.8", "Google DNS - US"),
        ("1.1.1.1", "Cloudflare - US"),
        ("114.114.114.114", "China DNS"),
        ("208.67.222.222", "OpenDNS - US"),
    ]
    
    results = []
    for ip, desc in test_ips:
        country = geoip_service.get_country(ip)
        results.append({
            "ip": ip,
            "description": desc,
            "country": country
        })
    
    return {
        "available": geoip_service.is_available(),
        "results": results
    }

@app.get("/api/geoip/version")
def get_geoip_version(_: bool = Depends(verify_session)):
    """Get local GeoIP database version info"""
    return get_local_version_info()

@app.get("/api/geoip/latest")
def get_geoip_latest(_: bool = Depends(verify_session)):
    """Get latest available GeoIP database version from GitHub"""
    return get_latest_version_info()

@app.get("/api/geoip/check-update")
def check_geoip_update(_: bool = Depends(verify_session)):
    """Check if GeoIP database update is available"""
    return check_update_available()

class GeoIPAutoUpdateSettingRequest(BaseModel):
    enabled: bool

@app.get("/api/geoip/auto-update-setting")
def get_geoip_auto_update_setting(_: bool = Depends(verify_session)):
    """Get GeoIP auto-update setting"""
    config = load_config()
    return {"enabled": config.get('geoip_auto_update', False)}

@app.post("/api/geoip/auto-update-setting")
def set_geoip_auto_update_setting(data: GeoIPAutoUpdateSettingRequest, _: bool = Depends(verify_session)):
    """Set GeoIP auto-update setting"""
    config = load_config()
    config['geoip_auto_update'] = data.enabled
    save_config(config)
    
    # Update scheduler
    scheduler = get_scheduler()
    if data.enabled:
        # Schedule daily GeoIP update at 3:00 AM
        scheduler.add_geoip_update_job()
    else:
        scheduler.remove_geoip_update_job()
    
    return {"success": True, "enabled": data.enabled}

class GeoIPAutoUpdateRequest(BaseModel):
    force: Optional[bool] = False  # Force update even if already latest

@app.post("/api/geoip/auto-update")
def auto_update_geoip(
    data: GeoIPAutoUpdateRequest,
    _: bool = Depends(verify_session)
):
    """
    Auto-update GeoIP database if newer version available.
    Downloads from the latest GitHub release.
    """
    # Check if update is available
    check_result = check_update_available()
    
    if not data.force:
        if check_result["update_available"] is None:
            return {
                "success": False,
                "message": check_result["message"],
                "updated": False
            }
        
        if not check_result["update_available"]:
            return {
                "success": True,
                "message": "已是最新版本，无需更新",
                "updated": False,
                "local_version": check_result["local_version"],
                "latest_version": check_result["latest_version"]
            }
    
    # Get download URL from latest version info
    latest_info = check_result.get("latest_version") or get_latest_version_info()
    download_url = latest_info.get("download_url") if latest_info else None
    
    # Download the update
    result = download_geoip_database(url=download_url)
    
    if result["success"]:
        # Reload the database after download
        geoip_service.reload()
        
        return {
            "success": True,
            "message": f"更新成功: {latest_info.get('latest_version', '未知版本')}",
            "updated": True,
            "download_result": result,
            "new_version": get_local_version_info()
        }
    else:
        return {
            "success": False,
            "message": result["message"],
            "updated": False
        }

# ==================== Scheduler API ====================

@app.on_event("startup")
async def startup_event():
    """Initialize scheduler and load scheduled tasks on startup"""
    # Load saved template from config
    config = load_config()
    if 'template' in config:
        template = config['template']
        if 'header' in template:
            ConfigMerger.TEMPLATES['header'] = template['header']
        if 'suffix' in template:
            ConfigMerger.TEMPLATES['suffix'] = template['suffix']
        print("Custom template loaded from config")
    
    scheduler.start()
    load_scheduled_subscriptions()
    
    # Load GeoIP auto-update setting
    if config.get('geoip_auto_update', False):
        scheduler.add_geoip_update_job()
        print("GeoIP auto-update enabled")
    
    print("Scheduler initialized and tasks loaded")

@app.on_event("shutdown")
async def shutdown_event():
    """Stop scheduler on shutdown"""
    scheduler.stop()

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
    timeout: Optional[int] = 5000  # milliseconds

@app.post("/api/nodes/{sub_id}/{node_idx}/test")
async def test_subscription_node(sub_id: str, node_idx: int, data: SpeedTestRequest = None, _: bool = Depends(verify_session)):
    """Test a node from subscription by index - TCP latency test and region lookup"""
    import socket
    import asyncio
    
    data = data or SpeedTestRequest()
    
    config = load_config()
    timeout_sec = (data.timeout or 5000) / 1000.0
    
    # Find node and track location for saving
    node = None
    node_location = None  # ('subscription', sub_id, node_idx) or ('custom', node_idx)
    yaml_nodes = None  # For subscription nodes, keep reference to the full list
    
    if sub_id == 'custom':
        custom_nodes = config.get('custom_nodes', [])
        if 0 <= node_idx < len(custom_nodes):
            node = custom_nodes[node_idx]
            node_location = ('custom', node_idx)
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
        "exit_ip": None,
        "error": None
    }
    
    server = node.get('server', '')
    port = node.get('port', 443)
    need_save = False
    
    # Test latency using TCP connection
    if data.test_latency and server:
        try:
            # Resolve hostname first
            try:
                ip = socket.gethostbyname(server)
            except socket.gaierror:
                ip = server
            
            # TCP connection test
            start_time = asyncio.get_event_loop().time()
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout_sec
                )
                latency = int((asyncio.get_event_loop().time() - start_time) * 1000)
                writer.close()
                await writer.wait_closed()
                result["latency"] = latency
                
                # Save latency to node
                node['last_latency'] = latency
                node['last_latency_time'] = int(time.time())
                need_save = True
            except asyncio.TimeoutError:
                result["latency"] = -1  # Timeout - use -1 to distinguish from untested (None)
                node['last_latency'] = -1  # -1 means timeout
                node['last_latency_time'] = int(time.time())
                need_save = True
            except Exception as e:
                result["error"] = str(e)
                result["latency"] = -2  # Error - use -2 to distinguish from timeout
                node['last_latency'] = -2  # -2 means error
                node['last_latency_time'] = int(time.time())
                need_save = True
        except Exception as e:
            result["error"] = str(e)
    
    # Test region - Priority: 1. Node name (flag/keyword), 2. GeoIP database
    if data.test_region and server:
        region_info = None
        node_name = node.get('name', '')
        
        # 1. Try to extract from node name first (most reliable)
        name_country = extract_country_from_name(node_name)
        if name_country:
            region_info = {
                "country": name_country['country'],
                "country_code": name_country['country_code'],
                "flag": name_country['flag'],
            }
        else:
            # 2. Fallback to GeoIP database
            try:
                geoip = get_geoip_service()
                geo_data = geoip.get_country(server)
                if geo_data:
                    region_info = {
                        "country": geo_data.get('country_name', ''),
                        "country_code": geo_data.get('iso_code', ''),
                        "flag": geo_data.get('flag', ''),
                    }
            except Exception:
                pass
        
        if region_info:
            result["region"] = region_info
            
            # Save region info to node for caching
            node['geoip'] = {
                'country': region_info['country'],
                'country_code': region_info['country_code'],
                'flag': region_info['flag'],
                'updated_at': int(time.time())
            }
            need_save = True
        else:
            result["region"] = None
    
    
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
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
            except Exception:
                pass  # Silently fail saving to YAML
        else:
            # Save to config.json for custom nodes
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
    """Get dashboard statistics"""
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
    
    return {
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

@app.get("/api/stats/nodes-by-country")
def get_nodes_by_country(_: bool = Depends(verify_session)):
    """Get node distribution by country (requires GeoIP)"""
    config = load_config()
    subs = config.get('subscriptions', [])
    custom_nodes = config.get('custom_nodes', [])
    geoip = get_geoip_service()
    
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
            
        # Parse flag and name from group_name (e.g., "🇺🇸 美国")
        parts = group_name.split(' ', 1)
        if len(parts) == 2:
            flag, name = parts
        else:
            flag, name = '🇺🇳', group_name
            
        count = len(nodes)
        
        # Try to find code in COUNTRY_NAMES for chart usage
        code = 'XX'
        for c, n in COUNTRY_NAMES.items():
            if n == name:
                code = c
                break
        
        processed_stats.append({
            'name': name,
            'flag': flag,
            'code': code,
            'count': count
        })
    
    # Sort by count desc
    processed_stats.sort(key=lambda x: x['count'], reverse=True)
    
    return {"countries": processed_stats, "total": len(all_nodes)}

@app.get("/api/stats/nodes-by-country/{country_code}")
def get_nodes_by_country_code(country_code: str, _: bool = Depends(verify_session)):
    """Get nodes for a specific country"""
    config = load_config()
    subs = config.get('subscriptions', [])
    custom_nodes = config.get('custom_nodes', [])
    geoip = get_geoip_service()
    
    nodes = []
    # Keywords to filter out info nodes (not real proxy nodes)
    info_keywords = [
        '剩余流量', '套餐到期', '距离下次重置', '建议', '官网', '未到期',
        '剩余', '到期', '重置', '流量', '过期', '订阅', '网址', '公告',
        '群组', 'Telegram', 'TG', '客服', '续费', '购买', '套餐',
        '使用说明', '教程', '更新', '通知', '邀请', '返利', '📊'
    ]
    
    # Process subscription nodes (use cached geoip if available)
    for sub in subs:
        if sub.get('enabled', True):
            # First check nodes stored in config (with cached geoip)
            config_nodes = sub.get('nodes', [])
            for node in config_nodes:
                name = node.get('name', '')
                if any(kw in name for kw in info_keywords):
                    continue
                
                server = node.get('server', '')
                cached_geoip = node.get('geoip')
                
                # Determine country code
                code = 'Unknown'
                if cached_geoip and cached_geoip.get('country_code'):
                    code = cached_geoip.get('country_code')
                elif server:
                    country = geoip.get_country(server)
                    code = country.get('iso_code', 'Unknown') if country else 'Unknown'
                
                if code == country_code or (country_code == 'Unknown' and code == 'Unknown'):
                    nodes.append({
                        "name": name,
                        "type": node.get('type', ''),
                        "server": server,
                        "source": sub.get('name', ''),
                        "latency": node.get('last_latency'),
                        "geoip": cached_geoip,
                    })
            
            # If no nodes in config, try loading from file
            if not config_nodes:
                filepath = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            cfg = yaml.safe_load(f)
                        sub_nodes = cfg.get('proxies', []) if cfg else []
                        for node in sub_nodes:
                            name = node.get('name', '')
                            if any(kw in name for kw in info_keywords):
                                continue
                            server = node.get('server', '')
                            if server:
                                country = geoip.get_country(server)
                                code = country.get('iso_code', 'Unknown') if country else 'Unknown'
                                if code == country_code or (country_code == 'Unknown' and not country):
                                    nodes.append({
                                        "name": name,
                                        "type": node.get('type', ''),
                                        "server": server,
                                        "source": sub.get('name', ''),
                                    })
                    except:
                        pass
    
    # Process custom nodes
    for node in custom_nodes:
        name = node.get('name', '')
        if any(kw in name for kw in info_keywords):
            continue
        
        server = node.get('server', '')
        cached_geoip = node.get('geoip')
        
        # Determine country code
        code = 'Unknown'
        if cached_geoip and cached_geoip.get('country_code'):
            code = cached_geoip.get('country_code')
        elif server:
            country = geoip.get_country(server)
            code = country.get('iso_code', 'Unknown') if country else 'Unknown'
        
        if code == country_code or (country_code == 'Unknown' and code == 'Unknown'):
            nodes.append({
                "name": name,
                "type": node.get('type', ''),
                "server": server,
                "source": '自建节点',
                "latency": node.get('last_latency'),
                "geoip": cached_geoip,
            })
    
    return {"nodes": nodes, "count": len(nodes)}

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
