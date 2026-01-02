import os
import requests
import yaml
import json
import time
import secrets
import hashlib
from urllib.parse import urlparse, parse_qs, unquote, quote
from typing import Optional, Tuple, Dict, List
from collections import OrderedDict
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Header
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from merge_config import ConfigMerger

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
        'users': []  # New: user management
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

# Run migration on startup
migrate_old_config()

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

class UserNodeAllocation(BaseModel):
    subscriptions: Dict[str, List[str]]  # {sub_id: [node_names] or ["*"] for all}

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
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        proxies = cfg.get('proxies', []) if cfg else []
        return {"nodes": proxies, "count": len(proxies)}
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

# ==================== Custom Node API ====================

@app.get("/api/custom-nodes")
def get_custom_nodes(_: bool = Depends(verify_session)):
    config = load_config()
    nodes = config.get('custom_nodes', [])
    return {"nodes": nodes, "count": len(nodes)}

@app.post("/api/custom-nodes")
def add_custom_node(data: CustomNode, _: bool = Depends(verify_session)):
    proxy = parse_node_link(data.link)
    if not proxy:
        raise HTTPException(status_code=400, detail="Cannot parse node link, supported: vless://, vmess://, ss://, ssr://, trojan://, hysteria://, hy://, hysteria2://, hy2://, tuic://, anytls://, wireguard://, wg://, socks5://, socks5+tls://, http://, https://, snell://")
    
    if data.name:
        proxy['name'] = data.name
    
    node = {
        'id': f"node_{int(time.time() * 1000)}",
        'link': data.link,
        'name': proxy['name'],
        'type': proxy['type'],
        'server': proxy['server'],
        'port': proxy['port'],
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
        'allocations': {}  # {sub_id: [node_names] or ["*"] for all}
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

@app.post("/api/users/{user_id}/regenerate-token")
def regenerate_user_token(user_id: str, _: bool = Depends(verify_session)):
    """Regenerate user's subscription token"""
    config = load_config()
    for user in config.get('users', []):
        if user['id'] == user_id:
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
    
    if auth.get('sub_token') and token == auth['sub_token']:
        # Admin token - full access
        is_admin = True
    else:
        # Check user tokens
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
                
                # Check custom nodes
                if not included and 'custom_nodes' in user_allocations:
                    allocated_custom = user_allocations['custom_nodes']
                    if allocated_custom == ['*']:
                        # Check if it's a custom node
                        for cn in config.get('custom_nodes', []):
                            if cn['name'] in proxy_name:
                                included = True
                                break
                    else:
                        for alloc_node in allocated_custom:
                            if alloc_node in proxy_name:
                                included = True
                                break
                
                if included:
                    filtered_proxies.append(proxy)
            
            proxies = filtered_proxies
            
            # Regenerate proxy groups based on filtered proxies
            from merge_config import CountryGrouper, ProxyGroupGenerator
            country_groups = CountryGrouper.group_by_country(proxies)
            proxy_groups = ProxyGroupGenerator.generate_groups(proxies, country_groups)
        
        # Get custom config name
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
        output_parts = [f'name: {sub_name}\n' + header_clean, '\nproxies:']
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

# ==================== Template API ====================

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
            if key in ['proxies', 'proxy-groups']:
                merged[key] = []
            elif key in uploaded_config:
                merged[key] = uploaded_config[key]
            else:
                merged[key] = base_config[key]
        
        for key in uploaded_config:
            if key not in merged:
                merged[key] = [] if key in ['proxies', 'proxy-groups'] else uploaded_config[key]
        
        merged['proxies'] = []
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

# ==================== Static Files ====================

frontend_dist = os.path.join(BASE_DIR, 'frontend', 'dist')
if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get('PORT', 8666))
    uvicorn.run(app, host="0.0.0.0", port=port)
