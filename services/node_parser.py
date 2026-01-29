"""
Node Link Parser Service
Parses various proxy protocol links (vmess, vless, ss, trojan, etc.)
"""
import base64
import json
import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional, Dict
from logger_config import get_logger

logger = get_logger(__name__)


def decode_base64(content: str) -> str:
    """Safely decode Base64"""
    content = content.strip().replace('-', '+').replace('_', '/')
    padding = 4 - len(content) % 4
    if padding != 4:
        content += '=' * padding
    try:
        decoded = base64.b64decode(content)
        try:
            return decoded.decode('utf-8')
        except UnicodeDecodeError:
            return decoded.decode('latin-1')
    except Exception as e:
        logger.debug(f"Base64 decode failed: {e}")
        return ""


def parse_vless_link(link: str) -> Optional[dict]:
    """Parse vless:// link to Clash format"""
    link = link.strip()
    if not link.startswith('vless://'):
        return None
    
    try:
        link = link[8:]
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        else:
            name = 'vless'
        
        uuid_part, rest = link.split('@', 1)
        if '?' in rest:
            server_port, params_str = rest.split('?', 1)
        else:
            server_port = rest
            params_str = ''
        
        if ':' in server_port:
            server, port = server_port.rsplit(':', 1)
        else:
            server = server_port
            port = '443'
        
        params = {}
        if params_str:
            for param in params_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = unquote(v)
        
        proxy = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid_part,
            'udp': True
        }
        
        # TLS settings
        security = params.get('security', 'none')
        if security == 'tls' or security == 'reality':
            proxy['tls'] = True
            if params.get('sni'):
                proxy['servername'] = params['sni']
            if params.get('fp'):
                proxy['client-fingerprint'] = params['fp']
            if params.get('alpn'):
                proxy['alpn'] = params['alpn'].split(',')
            if security == 'reality':
                proxy['reality-opts'] = {}
                if params.get('pbk'):
                    proxy['reality-opts']['public-key'] = params['pbk']
                if params.get('sid'):
                    proxy['reality-opts']['short-id'] = params['sid']
        
        # Transport settings
        transport = params.get('type', 'tcp')
        if transport == 'ws':
            proxy['network'] = 'ws'
            ws_opts = {}
            if params.get('path'):
                ws_opts['path'] = params['path']
            if params.get('host'):
                ws_opts['headers'] = {'Host': params['host']}
            if ws_opts:
                proxy['ws-opts'] = ws_opts
        elif transport == 'grpc':
            proxy['network'] = 'grpc'
            grpc_opts = {}
            if params.get('serviceName'):
                grpc_opts['grpc-service-name'] = params['serviceName']
            if grpc_opts:
                proxy['grpc-opts'] = grpc_opts
        elif transport == 'h2':
            proxy['network'] = 'h2'
            h2_opts = {}
            if params.get('path'):
                h2_opts['path'] = params['path']
            if params.get('host'):
                h2_opts['host'] = [params['host']]
            if h2_opts:
                proxy['h2-opts'] = h2_opts
        
        # Flow control
        if params.get('flow'):
            proxy['flow'] = params['flow']
        
        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse vless link: {e}")
        return None


def parse_vmess_link(link: str) -> Optional[dict]:
    """Parse vmess:// link to Clash format"""
    link = link.strip()
    if not link.startswith('vmess://'):
        return None
    
    try:
        encoded = link[8:]
        decoded = decode_base64(encoded)
        if not decoded:
            return None
        
        config = json.loads(decoded)
        
        proxy = {
            'name': config.get('ps', 'vmess'),
            'type': 'vmess',
            'server': config.get('add', ''),
            'port': int(config.get('port', 443)),
            'uuid': config.get('id', ''),
            'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto'),
            'udp': True
        }
        
        # TLS
        if config.get('tls') == 'tls':
            proxy['tls'] = True
            if config.get('sni'):
                proxy['servername'] = config['sni']
        
        # Transport
        net = config.get('net', 'tcp')
        if net == 'ws':
            proxy['network'] = 'ws'
            ws_opts = {}
            if config.get('path'):
                ws_opts['path'] = config['path']
            if config.get('host'):
                ws_opts['headers'] = {'Host': config['host']}
            if ws_opts:
                proxy['ws-opts'] = ws_opts
        elif net == 'grpc':
            proxy['network'] = 'grpc'
            if config.get('path'):
                proxy['grpc-opts'] = {'grpc-service-name': config['path']}
        elif net == 'h2':
            proxy['network'] = 'h2'
            h2_opts = {}
            if config.get('path'):
                h2_opts['path'] = config['path']
            if config.get('host'):
                h2_opts['host'] = [config['host']]
            if h2_opts:
                proxy['h2-opts'] = h2_opts
        
        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse vmess link: {e}")
        return None


def parse_ss_link(link: str) -> Optional[dict]:
    """Parse ss:// link to Clash format"""
    link = link.strip()
    if not link.startswith('ss://'):
        return None
    
    try:
        link = link[5:]
        
        # Extract name
        name = 'ss'
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        # Try SIP002 format first
        if '@' in link:
            userinfo, server_part = link.split('@', 1)
            
            # Decode userinfo if base64
            if ':' not in userinfo:
                userinfo = decode_base64(userinfo)
            
            if ':' in userinfo:
                method, password = userinfo.split(':', 1)
            else:
                return None
            
            # Parse server:port
            if ':' in server_part:
                server, port = server_part.rsplit(':', 1)
                port = port.split('?')[0].split('/')[0]
            else:
                return None
        else:
            # Legacy format
            decoded = decode_base64(link)
            if not decoded:
                return None
            
            if '@' in decoded:
                userinfo, server_part = decoded.rsplit('@', 1)
                method, password = userinfo.split(':', 1)
                server, port = server_part.rsplit(':', 1)
            else:
                return None
        
        return {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password,
            'udp': True
        }
    except Exception as e:
        logger.debug(f"Failed to parse ss link: {e}")
        return None


def parse_trojan_link(link: str) -> Optional[dict]:
    """Parse trojan:// link to Clash format"""
    link = link.strip()
    if not link.startswith('trojan://'):
        return None
    
    try:
        link = link[9:]
        
        name = 'trojan'
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        password, rest = link.split('@', 1)
        password = unquote(password)
        
        if '?' in rest:
            server_port, params_str = rest.split('?', 1)
        else:
            server_port = rest
            params_str = ''
        
        server, port = server_port.rsplit(':', 1)
        port = port.split('/')[0]
        
        params = {}
        if params_str:
            for param in params_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = unquote(v)
        
        proxy = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': password,
            'udp': True
        }
        
        # SNI
        if params.get('sni'):
            proxy['sni'] = params['sni']
        elif params.get('peer'):
            proxy['sni'] = params['peer']
        
        # Skip cert verify
        if params.get('allowInsecure') == '1':
            proxy['skip-cert-verify'] = True
        
        # Transport
        transport = params.get('type', 'tcp')
        if transport == 'ws':
            proxy['network'] = 'ws'
            ws_opts = {}
            if params.get('path'):
                ws_opts['path'] = params['path']
            if params.get('host'):
                ws_opts['headers'] = {'Host': params['host']}
            if ws_opts:
                proxy['ws-opts'] = ws_opts
        elif transport == 'grpc':
            proxy['network'] = 'grpc'
            if params.get('serviceName'):
                proxy['grpc-opts'] = {'grpc-service-name': params['serviceName']}
        
        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse trojan link: {e}")
        return None


def parse_hysteria2_link(link: str) -> Optional[dict]:
    """Parse hysteria2:// or hy2:// link to Clash format"""
    link = link.strip()
    if link.startswith('hysteria2://'):
        link = link[12:]
    elif link.startswith('hy2://'):
        link = link[6:]
    else:
        return None
    
    try:
        name = 'hysteria2'
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        auth, rest = link.split('@', 1)
        auth = unquote(auth)
        
        if '?' in rest:
            server_port, params_str = rest.split('?', 1)
        else:
            server_port = rest
            params_str = ''
        
        server, port = server_port.rsplit(':', 1)
        port = port.split('/')[0]
        
        params = {}
        if params_str:
            for param in params_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = unquote(v)
        
        proxy = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': int(port),
            'password': auth
        }
        
        if params.get('sni'):
            proxy['sni'] = params['sni']
        if params.get('insecure') == '1':
            proxy['skip-cert-verify'] = True
        if params.get('obfs'):
            proxy['obfs'] = params['obfs']
            if params.get('obfs-password'):
                proxy['obfs-password'] = params['obfs-password']
        
        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse hysteria2 link: {e}")
        return None


def parse_tuic_link(link: str) -> Optional[dict]:
    """Parse tuic:// link to Clash format"""
    link = link.strip()
    if not link.startswith('tuic://'):
        return None
    
    try:
        link = link[7:]
        
        name = 'tuic'
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        auth, rest = link.split('@', 1)
        
        if ':' in auth:
            uuid, password = auth.split(':', 1)
        else:
            uuid = auth
            password = ''
        
        if '?' in rest:
            server_port, params_str = rest.split('?', 1)
        else:
            server_port = rest
            params_str = ''
        
        server, port = server_port.rsplit(':', 1)
        port = port.split('/')[0]
        
        params = {}
        if params_str:
            for param in params_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = unquote(v)
        
        proxy = {
            'name': name,
            'type': 'tuic',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'password': password
        }
        
        if params.get('sni'):
            proxy['sni'] = params['sni']
        if params.get('alpn'):
            proxy['alpn'] = params['alpn'].split(',')
        if params.get('congestion_control'):
            proxy['congestion-controller'] = params['congestion_control']
        if params.get('udp_relay_mode'):
            proxy['udp-relay-mode'] = params['udp_relay_mode']
        
        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse tuic link: {e}")
        return None


def parse_ssr_link(link: str) -> Optional[dict]:
    """Parse ssr:// link to Clash format"""
    link = link.strip()
    if not link.startswith('ssr://'):
        return None
    
    try:
        encoded = link[6:]
        decoded = decode_base64(encoded)
        if not decoded:
            return None
        
        # Format: server:port:protocol:method:obfs:base64(password)/?params
        main_part = decoded.split('/?')[0]
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
        params = {}
        if '/?' in decoded:
            params_str = decoded.split('/?')[1]
            for param in params_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = decode_base64(v) if v else ''
        
        name = params.get('remarks', 'ssr')
        
        proxy = {
            'name': name,
            'type': 'ssr',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'protocol': protocol,
            'obfs': obfs
        }
        
        if params.get('protoparam'):
            proxy['protocol-param'] = params['protoparam']
        if params.get('obfsparam'):
            proxy['obfs-param'] = params['obfsparam']
        
        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse ssr link: {e}")
        return None


def parse_hysteria_link(link: str) -> Optional[dict]:
    """Parse hysteria:// or hy:// link to Clash format (Hysteria v1)"""
    link = link.strip()
    if link.startswith('hysteria://'):
        link = link[11:]
    elif link.startswith('hy://'):
        link = link[5:]
    else:
        return None
    
    try:
        name = 'hysteria'
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        if '?' in link:
            server_port, params_str = link.split('?', 1)
        else:
            server_port = link
            params_str = ''
        
        server, port = server_port.rsplit(':', 1)
        port = port.split('/')[0]
        
        params = {}
        if params_str:
            for param in params_str.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = unquote(v)
        
        proxy = {
            'name': name,
            'type': 'hysteria',
            'server': server,
            'port': int(port)
        }
        
        if params.get('auth'):
            proxy['auth-str'] = params['auth']
        if params.get('peer') or params.get('sni'):
            proxy['sni'] = params.get('peer') or params.get('sni')
        if params.get('upmbps'):
            proxy['up'] = params['upmbps']
        if params.get('downmbps'):
            proxy['down'] = params['downmbps']
        if params.get('alpn'):
            proxy['alpn'] = params['alpn'].split(',')
        if params.get('obfs'):
            proxy['obfs'] = params['obfs']
        if params.get('insecure') == '1':
            proxy['skip-cert-verify'] = True
        
        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse hysteria link: {e}")
        return None


def parse_socks_link(link: str) -> Optional[dict]:
    """Parse socks5://, socks5+tls://, socks:// link to Clash format"""
    link = link.strip()
    
    tls = False
    if link.startswith('socks5+tls://'):
        link = link[13:]
        tls = True
    elif link.startswith('socks5://'):
        link = link[9:]
    elif link.startswith('socks://'):
        link = link[8:]
    else:
        return None
    
    try:
        name = 'socks5'
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        username = None
        password = None
        
        if '@' in link:
            auth, server_port = link.rsplit('@', 1)
            if ':' in auth:
                username, password = auth.split(':', 1)
                username = unquote(username)
                password = unquote(password)
        else:
            server_port = link
        
        server, port = server_port.rsplit(':', 1)
        
        proxy = {
            'name': name,
            'type': 'socks5',
            'server': server,
            'port': int(port)
        }
        
        if username:
            proxy['username'] = username
        if password:
            proxy['password'] = password
        if tls:
            proxy['tls'] = True
        
        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse socks link: {e}")
        return None


def parse_http_link(link: str) -> Optional[dict]:
    """Parse http://, https:// proxy link to Clash format"""
    link = link.strip()
    
    tls = False
    if link.startswith('https://'):
        link = link[8:]
        tls = True
    elif link.startswith('http://'):
        link = link[7:]
    else:
        return None
    
    try:
        name = 'http'
        if '#' in link:
            link, name = link.rsplit('#', 1)
            name = unquote(name)
        
        username = None
        password = None
        
        if '@' in link:
            auth, server_port = link.rsplit('@', 1)
            if ':' in auth:
                username, password = auth.split(':', 1)
                username = unquote(username)
                password = unquote(password)
        else:
            server_port = link
        
        server, port = server_port.rsplit(':', 1)
        
        proxy = {
            'name': name,
            'type': 'http',
            'server': server,
            'port': int(port)
        }
        
        if username:
            proxy['username'] = username
        if password:
            proxy['password'] = password
        if tls:
            proxy['tls'] = True
        
        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse http link: {e}")
        return None


def parse_node_link(link: str) -> Optional[dict]:
    """Parse node link, supports multiple protocols"""
    link = link.strip()
    if not link:
        return None
    
    parsers = [
        ('vmess://', parse_vmess_link),
        ('vless://', parse_vless_link),
        ('ss://', parse_ss_link),
        ('ssr://', parse_ssr_link),
        ('trojan://', parse_trojan_link),
        ('hysteria2://', parse_hysteria2_link),
        ('hy2://', parse_hysteria2_link),
        ('hysteria://', parse_hysteria_link),
        ('hy://', parse_hysteria_link),
        ('tuic://', parse_tuic_link),
        ('socks5://', parse_socks_link),
        ('socks5+tls://', parse_socks_link),
        ('socks://', parse_socks_link),
        ('http://', parse_http_link),
        ('https://', parse_http_link),
    ]
    
    for prefix, parser in parsers:
        if link.startswith(prefix):
            return parser(link)
    
    return None
