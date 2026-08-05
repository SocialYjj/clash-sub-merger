"""
Node Link Parser Service
Parses various proxy protocol links (vmess, vless, ss, trojan, etc.)
"""
import base64
import json
from urllib.parse import urlparse, parse_qsl, unquote
from typing import Optional
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


def _parse_query_params(query: str):
    params = {}
    params_lower = {}
    for k, v in parse_qsl(query, keep_blank_values=True):
        if not k:
            continue
        params[k] = v
        params_lower[k.lower()] = v

    def get_param(*keys):
        for key in keys:
            if key in params:
                return params[key]
            low = key.lower()
            if low in params_lower:
                return params_lower[low]
        return None

    return params, get_param


def _split_alpn(value: str | None) -> list | None:
    if not value:
        return None
    parts = [p.strip() for p in value.split(',') if p.strip()]
    return parts or None


def _truthy(value: str | None) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in ['1', 'true', 'yes', 'y', 'on']


def _set_xhttp_opts(proxy: dict, mode=None, path=None, host=None):
    """Set mihomo-compatible xhttp options on a parsed proxy."""
    xhttp_opts = {}
    if mode not in (None, ''):
        xhttp_opts['mode'] = mode
    if path not in (None, ''):
        xhttp_opts['path'] = path
    if host not in (None, ''):
        xhttp_opts['host'] = host
    if xhttp_opts:
        proxy['xhttp-opts'] = xhttp_opts


def parse_vless_link(link: str) -> Optional[dict]:
    """Parse vless:// link to Clash format"""
    link = link.strip()
    if not link.lower().startswith('vless://'):
        return None
    
    try:
        parsed = urlparse(link)
        if parsed.scheme.lower() != 'vless':
            return None

        name = unquote(parsed.fragment) if parsed.fragment else 'vless'
        uuid_part = unquote(parsed.username) if parsed.username else ''
        server = parsed.hostname or ''
        port = parsed.port or 443

        _, get_param = _parse_query_params(parsed.query)
        
        proxy = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid_part,
            'udp': True
        }
        
        # TLS settings
        security = (get_param('security') or 'none').lower()
        if security == 'tls' or security == 'reality':
            proxy['tls'] = True
            sni = get_param('sni') or get_param('peer')
            if sni:
                proxy['servername'] = sni
            fp = get_param('fp')
            if fp:
                proxy['client-fingerprint'] = fp
            alpn = _split_alpn(get_param('alpn'))
            if alpn:
                proxy['alpn'] = alpn
            if _truthy(get_param('allowInsecure', 'allow_insecure', 'insecure')):
                proxy['skip-cert-verify'] = True
            if security == 'reality':
                proxy['reality-opts'] = {}
                pbk = get_param('pbk')
                if pbk:
                    proxy['reality-opts']['public-key'] = pbk
                sid = get_param('sid')
                if sid:
                    proxy['reality-opts']['short-id'] = sid
                spx = get_param('spx', 'spiderX', 'spider-x')
                if spx:
                    proxy['reality-opts']['spider-x'] = spx
        else:
            pbk = get_param('pbk')
            sid = get_param('sid')
            spx = get_param('spx', 'spiderX', 'spider-x')
            if pbk or sid or spx:
                proxy['tls'] = True
                proxy['reality-opts'] = {}
                if pbk:
                    proxy['reality-opts']['public-key'] = pbk
                if sid:
                    proxy['reality-opts']['short-id'] = sid
                if spx:
                    proxy['reality-opts']['spider-x'] = spx
        
        # Transport settings
        transport = (get_param('type') or get_param('transport') or get_param('network') or 'tcp').lower()
        if transport in ['ws', 'httpupgrade']:
            proxy['network'] = transport
            ws_opts = {}
            path = get_param('path')
            if path:
                ws_opts['path'] = path
            host = get_param('host')
            if host:
                ws_opts['headers'] = {'Host': host}
            if ws_opts:
                proxy['ws-opts'] = ws_opts
        elif transport == 'grpc':
            proxy['network'] = 'grpc'
            grpc_opts = {}
            service_name = get_param('serviceName', 'servicename')
            if service_name:
                grpc_opts['grpc-service-name'] = service_name
            mode = get_param('mode')
            if mode:
                grpc_opts['mode'] = mode
            authority = get_param('authority')
            if authority:
                grpc_opts['authority'] = authority
            if grpc_opts:
                proxy['grpc-opts'] = grpc_opts
        elif transport in ['http', 'h2']:
            proxy['network'] = 'h2'
            h2_opts = {}
            path = get_param('path')
            if path:
                h2_opts['path'] = path
            host = get_param('host')
            if host:
                h2_opts['host'] = [host]
            if h2_opts:
                proxy['h2-opts'] = h2_opts
        elif transport == 'xhttp':
            proxy['network'] = 'xhttp'
            xhttp_mode = get_param('mode', 'xhttp-mode', 'xhttpMode')
            path = get_param('path')
            host = get_param('host')
            _set_xhttp_opts(proxy, mode=xhttp_mode, path=path, host=host)
        elif transport in ['kcp', 'quic', 'tcp']:
            if transport != 'tcp':
                proxy['network'] = transport
            header_type = get_param('headerType', 'headertype')
            if header_type:
                proxy['header-type'] = header_type
        
        # Flow control
        flow = get_param('flow')
        if flow:
            proxy['flow'] = flow
        enc_value = get_param('encryption')
        if enc_value is not None:
            proxy['encryption'] = enc_value
        else:
            enc_alt = get_param('enc')
            if enc_alt:
                proxy['encryption'] = enc_alt.strip()

        ech_value = get_param('ech')
        if ech_value:
            proxy['ech'] = ech_value

        pqv_value = get_param('pqv')
        if pqv_value:
            proxy['pqv'] = pqv_value

        pcs_value = get_param('pcs')
        if pcs_value:
            proxy['cert-sha'] = pcs_value

        fm_value = get_param('fm')
        if fm_value:
            proxy['finalmask'] = fm_value
        
        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse vless link: {e}")
        return None


def parse_vmess_link(link: str) -> Optional[dict]:
    """Parse vmess:// link to Clash format"""
    link = link.strip()
    if not link.lower().startswith('vmess://'):
        return None
    
    try:
        encoded = link[8:]
        decoded = decode_base64(encoded)
        if decoded:
            try:
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
                if str(config.get('tls', '')).lower() in ['tls', '1', 'true']:
                    proxy['tls'] = True
                    if config.get('sni'):
                        proxy['servername'] = config['sni']
                    if config.get('fp'):
                        proxy['client-fingerprint'] = config['fp']
                    alpn = _split_alpn(config.get('alpn'))
                    if alpn:
                        proxy['alpn'] = alpn
                    if _truthy(config.get('allowInsecure')) or _truthy(config.get('insecure')):
                        proxy['skip-cert-verify'] = True

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
                    grpc_opts = {}
                    if config.get('path'):
                        grpc_opts['grpc-service-name'] = config['path']
                    if config.get('mode'):
                        grpc_opts['mode'] = config['mode']
                    if grpc_opts:
                        proxy['grpc-opts'] = grpc_opts
                elif net in ['http', 'h2']:
                    proxy['network'] = 'h2'
                    h2_opts = {}
                    if config.get('path'):
                        h2_opts['path'] = config['path']
                    if config.get('host'):
                        h2_opts['host'] = [config['host']]
                    if h2_opts:
                        proxy['h2-opts'] = h2_opts
                elif net == 'xhttp':
                    proxy['network'] = 'xhttp'
                    _set_xhttp_opts(
                        proxy,
                        mode=config.get('mode'),
                        path=config.get('path'),
                        host=config.get('host'),
                    )
                elif net in ['kcp', 'quic', 'tcp']:
                    if net != 'tcp':
                        proxy['network'] = net
                    header_type = config.get('type')
                    if header_type and header_type != 'none':
                        proxy['header-type'] = header_type

                return proxy
            except Exception:
                pass

        # Fallback: parse standard vmess URL
        parsed = urlparse(link)
        if parsed.scheme.lower() != 'vmess':
            return None

        name = unquote(parsed.fragment) if parsed.fragment else 'vmess'
        uuid_part = unquote(parsed.username) if parsed.username else ''
        server = parsed.hostname or ''
        port = parsed.port or 443
        _, get_param = _parse_query_params(parsed.query)

        proxy = {
            'name': name,
            'type': 'vmess',
            'server': server,
            'port': int(port),
            'uuid': uuid_part,
            'udp': True
        }

        alter_id = get_param('alterId', 'alterid', 'aid')
        if alter_id:
            try:
                proxy['alterId'] = int(alter_id)
            except ValueError:
                pass

        cipher = get_param('encryption', 'cipher', 'scy')
        if cipher:
            proxy['cipher'] = cipher

        security = (get_param('security') or '').lower()
        tls_flag = security in ['tls', 'reality'] or _truthy(get_param('tls'))
        if tls_flag:
            proxy['tls'] = True
            sni = get_param('sni') or get_param('peer')
            if sni:
                proxy['servername'] = sni
            fp = get_param('fp')
            if fp:
                proxy['client-fingerprint'] = fp
            alpn = _split_alpn(get_param('alpn'))
            if alpn:
                proxy['alpn'] = alpn
            if _truthy(get_param('allowInsecure', 'allow_insecure', 'insecure')):
                proxy['skip-cert-verify'] = True

        transport = (get_param('type') or get_param('transport') or get_param('network') or 'tcp').lower()
        if transport in ['ws', 'httpupgrade']:
            proxy['network'] = transport
            ws_opts = {}
            path = get_param('path')
            if path:
                ws_opts['path'] = path
            host = get_param('host')
            if host:
                ws_opts['headers'] = {'Host': host}
            if ws_opts:
                proxy['ws-opts'] = ws_opts
        elif transport == 'grpc':
            proxy['network'] = 'grpc'
            grpc_opts = {}
            service_name = get_param('serviceName', 'servicename')
            if service_name:
                grpc_opts['grpc-service-name'] = service_name
            mode = get_param('mode')
            if mode:
                grpc_opts['mode'] = mode
            authority = get_param('authority')
            if authority:
                grpc_opts['authority'] = authority
            if grpc_opts:
                proxy['grpc-opts'] = grpc_opts
        elif transport in ['http', 'h2']:
            proxy['network'] = 'h2'
            h2_opts = {}
            path = get_param('path')
            if path:
                h2_opts['path'] = path
            host = get_param('host')
            if host:
                h2_opts['host'] = [host]
            if h2_opts:
                proxy['h2-opts'] = h2_opts
        elif transport == 'xhttp':
            proxy['network'] = 'xhttp'
            xhttp_mode = get_param('mode', 'xhttp-mode', 'xhttpMode')
            path = get_param('path')
            host = get_param('host')
            _set_xhttp_opts(proxy, mode=xhttp_mode, path=path, host=host)
        elif transport in ['kcp', 'quic', 'tcp']:
            if transport != 'tcp':
                proxy['network'] = transport
            header_type = get_param('headerType', 'headertype')
            if header_type:
                proxy['header-type'] = header_type

        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse vmess link: {e}")
        return None


def parse_ss_link(link: str) -> Optional[dict]:
    """Parse ss:// link to Clash format"""
    link = link.strip()
    if not link.lower().startswith('ss://'):
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
            
            # Parse server:port and query
            params_str = ''
            if '?' in server_part:
                server_part, params_str = server_part.split('?', 1)
            if ':' in server_part:
                server, port = server_part.rsplit(':', 1)
                port = port.split('/')[0]
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
            params_str = ''
        
        proxy = {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password,
            'udp': True
        }

        # Plugin options (SIP002)
        if params_str:
            _, get_param = _parse_query_params(params_str)
            plugin_value = get_param('plugin')
            if plugin_value:
                plugin_str = unquote(plugin_value)
                parts = [p for p in plugin_str.split(';') if p]
                if parts:
                    plugin_name = parts[0]
                    if plugin_name == 'simple-obfs':
                        plugin_name = 'obfs-local'
                    opts = {}
                    flags = set()
                    for part in parts[1:]:
                        if '=' in part:
                            k, v = part.split('=', 1)
                            opts[k] = v
                        else:
                            flags.add(part)

                    if plugin_name in ['obfs-local', 'obfs']:
                        mode = opts.get('obfs')
                        host = opts.get('obfs-host') or opts.get('host')
                        proxy['plugin'] = 'obfs'
                        plugin_opts = {}
                        if mode:
                            plugin_opts['mode'] = mode.replace('obfs=', '') if mode.startswith('obfs=') else mode
                        if host:
                            plugin_opts['host'] = host.replace('obfs-host=', '') if host.startswith('obfs-host=') else host
                        if plugin_opts:
                            proxy['plugin-opts'] = plugin_opts
                    elif plugin_name == 'v2ray-plugin':
                        proxy['plugin'] = 'v2ray-plugin'
                        plugin_opts = {}
                        mode = opts.get('mode', 'websocket')
                        plugin_opts['mode'] = mode.replace('mode=', '') if mode.startswith('mode=') else mode
                        host = opts.get('host')
                        if host:
                            plugin_opts['host'] = host.replace('host=', '') if host.startswith('host=') else host
                        path = opts.get('path')
                        if path:
                            path_val = path.replace('path=', '') if path.startswith('path=') else path
                            path_val = path_val.replace('\\\\', '\\').replace('\\=', '=').replace('\\,', ',')
                            plugin_opts['path'] = path_val
                        if 'tls' in flags or _truthy(opts.get('tls')):
                            plugin_opts['tls'] = True
                        if opts.get('mux'):
                            plugin_opts['mux'] = opts.get('mux')
                        if plugin_opts:
                            proxy['plugin-opts'] = plugin_opts
                    else:
                        proxy['plugin'] = plugin_name
                        if opts:
                            proxy['plugin-opts'] = opts

        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse ss link: {e}")
        return None


def parse_trojan_link(link: str) -> Optional[dict]:
    """Parse trojan:// link to Clash format"""
    link = link.strip()
    if not link.lower().startswith('trojan://'):
        return None
    
    try:
        parsed = urlparse(link)
        if parsed.scheme.lower() != 'trojan':
            return None

        name = unquote(parsed.fragment) if parsed.fragment else 'trojan'
        raw_userinfo = ''
        if parsed.username:
            raw_userinfo = parsed.username
            if parsed.password:
                raw_userinfo = f"{parsed.username}:{parsed.password}"
        password = unquote(raw_userinfo) if raw_userinfo else ''
        server = parsed.hostname or ''
        port = parsed.port or 443

        _, get_param = _parse_query_params(parsed.query)

        proxy = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': password,
            'udp': True
        }

        # TLS / Reality settings
        security = (get_param('security') or 'tls').lower()
        if security in ['tls', 'reality']:
            proxy['tls'] = True
            sni = get_param('sni') or get_param('peer')
            if sni:
                proxy['sni'] = sni
            fp = get_param('fp')
            if fp:
                proxy['client-fingerprint'] = fp
            alpn = _split_alpn(get_param('alpn'))
            if alpn:
                proxy['alpn'] = alpn
            if _truthy(get_param('allowInsecure', 'allow_insecure', 'insecure')):
                proxy['skip-cert-verify'] = True
            if security == 'reality':
                proxy['reality-opts'] = {}
                pbk = get_param('pbk')
                if pbk:
                    proxy['reality-opts']['public-key'] = pbk
                sid = get_param('sid')
                if sid:
                    proxy['reality-opts']['short-id'] = sid
                spx = get_param('spx', 'spiderX', 'spider-x')
                if spx:
                    proxy['reality-opts']['spider-x'] = spx

        # Transport
        transport = (get_param('type') or get_param('transport') or get_param('network') or 'tcp').lower()
        if transport in ['ws', 'httpupgrade']:
            proxy['network'] = transport
            ws_opts = {}
            path = get_param('path')
            if path:
                ws_opts['path'] = path
            host = get_param('host')
            if host:
                ws_opts['headers'] = {'Host': host}
            if ws_opts:
                proxy['ws-opts'] = ws_opts
        elif transport == 'grpc':
            proxy['network'] = 'grpc'
            grpc_opts = {}
            service_name = get_param('serviceName', 'servicename')
            if service_name:
                grpc_opts['grpc-service-name'] = service_name
            mode = get_param('mode')
            if mode:
                grpc_opts['mode'] = mode
            authority = get_param('authority')
            if authority:
                grpc_opts['authority'] = authority
            if grpc_opts:
                proxy['grpc-opts'] = grpc_opts
        elif transport in ['http', 'h2']:
            proxy['network'] = 'h2'
            h2_opts = {}
            path = get_param('path')
            if path:
                h2_opts['path'] = path
            host = get_param('host')
            if host:
                h2_opts['host'] = [host]
            if h2_opts:
                proxy['h2-opts'] = h2_opts
        elif transport == 'xhttp':
            proxy['network'] = 'xhttp'
            xhttp_mode = get_param('mode', 'xhttp-mode', 'xhttpMode')
            path = get_param('path')
            host = get_param('host')
            _set_xhttp_opts(proxy, mode=xhttp_mode, path=path, host=host)
        elif transport in ['kcp', 'quic', 'tcp']:
            if transport != 'tcp':
                proxy['network'] = transport
            header_type = get_param('headerType', 'headertype')
            if header_type:
                proxy['header-type'] = header_type

        flow = get_param('flow')
        if flow:
            proxy['flow'] = flow

        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse trojan link: {e}")
        return None


def parse_hysteria2_link(link: str) -> Optional[dict]:
    """Parse hysteria2:// or hy2:// link to Clash format"""
    link = link.strip()
    if not (link.lower().startswith('hysteria2://') or link.lower().startswith('hy2://')):
        return None
    
    try:
        parsed = urlparse(link)
        if parsed.scheme.lower() not in ['hysteria2', 'hy2']:
            return None

        name = unquote(parsed.fragment) if parsed.fragment else 'hysteria2'
        raw_userinfo = ''
        if parsed.username:
            raw_userinfo = parsed.username
            if parsed.password:
                raw_userinfo = f"{parsed.username}:{parsed.password}"
        auth = unquote(raw_userinfo) if raw_userinfo else ''
        server = parsed.hostname or ''
        port = parsed.port or 443

        _, get_param = _parse_query_params(parsed.query)

        proxy = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': int(port),
            'password': auth
        }

        sni = get_param('sni') or get_param('peer')
        if sni:
            proxy['sni'] = sni
            proxy['tls'] = True

        alpn = _split_alpn(get_param('alpn'))
        if alpn:
            proxy['alpn'] = alpn
            proxy['tls'] = True

        if _truthy(get_param('insecure', 'allowInsecure', 'allow_insecure')):
            proxy['skip-cert-verify'] = True
            proxy['tls'] = True

        obfs = get_param('obfs')
        if obfs:
            proxy['obfs'] = obfs
            obfs_password = get_param('obfs-password')
            if obfs_password:
                proxy['obfs-password'] = obfs_password

        mport = get_param('mport') or get_param('ports')
        if mport:
            proxy['ports'] = mport.replace('-', ':')

        pin_sha = get_param('pinSHA256', 'pinsha256')
        if pin_sha:
            proxy['ca-sha256'] = pin_sha
            proxy['tls'] = True

        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse hysteria2 link: {e}")
        return None


def parse_tuic_link(link: str) -> Optional[dict]:
    """Parse tuic:// link to Clash format"""
    link = link.strip()
    if not link.lower().startswith('tuic://'):
        return None
    
    try:
        parsed = urlparse(link)
        if parsed.scheme.lower() != 'tuic':
            return None

        name = unquote(parsed.fragment) if parsed.fragment else 'tuic'
        raw_userinfo = ''
        if parsed.username:
            raw_userinfo = parsed.username
            if parsed.password:
                raw_userinfo = f"{parsed.username}:{parsed.password}"
        raw_userinfo = unquote(raw_userinfo)
        if ':' in raw_userinfo:
            uuid, password = raw_userinfo.split(':', 1)
        else:
            uuid = raw_userinfo
            password = ''

        server = parsed.hostname or ''
        port = parsed.port or 443

        _, get_param = _parse_query_params(parsed.query)

        proxy = {
            'name': name,
            'type': 'tuic',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'password': password
        }

        sni = get_param('sni') or get_param('peer')
        if sni:
            proxy['sni'] = sni
            proxy['tls'] = True
        alpn = _split_alpn(get_param('alpn'))
        if alpn:
            proxy['alpn'] = alpn
            proxy['tls'] = True
        if _truthy(get_param('insecure', 'allowInsecure', 'allow_insecure')):
            proxy['skip-cert-verify'] = True
            proxy['tls'] = True
        if get_param('congestion_control'):
            proxy['congestion-controller'] = get_param('congestion_control')
        if get_param('udp_relay_mode'):
            proxy['udp-relay-mode'] = get_param('udp_relay_mode')

        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse tuic link: {e}")
        return None


def parse_anytls_link(link: str) -> Optional[dict]:
    """Parse anytls:// link to Clash format"""
    link = link.strip()
    if not link.lower().startswith('anytls://'):
        return None

    try:
        parsed = urlparse(link)
        if parsed.scheme.lower() != 'anytls':
            return None

        name = unquote(parsed.fragment) if parsed.fragment else 'anytls'
        raw_userinfo = ''
        if parsed.username:
            raw_userinfo = parsed.username
            if parsed.password:
                raw_userinfo = f"{parsed.username}:{parsed.password}"
        password = unquote(raw_userinfo) if raw_userinfo else ''
        server = parsed.hostname or ''
        port = parsed.port or 443

        _, get_param = _parse_query_params(parsed.query)

        proxy = {
            'name': name,
            'type': 'anytls',
            'server': server,
            'port': int(port),
            'password': password
        }

        security = (get_param('security') or 'tls').lower()
        if security in ['tls', 'reality']:
            proxy['tls'] = True
            sni = get_param('sni') or get_param('peer')
            if sni:
                proxy['servername'] = sni
            fp = get_param('fp')
            if fp:
                proxy['client-fingerprint'] = fp
            alpn = _split_alpn(get_param('alpn'))
            if alpn:
                proxy['alpn'] = alpn
            if _truthy(get_param('allowInsecure', 'allow_insecure', 'insecure')):
                proxy['skip-cert-verify'] = True
            if security == 'reality':
                proxy['reality-opts'] = {}
                pbk = get_param('pbk')
                if pbk:
                    proxy['reality-opts']['public-key'] = pbk
                sid = get_param('sid')
                if sid:
                    proxy['reality-opts']['short-id'] = sid
                spx = get_param('spx', 'spiderX', 'spider-x')
                if spx:
                    proxy['reality-opts']['spider-x'] = spx

        transport = (get_param('type') or get_param('transport') or get_param('network') or 'tcp').lower()
        if transport in ['ws', 'httpupgrade']:
            proxy['network'] = transport
            ws_opts = {}
            path = get_param('path')
            if path:
                ws_opts['path'] = path
            host = get_param('host')
            if host:
                ws_opts['headers'] = {'Host': host}
            if ws_opts:
                proxy['ws-opts'] = ws_opts
        elif transport == 'grpc':
            proxy['network'] = 'grpc'
            grpc_opts = {}
            service_name = get_param('serviceName', 'servicename')
            if service_name:
                grpc_opts['grpc-service-name'] = service_name
            mode = get_param('mode')
            if mode:
                grpc_opts['mode'] = mode
            authority = get_param('authority')
            if authority:
                grpc_opts['authority'] = authority
            if grpc_opts:
                proxy['grpc-opts'] = grpc_opts
        elif transport in ['http', 'h2']:
            proxy['network'] = 'h2'
            h2_opts = {}
            path = get_param('path')
            if path:
                h2_opts['path'] = path
            host = get_param('host')
            if host:
                h2_opts['host'] = [host]
            if h2_opts:
                proxy['h2-opts'] = h2_opts
        elif transport == 'xhttp':
            proxy['network'] = 'xhttp'
            xhttp_mode = get_param('mode', 'xhttp-mode', 'xhttpMode')
            path = get_param('path')
            host = get_param('host')
            _set_xhttp_opts(proxy, mode=xhttp_mode, path=path, host=host)
        elif transport in ['kcp', 'quic', 'tcp']:
            if transport != 'tcp':
                proxy['network'] = transport
            header_type = get_param('headerType', 'headertype')
            if header_type:
                proxy['header-type'] = header_type

        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse anytls link: {e}")
        return None


def parse_wireguard_link(link: str) -> Optional[dict]:
    """Parse wireguard:// link to Clash format"""
    link = link.strip()
    if not link.lower().startswith('wireguard://'):
        return None

    try:
        parsed = urlparse(link)
        if parsed.scheme.lower() != 'wireguard':
            return None

        name = unquote(parsed.fragment) if parsed.fragment else 'wireguard'
        raw_userinfo = ''
        if parsed.username:
            raw_userinfo = parsed.username
            if parsed.password:
                raw_userinfo = f"{parsed.username}:{parsed.password}"
        private_key = unquote(raw_userinfo) if raw_userinfo else ''
        server = parsed.hostname or ''
        port = parsed.port or 51820

        _, get_param = _parse_query_params(parsed.query)

        proxy = {
            'name': name,
            'type': 'wireguard',
            'server': server,
            'port': int(port)
        }

        if private_key:
            proxy['private-key'] = private_key

        public_key = get_param('publickey', 'public-key')
        if public_key:
            proxy['public-key'] = public_key

        preshared_key = get_param('presharedkey', 'preshared-key', 'psk')
        if preshared_key:
            proxy['preshared-key'] = preshared_key

        reserved = get_param('reserved')
        if reserved:
            proxy['reserved'] = reserved

        address = get_param('address')
        if address:
            proxy['address'] = address

        mtu_val = get_param('mtu')
        if mtu_val:
            try:
                proxy['mtu'] = int(mtu_val)
            except ValueError:
                pass

        return proxy
    except Exception as e:
        logger.debug(f"Failed to parse wireguard link: {e}")
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

    lower = link.lower()
    if not (lower.startswith('socks5+tls://') or lower.startswith('socks5://') or lower.startswith('socks://')):
        return None

    try:
        parsed = urlparse(link)
        scheme = parsed.scheme.lower()
        tls = scheme == 'socks5+tls'

        name = unquote(parsed.fragment) if parsed.fragment else 'socks5'
        server = parsed.hostname or ''
        port = parsed.port or 1080

        username = None
        password = None
        if parsed.username:
            raw_userinfo = parsed.username
            if parsed.password:
                raw_userinfo = f"{parsed.username}:{parsed.password}"
            raw_userinfo = unquote(raw_userinfo)
            if ':' in raw_userinfo:
                username, password = raw_userinfo.split(':', 1)
            else:
                decoded = decode_base64(raw_userinfo)
                if ':' in decoded:
                    username, password = decoded.split(':', 1)

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

    lower = link.lower()
    if not (lower.startswith('http://') or lower.startswith('https://')):
        return None

    try:
        parsed = urlparse(link)
        scheme = parsed.scheme.lower()
        tls = scheme == 'https'

        name = unquote(parsed.fragment) if parsed.fragment else 'http'
        server = parsed.hostname or ''
        port = parsed.port or (443 if tls else 80)

        username = None
        password = None
        if parsed.username:
            raw_userinfo = parsed.username
            if parsed.password:
                raw_userinfo = f"{parsed.username}:{parsed.password}"
            raw_userinfo = unquote(raw_userinfo)
            if ':' in raw_userinfo:
                username, password = raw_userinfo.split(':', 1)
            else:
                decoded = decode_base64(raw_userinfo)
                if ':' in decoded:
                    username, password = decoded.split(':', 1)

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
        ('anytls://', parse_anytls_link),
        ('wireguard://', parse_wireguard_link),
        ('socks5://', parse_socks_link),
        ('socks5+tls://', parse_socks_link),
        ('socks://', parse_socks_link),
        ('http://', parse_http_link),
        ('https://', parse_http_link),
    ]
    
    lower_link = link.lower()
    for prefix, parser in parsers:
        if lower_link.startswith(prefix):
            return parser(link)
    
    return None
