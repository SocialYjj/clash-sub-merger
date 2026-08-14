"""
Node Link Parser Service
Parses various proxy protocol links (vmess, vless, ss, trojan, etc.)
"""
import base64
import ipaddress
import json
from urllib.parse import urlparse, parse_qsl, unquote
from typing import Optional
from logger_config import get_logger
from core.proxy_compat import store_certificate_pin
from services.xhttp_compat import XHTTPCompatibilityError, parse_xhttp_extra

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


def _copy_uri_tls_extensions(proxy: dict, get_param) -> None:
    """Map v2rayN TLS URI fields to Mihomo's canonical outbound keys."""
    ech_value = get_param('ech')
    if ech_value:
        # Keep the original share-link value for V2Ray export diagnostics;
        # ``ech-opts`` is the canonical Mihomo representation.
        proxy['ech'] = ech_value
        proxy['ech-opts'] = {'enable': True, 'config': ech_value}

    pqv_value = get_param('pqv')
    if pqv_value:
        # v2rayN/Xray extension without a Mihomo equivalent. Preserve it so
        # structural validation rejects the node instead of weakening TLS.
        proxy['pqv'] = pqv_value

    pcs_value = get_param('pcs')
    if pcs_value:
        store_certificate_pin(proxy, pcs_value)

    verify_name = get_param('vcn')
    if verify_name:
        # v2rayN calls this field ``vcn``. Mihomo does not consume it, but the
        # canonical share-link exporter must retain it until it can either
        # reproduce the URI or report an explicit incompatibility.
        proxy['verify-peer-cert-by-name'] = verify_name

    finalmask = get_param('fm')
    if finalmask:
        # v2rayN/Xray extension without a Mihomo equivalent.
        proxy['finalmask'] = finalmask


def _parse_wireguard_addresses(value) -> tuple[str | None, str | None] | None:
    """Split a v2rayN WireGuard address value into Mihomo ``ip``/``ipv6``."""
    if value in (None, '', []):
        return None, None

    candidates = value if isinstance(value, (list, tuple)) else str(value).split(',')
    ipv4 = None
    ipv6 = None
    for candidate in candidates:
        text = str(candidate).strip()
        if not text:
            continue
        try:
            interface = ipaddress.ip_interface(text)
        except ValueError:
            return None
        if interface.version == 4:
            if ipv4 is not None:
                return None
            ipv4 = str(interface)
        else:
            if ipv6 is not None:
                return None
            ipv6 = str(interface)
    if ipv4 is None and ipv6 is None:
        return None
    return ipv4, ipv6


def _truthy(value: str | None) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in ['1', 'true', 'yes', 'y', 'on']


def _has_enabled_tls_security(get_param, *, default_enabled: bool = False) -> bool:
    """Return whether a URI explicitly or implicitly enables TLS."""
    security = get_param('security')
    if security is None:
        return default_enabled
    return str(security).strip().lower() in {'tls', 'reality'}


def _copy_uri_security(proxy: dict, get_param) -> str:
    """Preserve an explicit URI security value for boundary validation."""
    value = get_param('security')
    if value in (None, ''):
        return ''
    normalized = str(value).strip().lower()
    proxy['security'] = normalized
    return normalized


def _parse_optional_int(get_param, *keys: str, minimum: int = 0):
    """Parse one integer query parameter without silently dropping bad input."""
    value = get_param(*keys)
    if value in (None, ''):
        return None, True
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None, False
    if parsed < minimum:
        return None, False
    return parsed, True


def _parse_optional_bool(get_param, *keys: str):
    """Parse a boolean query parameter while retaining explicit false values."""
    value = get_param(*keys)
    if value in (None, ''):
        return None, True
    normalized = str(value).strip().lower()
    if normalized in {'1', 'true', 'yes', 'on'}:
        return True, True
    if normalized in {'0', 'false', 'no', 'off'}:
        return False, True
    return None, False


def _normalize_port_ranges(value: str | None) -> str | None:
    """Normalize Mihomo port ranges and reject malformed or unsafe values."""
    if value in (None, ''):
        return None

    normalized_ranges = []
    for segment in str(value).strip().replace(':', '-').replace(',', '/').split('/'):
        segment = segment.strip()
        if not segment:
            continue
        bounds = segment.split('-')
        if len(bounds) not in {1, 2}:
            return None
        try:
            start = int(bounds[0])
            end = int(bounds[-1])
        except (TypeError, ValueError):
            return None
        if not 1 <= start <= 65535 or not 1 <= end <= 65535:
            return None
        if start > end:
            start, end = end, start
        normalized_ranges.append(str(start) if start == end else f'{start}-{end}')

    return '/'.join(normalized_ranges) or None


def _normalize_unsigned_range(value: str | None) -> str | None:
    """Normalize a positive integer or integer range without a port-size cap."""
    if value in (None, ''):
        return None
    bounds = str(value).strip().split('-')
    if len(bounds) not in {1, 2}:
        return None
    try:
        start = int(bounds[0])
        end = int(bounds[-1])
    except (TypeError, ValueError):
        return None
    if start < 1 or end < 1:
        return None
    if start > end:
        start, end = end, start
    return str(start) if start == end else f'{start}-{end}'


def _copy_int_query_params(proxy: dict, get_param, field_map: dict[str, tuple[str, ...]]):
    """Copy positive integer URI fields while preserving invalid input for rejection."""
    for proxy_key, query_keys in field_map.items():
        raw_value = get_param(*query_keys)
        if raw_value in (None, ''):
            continue
        parsed, valid = _parse_optional_int(get_param, *query_keys, minimum=1)
        proxy[proxy_key] = parsed if valid else raw_value


def _copy_bool_query_params(proxy: dict, get_param, field_map: dict[str, tuple[str, ...]]):
    """Copy explicit URI booleans while preserving invalid input for rejection."""
    for proxy_key, query_keys in field_map.items():
        raw_value = get_param(*query_keys)
        if raw_value in (None, ''):
            continue
        parsed, valid = _parse_optional_bool(get_param, *query_keys)
        proxy[proxy_key] = parsed if valid else raw_value


def _set_xhttp_opts(proxy: dict, mode=None, path=None, host=None, extra=None):
    """Set mihomo-compatible xhttp options on a parsed proxy."""
    xhttp_opts = {}
    if mode not in (None, ''):
        xhttp_opts['mode'] = mode
    if path not in (None, ''):
        xhttp_opts['path'] = path
    if host not in (None, ''):
        xhttp_opts['host'] = host
    if extra not in (None, ''):
        try:
            xhttp_opts.update(parse_xhttp_extra(extra))
        except XHTTPCompatibilityError:
            # The URI is syntactically parseable, but its XHTTP semantics are
            # unsupported or malformed. Preserve the original value so the
            # structural validator can reject it explicitly instead of making
            # the node disappear during subscription parsing.
            xhttp_opts['extra'] = extra
    if xhttp_opts:
        proxy['xhttp-opts'] = xhttp_opts


def _parse_websocket_opts(get_param) -> dict:
    """Parse common WebSocket fields, including v2rayN early-data aliases."""
    ws_opts = {}
    path = get_param('path')
    if path:
        ws_opts['path'] = path
    host = get_param('host')
    if host:
        ws_opts['headers'] = {'Host': host}

    early_data = get_param('ed', 'maxEarlyData', 'max-early-data')
    if early_data not in (None, ''):
        try:
            early_data = int(early_data)
        except (TypeError, ValueError):
            pass
        ws_opts['max-early-data'] = early_data

    early_data_header = get_param(
        'eh', 'earlyDataHeaderName', 'early-data-header-name'
    )
    if early_data_header not in (None, ''):
        ws_opts['early-data-header-name'] = early_data_header
    return ws_opts


def _apply_http_upgrade(proxy: dict, ws_opts: dict) -> None:
    """Store v2ray HTTP Upgrade in Mihomo's WebSocket representation."""
    proxy['network'] = 'ws'
    normalized_opts = dict(ws_opts or {})
    normalized_opts['v2ray-http-upgrade'] = True
    proxy['ws-opts'] = normalized_opts


def _parse_grpc_opts(get_param) -> dict | None:
    """Parse gRPC URI fields; runtime compatibility is validated later."""
    mode = str(get_param('mode', 'grpc-mode') or '').strip().lower()
    grpc_opts = {}
    service_name = get_param('serviceName', 'servicename')
    if service_name:
        grpc_opts['grpc-service-name'] = service_name
    if mode and mode != 'gun':
        grpc_opts['mode'] = mode
    authority = get_param('authority')
    if authority not in (None, ''):
        grpc_opts['authority'] = authority
    return grpc_opts


def _parse_reality_opts(get_param) -> dict | None:
    """Build Reality options while retaining unsupported URI-only fields."""
    reality_opts = {}
    public_key = get_param('pbk', 'publicKey', 'public-key')
    short_id = get_param('sid', 'shortId', 'short-id')
    spider_x = get_param('spx', 'spiderX', 'spider-x')
    if public_key:
        reality_opts['public-key'] = public_key
    if short_id:
        reality_opts['short-id'] = short_id
    if spider_x:
        reality_opts['spider-x'] = spider_x
    return reality_opts


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
        security = _copy_uri_security(proxy, get_param) or 'none'
        
        # TLS settings
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
                reality_opts = _parse_reality_opts(get_param)
                proxy['reality-opts'] = reality_opts
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
        if transport not in {'tcp', 'raw', 'http', 'h2', 'ws', 'httpupgrade', 'grpc', 'xhttp', 'kcp', 'quic'}:
            proxy['network'] = transport
            return proxy
        if transport == 'raw':
            transport = 'tcp'
        if transport in ['ws', 'httpupgrade']:
            ws_opts = _parse_websocket_opts(get_param)
            if transport == 'httpupgrade':
                _apply_http_upgrade(proxy, ws_opts)
            else:
                proxy['network'] = 'ws'
                if ws_opts:
                    proxy['ws-opts'] = ws_opts
        elif transport == 'grpc':
            proxy['network'] = 'grpc'
            grpc_opts = _parse_grpc_opts(get_param)
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
            _set_xhttp_opts(
                proxy, mode=xhttp_mode, path=path, host=host, extra=get_param('extra')
            )
        elif transport in ['kcp', 'quic', 'tcp']:
            if transport != 'tcp':
                proxy['network'] = transport
            header_type = get_param('headerType', 'headertype')
            if header_type:
                proxy['header-type'] = header_type
            if transport == 'kcp':
                seed = get_param('seed')
                if seed not in (None, ''):
                    proxy['seed'] = seed
                mtu = get_param('mtu')
                if mtu not in (None, ''):
                    try:
                        proxy['mtu'] = int(mtu)
                    except (TypeError, ValueError):
                        proxy['mtu'] = mtu
            elif transport == 'tcp':
                host = get_param('host')
                path = get_param('path')
                if host not in (None, ''):
                    proxy['host'] = host
                if path not in (None, ''):
                    proxy['path'] = path
        
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

        _copy_uri_tls_extensions(proxy, get_param)
        
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

                # TLS-related URI fields are independent in v2rayN's VMess
                # schema. Preserve them even when an upstream link omits the
                # explicit tls marker so a later export does not erase them.
                tls_mode = str(config.get('tls', '')).strip().lower()
                if tls_mode:
                    proxy['security'] = 'tls' if tls_mode in {'1', 'true'} else tls_mode
                if tls_mode in ['tls', '1', 'true', 'reality']:
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
                verify_name = config.get('vcn')
                if verify_name:
                    proxy['verify-peer-cert-by-name'] = verify_name
                cert_sha = config.get('pcs')
                if cert_sha:
                    store_certificate_pin(proxy, cert_sha)
                ech_config = config.get('ech')
                if ech_config:
                    proxy['ech-opts'] = {'enable': True, 'config': ech_config}
                # Legacy VMess JSON has no official Reality fields in v2rayN,
                # but retain provider extensions internally so V2Ray export can
                # reject rather than silently downgrade them to ordinary TLS.
                if tls_mode == 'reality':
                    reality_opts = {}
                    public_key = config.get('pbk') or config.get('publicKey') or config.get('public-key')
                    short_id = config.get('sid') or config.get('shortId') or config.get('short-id')
                    if public_key:
                        reality_opts['public-key'] = public_key
                    if short_id:
                        reality_opts['short-id'] = short_id
                    spider_x = config.get('spx') or config.get('spiderX') or config.get('spider-x')
                    if spider_x:
                        reality_opts['spider-x'] = spider_x
                    proxy['reality-opts'] = reality_opts

                # Transport
                net = str(config.get('net', 'tcp') or 'tcp').strip().lower()
                if net == 'raw':
                    net = 'tcp'
                if net not in {'tcp', 'http', 'h2', 'ws', 'httpupgrade', 'grpc', 'xhttp', 'kcp', 'quic'}:
                    proxy['network'] = net
                    return proxy
                if net in {'ws', 'httpupgrade'}:
                    ws_opts = {}
                    if config.get('path'):
                        ws_opts['path'] = config['path']
                    if config.get('host'):
                        ws_opts['headers'] = {'Host': config['host']}
                    if net == 'httpupgrade':
                        _apply_http_upgrade(proxy, ws_opts)
                    else:
                        proxy['network'] = 'ws'
                    if ws_opts and net == 'ws':
                        proxy['ws-opts'] = ws_opts
                elif net == 'grpc':
                    proxy['network'] = 'grpc'
                    grpc_mode = str(config.get('mode') or config.get('type') or '').strip().lower()
                    grpc_opts = {}
                    if config.get('path'):
                        grpc_opts['grpc-service-name'] = config['path']
                    if grpc_mode and grpc_mode not in {'none', 'gun'}:
                        grpc_opts['mode'] = grpc_mode
                    if config.get('host') not in (None, ''):
                        grpc_opts['authority'] = config['host']
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
                        mode=config.get('mode') or config.get('type'),
                        path=config.get('path'),
                        host=config.get('host'),
                        extra=config.get('extra'),
                    )
                elif net in ['kcp', 'quic', 'tcp']:
                    if net != 'tcp':
                        proxy['network'] = net
                    header_type = config.get('type')
                    if header_type and header_type != 'none':
                        proxy['header-type'] = header_type
                    if net == 'kcp' and config.get('path') not in (None, ''):
                        proxy['seed'] = config['path']
                    elif net == 'tcp':
                        if config.get('host') not in (None, ''):
                            proxy['host'] = config['host']
                        if config.get('path') not in (None, ''):
                            proxy['path'] = config['path']

                return proxy
            except (json.JSONDecodeError, TypeError, ValueError):
                # A decoded JSON object is the canonical VMess form. Do not
                # reinterpret a malformed JSON profile as the unrelated
                # standard-URI form, where fields could be silently shifted.
                if decoded.lstrip().startswith('{'):
                    return None

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
        security = _copy_uri_security(proxy, get_param)

        alter_id = get_param('alterId', 'alterid', 'aid')
        if alter_id:
            try:
                proxy['alterId'] = int(alter_id)
            except ValueError:
                pass

        cipher = get_param('encryption', 'cipher', 'scy')
        if cipher:
            proxy['cipher'] = cipher

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
            if security == 'reality':
                reality_opts = _parse_reality_opts(get_param)
                proxy['reality-opts'] = reality_opts

        transport = (get_param('type') or get_param('transport') or get_param('network') or 'tcp').lower()
        if transport not in {'tcp', 'raw', 'http', 'h2', 'ws', 'httpupgrade', 'grpc', 'xhttp', 'kcp', 'quic'}:
            proxy['network'] = transport
            return proxy
        if transport == 'raw':
            transport = 'tcp'
        if transport in ['ws', 'httpupgrade']:
            ws_opts = _parse_websocket_opts(get_param)
            if transport == 'httpupgrade':
                _apply_http_upgrade(proxy, ws_opts)
            else:
                proxy['network'] = 'ws'
                if ws_opts:
                    proxy['ws-opts'] = ws_opts
        elif transport == 'grpc':
            proxy['network'] = 'grpc'
            grpc_opts = _parse_grpc_opts(get_param)
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
            _set_xhttp_opts(
                proxy, mode=xhttp_mode, path=path, host=host, extra=get_param('extra')
            )
        elif transport in ['kcp', 'quic', 'tcp']:
            if transport != 'tcp':
                proxy['network'] = transport
            header_type = get_param('headerType', 'headertype')
            if header_type:
                proxy['header-type'] = header_type
            if transport == 'kcp':
                seed = get_param('seed')
                if seed not in (None, ''):
                    proxy['seed'] = seed
                mtu = get_param('mtu')
                if mtu not in (None, ''):
                    try:
                        proxy['mtu'] = int(mtu)
                    except (TypeError, ValueError):
                        proxy['mtu'] = mtu
            elif transport == 'tcp':
                host = get_param('host')
                path = get_param('path')
                if host not in (None, ''):
                    proxy['host'] = host
                if path not in (None, ''):
                    proxy['path'] = path

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
        security = _copy_uri_security(proxy, get_param) or 'tls'

        # TLS / Reality settings
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
                reality_opts = _parse_reality_opts(get_param)
                proxy['reality-opts'] = reality_opts

        # Transport
        transport = (get_param('type') or get_param('transport') or get_param('network') or 'tcp').lower()
        if transport not in {'tcp', 'raw', 'ws', 'httpupgrade', 'grpc', 'http', 'h2', 'xhttp', 'kcp', 'quic'}:
            proxy['network'] = transport
            return proxy
        if transport == 'raw':
            transport = 'tcp'
        if transport in ['ws', 'httpupgrade']:
            ws_opts = _parse_websocket_opts(get_param)
            if transport == 'httpupgrade':
                _apply_http_upgrade(proxy, ws_opts)
            else:
                proxy['network'] = 'ws'
                if ws_opts:
                    proxy['ws-opts'] = ws_opts
        elif transport == 'grpc':
            proxy['network'] = 'grpc'
            grpc_opts = _parse_grpc_opts(get_param)
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
            _set_xhttp_opts(
                proxy, mode=xhttp_mode, path=path, host=host, extra=get_param('extra')
            )
        elif transport in ['kcp', 'quic', 'tcp']:
            if transport != 'tcp':
                proxy['network'] = transport
            header_type = get_param('headerType', 'headertype')
            if header_type:
                proxy['header-type'] = header_type
            if transport == 'kcp':
                seed = get_param('seed')
                if seed not in (None, ''):
                    proxy['seed'] = seed
                mtu = get_param('mtu')
                if mtu not in (None, ''):
                    try:
                        proxy['mtu'] = int(mtu)
                    except (TypeError, ValueError):
                        proxy['mtu'] = mtu
            elif transport == 'tcp':
                host = get_param('host')
                path = get_param('path')
                if host not in (None, ''):
                    proxy['host'] = host
                if path not in (None, ''):
                    proxy['path'] = path

        flow = get_param('flow')
        if flow:
            proxy['flow'] = flow

        _copy_uri_tls_extensions(proxy, get_param)

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
        _copy_uri_security(proxy, get_param)

        # Hysteria2 is normally TLS-based. Preserve the explicit URI setting
        # even when every verification flag is false; otherwise a parse/export
        # round trip turns a valid pinned-certificate node into a different
        # profile that v2rayN may reject.
        if _has_enabled_tls_security(get_param, default_enabled=True):
            proxy['tls'] = True

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
            if obfs.strip().lower() == 'gecko':
                for query_key, proxy_key in (
                    ('minPacketSize', 'minPacketSize'),
                    ('maxPacketSize', 'maxPacketSize'),
                ):
                    packet_size = get_param(query_key)
                    if packet_size in (None, ''):
                        packet_size = '512' if query_key == 'minPacketSize' else '1200'
                    try:
                        proxy[proxy_key] = int(packet_size)
                    except (TypeError, ValueError):
                        # Keep an invalid provider value available to the
                        # exporter so it can reject the node instead of
                        # silently replacing the obfuscator configuration.
                        proxy[proxy_key] = packet_size

        mport = get_param('mport') or get_param('ports')
        if mport:
            normalized_ports = _normalize_port_ranges(mport)
            proxy['ports'] = normalized_ports if normalized_ports is not None else mport

        hop_interval = get_param('hop-interval', 'hop_interval', 'hopInterval')
        if hop_interval not in (None, ''):
            hop_interval = str(hop_interval).strip().lower()
            if hop_interval.endswith('s'):
                hop_interval = hop_interval[:-1]
            normalized_hop_interval = _normalize_unsigned_range(hop_interval)
            proxy['hop-interval'] = (
                normalized_hop_interval
                if normalized_hop_interval is not None
                else get_param('hop-interval', 'hop_interval', 'hopInterval')
            )

        for proxy_key, query_keys in {
            'up': ('up', 'upmbps'),
            'down': ('down', 'downmbps'),
            'bbr-profile': ('bbr-profile', 'bbr_profile'),
        }.items():
            value = get_param(*query_keys)
            if value not in (None, ''):
                proxy[proxy_key] = value

        _copy_int_query_params(proxy, get_param, {
            'cwnd': ('cwnd',),
            'udp-mtu': ('udp-mtu', 'udp_mtu'),
            'initial-stream-receive-window': ('initial-stream-receive-window', 'initial_stream_receive_window'),
            'max-stream-receive-window': ('max-stream-receive-window', 'max_stream_receive_window'),
            'initial-connection-receive-window': ('initial-connection-receive-window', 'initial_connection_receive_window'),
            'max-connection-receive-window': ('max-connection-receive-window', 'max_connection_receive_window'),
        })

        pin_sha = get_param('pinSHA256', 'pinsha256', 'pcs')
        if pin_sha:
            # Mihomo uses ``fingerprint`` for TLS certificate pinning. Keep
            # this distinct from ``client-fingerprint`` (the uTLS browser
            # fingerprint), otherwise the pin is silently ignored at runtime.
            store_certificate_pin(proxy, pin_sha)
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
        _copy_uri_security(proxy, get_param)

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

        pin_sha = get_param('pinSHA256', 'pinsha256', 'pcs')
        if pin_sha:
            store_certificate_pin(proxy, pin_sha)

        _copy_int_query_params(proxy, get_param, {
            'heartbeat-interval': ('heartbeat-interval', 'heartbeat_interval'),
            'request-timeout': ('request-timeout', 'request_timeout'),
            'max-udp-relay-packet-size': ('max-udp-relay-packet-size', 'max_udp_relay_packet_size'),
            'max-open-streams': ('max-open-streams', 'max_open_streams'),
            'cwnd': ('cwnd',),
            'recv-window-conn': ('recv-window-conn', 'recv_window_conn'),
            'recv-window': ('recv-window', 'recv_window'),
            'max-datagram-frame-size': ('max-datagram-frame-size', 'max_datagram_frame_size'),
        })
        _copy_bool_query_params(proxy, get_param, {
            'reduce-rtt': ('reduce-rtt', 'reduce_rtt'),
            'disable-sni': ('disable-sni', 'disable_sni'),
            'fast-open': ('fast-open', 'fast_open'),
            'disable-mtu-discovery': ('disable-mtu-discovery', 'disable_mtu_discovery'),
        })
        for proxy_key, query_keys in {
            'bbr-profile': ('bbr-profile', 'bbr_profile'),
        }.items():
            value = get_param(*query_keys)
            if value not in (None, ''):
                proxy[proxy_key] = value

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
        security = _copy_uri_security(proxy, get_param) or 'tls'

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
                proxy['reality-opts'] = _parse_reality_opts(get_param)

        transport = (get_param('type') or get_param('transport') or get_param('network') or 'tcp').lower()
        if transport not in {'tcp', 'raw'}:
            proxy['network'] = transport
            return proxy
        if transport == 'raw':
            transport = 'tcp'

        _copy_uri_tls_extensions(proxy, get_param)

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
            # Mihomo's schema uses ``pre-shared-key``; retain the historical
            # alias on the raw parser result for compatibility with older API
            # consumers. sanitize_proxy() removes the alias at the boundary.
            proxy['pre-shared-key'] = preshared_key
            proxy['preshared-key'] = preshared_key

        reserved = get_param('reserved')
        if reserved:
            values = [item.strip() for item in reserved.split(',') if item.strip()]
            try:
                proxy['reserved'] = [int(item) for item in values]
            except ValueError:
                proxy['reserved'] = reserved

        address = get_param('address')
        if address:
            parsed_addresses = _parse_wireguard_addresses(address)
            if parsed_addresses is None:
                proxy['address'] = address
            else:
                ipv4, ipv6 = parsed_addresses
                if ipv4:
                    proxy['ip'] = ipv4
                if ipv6:
                    proxy['ipv6'] = ipv6

        mtu_val = get_param('mtu')
        if mtu_val:
            try:
                proxy['mtu'] = int(mtu_val)
            except ValueError:
                proxy['mtu'] = mtu_val

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
    """Parse SOCKS links, including v2rayN's Base64 user-info format."""
    link = link.strip()

    lower = link.lower()
    if not (
        lower.startswith('socks5+tls://')
        or lower.startswith('socks5h://')
        or lower.startswith('socks5://')
        or lower.startswith('socks://')
    ):
        return None

    try:
        parsed = urlparse(link)
        scheme = parsed.scheme.lower()
        tls = scheme == 'socks5+tls'

        # Older v2rayN SOCKS links encode the complete
        # ``username:password@server:port`` authority after ``socks://``.
        # Decode that form before reading URL components so the server and
        # authentication fields are not silently shifted into the wrong keys.
        if (
            scheme == 'socks'
            and not parsed.username
            and not parsed.password
            and parsed.port is None
            and parsed.netloc
        ):
            decoded_authority = decode_base64(parsed.netloc)
            if decoded_authority and decoded_authority != parsed.netloc and '@' in decoded_authority:
                nested_link = f"socks5://{decoded_authority}"
                if parsed.fragment:
                    nested_link += f"#{parsed.fragment}"
                return parse_socks_link(nested_link)

        name = unquote(parsed.fragment) if parsed.fragment else 'socks5'
        server = parsed.hostname or ''
        port = parsed.port or 1080

        _, get_param = _parse_query_params(parsed.query)
        username = get_param('username', 'user')
        password = get_param('password', 'pass', 'pwd')
        if parsed.username:
            decoded_username = unquote(parsed.username)
            if parsed.password is not None:
                username = decoded_username
                password = unquote(parsed.password)
            else:
                decoded = decode_base64(decoded_username)
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
        ('socks5h://', parse_socks_link),
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
