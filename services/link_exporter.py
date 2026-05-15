"""
Proxy link exporter.

Converts Clash/Mihomo proxy dictionaries back into share-link formats used by
base64 subscriptions. Kept outside server.py so the export behavior can be
unit-tested without importing the whole FastAPI application.
"""
import base64
import ipaddress
import json
from urllib.parse import quote


def proxy_to_link(proxy: dict) -> str:
    """Convert Clash proxy config to node link"""
    proxy_type = proxy.get('type', '')
    name = proxy.get('name', '')
    server = proxy.get('server', '')
    port = proxy.get('port', '')

    def format_server_for_uri(host: str) -> str:
        if not host:
            return host
        if host.startswith('[') and host.endswith(']'):
            return host
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 6:
                return f'[{host}]'
        except ValueError:
            pass
        return host

    server_uri = format_server_for_uri(server)

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
            network = proxy.get('network')
            if network:
                if network == 'h2':
                    params.append("type=http")
                else:
                    params.append(f"type={network}")
            if proxy.get('encryption') is not None:
                params.append(f"encryption={quote(str(proxy.get('encryption')))}")
            if proxy.get('tls'):
                if proxy.get('reality-opts'):
                    params.append('security=reality')
                    if proxy['reality-opts'].get('public-key'):
                        params.append(f"pbk={proxy['reality-opts']['public-key']}")
                    if proxy['reality-opts'].get('short-id'):
                        params.append(f"sid={proxy['reality-opts']['short-id']}")
                    if proxy['reality-opts'].get('spider-x'):
                        params.append(f"spx={quote(str(proxy['reality-opts']['spider-x']))}")
                else:
                    params.append('security=tls')
            if proxy.get('servername'):
                params.append(f"sni={quote(str(proxy['servername']))}")
            if proxy.get('client-fingerprint'):
                params.append(f"fp={quote(str(proxy['client-fingerprint']))}")
            if proxy.get('alpn'):
                alpn_val = proxy.get('alpn')
                if isinstance(alpn_val, list):
                    alpn_val = ','.join(alpn_val)
                params.append(f"alpn={quote(str(alpn_val))}")
            if proxy.get('skip-cert-verify'):
                params.append("allowInsecure=1")
                params.append("insecure=1")
            if proxy.get('flow'):
                params.append(f"flow={quote(str(proxy['flow']))}")
            if proxy.get('ech'):
                params.append(f"ech={quote(str(proxy['ech']))}")
            if proxy.get('pqv'):
                params.append(f"pqv={quote(str(proxy['pqv']))}")
            if proxy.get('cert-sha'):
                params.append(f"pcs={quote(str(proxy['cert-sha']))}")
            if proxy.get('finalmask'):
                params.append(f"fm={quote(str(proxy['finalmask']))}")
            if network in ['ws', 'httpupgrade']:
                ws_opts = proxy.get('ws-opts', {})
                if ws_opts.get('path'):
                    params.append(f"path={quote(ws_opts['path'])}")
                if ws_opts.get('headers', {}).get('Host'):
                    params.append(f"host={ws_opts['headers']['Host']}")
            elif network == 'grpc':
                grpc_opts = proxy.get('grpc-opts', {})
                if grpc_opts.get('grpc-service-name'):
                    params.append(f"serviceName={grpc_opts['grpc-service-name']}")
                if grpc_opts.get('mode'):
                    params.append(f"mode={grpc_opts['mode']}")
                if grpc_opts.get('authority'):
                    params.append(f"authority={grpc_opts['authority']}")
            elif network in ['h2', 'http']:
                h2_opts = proxy.get('h2-opts', {})
                if h2_opts.get('path'):
                    params.append(f"path={quote(h2_opts['path'])}")
                host_val = h2_opts.get('host')
                if isinstance(host_val, list) and host_val:
                    host_val = host_val[0]
                if host_val:
                    params.append(f"host={host_val}")
            elif network == 'xhttp':
                xhttp_opts = proxy.get('xhttp-opts', {})
                if not isinstance(xhttp_opts, dict):
                    xhttp_opts = {}
                xhttp_mode = xhttp_opts.get('mode') or proxy.get('xhttp-mode')
                xhttp_host = xhttp_opts.get('host') or proxy.get('host')
                xhttp_path = xhttp_opts.get('path') or proxy.get('path')
                if xhttp_mode:
                    params.append(f"mode={quote(str(xhttp_mode))}")
                if xhttp_host:
                    params.append(f"host={quote(str(xhttp_host))}")
                if xhttp_path:
                    params.append(f"path={quote(str(xhttp_path))}")
            query = '&'.join(params) if params else ''
            return f"vless://{proxy.get('uuid', '')}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

        elif proxy_type == 'ss':
            # ss://base64(method:password)@server:port#name
            method = proxy.get('cipher', '')
            password = proxy.get('password', '')
            userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
            return f"ss://{userinfo}@{server_uri}:{port}#{quote(name)}"

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
            return f"trojan://{quote(proxy.get('password', ''))}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

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
            return f"hysteria2://{quote(proxy.get('password', ''))}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

        elif proxy_type == 'tuic':
            # tuic://uuid:password@server:port?params#name
            params = []
            if proxy.get('sni'):
                params.append(f"sni={proxy['sni']}")
            if proxy.get('congestion-controller'):
                params.append(f"congestion_control={proxy['congestion-controller']}")
            query = '&'.join(params) if params else ''
            return f"tuic://{proxy.get('uuid', '')}:{proxy.get('password', '')}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

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
            return f"hysteria://{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

        elif proxy_type == 'socks5':
            # socks5://user:pass@server:port#name
            auth = ''
            if proxy.get('username'):
                auth = f"{quote(proxy['username'])}:{quote(proxy.get('password', ''))}@"
            prefix = 'socks5+tls://' if proxy.get('tls') else 'socks5://'
            return f"{prefix}{auth}{server_uri}:{port}#{quote(name)}"

        elif proxy_type == 'http':
            # http://user:pass@server:port#name
            auth = ''
            if proxy.get('username'):
                auth = f"{quote(proxy['username'])}:{quote(proxy.get('password', ''))}@"
            prefix = 'https://' if proxy.get('tls') else 'http://'
            return f"{prefix}{auth}{server_uri}:{port}#{quote(name)}"

        else:
            # Unsupported type, return empty
            return ''
    except Exception:
        return ''
