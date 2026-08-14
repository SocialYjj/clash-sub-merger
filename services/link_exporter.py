"""
Proxy link exporter.

Converts Clash/Mihomo proxy dictionaries back into share-link formats used by
base64 subscriptions. Kept outside server.py so the export behavior can be
unit-tested without importing the whole FastAPI application.
"""
import base64
import ipaddress
import json
from dataclasses import dataclass
from urllib.parse import quote

from services.xhttp_compat import XHTTPCompatibilityError, xhttp_opts_to_extra


@dataclass(frozen=True)
class LinkExportResult:
    link: str
    reason: str | None = None


def _has_nonempty(proxy: dict, *keys: str) -> bool:
    return any(proxy.get(key) not in (None, '', [], {}) for key in keys)


def _certificate_pin(proxy: dict, *fallback_fields: str) -> object:
    """Return the original v2rayN pin before Mihomo-compatible aliases."""
    preserved = proxy.get('_v2rayn-certificate-pin')
    if preserved not in (None, ''):
        return preserved
    for field in fallback_fields:
        value = proxy.get(field)
        if value not in (None, ''):
            return value
    return None


def _conflicting_alias_reason(proxy: dict) -> str | None:
    sni = proxy.get('sni')
    servername = proxy.get('servername')
    if sni not in (None, '') and servername not in (None, '') and str(sni) != str(servername):
        return 'conflicting_server_name'

    pin_values = [
        str(proxy[key])
        for key in ('fingerprint', 'cert-sha', 'ca-sha256')
        if proxy.get(key) not in (None, '')
    ]
    if len(set(pin_values)) > 1:
        return 'conflicting_certificate_pin'
    return None


def _wireguard_addresses(proxy: dict) -> list[str] | None:
    addresses = []
    for key in ('ip', 'ipv6'):
        value = proxy.get(key)
        if value not in (None, ''):
            addresses.append(str(value).strip())

    legacy_address = proxy.get('address')
    if legacy_address not in (None, '', []):
        legacy_values = (
            list(legacy_address)
            if isinstance(legacy_address, (list, tuple))
            else str(legacy_address).split(',')
        )
        legacy_values = [str(value).strip() for value in legacy_values if str(value).strip()]
        if addresses and legacy_values != addresses:
            return None
        if not addresses:
            addresses = legacy_values
    return addresses


def _unsupported_v2ray_reason(proxy: dict) -> str | None:
    """Return why a Mihomo node cannot be represented by v2rayN share URIs."""
    proxy_type = str(proxy.get('type', '') or '').strip().lower()
    network = str(proxy.get('network', '') or '').strip().lower()
    ws_opts = proxy.get('ws-opts')
    http_upgrade = (
        network == 'httpupgrade'
        or network == 'ws'
        and isinstance(ws_opts, dict)
        and ws_opts.get('v2ray-http-upgrade') is True
    )

    if not proxy_type:
        return 'unsupported_type'
    if proxy_type in {'http', 'https'}:
        return 'unsupported_http'
    if proxy_type in {'ssr', 'hysteria'}:
        return 'unsupported_protocol'

    if proxy_type == 'socks5':
        if _has_nonempty(
            proxy,
            'tls', 'sni', 'servername', 'skip-cert-verify', 'fingerprint',
            'ca', 'certificate', 'cert', 'cert-sha', 'ca-sha256', 'private-key',
            'client-fingerprint', 'alpn',
        ):
            return 'unsupported_socks_tls'

    if proxy_type == 'hysteria2':
        certificate_pin = _certificate_pin(proxy, 'fingerprint')
        legacy_certificate_pin = proxy.get('ca-sha256')
        if (
            certificate_pin not in (None, '')
            and legacy_certificate_pin not in (None, '')
            and str(certificate_pin) != str(legacy_certificate_pin)
        ):
            return 'conflicting_hysteria2_certificate_pin'
    else:
        alias_conflict = _conflicting_alias_reason(proxy)
        if alias_conflict:
            return alias_conflict

    if proxy_type == 'hysteria2':
        if _has_nonempty(proxy, 'verify-peer-cert-by-name', 'vcn', 'ech', 'pqv', 'finalmask'):
            return 'unsupported_hysteria2_tls_option'
        if _has_nonempty(proxy, 'up', 'down'):
            return 'unsupported_bandwidth'
        if _has_nonempty(proxy, 'hop-interval'):
            # v2rayN's current Hysteria2 URI parser only reads mport and has no
            # hop-interval query key, so emitting the node would change hopping
            # timing instead of preserving it.
            return 'unsupported_hysteria2_hop_interval'
        if _has_nonempty(
            proxy,
            'cwnd', 'bbr-profile', 'udp-mtu',
            'initial-stream-receive-window', 'max-stream-receive-window',
            'initial-connection-receive-window', 'max-connection-receive-window',
            'recv-window', 'recv-window-conn', 'send-window',
            'congestion-controller', 'certificate', 'private-key', 'ca',
            'ech-opts',
        ):
            return 'unsupported_hysteria2_tuning'
        if _has_nonempty(proxy, 'cert-sha'):
            # ``cert-sha`` is used by other V2Ray protocols for ``pcs``.  A
            # Hysteria2 pin is stored as Mihomo ``fingerprint`` (with
            # ``ca-sha256`` accepted only as the project's legacy alias), so
            # treating this generic field as pinSHA256 would change meaning.
            return 'unsupported_hysteria2_certificate_hash'

        obfs = str(proxy.get('obfs', '') or '').strip().lower()
        if obfs and obfs not in {'salamander', 'gecko'}:
            return 'unsupported_hysteria2_obfs'
        if obfs and not proxy.get('obfs-password'):
            return 'unsupported_hysteria2_obfs'
        if _has_nonempty(proxy, 'minPacketSize', 'maxPacketSize') and obfs != 'gecko':
            return 'unsupported_hysteria2_gecko'
        if obfs == 'gecko':
            if not proxy.get('obfs-password'):
                return 'unsupported_hysteria2_gecko'
            # v2rayN supplies these exact defaults when a gecko URI omits the
            # packet-size bounds; use the same values so the round trip is
            # deterministic rather than silently changing the obfuscator.
            for key in ('obfs-min-packet-size', 'obfs-max-packet-size', 'minPacketSize', 'maxPacketSize'):
                value = proxy.get(key)
                if value in (None, ''):
                    continue
                try:
                    if int(value) <= 0:
                        return 'unsupported_hysteria2_gecko'
                except (TypeError, ValueError):
                    return 'unsupported_hysteria2_gecko'

    if proxy_type == 'anytls':
        # v2rayN's AnyTLS sing-box path consumes SNI, ALPN, insecure, uTLS and
        # ECH. Certificate pinning, vcn, ML-DSA and finalmask are only retained
        # by the generic URI model and do not affect the generated outbound.
        if _has_nonempty(
            proxy,
            'fingerprint', 'cert-sha', 'ca-sha256',
            'verify-peer-cert-by-name', 'vcn', 'pqv', 'finalmask',
        ):
            return 'unsupported_anytls_tls_option'
        ech_opts = proxy.get('ech-opts')
        if ech_opts not in (None, '', {}):
            if not isinstance(ech_opts, dict):
                return 'unsupported_anytls_tls_material'
            if set(ech_opts) - {'enable', 'config'}:
                return 'unsupported_anytls_tls_material'
            if ech_opts.get('enable') is not True or not str(ech_opts.get('config') or '').strip():
                return 'unsupported_anytls_tls_material'
            if proxy.get('ech') not in (None, '', ech_opts['config']):
                return 'conflicting_anytls_ech'
        # v2rayN's AnyTLS import path explicitly clears Network, so any Mihomo
        # transport setting would be discarded even though its generic URI
        # parser accepts a ``type`` query parameter.
        if network:
            return 'unsupported_anytls_transport'
        expected_defaults = {
            'idle-session-check-interval': 30,
            'idle-session-timeout': 30,
            'min-idle-session': 0,
        }
        for key, expected in expected_defaults.items():
            value = proxy.get(key)
            if value in (None, ''):
                continue
            try:
                if int(value) != expected:
                    return 'unsupported_anytls_tuning'
            except (TypeError, ValueError):
                return 'unsupported_anytls_tuning'
        udp_over_tcp = proxy.get('udp-over-tcp')
        if udp_over_tcp is True:
            # AnyTLS always tunnels UDP over its TCP session internally; the
            # v2rayN URI has no separate UOT switch to preserve this option.
            return 'unsupported_udp_over_tcp'
        if udp_over_tcp not in (None, False):
            return 'unsupported_anytls_tuning'
        if _has_nonempty(proxy, 'certificate', 'private-key', 'ca'):
            return 'unsupported_anytls_tls_material'
        if _has_nonempty(
            proxy,
            'disable-reuse', 'shadow-tls', 'shadow-tls-opts',
            'shadowtls', 'shadowtls-opts', 'restls', 'restls-opts',
            'jls', 'jls-opts',
        ):
            return 'unsupported_anytls_extension'

    if proxy_type == 'ss':
        if proxy.get('udp-over-tcp') is True:
            return 'unsupported_udp_over_tcp'
        if proxy.get('udp-over-tcp') not in (None, False):
            return 'unsupported_udp_over_tcp'
        if _has_nonempty(proxy, 'udp-over-tcp-version', 'client-fingerprint'):
            return 'unsupported_shadowsocks_option'

        plugin = str(proxy.get('plugin', '') or '').strip().lower()
        plugin_opts = proxy.get('plugin-opts')
        if plugin:
            if not isinstance(plugin_opts, dict):
                return 'unsupported_plugin_options'
            if plugin in {'obfs', 'obfs-local', 'simple-obfs'}:
                allowed_keys = {'mode', 'host'}
                if set(plugin_opts) - allowed_keys:
                    return 'unsupported_plugin_options'
                if str(plugin_opts.get('mode', '') or '').lower() not in {'http', 'tls'}:
                    return 'unsupported_plugin_mode'
            elif plugin == 'v2ray-plugin':
                allowed_keys = {'mode', 'host', 'path', 'tls', 'mux'}
                if set(plugin_opts) - allowed_keys:
                    return 'unsupported_plugin_options'
                if str(plugin_opts.get('mode', 'websocket') or 'websocket').lower() != 'websocket':
                    return 'unsupported_plugin_mode'
                mux = plugin_opts.get('mux')
                if mux in (None, ''):
                    return 'unsupported_plugin_mux'
                if mux not in (False, 0, '0', 'false', 'False'):
                    # v2rayN rejects a SIP002 link when mux parses to a value
                    # greater than zero; omitting Mihomo's default true would
                    # instead import a different profile.
                    return 'unsupported_plugin_mux'
            else:
                return 'unsupported_plugin'
        elif plugin_opts not in (None, {}, ''):
            return 'unsupported_plugin_options'

    if proxy_type == 'tuic':
        congestion_controller = str(proxy.get('congestion-controller') or '').strip().lower()
        if congestion_controller and congestion_controller not in {'cubic', 'new_reno', 'bbr'}:
            return 'unsupported_tuic_congestion_controller'
        if _has_nonempty(proxy, 'udp-relay-mode'):
            return 'unsupported_udp_relay_mode'
        if _has_nonempty(
            proxy,
            'token', 'heartbeat-interval', 'reduce-rtt', 'request-timeout',
            'disable-sni', 'max-udp-relay-packet-size', 'fast-open',
            'max-open-streams', 'cwnd', 'bbr-profile', 'recv-window-conn',
            'recv-window', 'disable-mtu-discovery', 'max-datagram-frame-size',
            'udp-over-stream', 'udp-over-stream-version', 'ip', 'fingerprint',
            'certificate', 'private-key', 'ca', 'ca-sha256', 'cert-sha',
            'client-fingerprint', 'ech-opts', 'pqv', 'finalmask',
            'verify-peer-cert-by-name', 'vcn',
        ):
            return 'unsupported_tuic_option'

    if proxy_type in {'vmess', 'vless', 'trojan'} and _has_nonempty(
        proxy, 'certificate', 'private-key', 'ca', 'ech-opts'
    ):
        return 'unsupported_tls_material'

    if proxy_type not in {
        'vmess', 'vless', 'ss', 'socks5', 'trojan', 'hysteria2', 'tuic',
        'anytls', 'wireguard',
    }:
        return 'unsupported_type'

    if proxy_type == 'wireguard':
        if _has_nonempty(
            proxy,
            'allowed-ips', 'persistent-keepalive', 'workers', 'dns',
            'remote-dns-resolve', 'peers', 'refresh-server-ip-interval',
            'amnezia-wg-option',
        ):
            return 'unsupported_wireguard_option'
        if _wireguard_addresses(proxy) is None:
            return 'conflicting_wireguard_address'

    if proxy_type in {'vmess', 'vless', 'trojan', 'anytls'}:
        reality_opts = proxy.get('reality-opts')
        if proxy_type in {'vless', 'trojan'} and reality_opts is not None:
            if not isinstance(reality_opts, dict) or not reality_opts:
                return 'invalid_reality_options'
            if set(reality_opts) - {'public-key', 'short-id', 'spider-x'}:
                return 'unsupported_reality_option'
            if not str(reality_opts.get('public-key') or '').strip():
                return 'missing_reality_public_key'
            if not proxy.get('tls'):
                return 'reality_without_tls'
        # v2rayN's legacy VMess JSON model has no Reality public-key fields.
        # Emitting ``tls`` here would turn a valid Reality node into a
        # different and usually unusable TLS profile.
        if proxy_type == 'vmess' and _has_nonempty(proxy, 'reality-opts'):
            return 'unsupported_vmess_reality'
        if proxy_type == 'vmess' and _has_nonempty(
            proxy,
            'flow', 'packet-addr', 'xudp', 'packet-encoding',
            'global-padding', 'authenticated-length', 'padding',
        ):
            # These Mihomo/Xray controls have no slots in v2rayN's legacy
            # VMess JSON QR schema.  Dropping any of them can make the imported
            # profile behave differently or stop carrying UDP.
            return 'unsupported_vmess_option'
        if proxy_type == 'vless' and _has_nonempty(proxy, 'packet-addr', 'xudp', 'packet-encoding'):
            return 'unsupported_vless_option'
        if proxy_type == 'vmess' and _has_nonempty(proxy, 'ech', 'pqv', 'finalmask'):
            # v2rayN's legacy VMess JSON DTO has no fields for these values.
            return 'unsupported_vmess_tls_extension'
        if network == 'kcp' and proxy_type in {'vless', 'trojan'}:
            return f'unsupported_{proxy_type}_network'
        if network in {'h2', 'http', 'quic'}:
            return 'unsupported_transport'
        if proxy_type == 'trojan' and network == 'tcp' and str(proxy.get('header-type', '') or '').strip().lower() == 'http':
            return 'unsupported_trojan_tcp_disguise'
        grpc_opts = proxy.get('grpc-opts')
        if network == 'grpc' and isinstance(grpc_opts, dict):
            if set(grpc_opts) - {'grpc-service-name', 'mode', 'grpc-mode', 'authority'}:
                return 'unsupported_grpc_options'
            grpc_mode = str(grpc_opts.get('mode') or grpc_opts.get('grpc-mode') or '').strip().lower()
            if grpc_mode not in {'', 'gun'}:
                return 'unsupported_grpc_mode'
            if grpc_opts.get('authority') not in (None, ''):
                return 'unsupported_grpc_authority'
        if network in {'ws', 'httpupgrade'} and isinstance(ws_opts, dict):
            headers = ws_opts.get('headers') or {}
            if not isinstance(headers, dict):
                return 'unsupported_custom_headers'
            if any(str(key).lower() != 'host' for key in headers):
                return 'unsupported_custom_headers'
            if _has_nonempty(ws_opts, 'max-early-data', 'early-data-header-name'):
                # Current v2rayN URI parsing does not read ed/eh for any V2Ray
                # protocol, so exporting them would silently drop the values.
                return 'unsupported_websocket_early_data'
            if http_upgrade:
                if ws_opts.get('v2ray-http-upgrade-fast-open') not in (None, False, 0, '', '0', 'false', 'False'):
                    return 'unsupported_httpupgrade_fast_open'
            elif _has_nonempty(ws_opts, 'v2ray-http-upgrade', 'v2ray-http-upgrade-fast-open'):
                return 'unsupported_websocket_options'
        if network == 'kcp' and proxy_type == 'vmess' and _has_nonempty(proxy, 'mtu'):
            # VMess legacy JSON has no KCP MTU field.
            return 'unsupported_kcp_mtu'
        xhttp_opts = proxy.get('xhttp-opts')
        if network == 'xhttp' and isinstance(xhttp_opts, dict):
            if proxy_type != 'vless':
                return 'unsupported_transport'
            try:
                xhttp_opts_to_extra(xhttp_opts)
            except XHTTPCompatibilityError:
                return 'unsupported_xhttp_options'

    return None


def export_proxy_link(proxy: dict) -> LinkExportResult:
    from services.proxy_filter import ProxyFilter

    if not isinstance(proxy, dict):
        return LinkExportResult('', 'invalid_proxy_object')
    raw_reason = _unsupported_v2ray_reason(proxy)
    if raw_reason:
        return LinkExportResult('', raw_reason)

    normalized_proxy = ProxyFilter.sanitize_proxy(proxy)
    if str(normalized_proxy.get('type', '') or '').strip().lower() == 'anytls':
        # AnyTLS is intrinsically TLS. Mark that invariant locally so the
        # generic Mihomo structural validator does not reject URI TLS fields.
        normalized_proxy['tls'] = True
    reason = _unsupported_v2ray_reason(normalized_proxy)
    if reason:
        return LinkExportResult('', reason)
    structural_reason = ProxyFilter.get_structural_invalid_reason(normalized_proxy)
    if structural_reason == 'unsupported-reality-option':
        reality_opts = normalized_proxy.get('reality-opts')
        if not (
            isinstance(reality_opts, dict)
            and set(reality_opts) <= {'public-key', 'short-id', 'spider-x'}
        ):
            return LinkExportResult('', structural_reason.replace('-', '_'))
    elif structural_reason:
        return LinkExportResult('', structural_reason.replace('-', '_'))
    link = _proxy_to_link(normalized_proxy)
    if link:
        return LinkExportResult(link)
    return LinkExportResult('', 'unsupported_configuration')


def proxy_to_link(proxy: dict) -> str:
    """Convert a proxy to a v2rayN-compatible share link, or return empty."""
    return export_proxy_link(proxy).link


def _proxy_to_link(proxy: dict) -> str:
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

    def q(value) -> str:
        """Quote a query parameter value without leaving reserved separators raw."""
        return quote(str(value), safe='')

    def append_common_tls_params(params: list, *, default_tls: bool = False) -> None:
        reality_opts = proxy.get('reality-opts')
        if isinstance(reality_opts, dict) and reality_opts:
            params.append('security=reality')
            if reality_opts.get('public-key'):
                params.append(f"pbk={q(reality_opts['public-key'])}")
            if reality_opts.get('short-id'):
                params.append(f"sid={q(reality_opts['short-id'])}")
            if reality_opts.get('spider-x'):
                params.append(f"spx={q(reality_opts['spider-x'])}")
        elif proxy.get('tls') or default_tls:
            params.append('security=tls')

        sni = proxy.get('servername') or proxy.get('sni')
        if sni:
            params.append(f"sni={q(sni)}")
        if proxy.get('client-fingerprint'):
            params.append(f"fp={q(proxy['client-fingerprint'])}")
        if proxy.get('alpn'):
            alpn_val = proxy.get('alpn')
            if isinstance(alpn_val, list):
                alpn_val = ','.join(str(v) for v in alpn_val)
            params.append(f"alpn={q(alpn_val)}")
        if proxy.get('skip-cert-verify'):
            params.append("allowInsecure=1")
            params.append("insecure=1")

    def append_transport_params(params: list) -> None:
        network = v2ray_transport_name()
        if not network:
            return

        params.append(f"type={'http' if network == 'h2' else q(network)}")
        if network in ['ws', 'httpupgrade']:
            ws_opts = proxy.get('ws-opts', {})
            if not isinstance(ws_opts, dict):
                raise ValueError('Invalid WebSocket options')
            headers = ws_opts.get('headers') or {}
            if not isinstance(headers, dict):
                raise ValueError('Invalid WebSocket headers')
            if any(str(key).lower() != 'host' for key in headers):
                raise ValueError('WebSocket share link cannot preserve custom headers')
            if ws_opts.get('path'):
                params.append(f"path={q(ws_opts['path'])}")
            host = headers.get('Host') or headers.get('host')
            if host:
                params.append(f"host={q(host)}")
            if ws_opts.get('max-early-data') not in (None, ''):
                params.append(f"ed={q(ws_opts['max-early-data'])}")
            if ws_opts.get('early-data-header-name') not in (None, ''):
                params.append(f"eh={q(ws_opts['early-data-header-name'])}")
        elif network == 'grpc':
            grpc_opts = proxy.get('grpc-opts', {})
            if grpc_opts.get('grpc-service-name'):
                params.append(f"serviceName={q(grpc_opts['grpc-service-name'])}")
            grpc_mode = grpc_opts.get('mode') or grpc_opts.get('grpc-mode')
            if grpc_mode:
                params.append(f"mode={q(grpc_mode)}")
            if grpc_opts.get('authority'):
                params.append(f"authority={q(grpc_opts['authority'])}")
        elif network in ['h2', 'http']:
            http_opts = (
                proxy.get('h2-opts', {})
                if network == 'h2'
                else proxy.get('http-opts') or proxy.get('h2-opts', {})
            )
            if not isinstance(http_opts, dict):
                http_opts = {}
            if http_opts.get('path'):
                params.append(f"path={q(http_opts['path'])}")
            host_val = http_opts.get('host')
            if not host_val:
                host_val = (http_opts.get('headers') or {}).get('Host')
            if isinstance(host_val, list) and host_val:
                host_val = host_val[0]
            if host_val:
                params.append(f"host={q(host_val)}")
        elif network == 'xhttp':
            xhttp_opts = proxy.get('xhttp-opts', {})
            if not isinstance(xhttp_opts, dict):
                xhttp_opts = {}
            xhttp_mode = xhttp_opts.get('mode') or proxy.get('xhttp-mode')
            xhttp_host = xhttp_opts.get('host') or proxy.get('host')
            xhttp_path = xhttp_opts.get('path') or proxy.get('path')
            if xhttp_mode:
                params.append(f"mode={q(xhttp_mode)}")
            if xhttp_host:
                params.append(f"host={q(xhttp_host)}")
            if xhttp_path:
                params.append(f"path={q(xhttp_path)}")
            extra_value = xhttp_opts_to_extra(xhttp_opts)
            if extra_value:
                params.append(
                    f"extra={q(json.dumps(extra_value, ensure_ascii=False, separators=(',', ':')))}"
                )
        elif network == 'kcp':
            if proxy.get('header-type'):
                params.append(f"headerType={q(proxy['header-type'])}")
            if proxy.get('seed') not in (None, ''):
                params.append(f"seed={q(proxy['seed'])}")
            if proxy.get('mtu') not in (None, ''):
                params.append(f"mtu={q(proxy['mtu'])}")
        elif network in ['tcp', 'raw']:
            if proxy.get('header-type'):
                params.append(f"headerType={q(proxy['header-type'])}")
            if proxy.get('host') not in (None, ''):
                params.append(f"host={q(proxy['host'])}")
            if proxy.get('path') not in (None, ''):
                params.append(f"path={q(proxy['path'])}")
        elif network == 'quic' and proxy.get('header-type'):
            params.append(f"headerType={q(proxy['header-type'])}")

    def stringify_list(value) -> str:
        if isinstance(value, list):
            return ','.join(str(v) for v in value)
        return str(value)

    def v2ray_transport_name() -> str:
        network = str(proxy.get('network') or '').strip().lower()
        ws_opts = proxy.get('ws-opts')
        if (
            network == 'httpupgrade'
            or network == 'ws'
            and isinstance(ws_opts, dict)
            and ws_opts.get('v2ray-http-upgrade') is True
        ):
            return 'httpupgrade'
        return network

    try:
        if proxy_type == 'vmess':
            # vmess://base64(json)
            network = v2ray_transport_name() or 'tcp'
            vmess_obj = {
                'v': '2',
                'ps': name,
                'add': server,
                'port': str(port),
                'id': proxy.get('uuid', ''),
                'aid': str(proxy.get('alterId', 0)),
                'scy': proxy.get('cipher', 'auto'),
                'net': network,
                'type': 'none',
            }
            if proxy.get('tls'):
                vmess_obj['tls'] = 'tls'
            sni = proxy.get('servername') or proxy.get('sni')
            if sni:
                vmess_obj['sni'] = sni
            if proxy.get('client-fingerprint'):
                vmess_obj['fp'] = proxy['client-fingerprint']
            if proxy.get('alpn'):
                vmess_obj['alpn'] = stringify_list(proxy['alpn'])
            if proxy.get('skip-cert-verify'):
                vmess_obj['insecure'] = '1'
                vmess_obj['allowInsecure'] = '1'
            if proxy.get('verify-peer-cert-by-name'):
                vmess_obj['vcn'] = proxy['verify-peer-cert-by-name']
            certificate_pin = _certificate_pin(proxy, 'fingerprint', 'cert-sha')
            if certificate_pin:
                vmess_obj['pcs'] = certificate_pin

            if network in ['ws', 'httpupgrade']:
                ws_opts = proxy.get('ws-opts', {})
                if not isinstance(ws_opts, dict):
                    return ''
                headers = ws_opts.get('headers') or {}
                if not isinstance(headers, dict):
                    return ''
                if any(str(key).lower() != 'host' for key in headers):
                    return ''
                vmess_obj['path'] = ws_opts.get('path', '/')
                host = headers.get('Host') or headers.get('host')
                if host:
                    vmess_obj['host'] = host
            elif network == 'grpc':
                grpc_opts = proxy.get('grpc-opts', {})
                if not isinstance(grpc_opts, dict):
                    return ''
                vmess_obj['path'] = grpc_opts.get('grpc-service-name', '')
                if grpc_opts.get('authority'):
                    vmess_obj['host'] = grpc_opts['authority']
                grpc_mode = grpc_opts.get('mode') or grpc_opts.get('grpc-mode')
                if grpc_mode:
                    vmess_obj['type'] = grpc_mode
            elif network in ['h2', 'http']:
                http_opts = (
                    proxy.get('h2-opts', {})
                    if network == 'h2'
                    else proxy.get('http-opts') or proxy.get('h2-opts', {})
                )
                if not isinstance(http_opts, dict):
                    return ''
                path_value = http_opts.get('path')
                if isinstance(path_value, list):
                    path_value = path_value[0] if len(path_value) == 1 else None
                host_value = http_opts.get('host') or (http_opts.get('headers') or {}).get('Host')
                if isinstance(host_value, list):
                    host_value = host_value[0] if len(host_value) == 1 else None
                if path_value:
                    vmess_obj['path'] = path_value
                if host_value:
                    vmess_obj['host'] = host_value
            elif network == 'xhttp':
                xhttp_opts = proxy.get('xhttp-opts', {})
                if not isinstance(xhttp_opts, dict):
                    return ''
                if xhttp_opts.get('mode'):
                    vmess_obj['type'] = xhttp_opts['mode']
                if xhttp_opts.get('path'):
                    vmess_obj['path'] = xhttp_opts['path']
                if xhttp_opts.get('host'):
                    vmess_obj['host'] = xhttp_opts['host']
                # Current v2rayN's legacy VMess QR model has no XHTTP ``extra``
                # field. Capability validation rejects non-basic options before
                # this branch is reached.
            elif network == 'kcp':
                if proxy.get('header-type'):
                    vmess_obj['type'] = proxy['header-type']
                if proxy.get('seed') not in (None, ''):
                    vmess_obj['path'] = proxy['seed']
            elif network == 'quic':
                if proxy.get('header-type'):
                    vmess_obj['type'] = proxy['header-type']
            elif network in ['tcp', 'raw']:
                if proxy.get('header-type'):
                    vmess_obj['type'] = proxy['header-type']
                if proxy.get('host') not in (None, ''):
                    vmess_obj['host'] = proxy['host']
                if proxy.get('path') not in (None, ''):
                    vmess_obj['path'] = proxy['path']
            else:
                return ''

            return 'vmess://' + base64.b64encode(json.dumps(vmess_obj).encode()).decode()

        elif proxy_type == 'vless':
            # vless://uuid@server:port?params#name
            params = []
            network = v2ray_transport_name()
            if network:
                if network == 'h2':
                    params.append("type=http")
                else:
                    params.append(f"type={q(network)}")
            if proxy.get('encryption') is not None:
                params.append(f"encryption={q(proxy.get('encryption'))}")
            if proxy.get('tls'):
                if proxy.get('reality-opts'):
                    params.append('security=reality')
                    if proxy['reality-opts'].get('public-key'):
                        params.append(f"pbk={q(proxy['reality-opts']['public-key'])}")
                    if proxy['reality-opts'].get('short-id'):
                        params.append(f"sid={q(proxy['reality-opts']['short-id'])}")
                    if proxy['reality-opts'].get('spider-x'):
                        params.append(f"spx={q(proxy['reality-opts']['spider-x'])}")
                else:
                    params.append('security=tls')
            sni = proxy.get('servername') or proxy.get('sni')
            if sni:
                params.append(f"sni={q(sni)}")
            if proxy.get('client-fingerprint'):
                params.append(f"fp={q(proxy['client-fingerprint'])}")
            if proxy.get('alpn'):
                alpn_val = proxy.get('alpn')
                if isinstance(alpn_val, list):
                    alpn_val = ','.join(alpn_val)
                params.append(f"alpn={q(alpn_val)}")
            if proxy.get('skip-cert-verify'):
                params.append("allowInsecure=1")
                params.append("insecure=1")
            if proxy.get('flow'):
                params.append(f"flow={q(proxy['flow'])}")
            if proxy.get('ech'):
                params.append(f"ech={q(proxy['ech'])}")
            if proxy.get('pqv'):
                params.append(f"pqv={q(proxy['pqv'])}")
            certificate_pin = _certificate_pin(proxy, 'fingerprint', 'cert-sha')
            if certificate_pin:
                params.append(f"pcs={q(certificate_pin)}")
            if proxy.get('verify-peer-cert-by-name'):
                params.append(f"vcn={q(proxy['verify-peer-cert-by-name'])}")
            if proxy.get('finalmask'):
                params.append(f"fm={q(proxy['finalmask'])}")
            if network in ['ws', 'httpupgrade']:
                ws_opts = proxy.get('ws-opts', {})
                if not isinstance(ws_opts, dict):
                    return ''
                headers = ws_opts.get('headers') or {}
                if not isinstance(headers, dict):
                    return ''
                if any(str(key).lower() != 'host' for key in headers):
                    return ''
                if ws_opts.get('path'):
                    params.append(f"path={q(ws_opts['path'])}")
                host = headers.get('Host') or headers.get('host')
                if host:
                    params.append(f"host={q(host)}")
                if ws_opts.get('max-early-data') not in (None, ''):
                    params.append(f"ed={q(ws_opts['max-early-data'])}")
                if ws_opts.get('early-data-header-name') not in (None, ''):
                    params.append(f"eh={q(ws_opts['early-data-header-name'])}")
            elif network == 'grpc':
                grpc_opts = proxy.get('grpc-opts', {})
                if grpc_opts.get('grpc-service-name'):
                    params.append(f"serviceName={q(grpc_opts['grpc-service-name'])}")
                grpc_mode = grpc_opts.get('mode') or grpc_opts.get('grpc-mode')
                if grpc_mode:
                    params.append(f"mode={q(grpc_mode)}")
                if grpc_opts.get('authority'):
                    params.append(f"authority={q(grpc_opts['authority'])}")
            elif network in ['h2', 'http']:
                http_opts = (
                    proxy.get('h2-opts', {})
                    if network == 'h2'
                    else proxy.get('http-opts') or proxy.get('h2-opts', {})
                )
                if not isinstance(http_opts, dict):
                    http_opts = {}
                if http_opts.get('path'):
                    params.append(f"path={q(http_opts['path'])}")
                host_val = http_opts.get('host')
                if not host_val:
                    host_val = (http_opts.get('headers') or {}).get('Host')
                if isinstance(host_val, list) and host_val:
                    host_val = host_val[0]
                if host_val:
                    params.append(f"host={q(host_val)}")
            elif network == 'xhttp':
                xhttp_opts = proxy.get('xhttp-opts', {})
                if not isinstance(xhttp_opts, dict):
                    xhttp_opts = {}
                xhttp_mode = xhttp_opts.get('mode') or proxy.get('xhttp-mode')
                xhttp_host = xhttp_opts.get('host') or proxy.get('host')
                xhttp_path = xhttp_opts.get('path') or proxy.get('path')
                if xhttp_mode:
                    params.append(f"mode={q(xhttp_mode)}")
                if xhttp_host:
                    params.append(f"host={q(xhttp_host)}")
                if xhttp_path:
                    params.append(f"path={q(xhttp_path)}")
                extra_value = xhttp_opts_to_extra(xhttp_opts)
                if extra_value:
                    params.append(
                        f"extra={q(json.dumps(extra_value, ensure_ascii=False, separators=(',', ':')))}"
                    )
            elif network == 'kcp':
                if proxy.get('header-type'):
                    params.append(f"headerType={q(proxy['header-type'])}")
                if proxy.get('seed') not in (None, ''):
                    params.append(f"seed={q(proxy['seed'])}")
                if proxy.get('mtu') not in (None, ''):
                    params.append(f"mtu={q(proxy['mtu'])}")
            elif network in ['tcp', 'raw']:
                if proxy.get('header-type'):
                    params.append(f"headerType={q(proxy['header-type'])}")
                if proxy.get('host') not in (None, ''):
                    params.append(f"host={q(proxy['host'])}")
                if proxy.get('path') not in (None, ''):
                    params.append(f"path={q(proxy['path'])}")
            elif network == 'quic' and proxy.get('header-type'):
                params.append(f"headerType={q(proxy['header-type'])}")
            query = '&'.join(params) if params else ''
            return f"vless://{proxy.get('uuid', '')}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

        elif proxy_type == 'ss':
            # ss://base64(method:password)@server:port?plugin=...#name
            method = proxy.get('cipher', '')
            password = proxy.get('password', '')
            userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
            params = []
            plugin = proxy.get('plugin')
            plugin_opts = proxy.get('plugin-opts')
            if plugin:
                if not isinstance(plugin_opts, dict):
                    return ''
                if plugin in ['obfs', 'obfs-local', 'simple-obfs']:
                    mode = plugin_opts.get('mode')
                    host = plugin_opts.get('host')
                    if not mode:
                        return ''
                    plugin_parts = ['obfs-local', f"obfs={mode}"]
                    if host:
                        plugin_parts.append(f"obfs-host={host}")
                elif plugin == 'v2ray-plugin':
                    plugin_parts = ['v2ray-plugin']
                    mode = plugin_opts.get('mode') or 'websocket'
                    plugin_parts.append(f"mode={mode}")
                    if plugin_opts.get('host'):
                        plugin_parts.append(f"host={plugin_opts['host']}")
                    if plugin_opts.get('path'):
                        escaped_path = str(plugin_opts['path']).replace('\\', '\\\\').replace('=', '\\=').replace(',', '\\,')
                        plugin_parts.append(f"path={escaped_path}")
                    if plugin_opts.get('tls'):
                        plugin_parts.append('tls')
                    if plugin_opts.get('mux') is not None:
                        plugin_parts.append(f"mux={plugin_opts['mux']}")
                else:
                    plugin_parts = [str(plugin)]
                    for key, value in plugin_opts.items():
                        if isinstance(value, bool):
                            if value:
                                plugin_parts.append(str(key))
                        elif value not in (None, ''):
                            plugin_parts.append(f"{key}={value}")
                params.append(f"plugin={q(';'.join(plugin_parts))}")
            query = '&'.join(params)
            return f"ss://{userinfo}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

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
            append_common_tls_params(params, default_tls=True)
            append_transport_params(params)
            if proxy.get('flow'):
                params.append(f"flow={q(proxy['flow'])}")
            if proxy.get('ech'):
                params.append(f"ech={q(proxy['ech'])}")
            if proxy.get('pqv'):
                params.append(f"pqv={q(proxy['pqv'])}")
            certificate_pin = _certificate_pin(proxy, 'fingerprint', 'cert-sha')
            if certificate_pin:
                params.append(f"pcs={q(certificate_pin)}")
            if proxy.get('verify-peer-cert-by-name'):
                params.append(f"vcn={q(proxy['verify-peer-cert-by-name'])}")
            if proxy.get('finalmask'):
                params.append(f"fm={q(proxy['finalmask'])}")
            query = '&'.join(params) if params else ''
            return f"trojan://{q(proxy.get('password', ''))}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

        elif proxy_type == 'hysteria2':
            # hysteria2://password@server:port?params#name
            params = []
            if proxy.get('tls'):
                params.append('security=tls')
            sni = proxy.get('sni') or proxy.get('servername')
            if sni:
                params.append(f"sni={q(sni)}")
            if proxy.get('alpn'):
                params.append(f"alpn={q(stringify_list(proxy['alpn']))}")
            if proxy.get('skip-cert-verify'):
                params.append('insecure=1')
                params.append('allowInsecure=1')
            certificate_sha256 = _certificate_pin(proxy, 'fingerprint', 'ca-sha256')
            if certificate_sha256:
                params.append(f"pinSHA256={q(certificate_sha256)}")
            if proxy.get('obfs'):
                params.append(f"obfs={q(proxy['obfs'])}")
                if proxy.get('obfs-password'):
                    params.append(f"obfs-password={q(proxy['obfs-password'])}")
                if str(proxy.get('obfs')).strip().lower() == 'gecko':
                    min_size = proxy.get('obfs-min-packet-size', proxy.get('minPacketSize'))
                    max_size = proxy.get('obfs-max-packet-size', proxy.get('maxPacketSize'))
                    if min_size in (None, ''):
                        min_size = 512
                    if max_size in (None, ''):
                        max_size = 1200
                    params.append(f"minPacketSize={q(min_size)}")
                    params.append(f"maxPacketSize={q(max_size)}")
            ports = proxy.get('ports') or proxy.get('mport')
            if ports:
                params.append(f"mport={q(str(ports).replace(':', '-'))}")
            query = '&'.join(params) if params else ''
            return f"hysteria2://{q(proxy.get('password', ''))}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

        elif proxy_type == 'tuic':
            # tuic://uuid:password@server:port?params#name
            params = []
            if proxy.get('sni'):
                params.append(f"sni={q(proxy['sni'])}")
            if proxy.get('alpn'):
                params.append(f"alpn={q(stringify_list(proxy['alpn']))}")
            if proxy.get('skip-cert-verify'):
                params.append('allow_insecure=1')
                params.append('insecure=1')
            if proxy.get('congestion-controller'):
                params.append(f"congestion_control={q(proxy['congestion-controller'])}")
            if proxy.get('udp-relay-mode'):
                params.append(f"udp_relay_mode={q(proxy['udp-relay-mode'])}")
            query = '&'.join(params) if params else ''
            return f"tuic://{q(proxy.get('uuid', ''))}:{q(proxy.get('password', ''))}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

        elif proxy_type == 'hysteria':
            # hysteria://server:port?params#name
            params = []
            if proxy.get('auth-str'):
                params.append(f"auth={q(proxy['auth-str'])}")
            if proxy.get('sni'):
                params.append(f"peer={q(proxy['sni'])}")
            if proxy.get('up'):
                params.append(f"upmbps={q(proxy['up'])}")
            if proxy.get('down'):
                params.append(f"downmbps={q(proxy['down'])}")
            if proxy.get('alpn'):
                params.append(f"alpn={q(stringify_list(proxy['alpn']))}")
            if proxy.get('obfs'):
                params.append(f"obfs={q(proxy['obfs'])}")
            if proxy.get('skip-cert-verify'):
                params.append('insecure=1')
            query = '&'.join(params) if params else ''
            return f"hysteria://{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

        elif proxy_type == 'socks5':
            # v2rayN's canonical format is socks://Base64(username:password)@host:port.
            userinfo = base64.urlsafe_b64encode(
                f"{proxy.get('username', '')}:{proxy.get('password', '')}".encode()
            ).decode().rstrip('=')
            return f"socks://{userinfo}@{server_uri}:{port}#{quote(name)}"

        elif proxy_type == 'http':
            return ''

        elif proxy_type == 'anytls':
            # anytls://password@server:port?params#name
            params = []
            append_common_tls_params(params, default_tls=True)
            append_transport_params(params)
            ech_config = proxy.get('ech')
            if not ech_config and isinstance(proxy.get('ech-opts'), dict):
                ech_config = proxy['ech-opts'].get('config')
            if ech_config:
                params.append(f"ech={q(ech_config)}")
            query = '&'.join(params) if params else ''
            password = quote(str(proxy.get('password', '')), safe='')
            return f"anytls://{password}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

        elif proxy_type == 'wireguard':
            # wireguard://private-key@server:port?params#name
            params = []
            if proxy.get('public-key'):
                params.append(f"publickey={q(proxy['public-key'])}")
            preshared_key = proxy.get('pre-shared-key') or proxy.get('preshared-key')
            if preshared_key:
                params.append(f"presharedkey={q(preshared_key)}")
            if proxy.get('reserved'):
                params.append(f"reserved={q(stringify_list(proxy['reserved']))}")
            addresses = _wireguard_addresses(proxy) or []
            if addresses:
                params.append(f"address={q(','.join(addresses))}")
            if proxy.get('mtu') is not None:
                params.append(f"mtu={q(proxy['mtu'])}")
            query = '&'.join(params) if params else ''
            private_key = quote(str(proxy.get('private-key', '')), safe='')
            return f"wireguard://{private_key}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"

        else:
            # Unsupported type, return empty
            return ''
    except Exception:
        return ''
