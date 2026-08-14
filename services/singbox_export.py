"""Convert generated Clash proxy data to a portable sing-box configuration."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from services.node_metadata import strip_node_metadata


class SingboxExportError(ValueError):
    """Raised when a proxy cannot be represented by sing-box."""


@dataclass(frozen=True)
class SingboxSkippedNode:
    """Describe a visible adjustment made while exporting to sing-box."""

    name: str
    reason: str
    kind: str = "node"


def _diagnostic_name(value: object, fallback: str = "unnamed") -> str:
    """Return a bounded display label without copying URI-like credentials."""

    text = str(value or fallback).replace("\r", " ").replace("\n", " ").strip()
    if any(marker in text.lower() for marker in ("://", "@", "token=", "password=")):
        return fallback
    return text[:160] or fallback


def _as_int(value: object, fallback: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _as_mbps(value: object) -> int | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)

    text = str(value).strip()
    try:
        return int(float(text))
    except ValueError:
        pass

    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([KMGT]?)([Bb])ps", text, re.IGNORECASE)
    if not match:
        return None
    number = float(match.group(1))
    unit = match.group(2).upper()
    is_bytes = match.group(3) == "B"
    scale = {"": 1e-6, "K": 1e-3, "M": 1, "G": 1e3, "T": 1e6}[unit]
    if is_bytes:
        number *= 8
    return int(number * scale)


def _has_meaningful_value(value: object) -> bool:
    return value not in (None, "", False, 0, [], {})


def _sip003_escape(value: object) -> str:
    """Escape one SIP003 plugin option value."""

    return str(value).replace("\\", "\\\\").replace(";", "\\;").replace("=", "\\=")


def _singbox_server_ports(value: object) -> list[str]:
    """Convert Mihomo's comma/slash port ranges to sing-box ranges."""

    raw_values = value if isinstance(value, (list, tuple)) else [value]
    normalized: list[str] = []
    for raw_value in raw_values:
        for segment in re.split(r"[,/]", str(raw_value)):
            segment = segment.strip()
            if not segment:
                continue
            match = re.fullmatch(r"(\d+)(?:\s*[:-]\s*(\d+))?", segment)
            if not match:
                raise SingboxExportError("invalid Hysteria server port range")
            start = int(match.group(1))
            end = int(match.group(2) or start)
            if not 1 <= start <= end <= 65535:
                raise SingboxExportError("invalid Hysteria server port range")
            # sing-box requires every server_ports item to contain a colon,
            # including a range that represents a single port.
            normalized.append(f"{start}:{end}")
    if not normalized:
        raise SingboxExportError("invalid Hysteria server port range")
    return normalized


def _singbox_hop_interval(value: object, protocol: str) -> str:
    """Convert Mihomo's integer-second interval without changing range semantics."""

    if isinstance(value, bool):
        raise SingboxExportError(f"invalid {protocol} hop interval")
    text = str(value).strip().lower()
    match = re.fullmatch(r"(\d+)s?", text)
    if not match or int(match.group(1)) < 1:
        # Mihomo accepts an interval range for Hysteria2, while sing-box only
        # accepts one duration. Choosing either endpoint would change behavior.
        raise SingboxExportError(f"unsupported {protocol} hop interval")
    return f"{int(match.group(1))}s"


def _http_headers(value: object, field_name: str) -> dict:
    if not isinstance(value, dict):
        raise SingboxExportError(f"invalid {field_name}")
    return {
        str(key): ([str(item) for item in item_value] if isinstance(item_value, list) else str(item_value))
        for key, item_value in value.items()
    }


def _tls_config(proxy: dict, *, force_enabled: bool = False) -> dict | None:
    certificate = proxy.get("certificate")
    private_key = proxy.get("private-key")
    has_certificate = certificate not in (None, "", [], {})
    has_private_key = private_key not in (None, "", [], {})
    if has_certificate != has_private_key:
        raise SingboxExportError(
            "client certificate and private key must be provided together"
        )
    if not force_enabled and not proxy.get("tls") and not proxy.get("reality-opts"):
        return None

    tls = {"enabled": True}
    server_name = proxy.get("servername") or proxy.get("sni")
    if server_name:
        tls["server_name"] = server_name
    if proxy.get("skip-cert-verify"):
        tls["insecure"] = True
    if proxy.get("disable-sni"):
        tls["disable_sni"] = True
    if proxy.get("alpn"):
        tls["alpn"] = proxy["alpn"] if isinstance(proxy["alpn"], list) else [proxy["alpn"]]
    if has_certificate:
        certificate_values = certificate if isinstance(certificate, list) else [certificate]
        private_key_values = private_key if isinstance(private_key, list) else [private_key]
        if not all("-----BEGIN" in str(value) for value in certificate_values + private_key_values):
            raise SingboxExportError(
                "client certificate paths cannot be embedded in a portable sing-box export"
            )
        tls["client_certificate"] = certificate_values
        tls["client_key"] = private_key_values
    # Mihomo's ``fingerprint`` and Hysteria2's ``pinSHA256`` hash the full
    # DER certificate and use hexadecimal text. sing-box 1.13's
    # ``certificate_public_key_sha256`` instead hashes SubjectPublicKeyInfo
    # and requires base64. These values cannot be converted without the
    # certificate itself, so the caller rejects pinned nodes rather than
    # silently weakening or changing certificate verification.
    fingerprint = proxy.get("client-fingerprint")
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}

    ech = proxy.get("ech-opts")
    if ech not in (None, "", {}, []):
        if not isinstance(ech, dict):
            raise SingboxExportError("invalid ECH options")
        ech_config = {"enabled": bool(ech.get("enable", True))}
        if ech.get("config"):
            ech_config["config"] = (
                ech["config"] if isinstance(ech["config"], list) else [ech["config"]]
            )
        if ech.get("query-server-name"):
            ech_config["query_server_name"] = ech["query-server-name"]
        tls["ech"] = ech_config

    reality = proxy.get("reality-opts")
    if isinstance(reality, dict) and reality:
        if reality.get("spider-x"):
            raise SingboxExportError("REALITY spider-x is unsupported by sing-box")
        if reality.get("support-x25519mlkem768"):
            raise SingboxExportError("REALITY X25519MLKEM option is unsupported by sing-box")
        reality_config = {"enabled": True}
        if reality.get("public-key"):
            reality_config["public_key"] = reality["public-key"]
        if reality.get("short-id"):
            reality_config["short_id"] = reality["short-id"]
        tls["reality"] = reality_config
    return tls


def _requires_tls(proxy: dict, proxy_type: str) -> bool:
    """Return whether a generated outbound must carry a TLS object."""

    if any(
        proxy.get(field) not in (None, "", False, [], {})
        for field in (
            "tls", "reality-opts", "servername", "sni", "skip-cert-verify",
            "alpn", "client-fingerprint", "certificate", "private-key",
            "ech-opts", "disable-sni",
        )
    ):
        return True
    # These protocols use TLS by definition even when a Clash/Mihomo source
    # omits the redundant ``tls: true`` field.  sing-box still requires an
    # explicit TLS object, so treating the missing flag as plaintext would
    # either drop a valid node or change its protocol semantics.
    return proxy_type in {"trojan", "hysteria", "hysteria2", "tuic", "anytls"}


def _first_value(value: object) -> object:
    """Return the first item from a Clash scalar-or-list option."""

    if isinstance(value, list):
        return value[0] if value else None
    return value


def _filter_client_proxy(proxy: dict) -> dict:
    return strip_node_metadata(proxy)


def _transport_config(proxy: dict) -> dict | None:
    """Map Mihomo's V2Ray transport field to a sing-box transport object."""

    network = str(proxy.get("network") or "").strip().lower()
    ws_options = proxy.get("ws-opts")
    if (
        network == "ws"
        and isinstance(ws_options, dict)
        and ws_options.get("v2ray-http-upgrade") is True
    ):
        network = "httpupgrade"
    if not network or network == "tcp":
        return None

    if network in {"ws", "httpupgrade"}:
        options = ws_options or {}
        if not isinstance(options, dict):
            options = {}
        headers = options.get("headers") if isinstance(options, dict) else None
        transport = {"type": "ws" if network == "ws" else network}
        path = _first_value(options.get("path"))
        if path:
            transport["path"] = path
        if network == "httpupgrade" and not headers:
            host = _first_value(options.get("host"))
            if host:
                headers = {"Host": host}
        if network == "httpupgrade" and any(
            _has_meaningful_value(options.get(field))
            for field in (
                "max-early-data", "early-data-header-name",
                "v2ray-http-upgrade-fast-open",
            )
        ):
            raise SingboxExportError("unsupported HTTP Upgrade extension option")
        if isinstance(headers, dict) and headers:
            normalized_headers = {
                str(key): _first_value(value)
                for key, value in headers.items()
                if _first_value(value) is not None
            }
            if normalized_headers:
                transport["headers"] = normalized_headers
        max_early_data = options.get("max-early-data")
        if max_early_data not in (None, ""):
            try:
                transport["max_early_data"] = int(max_early_data)
            except (TypeError, ValueError) as exc:
                raise SingboxExportError("invalid WebSocket max early data") from exc
        early_data_header = options.get("early-data-header-name")
        if early_data_header not in (None, ""):
            transport["early_data_header_name"] = str(early_data_header)
        return transport

    if network in {"raw", "none"}:
        # Mihomo uses raw/none for a plain TCP V2Ray transport. sing-box
        # represents that case by omitting the transport object entirely.
        return None

    if network == "quic":
        return {"type": "quic"}

    if network == "xhttp":
        raise SingboxExportError(
            "unsupported XHTTP transport"
        )

    if network == "grpc":
        options = proxy.get("grpc-opts") or {}
        if not isinstance(options, dict):
            options = {}
        transport = {"type": "grpc"}
        service_name = _first_value(options.get("grpc-service-name"))
        if service_name:
            transport["service_name"] = service_name
        unsupported_runtime_fields = (
            "grpc-user-agent", "ping-interval", "max-connections",
            "min-streams", "max-streams", "authority",
        )
        if any(_has_meaningful_value(options.get(field)) for field in unsupported_runtime_fields):
            raise SingboxExportError(
                "unsupported gRPC runtime option"
            )
        return transport

    if network in {"h2", "http"}:
        options = (
            proxy.get("h2-opts") if network == "h2" else proxy.get("http-opts")
        ) or proxy.get("h2-opts") or {}
        if not isinstance(options, dict):
            options = {}
        transport = {"type": "http"}
        paths = options.get("path")
        if isinstance(paths, list) and len(paths) > 1:
            raise SingboxExportError("multiple HTTP transport paths are unsupported")
        path = _first_value(paths)
        if path:
            transport["path"] = path
        if network == "http" and options.get("method") not in (None, ""):
            transport["method"] = str(options["method"])
        hosts = options.get("host")
        headers = options.get("headers")
        if isinstance(headers, dict):
            # Mihomo accepts HTTP Host through ``http-opts.headers.Host``;
            # sing-box keeps that value in the transport's ``headers`` map.
            # Preserve all explicitly supplied headers, including a list
            # value used by some subscription providers.
            normalized_headers = _http_headers(headers, "HTTP transport headers")
            if normalized_headers:
                transport["headers"] = normalized_headers
                if not hosts and "Host" in normalized_headers:
                    hosts = normalized_headers["Host"]
        if hosts:
            normalized_hosts = hosts if isinstance(hosts, list) else [hosts]
            transport["host"] = [str(host) for host in normalized_hosts if host]
        return transport

    raise SingboxExportError(
        "unsupported transport type"
    )


def _network_filter(proxy: dict) -> list[str] | None:
    """Map a Clash TCP/UDP capability filter to sing-box's network field."""

    value = proxy.get("network")
    if value in (None, "", [], {}):
        return None
    if isinstance(value, str):
        values = [item.strip().lower() for item in value.replace(",", " ").split() if item.strip()]
    elif isinstance(value, (list, tuple, set)):
        values = [str(item).strip().lower() for item in value if str(item).strip()]
    else:
        raise SingboxExportError(
            "invalid network filter"
        )

    normalized: list[str] = []
    for network in values:
        if network not in {"tcp", "udp"}:
            raise SingboxExportError(
                "unsupported network filter value"
            )
        if network not in normalized:
            normalized.append(network)
    return normalized or None


def proxy_to_singbox_outbound(proxy: dict) -> dict:
    """Convert one Clash/Mihomo proxy dictionary to a sing-box outbound."""
    proxy_type = str(proxy.get("type") or "").lower()
    name = str(proxy.get("name") or "unnamed")
    server = proxy.get("server")
    port = _as_int(proxy.get("port"))
    if not server or not port:
        raise SingboxExportError("missing or invalid server/port")

    outbound = {"type": proxy_type, "tag": name, "server": server, "server_port": port}
    if proxy.get("dialer-proxy"):
        outbound["detour"] = proxy["dialer-proxy"]

    unsupported_tls_extensions = {
        "pqv": proxy.get("pqv"),
        "finalmask": proxy.get("finalmask"),
        "verify-peer-cert-by-name": proxy.get("verify-peer-cert-by-name"),
    }
    unsupported_tls_fields = [
        key for key, value in unsupported_tls_extensions.items()
        if value not in (None, "", False, [], {})
    ]
    if unsupported_tls_fields:
        raise SingboxExportError(
            f"unsupported TLS fields: {', '.join(unsupported_tls_fields)}"
        )

    if proxy.get("ech") not in (None, "", [], {}):
        raise SingboxExportError(
            "share-link ECH field cannot be mapped losslessly"
        )

    certificate_pin_fields = (
        "fingerprint", "ca-sha256", "cert-sha", "pinSHA256",
        "_v2rayn-certificate-pin",
    )
    if any(proxy.get(field) not in (None, "", [], {}) for field in certificate_pin_fields):
        raise SingboxExportError(
            "full-certificate SHA-256 pin is unsupported by sing-box"
        )

    if proxy_type == "vmess":
        outbound.update({
            "type": "vmess",
            "uuid": proxy.get("uuid", ""),
            "security": proxy.get("cipher") or "auto",
            "alter_id": _as_int(proxy.get("alterId")),
        })
        for source, target in (
            ("global-padding", "global_padding"),
            ("authenticated-length", "authenticated_length"),
        ):
            value = proxy.get(source)
            if value not in (None, ""):
                if not isinstance(value, bool):
                    raise SingboxExportError(f"invalid VMess {source} option")
                outbound[target] = value
        packet_encoding = str(proxy.get("packet-encoding") or "").strip().lower()
        if proxy.get("xudp") is True:
            packet_encoding = "xudp"
        elif proxy.get("packet-addr") is True and not packet_encoding:
            packet_encoding = "packetaddr"
        if packet_encoding in {"xudp", "packetaddr"}:
            outbound["packet_encoding"] = packet_encoding
        elif packet_encoding not in {"", "none"}:
            raise SingboxExportError("unsupported VMess packet encoding")
    elif proxy_type == "vless":
        outbound["type"] = "vless"
        outbound["uuid"] = proxy.get("uuid", "")
        if proxy.get("flow"):
            outbound["flow"] = proxy["flow"]
        # Mihomo's ``encryption`` is a VLESS security extension field. It must
        # not be copied into sing-box's unrelated UDP ``packet_encoding``
        # field. X25519MLKEM values are currently not representable here.
        encryption = str(proxy.get("encryption") or "").strip().lower()
        if encryption not in {"", "none"}:
            raise SingboxExportError(
                "unsupported VLESS encryption field"
            )
        packet_encoding = str(
            proxy.get("packet-encoding") or proxy.get("packet_encoding") or ""
        ).strip().lower()
        if packet_encoding in {"xudp", "packetaddr"}:
            outbound["packet_encoding"] = packet_encoding
        elif packet_encoding not in {"", "none"}:
            raise SingboxExportError(
                "unsupported VLESS packet encoding"
            )
    elif proxy_type == "trojan":
        outbound["type"] = "trojan"
        outbound["password"] = proxy.get("password", "")
    elif proxy_type in {"ss", "shadowsocks"}:
        outbound.update({
            "type": "shadowsocks",
            "method": proxy.get("cipher", ""),
            "password": proxy.get("password", ""),
        })
        plugin = proxy.get("plugin")
        plugin_options = proxy.get("plugin-opts")
        if plugin:
            if plugin not in {"obfs", "obfs-local", "simple-obfs", "v2ray-plugin"}:
                raise SingboxExportError(
                    "unsupported Shadowsocks plugin type"
                )
            if not isinstance(plugin_options, dict):
                raise SingboxExportError(
                    "invalid Shadowsocks plugin options"
                )
            if plugin in {"obfs", "obfs-local", "simple-obfs"}:
                mode = str(plugin_options.get("mode") or "").lower()
                if mode not in {"http", "tls"}:
                    raise SingboxExportError(
                        "unsupported simple-obfs mode"
                    )
                extra_keys = {
                    key for key, value in plugin_options.items()
                    if key not in {"mode", "host"} and value not in (None, "", False, [], {})
                }
                if extra_keys:
                    raise SingboxExportError(
                        "unsupported simple-obfs options"
                    )
                outbound["plugin"] = "obfs-local"
                parts = [f"obfs={mode}"]
                if plugin_options.get("host"):
                    parts.append(f"obfs-host={_sip003_escape(plugin_options['host'])}")
                outbound["plugin_opts"] = ";".join(parts)
            else:
                mode = str(plugin_options.get("mode") or "websocket").lower()
                if mode != "websocket":
                    raise SingboxExportError(
                        "unsupported v2ray-plugin mode"
                    )
                mux_value = plugin_options.get("mux", True)
                if isinstance(mux_value, str):
                    mux_enabled = mux_value.strip().lower() in {"1", "true", "yes", "on"}
                else:
                    mux_enabled = bool(mux_value)
                supported_keys = {"mode", "host", "path", "tls", "mux"}
                extra_keys = {
                    key for key, value in plugin_options.items()
                    if key not in supported_keys and value not in (None, "", False, [], {})
                }
                if extra_keys:
                    raise SingboxExportError(
                        "unsupported v2ray-plugin options"
                    )
                outbound["plugin"] = "v2ray-plugin"
                parts = ["mode=websocket"]
                if plugin_options.get("host"):
                    parts.append(f"host={_sip003_escape(plugin_options['host'])}")
                if plugin_options.get("path"):
                    parts.append(f"path={_sip003_escape(plugin_options['path'])}")
                if plugin_options.get("tls"):
                    parts.append("tls")
                parts.append(f"mux={1 if mux_enabled else 0}")
                outbound["plugin_opts"] = ";".join(parts)
        if proxy.get("udp-over-tcp") is True:
            version = _as_int(proxy.get("udp-over-tcp-version"), 2)
            if version not in {1, 2}:
                raise SingboxExportError(
                    "unsupported UDP-over-TCP version"
                )
            outbound["udp_over_tcp"] = {"enabled": True, "version": version}
    elif proxy_type in {"socks5", "socks"}:
        outbound["type"] = "socks"
        outbound["version"] = "5"
        if proxy.get("username"):
            outbound["username"] = proxy["username"]
            outbound["password"] = proxy.get("password", "")
    elif proxy_type == "http":
        outbound["type"] = "http"
        if proxy.get("username"):
            outbound["username"] = proxy["username"]
            outbound["password"] = proxy.get("password", "")
    elif proxy_type in {"hysteria", "hysteria2", "tuic", "wireguard", "anytls"}:
        outbound["type"] = proxy_type
        if proxy_type == "hysteria":
            if _has_meaningful_value(proxy.get("auth")):
                raise SingboxExportError("Hysteria auth bytes cannot be mapped losslessly")
            if proxy.get("auth-str"):
                outbound["auth_str"] = proxy["auth-str"]
            ports = proxy.get("ports") or proxy.get("mport")
            if ports not in (None, "", []):
                outbound["server_ports"] = _singbox_server_ports(ports)
                outbound.pop("server_port", None)
            if proxy.get("hop-interval") not in (None, ""):
                outbound["hop_interval"] = _singbox_hop_interval(
                    proxy["hop-interval"], "Hysteria"
                )
            for source, target in (("up", "up_mbps"), ("down", "down_mbps")):
                if proxy.get(source) is not None:
                    mbps = _as_mbps(proxy[source])
                    if mbps is None:
                        raise SingboxExportError(f"unsupported Hysteria {source} rate")
                    outbound[target] = mbps
            if proxy.get("obfs") not in (None, ""):
                outbound["obfs"] = str(proxy["obfs"])
            for source, target in (
                ("recv-window-conn", "recv_window_conn"),
                ("recv-window", "recv_window"),
                ("disable-mtu-discovery", "disable_mtu_discovery"),
            ):
                if proxy.get(source) not in (None, ""):
                    outbound[target] = proxy[source]
            for field in ("protocol", "obfs-protocol", "fast-open"):
                if _has_meaningful_value(proxy.get(field)):
                    raise SingboxExportError(f"unsupported Hysteria {field} option")
        elif proxy_type == "hysteria2":
            outbound["password"] = proxy.get("password", "")
            ports = proxy.get("ports") or proxy.get("mport")
            if ports:
                outbound["server_ports"] = _singbox_server_ports(ports)
                outbound.pop("server_port", None)
            if proxy.get("hop-interval") not in (None, ""):
                outbound["hop_interval"] = _singbox_hop_interval(
                    proxy["hop-interval"], "Hysteria2"
                )
            for source, target in (("up", "up_mbps"), ("down", "down_mbps")):
                if proxy.get(source) not in (None, ""):
                    mbps = _as_mbps(proxy[source])
                    if mbps is None:
                        raise SingboxExportError(
                            f"unsupported Hysteria2 {source} rate"
                        )
                    outbound[target] = mbps
            unsupported_hysteria2_tuning = (
                "cwnd", "bbr-profile", "udp-mtu",
                "initial-stream-receive-window", "max-stream-receive-window",
                "initial-connection-receive-window", "max-connection-receive-window",
            )
            if any(
                proxy.get(field) not in (None, "", 0, False, [], {})
                for field in unsupported_hysteria2_tuning
            ):
                raise SingboxExportError(
                    "Hysteria2 tuning fields are unsupported by sing-box"
                )
            if proxy.get("obfs"):
                obfs_type = str(proxy["obfs"]).lower()
                if obfs_type not in {"salamander", "gecko"}:
                    raise SingboxExportError(
                        "unsupported Hysteria2 obfuscation type"
                    )
                if not proxy.get("obfs-password"):
                    raise SingboxExportError(
                        "missing Hysteria2 obfuscation password"
                    )
                outbound["obfs"] = {
                    "type": obfs_type,
                    "password": proxy["obfs-password"],
                }
                if obfs_type == "gecko":
                    outbound["obfs"]["min_packet_size"] = _as_int(
                        proxy.get("obfs-min-packet-size", proxy.get("minPacketSize", 512)), 512
                    )
                    outbound["obfs"]["max_packet_size"] = _as_int(
                        proxy.get("obfs-max-packet-size", proxy.get("maxPacketSize", 1200)), 1200
                    )
        elif proxy_type == "tuic":
            outbound.update({
                "uuid": proxy.get("uuid", ""),
                "password": proxy.get("password", ""),
            })
            if proxy.get("token") not in (None, ""):
                raise SingboxExportError(
                    "legacy TUIC token authentication is unsupported by sing-box"
                )
            if proxy.get("ip") not in (None, ""):
                raise SingboxExportError("TUIC IP override is unsupported by sing-box")
            if proxy.get("congestion-controller"):
                congestion_control = str(proxy["congestion-controller"]).strip().lower()
                if congestion_control not in {"cubic", "new_reno", "bbr"}:
                    raise SingboxExportError(
                        "unsupported TUIC congestion controller"
                    )
                outbound["congestion_control"] = congestion_control
            if proxy.get("udp-relay-mode"):
                udp_relay_mode = str(proxy["udp-relay-mode"]).strip().lower()
                if udp_relay_mode not in {"native", "quic"}:
                    raise SingboxExportError(
                        "unsupported TUIC UDP relay mode"
                    )
                outbound["udp_relay_mode"] = udp_relay_mode
            if proxy.get("udp-over-stream") is True:
                if proxy.get("udp-relay-mode") not in (None, ""):
                    raise SingboxExportError(
                        "TUIC UDP-over-stream conflicts with UDP relay mode"
                    )
                outbound["udp_over_stream"] = True
            if proxy.get("reduce-rtt") is True:
                outbound["zero_rtt_handshake"] = True
            if proxy.get("heartbeat-interval") not in (None, ""):
                heartbeat = str(proxy["heartbeat-interval"]).strip()
                outbound["heartbeat"] = (
                    heartbeat if any(ch.isalpha() for ch in heartbeat) else f"{heartbeat}ms"
                )
            unsupported_tuic_tuning = (
                "request-timeout", "max-udp-relay-packet-size", "fast-open",
                "max-open-streams", "cwnd", "bbr-profile", "recv-window-conn",
                "recv-window", "disable-mtu-discovery", "max-datagram-frame-size",
                "udp-over-stream-version",
            )
            if any(
                proxy.get(field) not in (None, "", 0, False, [], {})
                for field in unsupported_tuic_tuning
            ):
                raise SingboxExportError(
                    "TUIC tuning fields are unsupported by sing-box"
                )
        elif proxy_type == "wireguard":
            # sing-box 1.13 removed the legacy WireGuard outbound.  Its
            # replacement is an endpoint, which has different routing
            # semantics and cannot be substituted here without changing the
            # exported profile's behavior.  Omit it with a diagnostic instead
            # of emitting a config that current sing-box rejects.
            raise SingboxExportError(
                "WireGuard outbound was removed from sing-box 1.13; endpoint conversion is not lossless"
            )
        elif proxy_type == "anytls":
            outbound["password"] = proxy.get("password", "")
            unsupported_anytls_extensions = (
                "disable-reuse", "shadow-tls", "shadowtls", "restls", "jls",
            )
            if any(
                proxy.get(field) not in (None, "", False, 0, [], {})
                for field in unsupported_anytls_extensions
            ):
                raise SingboxExportError(
                    "AnyTLS extension fields are unsupported by sing-box"
                )
            for source, target in (
                ("idle-session-check-interval", "idle_session_check_interval"),
                ("idle-session-timeout", "idle_session_timeout"),
            ):
                if proxy.get(source) not in (None, ""):
                    value = str(proxy[source]).strip()
                    outbound[target] = value if any(ch.isalpha() for ch in value) else f"{value}s"
            if proxy.get("min-idle-session") not in (None, ""):
                outbound["min_idle_session"] = _as_int(proxy["min-idle-session"])
            # Mihomo exposes ``udp-over-tcp`` for AnyTLS because the protocol
            # carries UDP over its TLS session. sing-box's AnyTLS outbound
            # supports UDP natively and has no separate switch, so true maps
            # to the protocol's built-in behavior. Reject only malformed data.
            if proxy.get("udp-over-tcp") not in (None, False, True):
                raise SingboxExportError(
                    "invalid AnyTLS UDP-over-TCP value"
                )
    else:
        raise SingboxExportError("unsupported proxy type")

    tls_capable_types = {
        "vmess", "vless", "trojan", "http",
        "hysteria", "hysteria2", "tuic", "anytls",
    }
    has_tls_options = any(
        proxy.get(field)
        for field in (
            "tls", "reality-opts", "servername", "sni",
            "skip-cert-verify", "alpn", "client-fingerprint",
            "fingerprint", "ca-sha256", "cert-sha", "pinSHA256",
            "certificate", "private-key", "ech-opts", "disable-sni",
        )
    )
    if proxy_type not in tls_capable_types and has_tls_options:
        raise SingboxExportError(
            "TLS options are unsupported by this sing-box outbound type"
        )

    # VLESS/VMess/Trojan transport options commonly imply TLS even when the
    # source adapter omitted the boolean tls flag. Preserve that intent for
    # sing-box instead of emitting a plaintext transport accidentally.
    tls = None
    if proxy_type in tls_capable_types:
        tls = _tls_config(
            proxy,
            force_enabled=_requires_tls(proxy, proxy_type),
        )
    if proxy_type in {"vless", "vmess", "trojan", "anytls"} and not tls:
        # A few providers publish plaintext variants. sing-box accepts these
        # for VLESS/VMess, but Trojan and AnyTLS are TLS-only.
        if proxy_type in {"trojan", "anytls"}:
            raise SingboxExportError(
                "TLS configuration is required by this protocol"
            )
    if proxy_type in {"hysteria", "hysteria2", "tuic"} and not tls:
        raise SingboxExportError(
            "TLS configuration is required by this protocol"
        )
    if tls:
        outbound["tls"] = tls
    transport_protocols = {"vmess", "vless", "trojan"}
    network_filter_protocols = {
        "ss", "shadowsocks", "socks5", "socks", "hysteria", "hysteria2", "tuic"
    }
    if proxy_type in transport_protocols:
        transport = _transport_config(proxy)
        if transport:
            outbound["transport"] = transport
    elif proxy_type in network_filter_protocols:
        network_filter = _network_filter(proxy)
        if network_filter:
            outbound["network"] = network_filter
    elif proxy.get("network") not in (None, "", [], {}):
        raise SingboxExportError(
            "network option is unsupported by this sing-box outbound type"
        )
    return outbound


def _normalize_group_member(
    member: object,
    *,
    node_tags: set[str],
    source_tag_map: dict[str, str],
    group_tag_map: dict[str, str],
    direct_tag: str,
    block_tag: str,
) -> str:
    """Map Clash group references to the final sing-box outbound tags."""

    raw_member = str(member)
    if raw_member == "DIRECT":
        return direct_tag
    if raw_member in {"REJECT", "BLOCK"}:
        return block_tag
    if raw_member in source_tag_map:
        return source_tag_map[raw_member]
    if raw_member in node_tags:
        return raw_member
    return group_tag_map.get(raw_member, raw_member)


def _group_outbound(
    group: dict,
    available_tags: set[str],
    *,
    node_tags: set[str],
    source_tag_map: dict[str, str],
    group_tag_map: dict[str, str],
    direct_tag: str,
    block_tag: str,
) -> dict | None:
    name = str(group.get("name") or "").strip()
    if not name:
        return None
    output_tag = group_tag_map.get(name, name)
    members = [
        _normalize_group_member(
            member,
            node_tags=node_tags,
            source_tag_map=source_tag_map,
            group_tag_map=group_tag_map,
            direct_tag=direct_tag,
            block_tag=block_tag,
        )
        for member in group.get("proxies", []) or []
        if _normalize_group_member(
            member,
            node_tags=node_tags,
            source_tag_map=source_tag_map,
            group_tag_map=group_tag_map,
            direct_tag=direct_tag,
            block_tag=block_tag,
        ) in available_tags
        and _normalize_group_member(
            member,
            node_tags=node_tags,
            source_tag_map=source_tag_map,
            group_tag_map=group_tag_map,
            direct_tag=direct_tag,
            block_tag=block_tag,
        ) != output_tag
    ]
    if not members:
        return None
    group_type = str(group.get("type") or "select").lower()
    if group_type == "url-test":
        outbound = {
            "type": "urltest",
            "tag": output_tag,
            "outbounds": members,
            "url": group.get("url") or "https://www.gstatic.com/generate_204",
            "interval": f"{int(group.get('interval') or 300)}s",
        }
        if group.get("tolerance") is not None:
            outbound["tolerance"] = int(group["tolerance"])
        return outbound

    # fallback/load-balance have no sing-box equivalent. The caller records
    # this visible semantic approximation before they are emitted as selectors.
    return {"type": "selector", "tag": output_tag, "outbounds": members}


def _unique_tag(base: str, used_tags: set[str]) -> str:
    """Return a stable tag that does not collide with a node or group tag."""

    if base not in used_tags:
        return base
    suffix = " (sing-box)"
    candidate = f"{base}{suffix}"
    index = 2
    while candidate in used_tags:
        candidate = f"{base}{suffix} {index}"
        index += 1
    return candidate


def _build_groups(
    proxy_groups: Iterable[dict],
    node_tags: set[str],
    *,
    direct_tag: str,
    block_tag: str,
    source_tag_map: dict[str, str] | None = None,
    group_tag_map: dict[str, str] | None = None,
) -> list[dict]:
    """Convert groups after their node members are known.

    Group references can point to other groups, so resolve them iteratively.
    Only groups with at least one valid member are emitted.
    """

    group_list = [group for group in (proxy_groups or []) if isinstance(group, dict)]
    if group_tag_map is None:
        group_tag_map = _build_group_tag_map(
            group_list,
            node_tags,
            direct_tag=direct_tag,
            block_tag=block_tag,
        )
    if source_tag_map is None:
        source_tag_map = {}

    available_tags = set(node_tags) | {direct_tag, block_tag}
    pending = group_list
    converted_groups: list[dict] = []
    converted_names: set[str] = set()

    while pending:
        progressed = False
        remaining = []
        for group in pending:
            name = str(group.get("name") or "").strip()
            output_tag = group_tag_map.get(name)
            if not name or not output_tag or output_tag in converted_names:
                continue
            outbound = _group_outbound(
                group,
                available_tags,
                node_tags=node_tags,
                source_tag_map=source_tag_map,
                group_tag_map=group_tag_map,
                direct_tag=direct_tag,
                block_tag=block_tag,
            )
            if outbound is None:
                remaining.append(group)
                continue
            converted_groups.append(outbound)
            converted_names.add(output_tag)
            available_tags.add(output_tag)
            progressed = True
        if not progressed:
            break
        pending = remaining

    return converted_groups


def _build_group_tag_map(
    proxy_groups: Iterable[dict],
    node_tags: set[str],
    *,
    direct_tag: str,
    block_tag: str,
) -> dict[str, str]:
    """Assign collision-free sing-box tags to source proxy groups."""

    # These tags are generated by the exporter below.  Reserve them while
    # naming source groups so a user-provided group called ``PROXY`` (or
    # ``AUTO``/``MANUAL``) cannot collide with the generated control outbounds.
    used_tags = set(node_tags) | {
        direct_tag,
        block_tag,
        "PROXY",
        "AUTO",
        "MANUAL",
    }
    group_tag_map: dict[str, str] = {}
    for group in proxy_groups or []:
        if not isinstance(group, dict):
            continue
        name = str(group.get("name") or "").strip()
        if name and name not in group_tag_map:
            group_tag_map[name] = _unique_tag(name, used_tags)
            used_tags.add(group_tag_map[name])
    return group_tag_map


def _rename_reserved_source_tags(
    converted: list[dict],
) -> dict[str, str]:
    """Rename source node tags reserved by generated outbounds.

    The returned map is applied while resolving group members.  Group member
    names are intentionally not mutated here: ``DIRECT`` and ``BLOCK`` are
    special Clash references and must keep their generated sing-box meaning.
    """

    reserved_tags = {"DIRECT", "BLOCK", "PROXY", "AUTO", "MANUAL"}
    rename_map: dict[str, str] = {}
    used_tags = {str(item.get("tag") or "") for item in converted} | reserved_tags
    for item in converted:
        tag = str(item.get("tag") or "")
        if tag in reserved_tags:
            # Keep the original reserved tag occupied while choosing the
            # replacement, otherwise ``_unique_tag`` would return the same
            # value after the current item's tag was removed from the set.
            replacement = _unique_tag(tag, used_tags)
            rename_map[tag] = replacement
            used_tags.add(replacement)
            item["tag"] = replacement

    if not rename_map:
        return {}
    for item in converted:
        detour = item.get("detour")
        if detour in rename_map:
            item["detour"] = rename_map[detour]
    return rename_map


def build_singbox_config_with_diagnostics(
    proxies: Iterable[dict],
    proxy_groups: Iterable[dict],
) -> tuple[dict, tuple[SingboxSkippedNode, ...]]:
    """Build a sing-box config and skip nodes without a lossless mapping.

    sing-box cannot represent every Mihomo transport or VLESS extension. A
    single unsupported node should not make an otherwise usable subscription
    fail, so unsupported nodes are omitted and returned as diagnostics for the
    HTTP response headers/logging layer.
    """

    proxy_list = [proxy for proxy in (proxies or []) if isinstance(proxy, dict)]
    source_groups = [group for group in (proxy_groups or []) if isinstance(group, dict)]
    group_list: list[dict] = []
    converted = []
    skipped: list[SingboxSkippedNode] = []
    for group in source_groups:
        group_name = _diagnostic_name(group.get("name"))
        group_type = str(group.get("type") or "select").strip().lower()
        if group_type in {"select", "url-test"}:
            group_list.append(group)
        elif group_type in {"fallback", "load-balance"}:
            group_list.append(group)
            skipped.append(
                SingboxSkippedNode(
                    group_name,
                    f"proxy group type '{group_type}' was approximated as a manual selector",
                    kind="group",
                )
            )
        else:
            skipped.append(
                SingboxSkippedNode(
                    group_name,
                    "unsupported proxy group type was omitted",
                    kind="group",
                )
            )
    seen_tags: set[str] = set()
    for proxy in proxy_list:
        if str(proxy.get("name") or "").startswith("📊"):
            continue
        try:
            outbound = proxy_to_singbox_outbound(_filter_client_proxy(proxy))
        except SingboxExportError as exc:
            skipped.append(SingboxSkippedNode(_diagnostic_name(proxy.get("name")), str(exc)))
            continue

        tag = str(outbound.get("tag") or "").strip()
        if not tag or tag in seen_tags:
            skipped.append(
                SingboxSkippedNode(
                    _diagnostic_name(proxy.get("name")),
                    "duplicate or empty outbound tag",
                )
            )
            continue
        seen_tags.add(tag)
        converted.append(outbound)

    if not converted:
        if skipped:
            raise SingboxExportError(
                "No exportable proxy nodes: " + "; ".join(item.reason for item in skipped[:3])
            )
        raise SingboxExportError("No exportable proxy nodes")

    # Rename source nodes that use sing-box's generated control tags before
    # resolving groups/detours.  Doing this afterwards would make a group
    # member such as ``PROXY`` resolve to a group instead of the renamed node.
    source_tag_map = _rename_reserved_source_tags(converted)

    node_tags = {item["tag"] for item in converted}
    direct_tag = _unique_tag("DIRECT", node_tags)
    block_tag = _unique_tag("BLOCK", node_tags | {direct_tag})
    group_tag_map = _build_group_tag_map(
        group_list,
        node_tags,
        direct_tag=direct_tag,
        block_tag=block_tag,
    )

    # A chain node is invalid when its detour target was omitted. Remove such
    # nodes before group conversion and repeat until all detour references are
    # resolvable. This prevents sing-box from rejecting the whole config.
    while True:
        node_tags = {item["tag"] for item in converted}
        group_outbounds = _build_groups(
            group_list,
            node_tags,
            direct_tag=direct_tag,
            block_tag=block_tag,
            source_tag_map=source_tag_map,
            group_tag_map=group_tag_map,
        )
        available_tags = node_tags | {item["tag"] for item in group_outbounds} | {direct_tag, block_tag}
        invalid = [
            item for item in converted
            if item.get("detour")
            and (
                item["detour"] if item["detour"] in node_tags
                else group_tag_map.get(item["detour"], item["detour"])
            ) not in available_tags
        ]
        if not invalid:
            break
        invalid_tags = {item["tag"] for item in invalid}
        for item in invalid:
            skipped.append(
                SingboxSkippedNode(
                    _diagnostic_name(item["tag"]),
                    "detour target is not exportable",
                )
            )
        converted = [item for item in converted if item["tag"] not in invalid_tags]
        if not converted:
            raise SingboxExportError("No exportable proxy nodes")

        node_tags = {item["tag"] for item in converted}
        for item in converted:
            detour = item.get("detour")
            if detour and detour not in node_tags and detour in group_tag_map:
                item["detour"] = group_tag_map[detour]

    node_tags = {item["tag"] for item in converted}
    for item in converted:
        detour = item.get("detour")
        if detour and detour not in node_tags and detour in group_tag_map:
            item["detour"] = group_tag_map[detour]
    group_outbounds = _build_groups(
        group_list,
        node_tags,
        direct_tag=direct_tag,
        block_tag=block_tag,
        source_tag_map=source_tag_map,
        group_tag_map=group_tag_map,
    )
    # ``group_outbounds`` already contains the final resolved references; do
    # not rebuild it after node conversion, otherwise nested groups can be
    # duplicated or resolved against stale tags.
    group_tags = {item["tag"] for item in group_outbounds}
    used_tags = node_tags | group_tags | {direct_tag, block_tag}
    proxy_tag = _unique_tag("PROXY", used_tags)
    used_tags.add(proxy_tag)
    auto_tag = _unique_tag("AUTO", used_tags)
    used_tags.add(auto_tag)
    manual_tag = _unique_tag("MANUAL", used_tags)
    used_tags.add(manual_tag)

    node_names = [item["tag"] for item in converted]
    return {
        "log": {"level": "info"},
        "outbounds": [
            {"type": "selector", "tag": proxy_tag, "outbounds": [auto_tag, manual_tag]},
            {"type": "urltest", "tag": auto_tag, "outbounds": node_names, "url": "https://www.gstatic.com/generate_204", "interval": "5m"},
            {"type": "selector", "tag": manual_tag, "outbounds": node_names},
            {"type": "direct", "tag": direct_tag},
            {"type": "block", "tag": block_tag},
            *group_outbounds,
            *converted,
        ],
        "route": {
            # sing-box 1.12 removed the legacy embedded GeoIP/Geosite
            # databases. Keep the exported profile valid across current
            # versions and make the main selector the default route; clients
            # can add their own rule-sets without rewriting the node list.
            "final": proxy_tag,
            "auto_detect_interface": True,
        },
    }, tuple(skipped)


def build_singbox_config(proxies: Iterable[dict], proxy_groups: Iterable[dict]) -> dict:
    """Build a sing-box JSON configuration from generated proxy data."""

    config, _ = build_singbox_config_with_diagnostics(proxies, proxy_groups)
    return config
