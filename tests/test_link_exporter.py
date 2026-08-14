import unittest
from urllib.parse import parse_qs, urlparse

from services.link_exporter import export_proxy_link, proxy_to_link
from services.node_parser import parse_node_link
from services.proxy_filter import ProxyFilter


class LinkExporterTests(unittest.TestCase):
    def test_vless_xhttp_export_uses_xhttp_opts(self):
        link = proxy_to_link({
            "name": "xhttp node",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "xhttp",
            "tls": True,
            "servername": "www.apple.com",
            "xhttp-opts": {
                "mode": "stream-up",
                "path": "/xhttp",
                "host": "www.apple.com",
            },
        })

        parsed = urlparse(link)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, "vless")
        self.assertEqual(params["type"], ["xhttp"])
        self.assertEqual(params["security"], ["tls"])
        self.assertEqual(params["mode"], ["stream-up"])
        self.assertEqual(params["path"], ["/xhttp"])
        self.assertEqual(params["host"], ["www.apple.com"])

    def test_vless_ipv6_server_is_bracketed(self):
        link = proxy_to_link({
            "name": "ipv6",
            "type": "vless",
            "server": "2001:db8::1",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "tcp",
        })

        self.assertIn("@[2001:db8::1]:443", link)

    def test_vless_reality_query_values_are_url_encoded(self):
        link = proxy_to_link({
            "name": "reality",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "tcp",
            "tls": True,
            "reality-opts": {
                "public-key": "abc+def/ghi=",
                "short-id": "sid+/=",
            },
        })

        self.assertIn("pbk=abc%2Bdef%2Fghi%3D", link)
        self.assertIn("sid=sid%2B%2F%3D", link)
        params = parse_qs(urlparse(link).query)
        self.assertEqual(params["pbk"], ["abc+def/ghi="])
        self.assertEqual(params["sid"], ["sid+/="])

    def test_hysteria2_obfs_password_is_url_encoded(self):
        link = proxy_to_link({
            "name": "hy2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "sni": "sni.example.com",
            "obfs": "salamander",
            "obfs-password": "pa ss+/=",
        })

        self.assertIn("obfs-password=pa%20ss%2B%2F%3D", link)
        params = parse_qs(urlparse(link).query)
        self.assertEqual(params["obfs-password"], ["pa ss+/="])

    def test_hysteria2_round_trip_preserves_tls_and_pinned_certificate(self):
        original = (
            "hysteria2://secret@example.com:443?security=tls&alpn=h3"
            "&insecure=0&allowInsecure=0&sni=www.bing.com"
            "&pinSHA256=abc%2Bdef%2Fghi%3D#hy2-Hongkong"
        )

        parsed = parse_node_link(original)
        exported = proxy_to_link(parsed)
        exported_params = parse_qs(urlparse(exported).query)

        self.assertTrue(parsed["tls"])
        self.assertEqual(parsed["alpn"], ["h3"])
        self.assertEqual(parsed["_v2rayn-certificate-pin"], "abc+def/ghi=")
        self.assertNotIn("fingerprint", parsed)
        self.assertEqual(exported_params["security"], ["tls"])
        self.assertEqual(exported_params["alpn"], ["h3"])
        self.assertEqual(exported_params["sni"], ["www.bing.com"])
        self.assertEqual(exported_params["pinSHA256"], ["abc+def/ghi="])
        self.assertNotIn("insecure", exported_params)
        self.assertNotIn("allowInsecure", exported_params)

    def test_hysteria2_generic_cert_sha_is_rejected_instead_of_reinterpreted(self):
        exported = export_proxy_link({
            "name": "hy2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "tls": True,
            "cert-sha": "not-a-hy2-pin",
        })

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_hysteria2_certificate_hash")

    def test_hysteria2_base64_certificate_pin_round_trips_after_yaml_normalization(self):
        original = (
            "hysteria2://secret@example.com:443?security=tls&pinSHA256=opaque-pin%2B%2F%3D"
            "&sni=www.bing.com#hy2"
        )
        parsed = parse_node_link(original)
        normalized = ProxyFilter.sanitize_proxy(parsed)
        exported = export_proxy_link(normalized)

        self.assertIsNone(exported.reason)
        self.assertEqual(
            parse_qs(urlparse(exported.link).query)["pinSHA256"],
            ["opaque-pin+/="],
        )

    def test_hysteria2_conflicting_pin_aliases_are_rejected(self):
        exported = export_proxy_link({
            "name": "hy2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "fingerprint": "primary-pin",
            "ca-sha256": "different-legacy-pin",
        })

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "conflicting_hysteria2_certificate_pin")

    def test_hysteria2_export_preserves_insecure_and_port_hopping(self):
        exported = proxy_to_link({
            "name": "hy2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "tls": True,
            "skip-cert-verify": True,
            "ports": "20000:30000",
        })

        params = parse_qs(urlparse(exported).query)
        self.assertEqual(params["security"], ["tls"])
        self.assertEqual(params["insecure"], ["1"])
        self.assertEqual(params["allowInsecure"], ["1"])
        self.assertEqual(params["mport"], ["20000-30000"])

    def test_hysteria_v1_is_rejected_for_v2rayn_export(self):
        exported = export_proxy_link({
            "name": "hy",
            "type": "hysteria",
            "server": "example.com",
            "port": 443,
            "auth-str": "token+/= space",
            "sni": "peer.example.com",
        })

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_protocol")

    def test_vmess_xhttp_is_rejected_instead_of_exported_as_an_unusable_link(self):
        original = {
            "name": "vmess xhttp",
            "type": "vmess",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "alterId": 0,
            "cipher": "auto",
            "tls": True,
            "servername": "www.bing.com",
            "client-fingerprint": "chrome",
            "alpn": ["h2", "http/1.1"],
            "skip-cert-verify": True,
            "network": "xhttp",
            "xhttp-opts": {
                "mode": "stream-up",
                "path": "/xhttp",
                "host": "cdn.example.com",
            },
        }

        exported = export_proxy_link(original)

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_transport")

    def test_vmess_reality_input_is_retained_for_safe_rejection(self):
        import base64
        import json

        vmess_json = {
            "v": "2",
            "ps": "vmess reality input",
            "add": "example.com",
            "port": "443",
            "id": "11111111-1111-1111-1111-111111111111",
            "aid": "0",
            "tls": "reality",
            "pbk": "public-key",
            "sid": "abcd",
            "spx": "/spider",
        }
        link = "vmess://" + base64.b64encode(json.dumps(vmess_json).encode()).decode()

        parsed = parse_node_link(link)
        exported = export_proxy_link(parsed)

        self.assertEqual(parsed["reality-opts"]["public-key"], "public-key")
        self.assertEqual(parsed["reality-opts"]["spider-x"], "/spider")
        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_vmess_reality")

    def test_vmess_reality_is_rejected_instead_of_becoming_plain_tls(self):
        exported = export_proxy_link({
            "name": "vmess reality",
            "type": "vmess",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
            "reality-opts": {
                "public-key": "public-key",
                "short-id": "abcd",
                "spider-x": "/spider",
            },
        })

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_vmess_reality")

    def test_trojan_unsupported_reality_grpc_and_flow_fields_are_rejected(self):
        original = {
            "name": "trojan reality",
            "type": "trojan",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "tls": True,
            "sni": "www.bing.com",
            "client-fingerprint": "chrome",
            "alpn": ["h2", "http/1.1"],
            "skip-cert-verify": True,
            "reality-opts": {
                "public-key": "public+key=",
                "short-id": "abcd",
                "spider-x": "/spider",
            },
            "network": "grpc",
            "grpc-opts": {
                "grpc-service-name": "service",
                "mode": "multi",
                "authority": "authority.example.com",
            },
            "flow": "xtls-rprx-vision",
        }

        exported = export_proxy_link(original)

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_grpc_mode")

    def test_shadowsocks_plugin_round_trip_preserves_plugin_options(self):
        original = {
            "name": "ss plugin",
            "type": "ss",
            "server": "example.com",
            "port": 443,
            "cipher": "aes-128-gcm",
            "password": "secret",
            "plugin": "v2ray-plugin",
            "plugin-opts": {
                "mode": "websocket",
                "host": "cdn.example.com",
                "path": "/ws",
                "tls": True,
                "mux": "0",
            },
        }

        reparsed = parse_node_link(proxy_to_link(original))

        self.assertEqual(reparsed["plugin"], original["plugin"])
        self.assertEqual(reparsed["plugin-opts"], original["plugin-opts"])

    def test_hysteria2_bandwidth_is_rejected_instead_of_silently_lost(self):
        exported = export_proxy_link({
            "name": "hysteria2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "up": "20",
            "down": "100",
        })

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_bandwidth")

    def test_tuic_unsupported_udp_relay_mode_is_rejected(self):
        exported = export_proxy_link({
            "name": "tuic",
            "type": "tuic",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "password": "secret",
            "sni": "www.bing.com",
            "udp-relay-mode": "native",
        })

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_udp_relay_mode")

    def test_vmess_with_custom_websocket_headers_is_not_silently_degraded(self):
        link = proxy_to_link({
            "name": "vmess custom headers",
            "type": "vmess",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "ws",
            "ws-opts": {
                "path": "/ws",
                "headers": {
                    "Host": "cdn.example.com",
                    "User-Agent": "custom-agent",
                },
            },
        })

        self.assertEqual(link, "")

    def test_trojan_with_custom_websocket_headers_is_not_silently_degraded(self):
        link = proxy_to_link({
            "name": "trojan custom headers",
            "type": "trojan",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "network": "ws",
            "ws-opts": {
                "path": "/ws",
                "headers": {"User-Agent": "custom-agent"},
            },
        })

        self.assertEqual(link, "")

    def test_vless_kcp_is_rejected_because_mihomo_cannot_run_it(self):
        original = {
            "name": "vless kcp",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "kcp",
            "header-type": "wechat-video",
            "encryption": "none",
        }

        exported = export_proxy_link(original)

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_vless_network")

    def test_trojan_ws_options_without_network_are_normalized_before_export(self):
        from services.proxy_filter import ProxyFilter

        original = ProxyFilter.sanitize_proxy({
            "name": "implicit trojan ws",
            "type": "trojan",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "ws-opts": {"path": "/ws", "headers": {"Host": "cdn.example.com"}},
        })

        reparsed = parse_node_link(proxy_to_link(original))

        self.assertEqual(original["network"], "ws")
        self.assertEqual(reparsed["network"], "ws")
        self.assertEqual(reparsed["ws-opts"], original["ws-opts"])

    def test_trojan_explicit_websocket_round_trip_preserves_path_and_host(self):
        original = {
            "name": "trojan ws",
            "type": "trojan",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "network": "ws",
            "ws-opts": {"path": "/ws", "headers": {"Host": "cdn.example.com"}},
        }

        reparsed = parse_node_link(proxy_to_link(original))

        self.assertEqual(reparsed["network"], "ws")
        self.assertEqual(reparsed["ws-opts"], original["ws-opts"])

    def test_hysteria2_up_or_down_is_rejected(self):
        base = {
            "name": "hy2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
        }
        for field in ("up", "down"):
            with self.subTest(field=field):
                exported = export_proxy_link({**base, field: "100"})
                self.assertEqual(exported.link, "")
                self.assertEqual(exported.reason, "unsupported_bandwidth")

    def test_anytls_default_session_tuning_is_safe_to_omit(self):
        proxy = {
            "name": "anytls",
            "type": "anytls",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "tls": True,
            "idle-session-check-interval": 30,
            "idle-session-timeout": 30,
            "min-idle-session": 0,
            "udp-over-tcp": False,
        }

        exported = export_proxy_link(proxy)

        self.assertTrue(exported.link.startswith("anytls://"))
        query = parse_qs(urlparse(exported.link).query)
        self.assertNotIn("idle-session-check-interval", query)
        self.assertNotIn("udp-over-tcp", query)

    def test_anytls_explicit_udp_over_tcp_is_rejected(self):
        exported = export_proxy_link({
            "name": "anytls",
            "type": "anytls",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "udp-over-tcp": True,
        })

        self.assertEqual(exported.reason, "unsupported_udp_over_tcp")

    def test_anytls_nondefault_session_tuning_is_rejected(self):
        defaults = {
            "idle-session-check-interval": 30,
            "idle-session-timeout": 30,
            "min-idle-session": 0,
        }
        for field, value in (
            ("idle-session-check-interval", 31),
            ("idle-session-timeout", 29),
            ("min-idle-session", 1),
            ("udp-over-tcp", "true"),
        ):
            with self.subTest(field=field):
                proxy = {
                    "name": "anytls",
                    "type": "anytls",
                    "server": "example.com",
                    "port": 443,
                    "password": "secret",
                    **defaults,
                    field: value,
                }
                exported = export_proxy_link(proxy)
                self.assertEqual(exported.link, "")
                self.assertEqual(exported.reason, "unsupported_anytls_tuning")

    def test_http_and_ssr_are_rejected_for_v2rayn(self):
        for proxy_type in ("http", "ssr"):
            with self.subTest(proxy_type=proxy_type):
                exported = export_proxy_link({
                    "name": proxy_type,
                    "type": proxy_type,
                    "server": "example.com",
                    "port": 443,
                })
                self.assertEqual(exported.link, "")
                self.assertTrue(exported.reason)

    def test_socks_export_uses_v2rayn_base64_userinfo(self):
        original = {
            "name": "SOCKS",
            "type": "socks5",
            "server": "example.com",
            "port": 1080,
            "username": "user%2Fname",
            "password": "p:%/word",
        }

        link = proxy_to_link(original)
        reparsed = parse_node_link(link)

        self.assertTrue(link.startswith("socks://"))
        self.assertEqual(reparsed["username"], original["username"])
        self.assertEqual(reparsed["password"], original["password"])

    def test_socks_tls_related_fields_are_rejected(self):
        base = {
            "name": "SOCKS",
            "type": "socks5",
            "server": "example.com",
            "port": 1080,
        }
        for field, value in (
            ("tls", True),
            ("sni", "cdn.example.com"),
            ("skip-cert-verify", True),
            ("client-fingerprint", "chrome"),
            ("alpn", ["h2"]),
        ):
            with self.subTest(field=field):
                exported = export_proxy_link({**base, field: value})
                self.assertEqual(exported.link, "")
                self.assertEqual(exported.reason, "unsupported_socks_tls")

    def test_kcp_is_rejected_for_vless_and_trojan(self):
        cases = [
            {"type": "vless", "uuid": "11111111-1111-1111-1111-111111111111"},
            {"type": "trojan", "password": "secret"},
        ]
        for fields in cases:
            with self.subTest(proxy_type=fields["type"]):
                original = {
                    "name": "kcp",
                    "server": "example.com",
                    "port": 443,
                    "network": "kcp",
                    "header-type": "wechat-video",
                    "seed": "seed+/=",
                    "mtu": 1280,
                    **fields,
                }
                exported = export_proxy_link(original)
                self.assertEqual(exported.link, "")
                self.assertEqual(
                    exported.reason,
                    f"unsupported_{fields['type']}_network",
                )

    def test_raw_http_camouflage_is_rejected_when_v2rayn_cannot_import_it(self):
        cases = [
            {"type": "vless", "uuid": "11111111-1111-1111-1111-111111111111"},
            {"type": "trojan", "password": "secret"},
        ]
        for fields in cases:
            with self.subTest(proxy_type=fields["type"]):
                original = {
                    "name": "raw-http",
                    "server": "example.com",
                    "port": 443,
                    "network": "tcp",
                    "header-type": "http",
                    "host": "cdn.example.com",
                    "path": "/request",
                    **fields,
                }
                exported = export_proxy_link(original)
                self.assertEqual(exported.link, "")
                if fields["type"] == "trojan":
                    self.assertEqual(exported.reason, "unsupported_trojan_tcp_disguise")
                else:
                    self.assertEqual(exported.reason, "unsupported_transport")

    def test_vless_xhttp_canonical_options_round_trip_through_extra_json(self):
        original = {
            "name": "xhttp",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "xhttp",
            "xhttp-opts": {
                "mode": "stream-up",
                "path": "/x",
                "host": "cdn.example.com",
                "x-padding-bytes": "100-200",
                "no-grpc-header": True,
                "headers": {"User-Agent": "custom-agent"},
                "reuse-settings": {"max-connections": "2-4"},
                "download-settings": {
                    "server": "download.example.com",
                    "port": 8443,
                    "tls": True,
                    "servername": "download.example.com",
                    "path": "/download",
                },
            },
        }

        exported = export_proxy_link(original)
        reparsed = parse_node_link(exported.link)

        self.assertIsNone(exported.reason)
        self.assertEqual(reparsed["xhttp-opts"], original["xhttp-opts"])

    def test_grpc_multi_mode_is_rejected_instead_of_silently_downgraded(self):
        exported = export_proxy_link({
            "name": "grpc",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "grpc",
            "grpc-opts": {"grpc-service-name": "svc", "grpc-mode": "multi"},
        })

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_grpc_mode")

    def test_wireguard_uses_v2rayn_query_key_names(self):
        link = proxy_to_link({
            "name": "WG",
            "type": "wireguard",
            "server": "example.com",
            "port": 51820,
            "private-key": "private",
            "public-key": "public",
            "preshared-key": "psk",
            "ip": "10.0.0.2/32",
        })
        params = parse_qs(urlparse(link).query)

        self.assertEqual(params["publickey"], ["public"])
        self.assertEqual(params["presharedkey"], ["psk"])
        self.assertEqual(params["address"], ["10.0.0.2/32"])
        self.assertNotIn("public-key", params)
        self.assertNotIn("preshared-key", params)

    def test_unsupported_transports_are_rejected(self):
        base = {
            "name": "vless",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
        }
        for network in ("http", "h2", "quic"):
            with self.subTest(network=network):
                exported = export_proxy_link({**base, "network": network})
                self.assertEqual(exported.link, "")
                self.assertEqual(exported.reason, "unsupported_transport")

    def test_vless_websocket_early_data_is_rejected_for_v2rayn(self):
        original = {
            "name": "vless ws ed",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "ws",
            "ws-opts": {
                "path": "/",
                "headers": {"Host": "cdn.example.com"},
                "max-early-data": 2560,
                "early-data-header-name": "Sec-WebSocket-Protocol",
            },
        }

        exported = export_proxy_link(original)

        self.assertEqual(exported.reason, "unsupported_websocket_early_data")

    def test_vmess_websocket_early_data_is_rejected(self):
        exported = export_proxy_link({
            "name": "vmess ws ed",
            "type": "vmess",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "ws",
            "ws-opts": {"path": "/", "max-early-data": 2560},
        })

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_websocket_early_data")

    def test_vmess_tls_extensions_not_supported_by_legacy_json_are_rejected(self):
        for key, value in (
            ("ech", "ech-config"),
            ("pqv", "mldsa-public-key"),
            ("finalmask", '{"tcp":[]}'),
        ):
            proxy = {
                "name": "vmess advanced TLS",
                "type": "vmess",
                "server": "example.com",
                "port": 443,
                "uuid": "11111111-1111-1111-1111-111111111111",
                "tls": True,
                key: value,
            }

            with self.subTest(key=key):
                exported = export_proxy_link(proxy)
                self.assertEqual(exported.reason, "unsupported_vmess_tls_extension")

    def test_unsupported_proxy_type_returns_empty_string(self):
        self.assertEqual(proxy_to_link({"type": "unknown"}), "")

    def test_anytls_transport_is_rejected_because_v2rayn_clears_network(self):
        exported = export_proxy_link({
            "name": "AnyTLS transport",
            "type": "anytls",
            "server": "example.com",
            "port": 443,
            "password": "pass:word",
            "tls": True,
            "servername": "www.apple.com",
            "client-fingerprint": "chrome",
            "alpn": ["h2", "http/1.1"],
            "network": "xhttp",
            "xhttp-opts": {
                "mode": "stream-up",
                "path": "/xhttp",
                "host": "cdn.example.com",
            },
        })

        self.assertEqual(exported.link, "")
        self.assertEqual(exported.reason, "unsupported_anytls_transport")

    def test_anytls_without_transport_preserves_tls_fields(self):
        original = {
            "name": "AnyTLS Reality",
            "type": "anytls",
            "server": "example.com",
            "port": 443,
            "password": "pass:word",
            "tls": True,
            "servername": "www.apple.com",
            "client-fingerprint": "chrome",
            "alpn": ["h2", "http/1.1"],
        }

        reparsed = parse_node_link(proxy_to_link(original))

        self.assertEqual(reparsed["type"], "anytls")
        self.assertEqual(reparsed["password"], "pass:word")
        self.assertEqual(reparsed["client-fingerprint"], "chrome")
        self.assertEqual(reparsed["alpn"], ["h2", "http/1.1"])
        self.assertNotIn("network", reparsed)

    def test_wireguard_export_does_not_disappear_from_base64_output(self):
        link = proxy_to_link({
            "name": "WG",
            "type": "wireguard",
            "server": "2001:db8::2",
            "port": 51820,
            "private-key": "private/key=",
            "public-key": "public/key=",
            "preshared-key": "psk/key=",
            "reserved": [1, 2, 3],
            "address": ["10.0.0.2/32", "fd00::2/128"],
            "mtu": 1280,
        })

        self.assertTrue(link.startswith("wireguard://"))
        self.assertIn("@[2001:db8::2]:51820", link)
        parsed = parse_node_link(link)
        self.assertEqual(parsed["type"], "wireguard")
        self.assertEqual(parsed["private-key"], "private/key=")
        self.assertEqual(parsed["public-key"], "public/key=")
        self.assertEqual(parsed["preshared-key"], "psk/key=")
        self.assertEqual(parsed["reserved"], [1, 2, 3])
        self.assertEqual(parsed["ip"], "10.0.0.2/32")
        self.assertEqual(parsed["ipv6"], "fd00::2/128")
        self.assertEqual(parsed["mtu"], 1280)


    def test_shadowsocks_unknown_plugin_is_rejected(self):
        exported = export_proxy_link({
            "name": "ss unknown plugin",
            "type": "ss",
            "server": "example.com",
            "port": 443,
            "cipher": "aes-128-gcm",
            "password": "secret",
            "plugin": "shadow-tls",
            "plugin-opts": {"host": "cdn.example.com", "password": "plugin-secret"},
        })

        self.assertEqual(exported.reason, "unsupported_plugin")

    def test_shadowsocks_obfs_rejects_unknown_options(self):
        exported = export_proxy_link({
            "name": "ss obfs",
            "type": "ss",
            "server": "example.com",
            "port": 443,
            "cipher": "aes-128-gcm",
            "password": "secret",
            "plugin": "obfs",
            "plugin-opts": {"mode": "tls", "host": "cdn.example.com", "path": "/lost"},
        })

        self.assertEqual(exported.reason, "unsupported_plugin_options")

    def test_shadowsocks_v2ray_plugin_requires_websocket_and_mux_zero(self):
        base = {
            "name": "ss v2ray plugin",
            "type": "ss",
            "server": "example.com",
            "port": 443,
            "cipher": "aes-128-gcm",
            "password": "secret",
            "plugin": "v2ray-plugin",
        }
        cases = (
            ({"mode": "websocket"}, "unsupported_plugin_mux"),
            ({"mode": "quic", "mux": "0"}, "unsupported_plugin_mode"),
            ({"mode": "websocket", "mux": True}, "unsupported_plugin_mux"),
            ({"mode": "websocket", "mux": "8"}, "unsupported_plugin_mux"),
            ({"mode": "websocket", "headers": {"User-Agent": "custom"}}, "unsupported_plugin_options"),
        )
        for plugin_opts, expected_reason in cases:
            with self.subTest(plugin_opts=plugin_opts):
                exported = export_proxy_link({**base, "plugin-opts": plugin_opts})
                self.assertEqual(exported.reason, expected_reason)

    def test_shadowsocks_simple_obfs_alias_exports_canonical_options(self):
        original = {
            "name": "ss simple obfs",
            "type": "ss",
            "server": "example.com",
            "port": 443,
            "cipher": "aes-128-gcm",
            "password": "secret",
            "plugin": "simple-obfs",
            "plugin-opts": {"mode": "tls", "host": "cdn.example.com"},
        }

        reparsed = parse_node_link(proxy_to_link(original))

        self.assertEqual(reparsed["plugin"], "obfs")
        self.assertEqual(reparsed["plugin-opts"], original["plugin-opts"])

    def test_shadowsocks_v2ray_plugin_explicit_mux_zero_round_trips(self):
        original = {
            "name": "ss plugin",
            "type": "ss",
            "server": "example.com",
            "port": 443,
            "cipher": "aes-128-gcm",
            "password": "secret",
            "plugin": "v2ray-plugin",
            "plugin-opts": {
                "mode": "websocket",
                "host": "cdn.example.com",
                "path": r"/a=b,c\d",
                "tls": True,
                "mux": "0",
            },
        }

        reparsed = parse_node_link(proxy_to_link(original))

        self.assertEqual(reparsed["plugin"], original["plugin"])
        self.assertEqual(reparsed["plugin-opts"], original["plugin-opts"])

    def test_tuic_uri_only_preserves_supported_fields(self):
        original = {
            "name": "tuic",
            "type": "tuic",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "password": "secret",
            "sni": "www.bing.com",
            "alpn": ["h3"],
            "skip-cert-verify": True,
            "congestion-controller": "bbr",
        }

        reparsed = parse_node_link(proxy_to_link(original))

        for key in ("uuid", "password", "sni", "alpn", "skip-cert-verify", "congestion-controller"):
            self.assertEqual(reparsed[key], original[key])

    def test_tuic_advanced_options_are_rejected_instead_of_dropped(self):
        base = {
            "name": "tuic",
            "type": "tuic",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "password": "secret",
        }
        cases = (
            ("token", "legacy-token"),
            ("heartbeat-interval", 10000),
            ("reduce-rtt", True),
            ("disable-sni", True),
            ("udp-over-stream", True),
            ("recv-window", 8388608),
            ("certificate", "certificate-pem"),
            ("ca", "ca-pem"),
            ("ca-sha256", "ca-sha256"),
            ("cert-sha", "certificate-sha256"),
            ("client-fingerprint", "chrome"),
            ("ech-opts", {"enable": True}),
        )
        for field, value in cases:
            with self.subTest(field=field):
                exported = export_proxy_link({**base, field: value})
                self.assertEqual(exported.reason, "unsupported_tuic_option")

    def test_hysteria2_gecko_parameters_are_exported(self):
        exported = export_proxy_link({
            "name": "hy2 gecko",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "obfs": "gecko",
            "obfs-password": "mask-secret",
            "minPacketSize": 600,
            "maxPacketSize": 1300,
        })
        self.assertTrue(exported.link.startswith("hysteria2://"))
        params = parse_qs(urlparse(exported.link).query)
        self.assertEqual(params["obfs"], ["gecko"])
        self.assertEqual(params["minPacketSize"], ["600"])
        self.assertEqual(params["maxPacketSize"], ["1300"])

    def test_hysteria2_gecko_link_round_trips(self):
        original = (
            "hysteria2://secret@example.com:443?obfs=gecko"
            "&obfs-password=mask-secret&minPacketSize=600&maxPacketSize=1300#hy2-gecko"
        )

        parsed = parse_node_link(original)
        exported = export_proxy_link(parsed)

        self.assertEqual(parsed["minPacketSize"], 600)
        self.assertEqual(parsed["maxPacketSize"], 1300)
        exported_params = parse_qs(urlparse(exported.link).query)
        self.assertEqual(exported_params["obfs"], ["gecko"])
        self.assertEqual(exported_params["obfs-password"], ["mask-secret"])
        self.assertEqual(exported_params["minPacketSize"], ["600"])
        self.assertEqual(exported_params["maxPacketSize"], ["1300"])

    def test_hysteria2_gecko_link_import_applies_v2rayn_defaults(self):
        parsed = parse_node_link(
            "hysteria2://secret@example.com:443?obfs=gecko"
            "&obfs-password=mask-secret#hy2-gecko"
        )

        self.assertEqual(parsed["minPacketSize"], 512)
        self.assertEqual(parsed["maxPacketSize"], 1200)

    def test_hysteria2_gecko_invalid_packet_sizes_use_v2rayn_defaults(self):
        from services.proxy_filter import ProxyFilter

        sanitized = ProxyFilter.sanitize_proxy({
            "name": "hy2 gecko",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "obfs": "gecko",
            "obfs-password": "mask-secret",
            "minPacketSize": 1600,
            "maxPacketSize": 1300,
        })

        self.assertEqual(sanitized["obfs-min-packet-size"], 1600)
        self.assertEqual(sanitized["obfs-max-packet-size"], 1300)

    def test_hysteria2_gecko_without_bounds_uses_v2rayn_defaults(self):
        exported = export_proxy_link({
            "name": "hy2 gecko",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "obfs": "gecko",
            "obfs-password": "mask-secret",
        })

        params = parse_qs(urlparse(exported.link).query)
        self.assertEqual(params["minPacketSize"], ["512"])
        self.assertEqual(params["maxPacketSize"], ["1200"])

    def test_hysteria2_hop_and_runtime_tuning_are_rejected(self):
        base = {
            "name": "hy2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
        }
        cases = (
            ("hop-interval", "10s", "unsupported_hysteria2_hop_interval"),
            ("cwnd", 64, "unsupported_hysteria2_tuning"),
            ("bbr-profile", "aggressive", "unsupported_hysteria2_tuning"),
            ("udp-mtu", 1200, "unsupported_hysteria2_tuning"),
            ("max-stream-receive-window", 8388608, "unsupported_hysteria2_tuning"),
        )
        for field, value, expected_reason in cases:
            with self.subTest(field=field):
                exported = export_proxy_link({**base, field: value})
                self.assertEqual(exported.reason, expected_reason)

    def test_hysteria2_obfs_without_password_is_rejected(self):
        exported = export_proxy_link({
            "name": "hy2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "obfs": "salamander",
        })

        self.assertEqual(exported.reason, "unsupported_hysteria2_obfs")

    def test_hysteria2_unknown_obfs_is_rejected(self):
        exported = export_proxy_link({
            "name": "hy2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "obfs": "custom-mask",
            "obfs-password": "secret",
        })

        self.assertEqual(exported.reason, "unsupported_hysteria2_obfs")

    def test_anytls_structured_tls_material_is_rejected(self):
        base = {
            "name": "anytls",
            "type": "anytls",
            "server": "example.com",
            "port": 443,
            "password": "secret",
        }
        cases = (
            ("fingerprint", "certificate-sha256", "unsupported_anytls_tls_option"),
            ("certificate", "certificate-pem", "unsupported_anytls_tls_material"),
            ("private-key", "private-key-pem", "unsupported_anytls_tls_material"),
            ("ech-opts", {"enable": True}, "unsupported_anytls_tls_material"),
        )
        for field, value, expected_reason in cases:
            with self.subTest(field=field):
                exported = export_proxy_link({**base, field: value})
                self.assertEqual(exported.reason, expected_reason)

    def test_anytls_extensions_not_supported_by_v2rayn_are_rejected(self):
        base = {
            "name": "anytls",
            "type": "anytls",
            "server": "example.com",
            "port": 443,
            "password": "secret",
        }
        cases = (
            ("disable-reuse", True),
            ("shadow-tls", True),
            ("shadow-tls-opts", {"password": "mask"}),
            ("restls-opts", {"host": "cdn.example.com"}),
            ("jls-opts", {"token": "token"}),
        )
        for field, value in cases:
            with self.subTest(field=field):
                exported = export_proxy_link({**base, field: value})
                self.assertEqual(exported.reason, "unsupported_anytls_extension")

    def test_v2ray_protocol_custom_tls_material_is_rejected(self):
        cases = (
            {"type": "vmess", "uuid": "11111111-1111-1111-1111-111111111111"},
            {"type": "vless", "uuid": "11111111-1111-1111-1111-111111111111"},
            {"type": "trojan", "password": "secret"},
        )
        for protocol_fields in cases:
            with self.subTest(proxy_type=protocol_fields["type"]):
                exported = export_proxy_link({
                    "name": "tls material",
                    "server": "example.com",
                    "port": 443,
                    "certificate": "certificate-pem",
                    **protocol_fields,
                })
                self.assertEqual(exported.reason, "unsupported_tls_material")

    def test_grpc_runtime_options_not_supported_by_uri_are_rejected(self):
        exported = export_proxy_link({
            "name": "grpc tuning",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "grpc",
            "grpc-opts": {"grpc-service-name": "svc", "ping-interval": 10},
        })

        self.assertEqual(exported.reason, "unsupported_grpc_options")

    def test_vmess_runtime_options_not_in_legacy_json_are_rejected(self):
        base = {
            "name": "vmess",
            "type": "vmess",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
        }
        cases = (
            ("flow", "xtls-rprx-vision"),
            ("packet-addr", True),
            ("xudp", True),
            ("packet-encoding", "xudp"),
            ("global-padding", True),
            ("authenticated-length", True),
            ("padding", True),
        )
        for field, value in cases:
            with self.subTest(field=field):
                exported = export_proxy_link({**base, field: value})
                self.assertEqual(exported.reason, "unsupported_vmess_option")

    def test_vless_packet_encoding_options_not_in_uri_are_rejected(self):
        base = {
            "name": "vless",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
        }
        for field, value in (("packet-addr", True), ("xudp", True), ("packet-encoding", "xudp")):
            with self.subTest(field=field):
                exported = export_proxy_link({**base, field: value})
                self.assertEqual(exported.reason, "unsupported_vless_option")

    def test_hysteria2_share_link_preserves_certificate_requirements(self):
        original = (
            "hysteria2://secret@example.com:443?security=tls&alpn=h3"
            "&insecure=0&allowInsecure=0&sni=www.bing.com"
            "&pinSHA256=opaque-pin%2B%2F%3D#hy2-Hongkong"
        )

        exported = export_proxy_link(parse_node_link(original))
        query = parse_qs(urlparse(exported.link).query)

        self.assertIsNone(exported.reason)
        self.assertEqual(query["security"], ["tls"])
        self.assertEqual(query["sni"], ["www.bing.com"])
        self.assertEqual(query["alpn"], ["h3"])
        self.assertEqual(query["pinSHA256"], ["opaque-pin+/="])

    def test_hysteria2_unrepresentable_tls_extensions_are_rejected(self):
        base = {
            "name": "hy2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "tls": True,
        }
        for field, value in (
            ("verify-peer-cert-by-name", "www.bing.com"),
            ("ech", "ech-config"),
            ("pqv", "ml-dsa-public-key"),
            ("finalmask", '{"udp":[]}'),
        ):
            with self.subTest(field=field):
                exported = export_proxy_link({**base, field: value})
                self.assertEqual(exported.reason, "unsupported_hysteria2_tls_option")

    def test_tls_alias_conflicts_are_rejected_before_precedence_can_hide_them(self):
        base = {
            "name": "vless",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
        }
        cases = (
            ({"sni": "one.example.com", "servername": "two.example.com"}, "conflicting_server_name"),
            ({"fingerprint": "a", "cert-sha": "b"}, "conflicting_certificate_pin"),
        )
        for fields, expected_reason in cases:
            with self.subTest(fields=fields):
                exported = export_proxy_link({**base, **fields})
                self.assertEqual(exported.reason, expected_reason)

    def test_vless_reality_preserves_spider_x_and_requires_complete_options(self):
        valid = {
            "name": "reality",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
            "reality-opts": {
                "public-key": "public-key",
                "short-id": "abcd",
                "spider-x": "/spider/path",
            },
        }

        exported = export_proxy_link(valid)
        query = parse_qs(urlparse(exported.link).query)
        self.assertEqual(query["security"], ["reality"])
        self.assertEqual(query["spx"], ["/spider/path"])

        cases = (
            ({"reality-opts": {}}, "invalid_reality_options"),
            ({"reality-opts": {"short-id": "abcd"}}, "missing_reality_public_key"),
            ({"tls": False, "reality-opts": {"public-key": "public-key"}}, "reality_without_tls"),
            ({"reality-opts": {"public-key": "public-key", "support-x25519mlkem768": True}}, "unsupported_reality_option"),
        )
        for fields, expected_reason in cases:
            with self.subTest(fields=fields):
                candidate = dict(valid)
                candidate.update(fields)
                exported = export_proxy_link(candidate)
                self.assertEqual(exported.reason, expected_reason)

    def test_tuic_unknown_congestion_controller_is_rejected(self):
        base = {
            "name": "tuic",
            "type": "tuic",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "password": "secret",
        }
        for controller in ("cubic", "new_reno", "bbr"):
            with self.subTest(controller=controller):
                self.assertTrue(proxy_to_link({**base, "congestion-controller": controller}))

        exported = export_proxy_link({**base, "congestion-controller": "brutal"})
        self.assertEqual(exported.reason, "unsupported_tuic_congestion_controller")

    def test_anytls_only_exports_tls_extensions_used_by_v2rayn_singbox(self):
        original = {
            "name": "anytls",
            "type": "anytls",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "sni": "www.bing.com",
            "client-fingerprint": "chrome",
            "alpn": ["h2", "http/1.1"],
            "skip-cert-verify": True,
            "ech-opts": {"enable": True, "config": "ech-config"},
        }

        reparsed = parse_node_link(proxy_to_link(original))
        self.assertEqual(reparsed["sni"], original["sni"])
        self.assertEqual(reparsed["client-fingerprint"], original["client-fingerprint"])
        self.assertEqual(reparsed["alpn"], original["alpn"])
        self.assertTrue(reparsed["skip-cert-verify"])
        self.assertEqual(reparsed["ech-opts"], original["ech-opts"])

        for field, value in (
            ("cert-sha", "a" * 64),
            ("verify-peer-cert-by-name", "www.bing.com"),
            ("pqv", "ml-dsa-public-key"),
            ("finalmask", '{"tcp":[]}'),
        ):
            with self.subTest(field=field):
                exported = export_proxy_link({**original, field: value})
                self.assertEqual(exported.reason, "unsupported_anytls_tls_option")

    def test_wireguard_mihomo_addresses_round_trip_and_advanced_options_are_rejected(self):
        original = {
            "name": "WG",
            "type": "wireguard",
            "server": "example.com",
            "port": 51820,
            "private-key": "private",
            "public-key": "public",
            "pre-shared-key": "psk",
            "ip": "10.0.0.2/32",
            "ipv6": "fd00::2/128",
        }

        reparsed = parse_node_link(proxy_to_link(original))
        self.assertEqual(reparsed["ip"], original["ip"])
        self.assertEqual(reparsed["ipv6"], original["ipv6"])
        self.assertEqual(reparsed["pre-shared-key"], original["pre-shared-key"])

        conflict = export_proxy_link({**original, "address": "10.0.0.3/32,fd00::2/128"})
        self.assertEqual(conflict.reason, "conflicting_wireguard_address")

        for field, value in (
            ("allowed-ips", ["0.0.0.0/0"]),
            ("persistent-keepalive", 25),
            ("workers", 2),
            ("dns", ["1.1.1.1"]),
            ("remote-dns-resolve", True),
            ("peers", [{"server": "backup.example.com"}]),
            ("refresh-server-ip-interval", 60),
            ("amnezia-wg-option", {"jc": 4}),
        ):
            with self.subTest(field=field):
                exported = export_proxy_link({**original, field: value})
                self.assertEqual(exported.reason, "unsupported_wireguard_option")


if __name__ == "__main__":
    unittest.main()
