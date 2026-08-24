"""Tests for the extracted subscription output router."""

import copy
import base64
import json
import logging
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import unquote

import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.name_transformer import NameTransformer
from services.node_identity import proxy_chain_virtual_node_id
from services.subscription_output import create_subscription_output_router
from services.singbox_export import build_singbox_config_with_diagnostics
from services.socks_export import SocksExportError, build_socks_config
from services.node_metadata import strip_node_metadata


class SubscriptionOutputRouterTest(unittest.TestCase):
    def make_client(
        self,
        config,
        *,
        yaml_source_dir="/tmp/nonexistent-sub-output-tests",
        fetch_subscription_async=None,
        find_node_by_reference=None,
    ):
        app = FastAPI()

        def load_config():
            return copy.deepcopy(config)

        def update_config(mutator):
            result = mutator(config)
            return result

        app.include_router(create_subscription_output_router(
            yaml_source_dir=yaml_source_dir,
            output_file=str(Path(yaml_source_dir) / "config.yaml"),
            load_config=load_config,
            update_config=update_config,
            fetch_subscription=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("fetch should not run")),
            find_node_by_reference=find_node_by_reference or (lambda *args, **kwargs: None),
            is_name_allocated=lambda *args, **kwargs: False,
            filter_underscore_fields=strip_node_metadata,
            extract_country_from_name=lambda *args, **kwargs: None,
            split_template=lambda content: (content, ""),
            logger=logging.getLogger("test.subscription_output"),
            fetch_subscription_async=fetch_subscription_async,
        ))
        return TestClient(app)

    def test_rejects_invalid_subscription_token(self):
        client = self.make_client({
            "auth": {"sub_token": "admin-token"},
            "subscriptions": [],
            "custom_nodes": [],
            "users": [],
            "admin_tokens": [],
        })

        response = client.get("/sub?token=bad-token")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Invalid subscription token")

    def test_registers_legacy_admin_subscription_route(self):
        client = self.make_client({
            "auth": {"sub_token": "admin-token"},
            "subscriptions": [],
            "custom_nodes": [],
            "users": [],
            "admin_tokens": [],
        })

        response = client.get("/sub?token=admin-token")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "No enabled subscriptions or custom nodes")

    def test_missing_subscription_auto_refresh_uses_async_fetcher(self):
        calls = []

        async def async_fetch(url, proxy_node=None, force_proxy=False):
            calls.append((url, proxy_node, force_proxy))
            return (
                "proxies:\n"
                "  - name: Test Node\n"
                "    type: http\n"
                "    server: 127.0.0.1\n"
                "    port: 8080\n",
                {"upload": 1, "download": 2, "total": 3, "expire": 4},
                1,
            )

        with tempfile.TemporaryDirectory() as tempdir:
            config = {
                "auth": {"sub_token": "admin-token", "sub_name": "Aggregated"},
                "subscriptions": [{
                    "id": "sub_demo",
                    "name": "Demo",
                    "url": "https://example.test/sub",
                    "enabled": True,
                }],
                "custom_nodes": [],
                "users": [],
                "admin_tokens": [],
                "proxy_chains": [],
            }
            client = self.make_client(config, yaml_source_dir=tempdir, fetch_subscription_async=async_fetch)

            response = client.get("/sub?token=admin-token&format=yaml")

            self.assertEqual(calls, [("https://example.test/sub", None, False)])
            self.assertEqual(config["subscriptions"][0]["update_status"], "success")
            self.assertTrue((Path(tempdir) / "sub_demo.yaml").exists())
            self.assertNotEqual(response.status_code, 500)
            self.assertNotIn("_source_id", response.text)

    def test_stale_user_subscription_cache_is_not_returned_or_rewritten(self):
        node = {
            "name": "Node A",
            "type": "http",
            "server": "127.0.0.1",
            "port": 8080,
        }

        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": [node]}, sort_keys=False),
                encoding="utf-8",
            )
            stale_cache = {
                "content": "STALE_CACHE_CONTENT",
                "headers": {},
                "timestamp": time.time(),
            }
            config = {
                "auth": {},
                "subscriptions": [],
                "custom_nodes": [node],
                "users": [{
                    "id": "u1",
                    "name": "User",
                    "token": "user-token",
                    "enabled": True,
                    "allocations": {"custom_nodes": ["*"]},
                    "template_id": "builtin",
                    "sub_cache": copy.deepcopy(stale_cache),
                }],
                "admin_tokens": [],
                "templates": [],
                "source_order": ["custom_nodes"],
                "proxy_chains": [],
            }
            client = self.make_client(config, yaml_source_dir=tempdir)

            response = client.get(
                "/sub?token=user-token",
                headers={"user-agent": "clash"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.text, "STALE_CACHE_CONTENT")
        self.assertIn("Node A", response.text)
        self.assertEqual(config["users"][0]["sub_cache"], stale_cache)

    def test_base64_export_skips_chain_nodes_and_keeps_leaf_links(self):
        leaf = {
            "name": "Leaf Node",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
        }
        chain = {
            "name": "🔗 NYC家宽",
            "type": "http",
            "server": "127.0.0.2",
            "port": 8081,
            "dialer-proxy": "Transit Node",
        }

        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": [leaf, chain]}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {},
                "subscriptions": [],
                "custom_nodes": [leaf, chain],
                "users": [],
                "admin_tokens": [{
                    "id": "admin_1",
                    "name": "Admin",
                    "token": "admin-token",
                    "enabled": True,
                    "template_id": "builtin",
                }],
                "templates": [],
                "source_order": ["custom_nodes"],
                "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=v2ray"
            )

        self.assertEqual(response.status_code, 200)
        decoded = base64.b64decode(response.text).decode()
        self.assertIn("vless://11111111-1111-1111-1111-111111111111@example.com:443", decoded)
        self.assertNotIn("NYC", decoded)

    def test_legacy_base64_alias_still_returns_v2ray_payload(self):
        node = {
            "name": "Leaf Node",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
        }
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": [node]}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {},
                "subscriptions": [],
                "custom_nodes": [node],
                "users": [],
                "admin_tokens": [{"id": "admin_1", "name": "Admin", "token": "admin-token", "enabled": True}],
                "templates": [],
                "source_order": ["custom_nodes"],
                "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=base64"
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("vless://11111111-1111-1111-1111-111111111111@example.com:443", base64.b64decode(response.text).decode())

    def test_protocol_path_returns_same_payload_as_format_query(self):
        node = {
            "name": "Leaf Node",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
        }
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": [node]}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {}, "subscriptions": [], "custom_nodes": [node], "users": [],
                "admin_tokens": [{"id": "admin_1", "name": "Admin", "token": "admin-token", "enabled": True}],
                "templates": [], "source_order": ["custom_nodes"], "proxy_chains": [],
            }
            client = self.make_client(config, yaml_source_dir=tempdir)
            query_response = client.get("/sub?token=admin-token&format=v2ray")
            path_response = client.get("/sub/v2ray?token=admin-token")

        self.assertEqual(path_response.status_code, 200)
        self.assertEqual(path_response.text, query_response.text)

    def test_v2ray_export_skips_unsupported_standalone_nodes_and_keeps_leaf_links(self):
        supported = {
            "name": "Supported",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
        }
        unsupported = {
            "name": "Unsupported",
            "type": "http",
            "server": "secret.example.com",
            "port": 8443,
            "password": "must-not-leak",
        }
        nodes = [supported, unsupported]
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": nodes}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {}, "subscriptions": [], "custom_nodes": nodes, "users": [],
                "admin_tokens": [{"id": "admin_1", "name": "Admin", "token": "admin-token", "enabled": True}],
                "templates": [], "source_order": ["custom_nodes"], "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=v2ray"
            )

        self.assertEqual(response.status_code, 200)
        decoded = base64.b64decode(response.text).decode()
        self.assertIn("vless://11111111-1111-1111-1111-111111111111@example.com:443", decoded)
        self.assertEqual(response.headers["x-v2ray-skipped-nodes"], "1")
        self.assertIn("unsupported_http", response.headers["x-v2ray-export-diagnostics"])
        self.assertNotIn("secret.example.com", response.text)
        self.assertNotIn("must-not-leak", response.text)

    def test_v2ray_export_returns_safe_issues_when_no_nodes_are_exportable(self):
        unsupported = {
            "name": "Unsupported",
            "type": "http",
            "server": "secret.example.com",
            "port": 8443,
            "password": "must-not-leak",
        }
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": [unsupported]}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {}, "subscriptions": [], "custom_nodes": [unsupported], "users": [],
                "admin_tokens": [{"id": "admin_1", "name": "Admin", "token": "admin-token", "enabled": True}],
                "templates": [], "source_order": ["custom_nodes"], "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=v2ray"
            )

        self.assertEqual(response.status_code, 422)
        detail = response.json()["detail"]
        self.assertEqual(detail["count"], 1)
        self.assertTrue(detail["issues"][0]["name"].endswith("Unsupported"))
        self.assertEqual(detail["issues"][0]["type"], "http")
        self.assertNotIn("secret.example.com", response.text)
        self.assertNotIn("must-not-leak", response.text)

    def test_v2ray_export_reports_format_specific_nodes_before_mihomo_filtering(self):
        node = {
            "name": "VLESS PQV",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
            "pqv": "verification-key",
        }
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": [node]}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {}, "subscriptions": [], "custom_nodes": [node], "users": [],
                "admin_tokens": [{"id": "admin_1", "name": "Admin", "token": "admin-token", "enabled": True}],
                "templates": [], "source_order": ["custom_nodes"], "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=v2ray"
            )

        self.assertEqual(response.status_code, 200)
        decoded = base64.b64decode(response.text).decode()
        self.assertIn("vless://", decoded)
        self.assertIn("pqv=verification-key", decoded)
        self.assertEqual(response.headers["x-v2ray-skipped-nodes"], "0")

    def test_socks_export_allocates_ports_and_serializes_multiline_yaml(self):
        nodes = [
            {"name": "Node A", "type": "http", "server": "127.0.0.1", "port": 8080},
            {"name": "Node B", "type": "http", "server": "127.0.0.2", "port": 8081},
            {"name": "Node C", "type": "http", "server": "127.0.0.3", "port": 8082},
        ]
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": nodes}, sort_keys=False), encoding="utf-8"
            )
            config = {
                "auth": {}, "subscriptions": [], "custom_nodes": nodes, "users": [],
                "admin_tokens": [{"id": "admin_1", "name": "Admin", "token": "admin-token", "enabled": True}],
                "templates": [], "source_order": ["custom_nodes"], "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=socks&start_port=42000&exclude_ports=42002"
            )
        self.assertEqual(response.status_code, 200)
        rendered = yaml.safe_load(response.text)
        self.assertEqual([listener["port"] for listener in rendered["listeners"]], [42000, 42001, 42003])
        self.assertIn("- name: mixed0", response.text)
        self.assertNotIn('- {"name"', response.text)

    def test_socks_export_skips_traffic_summary_nodes_before_allocating_ports(self):
        nodes = [
            {"name": " 📊 总计 | 72.6MB/160GB", "type": "http", "server": "1.0.0.1", "port": 65535},
            {"name": "🇺🇸 Custom US-xhttp-reality", "type": "http", "server": "127.0.0.1", "port": 8080},
        ]
        rendered = build_socks_config(
            nodes,
            [],
            start_port=42000,
            excluded_ports=set(),
            dns_config={"enable": True},
            clean_proxy=dict,
        )
        self.assertEqual([listener["port"] for listener in rendered["listeners"]], [42000])
        self.assertEqual(
            [listener["proxy"] for listener in rendered["listeners"]],
            ["🇺🇸 Custom US-xhttp-reality"],
        )
        self.assertEqual(
            [proxy["name"] for proxy in rendered["proxies"]],
            ["🇺🇸 Custom US-xhttp-reality"],
        )

    def test_singbox_export_returns_json_with_vless_and_socks_auth(self):
        nodes = [
            {"name": "VLESS", "type": "vless", "server": "example.com", "port": 443, "uuid": "u", "tls": True},
            {"name": "SOCKS", "type": "socks5", "server": "127.0.0.1", "port": 1080, "username": "user", "password": "pass"},
        ]
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": nodes}, sort_keys=False), encoding="utf-8"
            )
            config = {
                "auth": {}, "subscriptions": [], "custom_nodes": nodes, "users": [],
                "admin_tokens": [{"id": "admin_1", "name": "Admin", "token": "admin-token", "enabled": True}],
                "templates": [], "source_order": ["custom_nodes"], "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=singbox"
            )
        self.assertEqual(response.status_code, 200)
        rendered = json.loads(response.text)
        outbounds = {item["tag"]: item for item in rendered["outbounds"] if "tag" in item}
        socks_outbound = next(item for item in outbounds.values() if item["type"] == "socks")
        self.assertEqual(socks_outbound["username"], "user")
        self.assertEqual(socks_outbound["password"], "pass")

    def test_singbox_export_preserves_http_headers_and_uses_current_route_schema(self):
        nodes = [{
            "name": "HTTP VLESS",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "http",
            "http-opts": {
                "path": "/proxy",
                "headers": {"Host": ["cdn.example.com"], "X-Test": ["enabled"]},
            },
            "tls": True,
        }]
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": nodes}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {}, "subscriptions": [], "custom_nodes": nodes, "users": [],
                "admin_tokens": [{"id": "admin_1", "name": "Admin", "token": "admin-token", "enabled": True}],
                "templates": [], "source_order": ["custom_nodes"], "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=singbox"
            )

        self.assertEqual(response.status_code, 200)
        rendered = json.loads(response.text)
        node = next(
            item
            for item in rendered["outbounds"]
            if item.get("type") == "vless" and item.get("transport", {}).get("type") == "http"
        )
        self.assertEqual(node["transport"]["headers"]["Host"], ["cdn.example.com"])
        self.assertEqual(node["transport"]["headers"]["X-Test"], ["enabled"])
        self.assertEqual(rendered["route"], {"final": "PROXY", "auto_detect_interface": True})

    def test_singbox_export_renames_reserved_tags_without_dangling_group_members(self):
        nodes = [
            {"name": "PROXY", "type": "http", "server": "127.0.0.1", "port": 8080},
            {"name": "Node", "type": "http", "server": "127.0.0.2", "port": 8081},
        ]
        rendered, skipped = build_singbox_config_with_diagnostics(
            nodes,
            [{"name": "PROXY", "type": "select", "proxies": ["PROXY", "Node"]}],
        )
        self.assertEqual(skipped, ())
        tags = {item["tag"] for item in rendered["outbounds"] if "tag" in item}
        self.assertIn("PROXY", tags)
        self.assertIn("PROXY (sing-box)", tags)
        for outbound in rendered["outbounds"]:
            for member in outbound.get("outbounds", []):
                self.assertIn(member, tags)

    def test_singbox_export_rejects_hysteria2_full_certificate_pin(self):
        supported = {
            "name": "VLESS",
            "type": "vless",
            "server": "example.net",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
        }
        pinned = {
            "name": "HY2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "tls": True,
            "fingerprint": "0123456789abcdef" * 4,
        }
        rendered, skipped = build_singbox_config_with_diagnostics(
            [supported, pinned],
            [],
        )
        self.assertNotIn(
            "HY2",
            {item.get("tag") for item in rendered["outbounds"]},
        )
        self.assertEqual([item.name for item in skipped], ["HY2"])
        self.assertIn("full-certificate SHA-256 pin", skipped[0].reason)

    def test_singbox_export_preserves_supported_advanced_options(self):
        nodes = [
            {
                "name": "HY2 options",
                "type": "hysteria2",
                "server": "example.com",
                "port": 443,
                "password": "secret",
                "ports": "20000-50000",
                "hop-interval": 30,
                "up": "200 Mbps",
                "down": "1000",
            },
            {
                "name": "AnyTLS options",
                "type": "anytls",
                "server": "example.net",
                "port": 443,
                "password": "secret",
                "idle-session-check-interval": 30,
                "idle-session-timeout": "45s",
                "min-idle-session": 2,
                "udp-over-tcp": True,
            },
            {
                "name": "VLESS early data",
                "type": "vless",
                "server": "example.org",
                "port": 443,
                "uuid": "11111111-1111-1111-1111-111111111111",
                "tls": True,
                "network": "ws",
                "ws-opts": {
                    "path": "/ws",
                    "max-early-data": 2048,
                    "early-data-header-name": "Sec-WebSocket-Protocol",
                },
            },
        ]
        rendered, skipped = build_singbox_config_with_diagnostics(nodes, [])
        self.assertEqual(skipped, ())
        outbounds = {item.get("tag"): item for item in rendered["outbounds"]}
        hy2 = outbounds["HY2 options"]
        self.assertNotIn("server_port", hy2)
        self.assertEqual(hy2["server_ports"], ["20000:50000"])
        self.assertEqual(hy2["hop_interval"], "30s")
        self.assertEqual(hy2["up_mbps"], 200)
        self.assertEqual(hy2["down_mbps"], 1000)
        anytls = outbounds["AnyTLS options"]
        self.assertEqual(anytls["idle_session_check_interval"], "30s")
        self.assertEqual(anytls["idle_session_timeout"], "45s")
        self.assertEqual(anytls["min_idle_session"], 2)
        ws = outbounds["VLESS early data"]["transport"]
        self.assertEqual(ws["max_early_data"], 2048)
        self.assertEqual(ws["early_data_header_name"], "Sec-WebSocket-Protocol")

    def test_singbox_export_preserves_lossless_protocol_options_and_rejects_runtime_only_fields(self):
        nodes = [
            {
                "name": "HY2 single port",
                "type": "hysteria2",
                "server": "example.com",
                "port": 443,
                "password": "secret",
                "ports": "443",
                "hop-interval": "10",
                "tls": True,
            },
            {
                "name": "VMess options",
                "type": "vmess",
                "server": "example.com",
                "port": 443,
                "uuid": "11111111-1111-1111-1111-111111111111",
                "global-padding": True,
                "authenticated-length": True,
                "packet-encoding": "xudp",
            },
            {
                "name": "HTTP Upgrade runtime",
                "type": "vless",
                "server": "example.com",
                "port": 443,
                "uuid": "22222222-2222-2222-2222-222222222222",
                "network": "ws",
                "ws-opts": {"v2ray-http-upgrade": True, "max-early-data": 1},
            },
            {
                "name": "gRPC runtime",
                "type": "vless",
                "server": "example.com",
                "port": 443,
                "uuid": "33333333-3333-3333-3333-333333333333",
                "network": "grpc",
                "grpc-opts": {"grpc-service-name": "svc", "ping-interval": 10},
            },
            {
                "name": "TUIC IP override",
                "type": "tuic",
                "server": "example.com",
                "port": 443,
                "uuid": "44444444-4444-4444-4444-444444444444",
                "password": "secret",
                "ip": "192.0.2.1",
            },
        ]

        rendered, diagnostics = build_singbox_config_with_diagnostics(nodes, [])
        outbounds = {item.get("tag"): item for item in rendered["outbounds"]}

        self.assertEqual(outbounds["HY2 single port"]["server_ports"], ["443:443"])
        self.assertEqual(outbounds["HY2 single port"]["hop_interval"], "10s")
        self.assertTrue(outbounds["VMess options"]["global_padding"])
        self.assertTrue(outbounds["VMess options"]["authenticated_length"])
        self.assertEqual(outbounds["VMess options"]["packet_encoding"], "xudp")
        self.assertEqual(
            {item.name for item in diagnostics if item.kind == "node"},
            {"HTTP Upgrade runtime", "gRPC runtime", "TUIC IP override"},
        )

    def test_singbox_export_preserves_shadowsocks_plugin_and_udp_over_tcp(self):
        rendered, skipped = build_singbox_config_with_diagnostics(
            [{
                "name": "SS plugin",
                "type": "ss",
                "server": "example.com",
                "port": 443,
                "cipher": "aes-128-gcm",
                "password": "secret",
                "plugin": "v2ray-plugin",
                "plugin-opts": {
                    "mode": "websocket",
                    "host": "cdn.example.com",
                    "path": "/proxy",
                    "tls": True,
                    "mux": False,
                },
                "udp-over-tcp": True,
                "udp-over-tcp-version": 2,
            }],
            [],
        )
        self.assertEqual(skipped, ())
        outbound = next(item for item in rendered["outbounds"] if item.get("tag") == "SS plugin")
        self.assertEqual(outbound["plugin"], "v2ray-plugin")
        self.assertIn("host=cdn.example.com", outbound["plugin_opts"])
        self.assertEqual(outbound["udp_over_tcp"], {"enabled": True, "version": 2})

    def test_singbox_export_maps_tuic_disable_sni_and_rejects_udp_mode_conflict(self):
        supported = {
            "name": "TUIC",
            "type": "tuic",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "password": "secret",
            "disable-sni": True,
            "reduce-rtt": True,
            "heartbeat-interval": 10000,
        }
        conflict = {
            **supported,
            "name": "TUIC conflict",
            "udp-over-stream": True,
            "udp-relay-mode": "quic",
        }
        rendered, skipped = build_singbox_config_with_diagnostics(
            [supported, conflict], []
        )
        outbound = next(item for item in rendered["outbounds"] if item.get("tag") == "TUIC")
        self.assertTrue(outbound["tls"]["disable_sni"])
        self.assertTrue(outbound["zero_rtt_handshake"])
        self.assertEqual(outbound["heartbeat"], "10000ms")
        self.assertEqual([item.name for item in skipped], ["TUIC conflict"])

    def test_singbox_export_supports_hysteria2_gecko_obfuscation(self):
        supported = {
            "name": "Supported",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
        }
        gecko = {
            "name": "HY2 gecko",
            "type": "hysteria2",
            "server": "example.net",
            "port": 443,
            "password": "secret",
            "obfs": "gecko",
            "obfs-password": "secret",
        }
        rendered, skipped = build_singbox_config_with_diagnostics([supported, gecko], [])
        self.assertEqual(skipped, ())
        hy2 = next(item for item in rendered["outbounds"] if item.get("tag") == "HY2 gecko")
        self.assertEqual(hy2["obfs"], {
            "type": "gecko",
            "password": "secret",
            "min_packet_size": 512,
            "max_packet_size": 1200,
        })

    def test_singbox_export_rejects_unrepresentable_tls_extensions(self):
        supported = {
            "name": "Supported",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
        }
        rejected = [
            {**supported, "name": "PQV", "pqv": "verification-key"},
            {**supported, "name": "FinalMask", "finalmask": "{}"},
            {**supported, "name": "Reality spider", "reality-opts": {
                "public-key": "key", "short-id": "abcd", "spider-x": "/spider"
            }},
        ]
        rendered, skipped = build_singbox_config_with_diagnostics([supported, *rejected], [])
        self.assertIn("Supported", {item.get("tag") for item in rendered["outbounds"]})
        self.assertEqual([item.name for item in skipped], ["PQV", "FinalMask", "Reality spider"])

    def test_singbox_export_enables_implicit_tls_protocols_without_source_flag(self):
        rendered, skipped = build_singbox_config_with_diagnostics(
            [
                {
                    "name": "HY2 implicit TLS",
                    "type": "hysteria2",
                    "server": "example.com",
                    "port": 443,
                    "password": "hy2-secret",
                },
                {
                    "name": "Trojan implicit TLS",
                    "type": "trojan",
                    "server": "example.net",
                    "port": 443,
                    "password": "trojan-secret",
                },
            ],
            [],
        )
        self.assertEqual(skipped, ())
        outbounds = {item.get("tag"): item for item in rendered["outbounds"]}
        self.assertEqual(outbounds["HY2 implicit TLS"]["tls"], {"enabled": True})
        self.assertEqual(outbounds["Trojan implicit TLS"]["tls"], {"enabled": True})

    def test_singbox_export_distinguishes_transport_and_network_filter_semantics(self):
        rendered, skipped = build_singbox_config_with_diagnostics(
            [
                {
                    "name": "VLESS WS",
                    "type": "vless",
                    "server": "example.com",
                    "port": 443,
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "tls": True,
                    "network": "ws",
                    "ws-opts": {"path": "/ws"},
                },
                {
                    "name": "HY2 UDP only",
                    "type": "hysteria2",
                    "server": "example.net",
                    "port": 443,
                    "password": "secret",
                    "network": "udp",
                },
                {
                    "name": "SS TCP only",
                    "type": "ss",
                    "server": "example.org",
                    "port": 8388,
                    "cipher": "aes-128-gcm",
                    "password": "secret",
                    "network": ["tcp"],
                },
            ],
            [],
        )
        self.assertEqual(skipped, ())
        outbounds = {item.get("tag"): item for item in rendered["outbounds"]}
        self.assertEqual(outbounds["VLESS WS"]["transport"]["type"], "ws")
        self.assertNotIn("network", outbounds["VLESS WS"])
        self.assertEqual(outbounds["HY2 UDP only"]["network"], ["udp"])
        self.assertNotIn("transport", outbounds["HY2 UDP only"])
        self.assertEqual(outbounds["SS TCP only"]["network"], ["tcp"])

    def test_singbox_export_requires_embedded_client_certificate_key_pair(self):
        supported = {
            "name": "Supported",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
        }
        incomplete = {
            **supported,
            "name": "Incomplete mTLS",
            "certificate": "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
        }
        paths = {
            **supported,
            "name": "Path mTLS",
            "certificate": "/etc/client.crt",
            "private-key": "/etc/client.key",
        }
        _, skipped = build_singbox_config_with_diagnostics([supported, incomplete, paths], [])
        self.assertEqual([item.name for item in skipped], ["Incomplete mTLS", "Path mTLS"])
        self.assertIn("provided together", skipped[0].reason)
        self.assertIn("cannot be embedded", skipped[1].reason)

    def test_singbox_export_reports_group_approximations_without_breaking_json(self):
        node = {"name": "Node", "type": "http", "server": "127.0.0.1", "port": 8080}
        rendered, diagnostics = build_singbox_config_with_diagnostics(
            [node],
            [
                {"name": "Fallback", "type": "fallback", "proxies": ["Node"]},
                {"name": "Balanced", "type": "load-balance", "proxies": ["Node"]},
            ],
        )
        groups = {item.get("tag"): item for item in rendered["outbounds"]}
        self.assertEqual(groups["Fallback"]["type"], "selector")
        self.assertEqual(groups["Balanced"]["type"], "selector")
        self.assertEqual([item.kind for item in diagnostics], ["group", "group"])
        self.assertTrue(all("approximated" in item.reason for item in diagnostics))

    def test_singbox_http_response_exposes_safe_limited_diagnostics(self):
        nodes = [
            {"name": "HTTP", "type": "http", "server": "127.0.0.1", "port": 8080},
            {
                "name": "Pinned\r\nHeader",
                "type": "hysteria2",
                "server": "example.com",
                "port": 443,
                "password": "secret",
                "fingerprint": "01" * 32,
            },
        ]
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": nodes}, sort_keys=False), encoding="utf-8"
            )
            config = {
                "auth": {}, "subscriptions": [], "custom_nodes": nodes, "users": [],
                "admin_tokens": [{"id": "admin_1", "name": "Admin", "token": "admin-token", "enabled": True}],
                "templates": [], "source_order": ["custom_nodes"], "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=singbox"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["x-singbox-skipped-nodes"], "1")
        header = response.headers["x-singbox-export-diagnostics"]
        self.assertLessEqual(len(header), 2048)
        self.assertNotIn("\r", header)
        self.assertNotIn("\n", header)
        decoded = unquote(header)
        self.assertIn("node:", decoded)
        self.assertIn("Pinned Header", decoded)
        self.assertIn("full-certificate SHA-256 pin", decoded)
        self.assertIn("group:", decoded)
        self.assertIn("approximated as a manual selector", decoded)

    def test_singbox_diagnostics_never_expose_vless_encryption_value(self):
        sensitive_encryption = "mlkem768plus-PRIVATE-KEY-MATERIAL-" + "A" * 256
        nodes = [
            {"name": "HTTP", "type": "http", "server": "127.0.0.1", "port": 8080},
            {
                "name": "VLESS MLKEM",
                "type": "vless",
                "server": "example.com",
                "port": 443,
                "uuid": "11111111-1111-1111-1111-111111111111",
                "tls": True,
                "encryption": sensitive_encryption,
            },
        ]
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": nodes}, sort_keys=False), encoding="utf-8"
            )
            config = {
                "auth": {}, "subscriptions": [], "custom_nodes": nodes, "users": [],
                "admin_tokens": [{"id": "admin_1", "name": "Admin", "token": "admin-token", "enabled": True}],
                "templates": [], "source_order": ["custom_nodes"], "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=singbox"
            )

        self.assertEqual(response.status_code, 200)
        decoded = unquote(response.headers["x-singbox-export-diagnostics"])
        self.assertIn("unsupported VLESS encryption field", decoded)
        self.assertNotIn(sensitive_encryption, response.headers["x-singbox-export-diagnostics"])
        self.assertNotIn(sensitive_encryption, decoded)
        self.assertNotIn("PRIVATE-KEY-MATERIAL", decoded)

    def test_singbox_export_skips_socks_tls_instead_of_emitting_invalid_config(self):
        rendered, skipped = build_singbox_config_with_diagnostics(
            [
                {
                    "name": "SOCKS TLS",
                    "type": "socks5",
                    "server": "example.com",
                    "port": 443,
                    "tls": True,
                },
                {
                    "name": "HTTP TLS",
                    "type": "http",
                    "server": "example.com",
                    "port": 443,
                    "tls": True,
                },
            ],
            [],
        )
        tags = {item.get("tag") for item in rendered["outbounds"]}
        self.assertNotIn("SOCKS TLS", tags)
        self.assertIn("HTTP TLS", tags)
        self.assertEqual([item.name for item in skipped], ["SOCKS TLS"])

    def test_socks_export_omits_proxy_groups_for_direct_listeners(self):
        rendered = build_socks_config(
            [{"name": "Node", "type": "http", "server": "127.0.0.1", "port": 8080}],
            [
                {"name": "Outer", "type": "select", "proxies": ["DIRECT", "Inner"]},
                {"name": "Inner", "type": "select", "proxies": ["Node"]},
            ],
            start_port=42000,
            excluded_ports=set(),
            dns_config={"enable": True},
            clean_proxy=dict,
        )
        self.assertNotIn("proxy-groups", rendered)

    def test_socks_export_keeps_groups_referenced_by_dialer_proxy(self):
        rendered = build_socks_config(
            [
                {
                    "name": "Transit Node",
                    "type": "http",
                    "server": "127.0.0.1",
                    "port": 8080,
                },
                {
                    "name": "🔗 NYC家宽",
                    "type": "http",
                    "server": "127.0.0.2",
                    "port": 8081,
                    "dialer-proxy": "🔀 NYC家宽 中转池",
                },
            ],
            [
                {
                    "name": "🔀 NYC家宽 中转池",
                    "type": "fallback",
                    "proxies": ["Transit Node"],
                    "url": "https://cp.cloudflare.com/generate_204",
                    "interval": 300,
                },
                {"name": "Unrelated", "type": "select", "proxies": ["Transit Node"]},
            ],
            start_port=42000,
            excluded_ports=set(),
            dns_config={"enable": True},
            clean_proxy=dict,
        )

        groups = {group["name"]: group for group in rendered["proxy-groups"]}
        self.assertEqual(groups["🔀 NYC家宽 中转池"]["proxies"], ["Transit Node"])
        self.assertNotIn("Unrelated", groups)
        self.assertEqual(rendered["listeners"][1]["proxy"], "🔗 NYC家宽")

    def test_socks_export_rejects_missing_dialer_proxy_reference(self):
        with self.assertRaisesRegex(
            SocksExportError,
            r"Proxy \[Chain\] dialer-proxy \[Missing Pool\] not found",
        ):
            build_socks_config(
                [
                    {
                        "name": "Chain",
                        "type": "http",
                        "server": "127.0.0.1",
                        "port": 8080,
                        "dialer-proxy": "Missing Pool",
                    }
                ],
                [],
                start_port=42000,
                excluded_ports=set(),
                dns_config={"enable": True},
                clean_proxy=dict,
            )

    def test_admin_token_group_configuration_changes_generated_yaml(self):
        node_a = {
            "name": "Node A",
            "type": "http",
            "server": "127.0.0.1",
            "port": 8080,
        }
        node_b = {
            "name": "Node B",
            "type": "http",
            "server": "127.0.0.2",
            "port": 8081,
        }
        selected_name = NameTransformer.transform_name(node_a, "Custom")["name"]

        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": [node_a, node_b]}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {},
                "subscriptions": [],
                "custom_nodes": [node_a, node_b],
                "users": [],
                "admin_tokens": [{
                    "id": "admin_1",
                    "name": "Admin",
                    "token": "admin-token",
                    "enabled": True,
                    "template_id": "tpl_custom",
                    "group_config": {"Manual": [selected_name]},
                }],
                "templates": [{
                    "id": "tpl_custom",
                    "name": "Custom",
                    "header": "mixed-port: 7890\n",
                    "suffix": "",
                    "proxy_groups": [{
                        "name": "Manual",
                        "type": "select",
                        "proxies": [],
                    }],
                }],
                "source_order": ["custom_nodes"],
                "proxy_chains": [],
            }
            client = self.make_client(config, yaml_source_dir=tempdir)

            response = client.get("/sub?token=admin-token&format=clash")

        self.assertEqual(response.status_code, 200)
        rendered = yaml.safe_load(response.text)
        manual_group = next(
            group for group in rendered["proxy-groups"]
            if group["name"] == "Manual"
        )
        self.assertEqual(manual_group["proxies"], [selected_name])

    def test_builtin_group_configuration_targets_the_groups_in_generated_yaml(self):
        node_a = {
            "name": "Node A",
            "type": "http",
            "server": "127.0.0.1",
            "port": 8080,
        }
        node_b = {
            "name": "Node B",
            "type": "http",
            "server": "127.0.0.2",
            "port": 8081,
        }
        selected_name = NameTransformer.transform_name(node_a, "Custom")["name"]

        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": [node_a, node_b]}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {},
                "subscriptions": [],
                "custom_nodes": [node_a, node_b],
                "users": [],
                "admin_tokens": [{
                    "id": "admin_1",
                    "name": "Admin",
                    "token": "admin-token",
                    "enabled": True,
                    "template_id": "builtin",
                    "group_config": {"🚀 手动选择": [selected_name]},
                }],
                "templates": [],
                "source_order": ["custom_nodes"],
                "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=clash"
            )

        self.assertEqual(response.status_code, 200)
        rendered = yaml.safe_load(response.text)
        manual_group = next(
            group for group in rendered["proxy-groups"]
            if group["name"] == "🚀 手动选择"
        )
        self.assertEqual(manual_group["proxies"], [selected_name])

    def test_clash_export_omits_traffic_summary_pseudo_nodes(self):
        node = {
            "name": "Real Node",
            "type": "http",
            "server": "127.0.0.1",
            "port": 8080,
        }

        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "sub_demo.yaml").write_text(
                yaml.safe_dump({"proxies": [node]}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {"sub_name": "Aggregated"},
                "subscriptions": [{
                    "id": "sub_demo",
                    "name": "Demo",
                    "enabled": True,
                    "upload": 1024,
                    "download": 2048,
                    "total": 10240,
                    "expire": 0,
                }],
                "custom_nodes": [],
                "users": [],
                "admin_tokens": [{
                    "id": "admin_1",
                    "name": "Admin",
                    "token": "admin-token",
                    "enabled": True,
                }],
                "templates": [],
                "source_order": ["sub_demo"],
                "proxy_chains": [],
            }
            response = self.make_client(config, yaml_source_dir=tempdir).get(
                "/sub?token=admin-token&format=clash"
            )

        self.assertEqual(response.status_code, 200)
        rendered = yaml.safe_load(response.text)
        proxy_names = [proxy["name"] for proxy in rendered["proxies"]]
        self.assertEqual(len(proxy_names), 1)
        self.assertIn("Demo Real Node", proxy_names[0])
        self.assertTrue(all(not name.startswith("📊") for name in proxy_names))
        for group in rendered["proxy-groups"]:
            self.assertTrue(all(
                not str(name).startswith("📊")
                for name in group.get("proxies", [])
            ))
        self.assertIn("upload=1024; download=2048; total=10240; expire=0", response.headers["subscription-userinfo"])

    def test_stable_chain_pool_reference_survives_template_name_collision(self):
        node_a = {
            "id": "custom_a",
            "name": "Node A",
            "type": "http",
            "server": "127.0.0.1",
            "port": 8080,
        }
        node_b = {
            "id": "custom_b",
            "name": "Node B",
            "type": "http",
            "server": "127.0.0.2",
            "port": 8081,
        }
        transformed_nodes = {
            node["id"]: NameTransformer.transform_name(node, "Custom")
            for node in (node_a, node_b)
        }
        pool_reference_id = proxy_chain_virtual_node_id(
            "chain_pools",
            "chain_1",
            "grp_pool_abcd",
        )

        def find_node(_source_id, _node_index, _node_name, *, node_id=None):
            node = transformed_nodes.get(node_id)
            return copy.deepcopy(node) if node else None

        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "custom_nodes.yaml").write_text(
                yaml.safe_dump({"proxies": [node_a, node_b]}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {},
                "subscriptions": [],
                "custom_nodes": [node_a, node_b],
                "users": [],
                "admin_tokens": [{
                    "id": "admin_1",
                    "name": "Admin",
                    "token": "admin-token",
                    "enabled": True,
                    "template_id": "tpl_custom",
                    "group_config": {"Manual": [pool_reference_id]},
                }],
                "templates": [{
                    "id": "tpl_custom",
                    "name": "Custom",
                    "header": "mixed-port: 7890\n",
                    "suffix": "",
                    "proxy_groups": [
                        {"name": "Manual", "type": "select", "proxies": []},
                        {"name": "🔀 Exit Pool", "type": "select", "proxies": ["DIRECT"]},
                    ],
                }],
                "source_order": ["custom_nodes"],
                "proxy_chains": [{
                    "id": "chain_1",
                    "name": "Chain",
                    "enabled": True,
                    "rows": [{
                        "row_id": "row_1",
                        "nodes": [
                            {
                                "type": "node",
                                "sub_id": "custom",
                                "node_id": "custom_a",
                                "node_name": "Node A",
                            },
                            {
                                "type": "group",
                                "group_id": "grp_pool_abcd",
                                "group_name": "Exit Pool",
                                "group_nodes": [{
                                    "type": "node",
                                    "sub_id": "custom",
                                    "node_id": "custom_b",
                                    "node_name": "Node B",
                                }],
                            },
                        ],
                    }],
                }],
                "port_mappings": {pool_reference_id: 42000},
            }
            response = self.make_client(
                config,
                yaml_source_dir=tempdir,
                find_node_by_reference=find_node,
            ).get("/sub?token=admin-token&format=clash")

        self.assertEqual(response.status_code, 200)
        rendered = yaml.safe_load(response.text)
        groups = {group["name"]: group for group in rendered["proxy-groups"]}
        generated_pool_name = "🔀 Exit Pool (abcd)"
        self.assertIn("🔀 Exit Pool", groups)
        self.assertIn(generated_pool_name, groups)
        self.assertEqual(groups["Manual"]["proxies"], [generated_pool_name])
        self.assertEqual(rendered["listeners"][0]["proxy"], generated_pool_name)

    def test_user_chain_allocation_does_not_leak_dependencies_from_unallocated_rows(self):
        node_a = {
            "id": "custom_a",
            "name": "Node A",
            "type": "http",
            "server": "a.example",
            "port": 8080,
        }
        node_b = {
            "id": "custom_b",
            "name": "Node B",
            "type": "http",
            "server": "b.example",
            "port": 8081,
        }
        allowed_chain_id = proxy_chain_virtual_node_id("chain_nodes", "chain_allowed", "row_allowed")

        def find_node(_source_id, _node_index, _node_name, *, node_id=None):
            return copy.deepcopy({
                "custom_a": node_a,
                "custom_b": node_b,
            }.get(node_id))

        config = {
            "auth": {},
            "subscriptions": [],
            "custom_nodes": [node_a, node_b],
            "users": [{
                "id": "user_1",
                "name": "User",
                "token": "user-token",
                "enabled": True,
                "allocations": {"chain_nodes": [allowed_chain_id]},
            }],
            "admin_tokens": [],
            "templates": [],
            "source_order": [],
            "proxy_chains": [
                {
                    "id": "chain_allowed",
                    "name": "Allowed",
                    "enabled": True,
                    "rows": [{
                        "row_id": "row_allowed",
                        "nodes": [
                            {"type": "node", "sub_id": "custom", "node_id": "custom_a"},
                            {"type": "node", "sub_id": "custom", "node_id": "custom_a"},
                        ],
                    }],
                },
                {
                    "id": "chain_hidden",
                    "name": "Hidden",
                    "enabled": True,
                    "rows": [{
                        "row_id": "row_hidden",
                        "nodes": [
                            {"type": "node", "sub_id": "custom", "node_id": "custom_b"},
                            {"type": "node", "sub_id": "custom", "node_id": "custom_b"},
                        ],
                    }],
                },
            ],
        }

        with tempfile.TemporaryDirectory() as tempdir:
            response = self.make_client(
                config,
                yaml_source_dir=tempdir,
                find_node_by_reference=find_node,
            ).get("/sub?token=user-token&format=clash")

        self.assertEqual(response.status_code, 200)
        self.assertIn("🔗 Allowed", response.text)
        self.assertIn("a.example", response.text)
        self.assertNotIn("🔗 Hidden", response.text)
        self.assertNotIn("b.example", response.text)
        self.assertNotIn('"id":"custom_a"', response.text)

    def test_user_v2ray_export_does_not_leak_chain_dependencies(self):
        node_a = {
            "id": "custom_a",
            "name": "Node A",
            "type": "http",
            "server": "a.example",
            "port": 8080,
        }
        node_b = {
            "id": "custom_b",
            "name": "Node B",
            "type": "http",
            "server": "b.example",
            "port": 8081,
        }
        chain_id = "chain_private"
        row_id = "row_private"
        allowed_chain_id = proxy_chain_virtual_node_id("chain_nodes", chain_id, row_id)

        def find_node(_source_id, _node_index, _node_name, *, node_id=None):
            return copy.deepcopy({"custom_a": node_a, "custom_b": node_b}.get(node_id))

        config = {
            "auth": {},
            "subscriptions": [],
            "custom_nodes": [],
            "users": [{
                "id": "user_1",
                "name": "User",
                "token": "user-token",
                "enabled": True,
                "allocations": {"chain_nodes": [allowed_chain_id]},
            }],
            "admin_tokens": [],
            "templates": [],
            "source_order": [],
            "proxy_chains": [{
                "id": chain_id,
                "name": "Private",
                "enabled": True,
                "rows": [{
                    "row_id": row_id,
                    "nodes": [
                        {"type": "node", "sub_id": "custom", "node_id": "custom_a"},
                        {"type": "node", "sub_id": "custom", "node_id": "custom_b"},
                    ],
                }],
            }],
        }

        with tempfile.TemporaryDirectory() as tempdir:
            response = self.make_client(
                config,
                yaml_source_dir=tempdir,
                find_node_by_reference=find_node,
            ).get("/sub?token=user-token&format=v2ray")

        self.assertEqual(response.status_code, 422)
        detail = response.json()["detail"]
        self.assertTrue(any(issue["reason"] == "chain_dependency_not_allocated" for issue in detail["issues"]))
        self.assertNotIn("a.example", response.text)
        self.assertNotIn("b.example", response.text)
