"""Regression tests for the VPN Gate dynamic node source."""

import base64
import copy
import logging
import tempfile
import unittest
from unittest.mock import patch

import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.node_metadata import strip_node_metadata
from services.node_manager import find_vpngate_node
from services.proxy_filter import ProxyFilter
from services.subscription_output import create_subscription_output_router
from services.vpngate import (
    VpnGateRefreshError,
    _merge_nodes_with_previous_cache,
    parse_vpngate_csv,
    parse_vpngate_record,
    public_vpngate_node,
)


OPENVPN_PROFILE = """client
dev tun
proto udp
remote 198.51.100.10 1194
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
comp-lzo adaptive
<ca>
CA DATA
</ca>
<cert>
CERT DATA
</cert>
<key>
KEY DATA
</key>
<tls-crypt>
TLS DATA
</tls-crypt>
"""


def _record(**overrides):
    record = {
        "HostName": "vpngate.example",
        "IP": "198.51.100.10",
        "CountryShort": "US",
        "Ping": "42",
        "Speed": "100000000",
        "NumVpnSessions": "3",
        "OpenVPN_ConfigData_Base64": base64.b64encode(OPENVPN_PROFILE.encode()).decode(),
    }
    record.update(overrides)
    return record


class VpnGateParsingTests(unittest.TestCase):
    def test_csv_parser_ignores_comments_and_malformed_rows(self):
        content = "\n".join([
            "#comment",
            "#HostName,IP,CountryShort,OpenVPN_ConfigData_Base64",
            "vpngate.example,198.51.100.10,US,encoded",
            "broken,198.51.100.11,US",
            "* end",
        ])

        records = parse_vpngate_csv(content)

        self.assertEqual(records, [{
            "HostName": "vpngate.example",
            "IP": "198.51.100.10",
            "CountryShort": "US",
            "OpenVPN_ConfigData_Base64": "encoded",
        }])

    def test_record_becomes_mihomo_openvpn_and_public_metadata_is_safe(self):
        proxy = parse_vpngate_record(_record())

        self.assertEqual(proxy["type"], "openvpn")
        self.assertEqual(proxy["server"], "198.51.100.10")
        self.assertEqual(proxy["port"], 1194)
        self.assertEqual(proxy["proto"], "udp")
        self.assertEqual(proxy["username"], "vpn")
        self.assertEqual(proxy["password"], "vpn")
        self.assertEqual(proxy["ca"], "CA DATA")
        self.assertEqual(proxy["cert"], "CERT DATA")
        self.assertEqual(proxy["key"], "KEY DATA")
        self.assertEqual(proxy["tls-crypt"], "TLS DATA")
        self.assertTrue(ProxyFilter.is_valid_proxy(proxy))

        public = public_vpngate_node(proxy)
        self.assertEqual(public["node_type"], "openvpn")
        self.assertNotIn("ca", public)
        self.assertNotIn("cert", public)
        self.assertNotIn("key", public)
        self.assertNotIn("password", public)

    def test_id_does_not_change_when_server_rotates_credentials(self):
        first = parse_vpngate_record(_record())
        rotated_profile = OPENVPN_PROFILE.replace("KEY DATA", "ROTATED KEY")
        second = parse_vpngate_record(_record(
            OpenVPN_ConfigData_Base64=base64.b64encode(rotated_profile.encode()).decode(),
        ))

        self.assertEqual(first["id"], second["id"])

    def test_invalid_profile_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_vpngate_record(_record(
                OpenVPN_ConfigData_Base64=base64.b64encode(b"client\nremote 198.51.100.10 1194\n").decode(),
            ))


class VpnGateCacheTests(unittest.TestCase):
    def test_missing_nodes_are_marked_stale_without_replacing_fresh_nodes(self):
        old_node = parse_vpngate_record(_record(IP="198.51.100.11", HostName="old.example"))
        fresh_node = parse_vpngate_record(_record())

        merged = _merge_nodes_with_previous_cache([fresh_node], [old_node], 123)

        by_id = {node["id"]: node for node in merged}
        self.assertFalse(by_id[fresh_node["id"]]["stale"])
        self.assertTrue(by_id[old_node["id"]]["stale"])
        self.assertFalse(by_id[old_node["id"]]["enabled"])

    def test_refresh_failure_preserves_previous_cache(self):
        previous = {
            "nodes": [parse_vpngate_record(_record())],
            "last_success_at": 100,
            "last_attempt_at": 100,
            "last_error": None,
        }
        written = []

        with (
            patch("services.vpngate._get_cache_payload", return_value=copy.deepcopy(previous)),
            patch("services.vpngate._write_cache_payload", side_effect=written.append),
            patch("services.vpngate._download_vpngate_csv", side_effect=VpnGateRefreshError("offline")),
            patch("core.database.load_config", return_value={}),
        ):
            with self.assertRaises(VpnGateRefreshError):
                from services.vpngate import refresh_vpngate_cache

                refresh_vpngate_cache()

        self.assertEqual(written[-1]["nodes"], previous["nodes"])
        self.assertEqual(written[-1]["last_success_at"], 100)
        self.assertEqual(written[-1]["last_error"], "offline")


class VpnGateChainIntegrationTests(unittest.TestCase):
    def test_resolver_keeps_openvpn_material_and_stable_allocation_id(self):
        node = parse_vpngate_record(_record())

        with patch("services.node_manager.list_vpngate_nodes", return_value=[node]):
            resolved = find_vpngate_node(node_id=node["id"])

        self.assertEqual(resolved["type"], "openvpn")
        self.assertEqual(resolved["_allocation_id"], node["id"])
        self.assertEqual(resolved["ca"], "CA DATA")
        self.assertEqual(resolved["key"], "KEY DATA")

    def test_clash_output_supports_custom_front_to_vpngate_landing_node(self):
        front = {
            "id": "front-1",
            "name": "Front",
            "type": "http",
            "server": "front.example",
            "port": 8080,
        }
        landing = parse_vpngate_record(_record())
        resolved_nodes = {
            ("custom", front["id"]): front,
            ("vpngate", landing["id"]): landing,
        }

        def resolve_node(sub_id, _node_index, _node_name, *, node_id=None):
            node = resolved_nodes.get((sub_id, node_id))
            return copy.deepcopy(node) if node else None

        config = {
            "auth": {"sub_token": "admin-token"},
            "subscriptions": [],
            "custom_nodes": [front],
            "users": [],
            "admin_tokens": [],
            "templates": [],
            "source_order": ["custom_nodes"],
            "proxy_chains": [{
                "id": "chain-vpngate",
                "name": "VPN Gate chain",
                "enabled": True,
                "rows": [{
                    "row_id": "row-1",
                    "nodes": [
                        {"type": "node", "sub_id": "custom", "node_id": front["id"]},
                        {"type": "node", "sub_id": "vpngate", "node_id": landing["id"]},
                    ],
                }],
            }],
        }

        app = FastAPI()

        def load_config():
            return copy.deepcopy(config)

        def update_config(mutator):
            return mutator(config)

        app.include_router(create_subscription_output_router(
            yaml_source_dir="/tmp/vpngate-chain-tests",
            output_file="/tmp/vpngate-chain-tests/config.yaml",
            load_config=load_config,
            update_config=update_config,
            fetch_subscription=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("fetch should not run")),
            find_node_by_reference=resolve_node,
            is_name_allocated=lambda *args, **kwargs: False,
            filter_underscore_fields=strip_node_metadata,
            extract_country_from_name=lambda *args, **kwargs: None,
            split_template=lambda content: (content, ""),
            logger=logging.getLogger("test.vpngate.subscription_output"),
        ))

        with tempfile.TemporaryDirectory():
            response = TestClient(app).get("/sub?token=admin-token&format=clash")

        self.assertEqual(response.status_code, 200)
        rendered = yaml.safe_load(response.text)
        landing_proxy = next(proxy for proxy in rendered["proxies"] if proxy["type"] == "openvpn")
        self.assertEqual(landing_proxy["server"], "198.51.100.10")
        self.assertIn("dialer-proxy", landing_proxy)
        self.assertTrue(landing_proxy["dialer-proxy"])

    def test_clash_output_expands_dynamic_vpngate_landing_pool(self):
        front = {
            "id": "front-1",
            "name": "Front",
            "type": "http",
            "server": "front.example",
            "port": 8080,
        }
        landing = parse_vpngate_record(_record())
        resolved_nodes = {
            ("custom", front["id"]): front,
            ("vpngate", landing["id"]): landing,
        }

        def resolve_node(sub_id, _node_index, _node_name, *, node_id=None):
            node = resolved_nodes.get((sub_id, node_id))
            return copy.deepcopy(node) if node else None

        config = {
            "auth": {"sub_token": "admin-token"},
            "subscriptions": [],
            "custom_nodes": [front],
            "users": [],
            "admin_tokens": [],
            "templates": [],
            "source_order": ["custom_nodes"],
            "proxy_chains": [{
                "id": "chain-vpngate-pool",
                "name": "VPN Gate pool chain",
                "enabled": True,
                "rows": [{
                    "row_id": "row-1",
                    "nodes": [
                        {"type": "node", "sub_id": "custom", "node_id": front["id"]},
                        {
                            "type": "group",
                            "group_id": "pool-1",
                            "group_name": "VPN Gate 动态池",
                            "group_source": "vpngate",
                            "group_strategy": "url-test",
                        },
                    ],
                }],
            }],
        }

        app = FastAPI()

        def load_config():
            return copy.deepcopy(config)

        def update_config(mutator):
            return mutator(config)

        app.include_router(create_subscription_output_router(
            yaml_source_dir="/tmp/vpngate-pool-chain-tests",
            output_file="/tmp/vpngate-pool-chain-tests/config.yaml",
            load_config=load_config,
            update_config=update_config,
            fetch_subscription=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("fetch should not run")),
            find_node_by_reference=resolve_node,
            is_name_allocated=lambda *args, **kwargs: False,
            filter_underscore_fields=strip_node_metadata,
            extract_country_from_name=lambda *args, **kwargs: None,
            split_template=lambda content: (content, ""),
            logger=logging.getLogger("test.vpngate.dynamic-pool"),
        ))

        with patch("services.subscription_output.list_vpngate_nodes", return_value=[landing]):
            with tempfile.TemporaryDirectory():
                response = TestClient(app).get("/sub?token=admin-token&format=clash")

        self.assertEqual(response.status_code, 200)
        rendered = yaml.safe_load(response.text)
        pool = next(
            group for group in rendered["proxy-groups"]
            if group.get("name", "").startswith("🔀 VPN Gate 动态池")
        )
        self.assertTrue(pool["proxies"])
        generated_proxy = next(
            proxy for proxy in rendered["proxies"]
            if proxy.get("type") == "openvpn"
        )
        self.assertEqual(generated_proxy["server"], "198.51.100.10")
        self.assertTrue(generated_proxy.get("dialer-proxy"))


if __name__ == "__main__":
    unittest.main()
