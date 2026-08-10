import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from core.config import AppConfig
from services.custom_node_storage import write_custom_nodes_yaml
from services.link_exporter import proxy_to_link
from services.node_parser import parse_node_link
from services.proxy_filter import ProxyFilter


class Socks5SupportTests(unittest.TestCase):
    def test_standard_socks5_credentials_are_preserved(self):
        node = parse_node_link(
            "socks5://user%40name:p%40ss@example.com:11111#US-NYC"
        )

        self.assertEqual(node["type"], "socks5")
        self.assertEqual(node["server"], "example.com")
        self.assertEqual(node["port"], 11111)
        self.assertEqual(node["username"], "user@name")
        self.assertEqual(node["password"], "p@ss")

    def test_v2rayn_base64_user_info_is_decoded(self):
        encoded_user_info = base64.urlsafe_b64encode(b"user:pass").decode().rstrip("=")
        node = parse_node_link(
            f"socks://{encoded_user_info}@example.com:11111#US-NYC"
        )

        self.assertEqual(node["username"], "user")
        self.assertEqual(node["password"], "pass")

    def test_legacy_v2rayn_base64_authority_is_decoded(self):
        encoded_authority = base64.urlsafe_b64encode(
            b"user:pass@example.com:11111"
        ).decode().rstrip("=")
        node = parse_node_link(f"socks://{encoded_authority}#US-NYC")

        self.assertEqual(node["server"], "example.com")
        self.assertEqual(node["port"], 11111)
        self.assertEqual(node["username"], "user")
        self.assertEqual(node["password"], "pass")

    def test_socks5_query_credentials_are_supported(self):
        node = parse_node_link(
            "socks5://example.com:11111?username=user&password=pass#US-NYC"
        )

        self.assertEqual(node["username"], "user")
        self.assertEqual(node["password"], "pass")

    def test_socks5h_is_normalized_to_mihomo_socks5(self):
        node = parse_node_link("socks5h://user:pass@example.com:11111#US-NYC")

        self.assertEqual(node["type"], "socks5")
        self.assertEqual(node["username"], "user")
        self.assertEqual(node["password"], "pass")

        stored_node = ProxyFilter.sanitize_proxy({
            "name": "US-NYC",
            "type": "socks5h",
            "server": "example.com",
            "port": 11111,
            "username": "user",
            "password": "pass",
        })
        self.assertEqual(stored_node["type"], "socks5")

    def test_socks5_export_round_trips_credentials(self):
        link = proxy_to_link(
            {
                "name": "US-NYC",
                "type": "socks5",
                "server": "example.com",
                "port": 11111,
                "username": "user@name",
                "password": "p:ss",
            }
        )
        node = parse_node_link(link)

        self.assertEqual(node["username"], "user@name")
        self.assertEqual(node["password"], "p:ss")

    def test_custom_node_yaml_export_preserves_credentials(self):
        node = {
            "id": "node_1",
            "link": "socks5://user:pass@example.com:11111#US-NYC",
            "name": "US-NYC",
            "type": "socks5",
            "server": "example.com",
            "port": 11111,
            "username": "user",
            "password": "pass",
        }

        with tempfile.TemporaryDirectory() as tempdir:
            with patch.object(AppConfig, "YAML_SOURCE_DIR", tempdir):
                write_custom_nodes_yaml([node])

            exported = yaml.safe_load(
                Path(tempdir, "custom_nodes.yaml").read_text(encoding="utf-8")
            )

        self.assertEqual(exported["proxies"][0]["username"], "user")
        self.assertEqual(exported["proxies"][0]["password"], "pass")


if __name__ == "__main__":
    unittest.main()
