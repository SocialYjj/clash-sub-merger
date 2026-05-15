"""Tests for port-mapping active status."""

import copy
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.settings as settings_api
from core.dependencies import verify_session


class PortMappingsRoutesTest(unittest.TestCase):
    def make_client(self, config):
        app = FastAPI()
        app.dependency_overrides[verify_session] = lambda: True
        app.include_router(settings_api.port_mappings_router, prefix="/api/port-mappings")
        return TestClient(app), patch.object(
            settings_api,
            "load_config",
            side_effect=lambda: copy.deepcopy(config),
        )

    def test_chain_node_port_mapping_is_active(self):
        config = {
            "auth": {},
            "subscriptions": [],
            "custom_nodes": [
                {"name": "JP-ws", "type": "vless", "server": "jp.example.com"},
                {"name": "US-reality", "type": "vless", "server": "us.example.com"},
            ],
            "proxy_chains": [
                {
                    "id": "chain_us_home",
                    "name": "美国家宽",
                    "enabled": True,
                    "rows": [
                        {
                            "nodes": [
                                {"sub_id": "custom", "node_index": 0, "node_name": "JP Custom JP-ws"},
                                {"sub_id": "custom", "node_index": 1, "node_name": "US Custom US-reality"},
                            ]
                        }
                    ],
                }
            ],
            "port_mappings": {"🔗 美国家宽": 42000},
        }
        client, load_config_patch = self.make_client(config)

        with load_config_patch:
            response = client.get("/api/port-mappings")

        self.assertEqual(response.status_code, 200)
        mappings = response.json()["mappings"]
        self.assertEqual(mappings, [{"final_name": "🔗 美国家宽", "port": 42000, "active": True}])

    def test_disabled_chain_node_port_mapping_is_inactive(self):
        config = {
            "auth": {},
            "subscriptions": [],
            "custom_nodes": [],
            "proxy_chains": [
                {
                    "id": "chain_us_home",
                    "name": "美国家宽",
                    "enabled": False,
                    "rows": [{"nodes": [{"node_name": "A"}, {"node_name": "B"}]}],
                }
            ],
            "port_mappings": {"🔗 美国家宽": 42000},
        }
        client, load_config_patch = self.make_client(config)

        with load_config_patch:
            response = client.get("/api/port-mappings")

        self.assertEqual(response.status_code, 200)
        mappings = response.json()["mappings"]
        self.assertEqual(mappings, [{"final_name": "🔗 美国家宽", "port": 42000, "active": False}])


if __name__ == "__main__":
    unittest.main()
