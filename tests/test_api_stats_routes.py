"""Route-level tests for the dashboard statistics endpoints."""

import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.stats as stats_api
import core.dependencies as core_dependencies
from core.dependencies import verify_session


class StatsRoutesTest(unittest.TestCase):
    def make_client(self):
        app = FastAPI()
        app.dependency_overrides[verify_session] = lambda: True
        app.include_router(stats_api.router, prefix="/api/stats")
        return TestClient(app)

    def test_overview_route_returns_dashboard_counts(self):
        config = {
            "subscriptions": [{"id": "sub_demo", "name": "Demo", "enabled": True}],
            "custom_nodes": [
                {
                    "name": "Custom US 01",
                    "type": "vmess",
                    "server": "custom.example.com",
                    "port": 443,
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "last_latency": 88,
                }
            ],
            "users": [],
            "templates": [],
            "admin_tokens": [],
        }
        subscription = {
            "proxies": [
                {
                    "name": "Japan 01",
                    "type": "trojan",
                    "server": "node.example.com",
                    "port": 443,
                    "password": "secret",
                    "last_latency": 42,
                },
                {
                    "name": "防丢失官网:https://example.com",
                    "type": "trojan",
                    "server": "info.example.com",
                    "password": "secret",
                },
            ]
        }

        with (
            patch.object(stats_api, "get_overview", return_value=None),
            patch.object(stats_api, "set_overview"),
            patch.object(stats_api, "load_config", return_value=config),
            patch.object(stats_api, "load_subscription_yaml", return_value=subscription),
        ):
            response = self.make_client().get("/api/stats/overview")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["nodes"]["total"], 2)
        self.assertEqual(body["nodes"]["by_protocol"], {"trojan": 1, "vmess": 1})
        self.assertEqual(body["best_node"]["latency"], 42)
        self.assertEqual(body["subscriptions"], {"total": 1, "active": 1})

    def test_nodes_by_country_route_normalizes_country_code(self):
        empty_config = {"subscriptions": [], "custom_nodes": []}

        with patch.object(stats_api, "load_config", return_value=empty_config):
            response = self.make_client().get("/api/stats/nodes-by-country/jp")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["country_code"], "JP")
        self.assertEqual(body["count"], 0)
        self.assertEqual(body["nodes"], [])

    def test_stats_routes_require_session(self):
        app = FastAPI()
        app.include_router(stats_api.router, prefix="/api/stats")
        client = TestClient(app)

        with patch.object(
            core_dependencies,
            "load_config",
            return_value={"auth": {"password_hash": "set", "sessions": {}}},
        ):
            response = client.get("/api/stats/overview")

        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
