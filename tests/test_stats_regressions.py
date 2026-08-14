"""Regression tests for dashboard node statistics."""

import inspect
import unittest
from unittest.mock import patch

import api.stats as stats_api


class DashboardStatsRegressionTests(unittest.TestCase):
    def test_info_node_filter_uses_name_rules_without_structural_validation(self):
        self.assertFalse(stats_api._is_info_node("🇯🇵 Japan 01"))
        self.assertTrue(stats_api._is_info_node("防丢失官网:https://example.com"))

    def test_overview_counts_subscription_nodes_and_best_latency(self):
        config = {
            "subscriptions": [
                {"id": "sub_demo", "name": "Demo", "enabled": True},
            ],
            "custom_nodes": [
                {
                    "name": "Custom US 01",
                    "type": "vmess",
                    "server": "custom.example.com",
                    "port": 443,
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "last_latency": 88,
                },
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
                    "port": 443,
                    "password": "secret",
                },
            ],
        }

        with (
            patch.object(stats_api, "get_overview", return_value=None),
            patch.object(stats_api, "set_overview"),
            patch.object(stats_api, "load_config", return_value=config),
            patch.object(stats_api, "load_subscription_yaml", return_value=subscription),
        ):
            overview = inspect.unwrap(stats_api.get_stats_overview)(True)

        self.assertEqual(overview["nodes"]["total"], 2)
        self.assertEqual(overview["nodes"]["by_protocol"], {"trojan": 1, "vmess": 1})
        self.assertEqual(overview["best_node"]["latency"], 42)
        self.assertEqual(overview["best_node"]["name"], "🇯🇵 Demo Japan 01")


if __name__ == "__main__":
    unittest.main()
