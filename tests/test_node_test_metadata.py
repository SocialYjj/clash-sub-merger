"""Regression tests for preserving node test metadata across source refreshes."""

import asyncio
import inspect
import unittest
from unittest.mock import patch

import yaml

from services.region_history import (
    apply_node_test_metadata_to_yaml_content,
    inherit_node_test_metadata,
)


class NodeTestMetadataTests(unittest.TestCase):
    def test_refresh_inherits_region_latency_and_speed_without_overwriting_new_values(self):
        previous = {
            "name": "JP 01",
            "server": "node.example",
            "port": 443,
            "type": "trojan",
            "last_latency": 120,
            "last_latency_time": "2026-08-07 10:00:00",
            "last_speed": 42.5,
            "last_speed_time": "2026-08-07 10:01:00",
            "region": {"country_code": "JP", "country": "Japan", "flag": "🇯🇵"},
            "city": "Tokyo",
            "exit_ip": "192.0.2.10",
            "ip_profile": {
                "exit_ip": "192.0.2.10",
                "ip_source": "native",
                "network_type": "residential",
                "fraud_score": 4,
            },
        }
        refreshed = {
            "name": "JP 01",
            "server": "node.example",
            "port": 443,
            "type": "trojan",
            "last_latency": 88,
        }

        inherited = inherit_node_test_metadata([refreshed], [previous])

        self.assertEqual(inherited, 1)
        self.assertEqual(refreshed["last_latency"], 88)
        self.assertEqual(refreshed["last_speed"], 42.5)
        self.assertEqual(refreshed["region"]["country_code"], "JP")
        self.assertEqual(refreshed["city"], "Tokyo")
        self.assertEqual(refreshed["exit_ip"], "192.0.2.10")
        self.assertEqual(refreshed["ip_profile"]["ip_source"], "native")

    def test_ambiguous_endpoint_does_not_copy_wrong_measurement(self):
        previous = [
            {
                "name": "Line A",
                "server": "shared.example",
                "port": 443,
                "type": "trojan",
                "last_latency": 100,
            },
            {
                "name": "Line B",
                "server": "shared.example",
                "port": 443,
                "type": "trojan",
                "last_latency": 300,
            },
        ]
        refreshed = [{
            "name": "New label",
            "server": "shared.example",
            "port": 443,
            "type": "trojan",
        }]

        self.assertEqual(inherit_node_test_metadata(refreshed, previous), 0)
        self.assertNotIn("last_latency", refreshed[0])

    def test_yaml_refresh_persists_inherited_metadata(self):
        previous = [{
            "name": "US 01",
            "server": "us.example",
            "port": 443,
            "type": "trojan",
            "last_latency": 75,
            "last_speed": 18.2,
            "region": {"country_code": "US", "country": "United States", "flag": "🇺🇸"},
        }]
        content = yaml.safe_dump(
            {"proxies": [{"name": "US 01", "server": "us.example", "port": 443, "type": "trojan"}]},
            allow_unicode=True,
            sort_keys=False,
        )

        refreshed_content, inherited = apply_node_test_metadata_to_yaml_content(content, previous)
        refreshed = yaml.safe_load(refreshed_content)["proxies"][0]

        self.assertEqual(inherited, 1)
        self.assertEqual(refreshed["last_latency"], 75)
        self.assertEqual(refreshed["last_speed"], 18.2)
        self.assertEqual(refreshed["region"]["country_code"], "US")

    def test_custom_batch_speed_result_is_persisted(self):
        import api.nodes as nodes_api

        config = {
            "custom_nodes": [{
                "id": "node_1",
                "name": "US 01",
                "type": "http",
                "server": "us.example",
                "port": 8080,
            }]
        }

        def fake_update_custom_nodes(mutator):
            return mutator(config)

        endpoint = inspect.unwrap(nodes_api.batch_save_test_results)
        request = nodes_api.BatchSaveRequest(
            results={"custom": {"node_1": {"speed": 12.5, "peak_speed": 20.0}}}
        )

        with patch.object(nodes_api, "update_custom_nodes", side_effect=fake_update_custom_nodes):
            response = asyncio.run(endpoint(request, request=None, _=True))

        self.assertEqual(response["saved_count"], 1)
        self.assertEqual(config["custom_nodes"][0]["last_speed"], 12.5)
        self.assertEqual(config["custom_nodes"][0]["last_peak_speed"], 20.0)
        self.assertTrue(config["custom_nodes"][0]["last_speed_time"])

    def test_batch_ip_profile_update_preserves_fields_from_previous_phase(self):
        import api.nodes as nodes_api

        config = {
            "custom_nodes": [{
                "id": "node_1",
                "name": "US 01",
                "type": "http",
                "server": "us.example",
                "port": 8080,
                "exit_ip": "203.0.113.10",
                "ip_profile": {
                    "exit_ip": "203.0.113.10",
                    "ip_source": "native",
                    "network_type": "residential",
                    "fraud_score": 8,
                },
            }]
        }

        def fake_update_custom_nodes(mutator):
            return mutator(config)

        endpoint = inspect.unwrap(nodes_api.batch_save_test_results)
        request = nodes_api.BatchSaveRequest(
            results={"custom": {"node_1": {
                # A rotating provider can expose a different egress IP during
                # the Radar request.  The partial Radar profile must not erase
                # the previously saved IPPure values.
                "exit_ip": "203.0.113.11",
                "ip_profile": {
                    "exit_ip": "203.0.113.11",
                    "radar_status": "no_data",
                },
            }}}
        )

        with patch.object(nodes_api, "update_custom_nodes", side_effect=fake_update_custom_nodes):
            response = asyncio.run(endpoint(request, request=None, _=True))

        self.assertEqual(response["saved_count"], 1)
        saved_profile = config["custom_nodes"][0]["ip_profile"]
        self.assertEqual(saved_profile["exit_ip"], "203.0.113.11")
        self.assertEqual(saved_profile["ip_source"], "native")
        self.assertEqual(saved_profile["network_type"], "residential")
        self.assertEqual(saved_profile["fraud_score"], 8)
        self.assertEqual(saved_profile["radar_status"], "no_data")

    def test_vpngate_batch_speed_result_uses_cache_metadata_writer(self):
        import api.nodes as nodes_api

        captured = []
        endpoint = inspect.unwrap(nodes_api.batch_save_test_results)
        request = nodes_api.BatchSaveRequest(
            results={"vpngate": {"vpngate_node_1": {
                "latency": 88,
                "speed": 12.5,
                "peak_speed": 20.0,
                "exit_ip": "203.0.113.10",
            }}}
        )

        def save_vpngate_node(node_id, updates):
            captured.append((node_id, updates))
            return True

        with patch.object(nodes_api, "update_vpngate_node_test_metadata", side_effect=save_vpngate_node):
            response = asyncio.run(endpoint(request, request=None, _=True))

        self.assertEqual(response["saved_count"], 1)
        self.assertEqual(captured[0][0], "vpngate_node_1")
        self.assertEqual(captured[0][1]["last_latency"], 88)
        self.assertEqual(captured[0][1]["last_speed"], 12.5)
        self.assertTrue(captured[0][1]["last_speed_time"])


if __name__ == "__main__":
    unittest.main()
