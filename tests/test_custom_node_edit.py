"""Tests for editing a stored custom node through the full-update endpoint."""

import unittest
from unittest.mock import patch

from pydantic import ValidationError

import api.nodes as nodes_api


class UpdateNodePayloadTests(unittest.TestCase):
    def test_rejects_backend_managed_metadata_echoed_by_the_client(self):
        with self.assertRaises(ValidationError):
            nodes_api.UpdateNodeFull(
                node={
                    "name": "US-tailscale",
                    "type": "vless",
                    "server": "2001:550:a20::16c",
                    "port": 10203,
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "ip_profile": {"exit_ip": "2001:550:a20::16c"},
                }
            )


class ReplaceCustomNodeTests(unittest.TestCase):
    def _update(self, config, payload):
        def update_custom_nodes(mutator):
            return mutator(config)

        with patch.object(nodes_api, "update_custom_nodes", side_effect=update_custom_nodes):
            return nodes_api.update_custom_node_full(
                "node_1",
                nodes_api.UpdateNodeFull(node=payload),
                _=True,
            )

    def test_keeps_detection_metadata_when_the_address_changes(self):
        config = {
            "custom_nodes": [
                {
                    "id": "node_1",
                    "link": "vless://original",
                    "name": "US-tailscale",
                    "type": "vless",
                    "server": "2001:550:a20::16c",
                    "port": 10203,
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "enabled": False,
                    "exit_ip": "2001:550:a20::16c",
                    "ip_profile": {"exit_ip": "2001:550:a20::16c", "fraud_score": 7},
                    "last_latency": 210,
                    "region": {"code": "US"},
                    "city": "Los Angeles",
                }
            ]
        }

        response = self._update(
            config,
            {
                "name": "US-tailscale",
                "type": "vless",
                "server": "203.0.113.10",
                "port": 10203,
                "uuid": "11111111-1111-1111-1111-111111111111",
            },
        )

        stored = config["custom_nodes"][0]
        self.assertEqual(stored["server"], "203.0.113.10")
        self.assertEqual(stored["ip_profile"]["fraud_score"], 7)
        self.assertEqual(stored["last_latency"], 210)
        self.assertFalse(stored["enabled"])
        self.assertEqual(response["node"]["server"], "203.0.113.10")

    def test_missing_node_still_raises_404(self):
        config = {"custom_nodes": []}

        with self.assertRaises(Exception) as raised:
            self._update(
                config,
                {
                    "name": "US-tailscale",
                    "type": "vless",
                    "server": "203.0.113.10",
                    "port": 10203,
                    "uuid": "11111111-1111-1111-1111-111111111111",
                },
            )

        self.assertEqual(getattr(raised.exception, "status_code", None), 404)


if __name__ == "__main__":
    unittest.main()
