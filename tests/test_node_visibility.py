"""Tests for node-level enable/disable behavior."""

import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from services.config_merger import ConfigMerger
from services.node_visibility import (
    apply_node_visibility_history,
    apply_node_visibility_to_yaml_content,
    filter_enabled_nodes,
    is_node_enabled,
)


class NodeVisibilityTests(unittest.TestCase):
    def test_disabled_nodes_are_filtered_and_visibility_field_is_not_exported(self):
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "sub_demo.yaml").write_text(
                "proxies:\n"
                "  - name: Disabled US\n"
                "    type: http\n"
                "    server: disabled.example.com\n"
                "    port: 8080\n"
                "    enabled: false\n"
                "  - name: Enabled JP\n"
                "    type: http\n"
                "    server: enabled.example.com\n"
                "    port: 8080\n"
                "    enabled: true\n",
                encoding="utf-8",
            )

            merger = ConfigMerger(
                yaml_dir=tempdir,
                output_file=str(Path(tempdir) / "out.yaml"),
                file_aliases={"sub_demo.yaml": "Demo"},
            )
            proxies = merger.merge_and_generate()["proxies"]

        self.assertEqual(len(proxies), 1)
        self.assertIn("Enabled JP", proxies[0]["name"])
        self.assertNotIn("enabled", proxies[0])

    def test_filter_enabled_nodes_accepts_missing_enabled_as_enabled(self):
        nodes = [
            {"name": "implicit"},
            {"name": "string-false", "enabled": "false"},
            {"name": "bool-false", "enabled": False},
        ]

        self.assertTrue(is_node_enabled(nodes[0]))
        self.assertEqual(filter_enabled_nodes(nodes), [nodes[0]])

    def test_disabled_state_is_inherited_on_exact_refresh_match(self):
        old_nodes = [{
            "name": "US 01",
            "type": "vless",
            "server": "edge.example.com",
            "port": 443,
            "enabled": False,
        }]
        new_nodes = [{
            "name": "US 01",
            "type": "vless",
            "server": "edge.example.com",
            "port": 443,
        }]

        inherited = apply_node_visibility_history(new_nodes, old_nodes)

        self.assertEqual(inherited, 1)
        self.assertFalse(new_nodes[0]["enabled"])

    def test_endpoint_fallback_does_not_disable_mixed_old_endpoint(self):
        old_nodes = [
            {
                "name": "US A",
                "type": "vless",
                "server": "shared.example.com",
                "port": 443,
                "enabled": False,
            },
            {
                "name": "US B",
                "type": "vless",
                "server": "shared.example.com",
                "port": 443,
                "enabled": True,
            },
        ]
        new_nodes = [{
            "name": "US Renamed",
            "type": "vless",
            "server": "shared.example.com",
            "port": 443,
        }]

        inherited = apply_node_visibility_history(new_nodes, old_nodes)

        self.assertEqual(inherited, 0)
        self.assertNotIn("enabled", new_nodes[0])

    def test_yaml_visibility_inheritance_preserves_disabled_state(self):
        old_nodes = [{
            "name": "JP 01",
            "type": "http",
            "server": "jp.example.com",
            "port": 8080,
            "enabled": False,
        }]
        yaml_content = (
            "proxies:\n"
            "  - name: JP 01\n"
            "    type: http\n"
            "    server: jp.example.com\n"
            "    port: 8080\n"
        )

        new_content, inherited = apply_node_visibility_to_yaml_content(yaml_content, old_nodes)

        self.assertEqual(inherited, 1)
        self.assertIn("enabled: false", new_content)

    def test_custom_nodes_yaml_skips_disabled_nodes(self):
        import server

        saved_payloads = []

        with patch.object(server, "load_config", return_value={
            "custom_nodes": [
                {
                    "id": "node_1",
                    "link": "x",
                    "name": "Disabled",
                    "type": "http",
                    "server": "disabled.example.com",
                    "port": 8080,
                    "enabled": False,
                },
                {
                    "id": "node_2",
                    "link": "x",
                    "name": "Enabled",
                    "type": "http",
                    "server": "enabled.example.com",
                    "port": 8080,
                    "enabled": True,
                },
            ]
        }), patch.object(server, "save_subscription_yaml", side_effect=lambda *args: saved_payloads.append(args)):
            server.update_custom_nodes_yaml()

        self.assertEqual(saved_payloads[0][0], "custom_nodes")
        proxies = saved_payloads[0][1]["proxies"]
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0]["name"], "Enabled")
        self.assertNotIn("enabled", proxies[0])

    def test_custom_node_toggle_persists_visibility_and_clears_user_cache(self):
        import api.nodes as nodes_api

        config = {
            "custom_nodes": [{"id": "node_1", "name": "US 01"}],
            "users": [{"id": "u1", "sub_cache": {"content": "old"}}],
        }
        calls = {"yaml": 0, "stats": 0}

        def update_config(mutator):
            return mutator(config)

        fake_server = SimpleNamespace(
            update_custom_nodes_yaml=lambda: calls.__setitem__("yaml", calls["yaml"] + 1),
            invalidate_stats_cache=lambda: calls.__setitem__("stats", calls["stats"] + 1),
        )

        with (
            patch.object(nodes_api, "update_config", side_effect=update_config),
            patch.object(nodes_api, "_get_server", return_value=fake_server),
        ):
            response = nodes_api.toggle_custom_node("node_1", _=True)

        self.assertFalse(response["enabled"])
        self.assertFalse(config["custom_nodes"][0]["enabled"])
        self.assertNotIn("sub_cache", config["users"][0])
        self.assertEqual(calls, {"yaml": 1, "stats": 1})

    def test_subscription_node_toggle_persists_visibility_and_clears_user_cache(self):
        import api.nodes as nodes_api

        config = {
            "subscriptions": [{"id": "sub_1", "name": "Provider"}],
            "users": [{"id": "u1", "sub_cache": {"content": "old"}}],
        }
        sub_data = {"proxies": [{"name": "US 01", "type": "http", "server": "example.com", "port": 8080}]}
        calls = {"stats": 0}

        def update_config(mutator):
            return mutator(config)

        def update_subscription_yaml(sub_id, yaml_dir, mutator):
            self.assertEqual(sub_id, "sub_1")
            return mutator(sub_data)

        fake_server = SimpleNamespace(
            invalidate_stats_cache=lambda: calls.__setitem__("stats", calls["stats"] + 1),
        )

        with (
            patch.object(nodes_api, "load_config", return_value=config),
            patch.object(nodes_api, "update_config", side_effect=update_config),
            patch.object(nodes_api, "update_subscription_yaml", side_effect=update_subscription_yaml),
            patch.object(nodes_api, "_get_server", return_value=fake_server),
        ):
            response = nodes_api.toggle_subscription_node("sub_1", 0, _=True)

        self.assertFalse(response["enabled"])
        self.assertFalse(sub_data["proxies"][0]["enabled"])
        self.assertNotIn("sub_cache", config["users"][0])
        self.assertEqual(calls["stats"], 1)


if __name__ == "__main__":
    unittest.main()
