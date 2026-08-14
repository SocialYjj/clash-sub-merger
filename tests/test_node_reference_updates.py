"""Regression tests for stable node references and rollback-safe node writes."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from services.custom_node_storage import update_custom_nodes
from services.name_transformer import NameTransformer
from services.node_identity import subscription_node_id, subscription_node_ids
from services.node_reference_updates import (
    reconcile_subscription_node_references,
    update_subscription_yaml_with_references,
)
from services.subscription_cleanup import cleanup_deleted_subscription


def _subscription_node(name: str, server: str) -> dict:
    return {
        "name": name,
        "type": "ss",
        "server": server,
        "port": 443,
        "cipher": "aes-128-gcm",
        "password": "test-password",
    }


class StableNodeReferenceTests(unittest.TestCase):
    def test_duplicate_technical_nodes_survive_display_name_rename(self):
        old_nodes = [
            _subscription_node("Old A", "same.example"),
            _subscription_node("Old B", "same.example"),
        ]
        new_nodes = [
            _subscription_node("New A", "same.example"),
            _subscription_node("New B", "same.example"),
        ]
        old_ids = subscription_node_ids("sub_1", old_nodes)
        new_ids = subscription_node_ids("sub_1", new_nodes)
        config = {
            "subscriptions": [{"id": "sub_1", "name": "Provider"}],
            "users": [{"allocations": {"sub_1": old_ids}}],
            "admin_tokens": [],
            "custom_nodes": [],
            "proxy_chains": [],
            "speedtest_results": {"sub_1": {
                old_ids[0]: {"latency": 10},
                old_ids[1]: {"latency": 20},
            }},
        }

        with patch("services.proxy_chain_references._base_node_names", side_effect=lambda _config: set()):
            reconcile_subscription_node_references(
                config,
                "sub_1",
                old_nodes=old_nodes,
                new_nodes=new_nodes,
                old_subscription_name="Provider",
                new_subscription_name="Provider",
            )

        self.assertNotEqual(old_ids, new_ids)
        self.assertEqual(config["users"][0]["allocations"]["sub_1"], new_ids)
        self.assertEqual(
            config["speedtest_results"]["sub_1"],
            {new_ids[0]: {"latency": 10}, new_ids[1]: {"latency": 20}},
        )

    def test_unique_same_name_migrates_after_technical_configuration_change(self):
        old_node = _subscription_node("Stable Name", "old.example")
        new_node = _subscription_node("Stable Name", "new.example")
        old_id = subscription_node_id("sub_1", old_node)
        new_id = subscription_node_id("sub_1", new_node)
        display_name = NameTransformer.transform_name(old_node, "Provider")["name"]
        config = {
            "subscriptions": [{"id": "sub_1", "name": "Provider", "enabled": True}],
            "custom_nodes": [],
            "users": [{
                "allocations": {"sub_1": [old_id]},
                "group_config": {"Select": [display_name]},
                "sub_cache": "stale",
            }],
            "admin_tokens": [{"group_config": {"Select": [display_name]}}],
            "settings": {"proxy_node_id": old_id, "proxy_node_name": display_name},
            "speedtest_results": {"sub_1": {old_id: {"latency": 10}}},
            "port_mappings": {display_name: 12000},
            "proxy_chains": [{
                "id": "chain_1",
                "name": "Chain",
                "rows": [{
                    "row_id": "row_1",
                    "nodes": [
                        {
                            "type": "node",
                            "sub_id": "sub_1",
                            "node_id": old_id,
                            "node_name": display_name,
                            "node_index": 0,
                        },
                        {
                            "type": "node",
                            "sub_id": "custom",
                            "node_id": "custom_1",
                            "node_name": "Custom Exit",
                        },
                    ],
                }],
                "enabled": True,
            }],
        }

        with patch("services.proxy_chain_references._base_node_names", side_effect=lambda _config: set()):
            reconcile_subscription_node_references(
                config,
                "sub_1",
                old_nodes=[old_node],
                new_nodes=[new_node],
                old_subscription_name="Provider",
                new_subscription_name="Provider",
            )

        self.assertNotEqual(old_id, new_id)
        self.assertEqual(config["users"][0]["allocations"]["sub_1"], [new_id])
        self.assertNotIn("sub_cache", config["users"][0])
        self.assertEqual(config["settings"]["proxy_node_id"], new_id)
        self.assertEqual(config["speedtest_results"]["sub_1"], {new_id: {"latency": 10}})
        stored_reference = config["proxy_chains"][0]["rows"][0]["nodes"][0]
        self.assertEqual(stored_reference["node_id"], new_id)
        self.assertNotIn("node_index", stored_reference)

    def test_duplicate_name_ambiguity_does_not_redirect_reference(self):
        old_node = _subscription_node("Duplicate", "old.example")
        new_nodes = [
            _subscription_node("Duplicate", "first.example"),
            _subscription_node("Duplicate", "second.example"),
        ]
        old_id = subscription_node_id("sub_1", old_node)
        config = {
            "subscriptions": [{"id": "sub_1", "name": "Provider"}],
            "users": [{"allocations": {"sub_1": [old_id]}}],
            "admin_tokens": [],
            "custom_nodes": [],
            "proxy_chains": [],
        }

        with patch("services.proxy_chain_references._base_node_names", side_effect=lambda _config: set()):
            reconcile_subscription_node_references(
                config,
                "sub_1",
                old_nodes=[old_node],
                new_nodes=new_nodes,
                old_subscription_name="Provider",
                new_subscription_name="Provider",
            )

        self.assertEqual(config["users"][0]["allocations"]["sub_1"], [])
        new_ids = {subscription_node_id("sub_1", node) for node in new_nodes}
        self.assertTrue(new_ids.isdisjoint(config["users"][0]["allocations"]["sub_1"]))

    def test_deleting_subscription_removes_every_owned_reference(self):
        old_node = _subscription_node("Removed", "removed.example")
        old_id = subscription_node_id("sub_1", old_node)
        display_name = NameTransformer.transform_name(old_node, "Provider")["name"]
        config = {
            "subscriptions": [{"id": "sub_1", "name": "Provider"}],
            "source_order": ["sub_1"],
            "custom_nodes": [],
            "users": [{
                "allocations": {"sub_1": [old_id]},
                "group_config": {"Select": [display_name]},
                "sub_cache": "stale",
            }],
            "admin_tokens": [{"group_config": {"Select": [display_name]}}],
            "settings": {"proxy_node_id": old_id, "proxy_node_name": display_name},
            "speedtest_results": {"sub_1": {old_id: {"latency": 10}}},
            "speedtest_profiles": [{"subscription_ids": ["sub_1", "sub_2"]}],
            "port_mappings": {display_name: 12000},
            "proxy_chains": [{
                "id": "chain_1",
                "name": "Chain",
                "rows": [{
                    "row_id": "row_1",
                    "nodes": [
                        {"type": "node", "sub_id": "sub_1", "node_id": old_id, "node_name": display_name},
                        {"type": "node", "sub_id": "custom", "node_id": "custom_1", "node_name": "Exit"},
                    ],
                }],
            }],
        }

        with patch("services.proxy_chain_references._base_node_names", side_effect=lambda _config: set()):
            removed = cleanup_deleted_subscription(config, "sub_1", [old_node])

        self.assertEqual(removed["id"], "sub_1")
        self.assertEqual(config["subscriptions"], [])
        self.assertEqual(config["source_order"], [])
        self.assertEqual(config["proxy_chains"], [])
        self.assertNotIn("sub_1", config["users"][0]["allocations"])
        self.assertEqual(config["users"][0]["group_config"]["Select"], [])
        self.assertEqual(config["admin_tokens"][0]["group_config"]["Select"], [])
        self.assertEqual(config["settings"], {})
        self.assertEqual(config["port_mappings"], {})
        self.assertNotIn("sub_1", config["speedtest_results"])
        self.assertEqual(config["speedtest_profiles"][0]["subscription_ids"], ["sub_2"])


class NodeWriteRollbackTests(unittest.TestCase):
    def test_subscription_yaml_is_restored_when_config_commit_fails(self):
        with tempfile.TemporaryDirectory() as tempdir:
            uploads = Path(tempdir) / "uploads"
            uploads.mkdir()
            yaml_path = uploads / "sub_1.yaml"
            original_content = (
                "proxies:\n"
                "  - name: Original\n"
                "    type: ss\n"
                "    server: old.example\n"
                "    port: 443\n"
                "    cipher: aes-128-gcm\n"
                "    password: test-password\n"
            )
            yaml_path.write_text(original_content, encoding="utf-8")

            def rename_node(subscription_yaml):
                subscription_yaml["proxies"][0]["name"] = "Changed"

            with (
                patch("services.node_reference_updates.AppConfig.YAML_SOURCE_DIR", str(uploads)),
                patch("services.subscription_refresh_lock.REFRESH_LOCK_DIR", str(Path(tempdir) / "locks")),
                patch("services.node_reference_updates.update_config", side_effect=RuntimeError("commit failed")),
            ):
                with self.assertRaises(RuntimeError):
                    update_subscription_yaml_with_references("sub_1", rename_node)

            self.assertEqual(yaml_path.read_text(encoding="utf-8"), original_content)

    def test_custom_nodes_yaml_is_restored_when_config_commit_fails(self):
        with tempfile.TemporaryDirectory() as tempdir:
            uploads = Path(tempdir) / "uploads"
            uploads.mkdir()
            yaml_path = uploads / "custom_nodes.yaml"
            original_content = "proxies: []\n"
            yaml_path.write_text(original_content, encoding="utf-8")
            latest_config = {"custom_nodes": [], "users": [], "admin_tokens": [], "proxy_chains": []}

            def fail_after_mutation(config_mutator):
                config_mutator(latest_config)
                raise RuntimeError("commit failed")

            def add_node(config):
                config["custom_nodes"].append({
                    "id": "custom_1",
                    "name": "Custom",
                    "type": "ss",
                    "server": "custom.example",
                    "port": 443,
                    "cipher": "aes-128-gcm",
                    "password": "test-password",
                })

            with (
                patch("services.custom_node_storage.AppConfig.YAML_SOURCE_DIR", str(uploads)),
                patch("services.subscription_refresh_lock.REFRESH_LOCK_DIR", str(Path(tempdir) / "locks")),
                patch("services.custom_node_storage.update_config", side_effect=fail_after_mutation),
                patch("services.proxy_chain_references._base_node_names", side_effect=lambda _config: set()),
            ):
                with self.assertRaises(RuntimeError):
                    update_custom_nodes(add_node)

            self.assertEqual(yaml_path.read_text(encoding="utf-8"), original_content)


if __name__ == "__main__":
    unittest.main()
