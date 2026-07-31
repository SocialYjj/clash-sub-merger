"""Tests for the extracted subscription output router."""

import copy
import logging
import tempfile
import time
import unittest
from pathlib import Path

import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.name_transformer import NameTransformer
from services.node_identity import proxy_chain_virtual_node_id
from services.subscription_output import create_subscription_output_router


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
            filter_underscore_fields=lambda data: {k: v for k, v in data.items() if not str(k).startswith("_")},
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
