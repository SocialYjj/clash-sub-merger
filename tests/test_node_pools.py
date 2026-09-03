"""Regression tests for configured node pools."""

import copy
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.node_pools as node_pools_api
from core.dependencies import verify_session
from services.node_identity import node_pool_virtual_node_id, subscription_node_ids
from services.node_metadata import strip_node_metadata
from services.subscription_output import create_subscription_output_router


def _http_node(name: str, server: str, port: int) -> dict:
    return {"name": name, "type": "http", "server": server, "port": port}


class NodePoolApiTests(unittest.TestCase):
    def test_create_and_toggle_node_pool_uses_stable_members(self):
        nodes = [_http_node("Node A", "a.example", 8080)]
        config = {
            "subscriptions": [{"id": "sub_1", "name": "Demo", "enabled": True}],
            "custom_nodes": [],
            "node_pools": [],
        }
        app = FastAPI()
        app.dependency_overrides[verify_session] = lambda: True
        app.include_router(node_pools_api.router, prefix="/api/node-pools")

        def update_config(mutator):
            return mutator(config)

        with (
            patch.object(node_pools_api, "load_config", side_effect=lambda: copy.deepcopy(config)),
            patch.object(node_pools_api, "update_config", side_effect=update_config),
            patch("services.node_pool_references.load_subscription_yaml", return_value={"proxies": nodes}),
        ):
            client = TestClient(app)
            node_id = subscription_node_ids("sub_1", nodes)[0]
            response = client.post(
                "/api/node-pools",
                json={
                    "name": "Direct Pool",
                    "nodes": [{"sub_id": "sub_1", "node_id": node_id}],
                    "group_strategy": "load-balance",
                    "lb_strategy": "sticky-sessions",
                },
            )

            self.assertEqual(response.status_code, 200)
            pool = config["node_pools"][0]
            self.assertEqual(pool["nodes"][0]["node_id"], node_id)
            pool_id = pool["id"]

            toggle_response = client.put(f"/api/node-pools/{pool_id}/toggle")
            self.assertEqual(toggle_response.status_code, 200)
            self.assertFalse(config["node_pools"][0]["enabled"])

    def test_update_rejects_invalid_group_url(self):
        app = FastAPI()
        app.dependency_overrides[verify_session] = lambda: True
        app.include_router(node_pools_api.router, prefix="/api/node-pools")
        with patch.object(node_pools_api, "load_config", return_value={"node_pools": []}):
            response = TestClient(app).put(
                "/api/node-pools/pool_1",
                json={"group_url": "file:///tmp/test"},
            )
        self.assertEqual(response.status_code, 422)


class NodePoolOutputTests(unittest.TestCase):
    @staticmethod
    def _make_output_client(config, yaml_source_dir):
        app = FastAPI()
        app.include_router(create_subscription_output_router(
            yaml_source_dir=yaml_source_dir,
            output_file=str(Path(yaml_source_dir, "output.yaml")),
            load_config=lambda: copy.deepcopy(config),
            update_config=lambda mutator: mutator(config),
            fetch_subscription=lambda *args, **kwargs: None,
            find_node_by_reference=lambda *args, **kwargs: None,
            is_name_allocated=lambda name, allocations, node_id=None: (
                allocations == ["*"]
                or (node_id is not None and node_id in (allocations or []))
                or name in (allocations or [])
            ),
            filter_underscore_fields=strip_node_metadata,
            extract_country_from_name=lambda *args, **kwargs: None,
            split_template=lambda content: (content, ""),
            logger=logging.getLogger("test.node_pools"),
        ))
        return TestClient(app)

    def test_clash_output_emits_one_pool_group_and_one_listener(self):
        nodes = [_http_node("🇺🇸 Node A", "a.example", 8080), _http_node("🇺🇸 Node B", "b.example", 8081)]
        node_ids = subscription_node_ids("sub_1", nodes)

        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "sub_1.yaml").write_text(
                yaml.safe_dump({"proxies": nodes}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {"sub_token": "admin-token"},
                "subscriptions": [{"id": "sub_1", "name": "Demo", "enabled": True}],
                "custom_nodes": [],
                "users": [],
                "admin_tokens": [],
                "templates": [],
                "source_order": ["sub_1"],
                "proxy_chains": [],
                "node_pools": [{
                    "id": "pool_1",
                    "name": "Direct Pool",
                    "enabled": True,
                    "nodes": [
                        {"sub_id": "sub_1", "node_id": node_ids[0]},
                        {"sub_id": "sub_1", "node_id": node_ids[1]},
                    ],
                    "group_strategy": "load-balance",
                    "lb_strategy": "consistent-hashing",
                }],
                "port_mappings": {
                    node_pool_virtual_node_id("pool_1"): 42000,
                },
            }

            response = self._make_output_client(config, tempdir).get(
                "/sub?token=admin-token&format=clash"
            )

        self.assertEqual(response.status_code, 200)
        rendered = yaml.safe_load(response.text)
        groups = {group["name"]: group for group in rendered["proxy-groups"]}
        pool_names = [name for name in groups if "Direct Pool" in name]
        self.assertEqual(len(pool_names), 1)
        pool_name = pool_names[0]
        self.assertEqual(groups[pool_name]["type"], "load-balance")
        self.assertEqual(groups[pool_name]["strategy"], "consistent-hashing")
        self.assertEqual(len([listener for listener in rendered["listeners"] if listener["proxy"] == pool_name]), 1)
        self.assertIn(pool_name, groups["GLOBAL"]["proxies"])
        self.assertIn(pool_name, groups["🚀 手动选择"]["proxies"])

        group_names = [group["name"] for group in rendered["proxy-groups"]]
        pool_position = group_names.index(pool_name)
        fallback_position = group_names.index("🔯 故障转移")
        country_positions = [
            position
            for position, name in enumerate(group_names)
            if name in {"🇺🇸 美国", "🔰 其他"}
        ]
        self.assertEqual(pool_position, fallback_position + 1)
        self.assertTrue(country_positions)
        self.assertLess(pool_position, min(country_positions))

    def test_user_pool_allocation_emits_only_pool_members(self):
        nodes = [_http_node("Node A", "a.example", 8080), _http_node("Node B", "b.example", 8081)]
        node_ids = subscription_node_ids("sub_1", nodes)
        pool_id = "pool_user"
        pool_virtual_id = node_pool_virtual_node_id(pool_id)

        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "sub_1.yaml").write_text(
                yaml.safe_dump({"proxies": nodes}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {"sub_token": "admin-token"},
                "subscriptions": [{"id": "sub_1", "name": "Demo", "enabled": True}],
                "custom_nodes": [],
                "users": [{
                    "token": "user-token",
                    "name": "Pool user",
                    "enabled": True,
                    "allocations": {"node_pools": [pool_virtual_id]},
                }],
                "admin_tokens": [],
                "templates": [],
                "source_order": ["sub_1"],
                "proxy_chains": [],
                "node_pools": [{
                    "id": pool_id,
                    "name": "User Pool",
                    "enabled": True,
                    "nodes": [{"sub_id": "sub_1", "node_id": node_ids[0]}],
                    "group_strategy": "select",
                }],
                "port_mappings": {pool_virtual_id: 42001},
            }

            response = self._make_output_client(config, tempdir).get(
                "/sub?token=user-token&format=clash"
            )

        self.assertEqual(response.status_code, 200)
        rendered = yaml.safe_load(response.text)
        self.assertEqual({proxy["server"] for proxy in rendered["proxies"]}, {"a.example"})
        pool_groups = [
            group for group in rendered["proxy-groups"]
            if "User Pool" in group.get("name", "")
        ]
        self.assertEqual(len(pool_groups), 1)
        pool_name = pool_groups[0]["name"]
        listeners = [
            listener for listener in rendered.get("listeners", [])
            if listener.get("proxy") == pool_name
        ]
        self.assertEqual(len(listeners), 1)
        self.assertEqual(listeners[0]["port"], 42001)

    def test_disabled_pool_does_not_emit_group_or_listener(self):
        nodes = [_http_node("Node A", "a.example", 8080)]
        pool_id = "pool_disabled"
        pool_virtual_id = node_pool_virtual_node_id(pool_id)

        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "sub_1.yaml").write_text(
                yaml.safe_dump({"proxies": nodes}, sort_keys=False),
                encoding="utf-8",
            )
            config = {
                "auth": {"sub_token": "admin-token"},
                "subscriptions": [{"id": "sub_1", "name": "Demo", "enabled": True}],
                "custom_nodes": [],
                "users": [],
                "admin_tokens": [],
                "templates": [],
                "source_order": ["sub_1"],
                "proxy_chains": [],
                "node_pools": [{
                    "id": pool_id,
                    "name": "Disabled Pool",
                    "enabled": False,
                    "nodes": [{"sub_id": "sub_1", "node_id": subscription_node_ids("sub_1", nodes)[0]}],
                    "group_strategy": "select",
                }],
                "port_mappings": {pool_virtual_id: 42002},
            }

            response = self._make_output_client(config, tempdir).get(
                "/sub?token=admin-token&format=clash"
            )

        self.assertEqual(response.status_code, 200)
        rendered = yaml.safe_load(response.text)
        self.assertFalse(any("Disabled Pool" in group.get("name", "") for group in rendered["proxy-groups"]))
        self.assertFalse(any(listener.get("port") == 42002 for listener in rendered.get("listeners", [])))


if __name__ == "__main__":
    unittest.main()
