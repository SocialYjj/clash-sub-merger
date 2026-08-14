"""Tests for the extracted user-allocation helper route."""

import copy
import logging
import tempfile
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.user_allocation import create_user_allocation_router
from core.dependencies import verify_session


class UserAllocationRoutesTest(unittest.TestCase):
    def test_available_nodes_route_filters_info_custom_nodes(self):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        config = {
            "auth": {},
            "subscriptions": [],
            "custom_nodes": [
                {
                    "name": "US 01", "type": "ss", "server": "example.com",
                    "port": 443, "cipher": "aes-128-gcm", "password": "secret",
                },
                {"name": "US Disabled", "type": "ss", "server": "disabled.example.com", "enabled": False},
                {"name": "剩余流量 10G", "type": "ss", "server": "info.example.com"},
            ],
            "proxy_chains": [],
        }
        app = FastAPI()
        app.dependency_overrides[verify_session] = lambda: True
        app.include_router(create_user_allocation_router(
            yaml_source_dir=tempdir.name,
            load_config=lambda: copy.deepcopy(config),
            get_all_final_node_names=lambda: set(),
            logger=logging.getLogger("test.user_allocation"),
        ))
        client = TestClient(app)

        response = client.get("/api/available-nodes")

        self.assertEqual(response.status_code, 200)
        sources = response.json()["sources"]
        self.assertIn("custom_nodes", sources)
        nodes = sources["custom_nodes"]["nodes"]
        self.assertEqual(len(nodes), 1)
        self.assertIn("US 01", nodes[0]["name"])
        self.assertTrue(nodes[0]["id"])
        self.assertNotIn("US Disabled", [node["name"] for node in nodes])
        self.assertNotIn("剩余流量", nodes[0]["name"])
