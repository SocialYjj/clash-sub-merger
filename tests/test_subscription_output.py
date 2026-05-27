"""Tests for the extracted subscription output router."""

import copy
import logging
import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.subscription_output import create_subscription_output_router


class SubscriptionOutputRouterTest(unittest.TestCase):
    def make_client(self, config, *, yaml_source_dir="/tmp/nonexistent-sub-output-tests", fetch_subscription_async=None):
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
            find_node_by_reference=lambda *args, **kwargs: None,
            is_name_allocated=lambda name, allocated_nodes: False,
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
