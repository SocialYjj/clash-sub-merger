"""Tests for the extracted subscription output router."""

import copy
import logging
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.subscription_output import create_subscription_output_router


class SubscriptionOutputRouterTest(unittest.TestCase):
    def make_client(self, config):
        app = FastAPI()

        def load_config():
            return copy.deepcopy(config)

        def update_config(mutator):
            result = mutator(config)
            return result

        app.include_router(create_subscription_output_router(
            yaml_source_dir="/tmp/nonexistent-sub-output-tests",
            output_file="/tmp/nonexistent-sub-output-tests/config.yaml",
            load_config=load_config,
            update_config=update_config,
            fetch_subscription=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("fetch should not run")),
            get_configured_proxy_node=lambda: {},
            find_node_by_reference=lambda *args, **kwargs: None,
            is_name_allocated=lambda name, allocated_nodes: False,
            filter_underscore_fields=lambda data: {k: v for k, v in data.items() if not str(k).startswith("_")},
            extract_country_from_name=lambda *args, **kwargs: None,
            split_template=lambda content: (content, ""),
            logger=logging.getLogger("test.subscription_output"),
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
