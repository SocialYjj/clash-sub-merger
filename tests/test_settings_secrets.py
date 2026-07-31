"""Regression tests for write-only proxy credentials and settings validation."""

import asyncio
import inspect
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

import api.settings as settings_api


class ProxyCredentialBoundaryTests(unittest.TestCase):
    def test_proxy_setting_reads_never_return_saved_credentials(self):
        secret_ipv6_proxy = "socks5://private-user:private-password@proxy.example:1080"
        secret_subscription_proxy = "http://fetch-user:fetch-password@proxy.example:8080"
        config = {
            "settings": {
                "ipv6_proxy": {
                    "enabled": True,
                    "proxy_url": secret_ipv6_proxy,
                    "ipv6_only": False,
                },
                "subscription_proxy_url": secret_subscription_proxy,
            }
        }

        with patch.object(settings_api, "load_config", return_value=config):
            ipv6_response = inspect.unwrap(settings_api.get_ipv6_proxy_setting)(_=True)
            subscription_response = inspect.unwrap(settings_api.get_subscription_proxy_setting)(_=True)

        serialized = repr((ipv6_response, subscription_response))
        self.assertEqual(
            ipv6_response,
            {"enabled": True, "has_proxy_url": True, "ipv6_only": False},
        )
        self.assertEqual(subscription_response, {"has_proxy_url": True})
        self.assertNotIn("private-user", serialized)
        self.assertNotIn("private-password", serialized)
        self.assertNotIn("fetch-user", serialized)
        self.assertNotIn("fetch-password", serialized)

    def test_subscription_proxy_can_only_be_replaced_or_explicitly_cleared(self):
        config = {"settings": {"subscription_proxy_url": "socks5://old.example:1080"}}

        def update_config(config_mutator):
            return config_mutator(config)

        endpoint = inspect.unwrap(settings_api.update_subscription_proxy_setting)
        with patch.object(settings_api, "update_config", side_effect=update_config):
            endpoint(
                settings_api.SubscriptionProxySetting(proxy_url="https://new-user:new-password@new.example:443"),
                _=True,
            )
            self.assertEqual(
                config["settings"]["subscription_proxy_url"],
                "https://new-user:new-password@new.example:443",
            )
            endpoint(settings_api.SubscriptionProxySetting(proxy_url=None), _=True)

        self.assertIsNone(config["settings"]["subscription_proxy_url"])

    def test_proxy_connection_failure_does_not_return_credentials(self):
        secret_proxy = "socks5://private-user:private-password@proxy.example:1080"

        class FailingClient:
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            async def get(self, *_args, **_kwargs):
                raise RuntimeError(f"connection failed via {secret_proxy}")

        endpoint = inspect.unwrap(settings_api.test_ipv6_proxy)
        with patch("httpx.AsyncClient", FailingClient):
            with self.assertRaises(HTTPException) as error_context:
                asyncio.run(
                    endpoint(
                        settings_api.IPv6ProxyTest(proxy_url=secret_proxy),
                        request=None,
                        _=True,
                    )
                )

        self.assertEqual(error_context.exception.status_code, 502)
        self.assertEqual(error_context.exception.detail, "Proxy connection failed")
        self.assertNotIn("private-user", str(error_context.exception))
        self.assertNotIn("private-password", str(error_context.exception))


class SourceOrderValidationTests(unittest.TestCase):
    def test_source_order_model_rejects_duplicates_and_extra_fields(self):
        with self.assertRaises(ValidationError):
            settings_api.SourceOrderUpdate(order=["sub_1", "sub_1"])
        with self.assertRaises(ValidationError):
            settings_api.SourceOrderUpdate(order=["sub_1"], unexpected=True)

    def test_source_order_endpoint_rejects_unknown_source(self):
        config = {"subscriptions": [{"id": "sub_1"}], "custom_nodes": []}

        def update_config(config_mutator):
            return config_mutator(config)

        endpoint = inspect.unwrap(settings_api.update_source_order)
        with patch.object(settings_api, "update_config", side_effect=update_config):
            with self.assertRaises(HTTPException) as error_context:
                endpoint(settings_api.SourceOrderUpdate(order=["missing"]), _=True)

        self.assertEqual(error_context.exception.status_code, 400)
        self.assertEqual(config.get("source_order"), None)


if __name__ == "__main__":
    unittest.main()
