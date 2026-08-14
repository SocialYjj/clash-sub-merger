"""Input validation tests for speedtest API resource limits."""

import asyncio
import inspect
import unittest
from unittest.mock import patch

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.speedtest as speedtest_api
from core.dependencies import verify_session
from services.node_identity import subscription_node_id


class SpeedtestValidationTests(unittest.TestCase):
    def make_client(self):
        app = FastAPI()
        app.dependency_overrides[verify_session] = lambda: True
        app.include_router(speedtest_api.router, prefix="/api/speedtest")
        return TestClient(app)

    def test_rejects_unbounded_concurrency(self):
        client = self.make_client()

        response = client.post("/api/speedtest/batch", json={
            "node_ids": ["sub_demo_0"],
            "concurrency": speedtest_api.MAX_SPEEDTEST_CONCURRENCY + 1,
            "timeout": 10,
        })

        self.assertEqual(response.status_code, 422)

    def test_rejects_invalid_timeout(self):
        client = self.make_client()

        response = client.post("/api/speedtest/single", json={
            "node_id": "sub_demo_0",
            "timeout": 0,
        })

        self.assertEqual(response.status_code, 422)

    def test_rejects_empty_batch(self):
        client = self.make_client()

        response = client.post("/api/speedtest/batch", json={
            "node_ids": [],
            "concurrency": 10,
            "timeout": 10,
        })

        self.assertEqual(response.status_code, 422)

    def test_internal_batch_clamps_concurrency(self):
        self.assertEqual(
            speedtest_api._bounded_int(
                speedtest_api.MAX_SPEEDTEST_CONCURRENCY + 1,
                default=10,
                minimum=1,
                maximum=speedtest_api.MAX_SPEEDTEST_CONCURRENCY,
            ),
            speedtest_api.MAX_SPEEDTEST_CONCURRENCY,
        )

    def test_go_request_reports_timeout_without_empty_error(self):
        class TimeoutClient:
            async def post(self, *args, **kwargs):
                raise httpx.ReadTimeout("request timed out")

        async def get_timeout_client():
            return TimeoutClient()

        async def run_test():
            with patch.object(speedtest_api, "_get_speedtest_client", side_effect=get_timeout_client):
                return await speedtest_api._go_speedtest_request(
                    "/api/delay",
                    {"node": {"type": "trojan"}},
                    timeout=3,
                )

        result = asyncio.run(run_test())

        self.assertFalse(result["success"])
        self.assertIn("timed out after 3s", result["error"])

    def test_single_speedtest_calls_go_service_with_node_payload(self):
        fake_node = {"name": "Demo", "type": "http", "server": "127.0.0.1", "port": 8080}

        calls = []

        async def fake_go_request(endpoint, payload, timeout):
            calls.append((endpoint, payload, timeout))
            if endpoint == "/api/delay":
                return {"success": True, "latency": 123}
            if endpoint == "/api/ip":
                return {"success": True, "ip": "203.0.113.1"}
            if endpoint == "/api/speed":
                return {"success": True, "speed": 1.5, "peakSpeed": 2.5, "bytes": 1024}
            return {"success": False}

        async def run_test():
            with (
                patch.object(speedtest_api, "get_proxy_node_by_id", return_value=fake_node),
                patch.object(speedtest_api, "_go_speedtest_request", side_effect=fake_go_request),
            ):
                return await speedtest_api._speedtest_single("sub_demo_0", test_speed=True, timeout=5)

        result = asyncio.run(run_test())

        self.assertEqual(result["result"]["latency"], 123)
        self.assertEqual(result["result"]["landing_ip"], "203.0.113.1")
        self.assertEqual(result["result"]["speed"], 1.5)
        self.assertEqual(result["result"]["peak_speed"], 2.5)
        self.assertEqual([call[0] for call in calls], ["/api/delay", "/api/ip", "/api/speed"])
        self.assertEqual(calls[0][1]["node"]["name"], "Demo")

    def test_subscription_speedtest_uses_canonical_prefixed_node_ids(self):
        nodes = [
            {"name": "a", "type": "http", "server": "a.example.com", "port": 8080},
            {"name": "b", "type": "http", "server": "b.example.com", "port": 8080},
        ]
        async def fake_batch(node_ids, test_speed=False, timeout=10, concurrency=10):
            return {"node_ids": node_ids, "test_speed": test_speed, "timeout": timeout, "concurrency": concurrency}

        async def run_test():
            with (
                patch.object(speedtest_api, "load_config", return_value={
                    "subscriptions": [{"id": "my_sub_1", "name": "Demo"}]
                }),
                patch.object(speedtest_api, "load_subscription_yaml", return_value={
                    "proxies": nodes
                }),
                patch.object(speedtest_api, "_speedtest_batch", side_effect=fake_batch),
            ):
                endpoint = inspect.unwrap(speedtest_api.speedtest_subscription)
                return await endpoint("my_sub_1", request=None, _=True)

        result = asyncio.run(run_test())

        self.assertEqual(
            result["node_ids"],
            [subscription_node_id("my_sub_1", node) for node in nodes],
        )

    def test_subscription_speedtest_skips_disabled_and_information_nodes_without_renumbering(self):
        nodes = [
            {"name": "US 01", "type": "http", "server": "a.example.com", "port": 8080},
            {"name": "加入频道获取更多节点", "type": "http", "server": "info.example.com", "port": 8080},
            {"name": "US 02", "type": "http", "server": "disabled.example.com", "port": 8080, "enabled": False},
            {"name": "US 03", "type": "http", "server": "c.example.com", "port": 8080},
        ]

        async def fake_batch(node_ids, test_speed=False, timeout=10, concurrency=10):
            return {"node_ids": node_ids}

        async def run_test():
            with (
                patch.object(speedtest_api, "load_config", return_value={
                    "subscriptions": [{"id": "my_sub_1", "name": "Demo", "enabled": True}]
                }),
                patch.object(speedtest_api, "load_subscription_yaml", return_value={"proxies": nodes}),
                patch.object(speedtest_api, "_speedtest_batch", side_effect=fake_batch),
            ):
                endpoint = inspect.unwrap(speedtest_api.speedtest_subscription)
                return await endpoint("my_sub_1", request=None, _=True)

        result = asyncio.run(run_test())

        self.assertEqual(
            result["node_ids"],
            [
                subscription_node_id("my_sub_1", nodes[0]),
                subscription_node_id("my_sub_1", nodes[3]),
            ],
        )


if __name__ == "__main__":
    unittest.main()
