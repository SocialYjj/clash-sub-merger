"""Input validation tests for speedtest API resource limits."""

import asyncio
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.speedtest as speedtest_api
from core.dependencies import verify_session


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

    def test_single_speedtest_calls_go_service_with_node_payload(self):
        class FakeServer:
            @staticmethod
            def get_proxy_node_by_id(node_id):
                self.assertEqual(node_id, "sub_demo_0")
                return {"name": "Demo", "type": "http", "server": "127.0.0.1", "port": 8080}

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
                patch.object(speedtest_api, "_get_server", return_value=FakeServer()),
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
        async def fake_batch(node_ids, test_speed=False, timeout=10, concurrency=10):
            return {"node_ids": node_ids, "test_speed": test_speed, "timeout": timeout, "concurrency": concurrency}

        async def run_test():
            with (
                patch.object(speedtest_api, "load_config", return_value={
                    "subscriptions": [{"id": "my_sub_1", "name": "Demo"}]
                }),
                patch.object(speedtest_api, "load_subscription_yaml", return_value={
                    "proxies": [{"name": "a"}, {"name": "b"}]
                }),
                patch.object(speedtest_api, "_speedtest_batch", side_effect=fake_batch),
            ):
                return await speedtest_api.speedtest_subscription("my_sub_1", request=None, _=True)

        result = asyncio.run(run_test())

        self.assertEqual(result["node_ids"], ["sub_my_sub_1_0", "sub_my_sub_1_1"])


if __name__ == "__main__":
    unittest.main()
