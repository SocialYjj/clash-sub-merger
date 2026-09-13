"""Route-level tests for the speedtest endpoints."""

import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import api.speedtest as speedtest_api
import core.dependencies as core_dependencies
from core.dependencies import verify_session


class SpeedtestRoutesTest(unittest.TestCase):
    def setUp(self):
        speedtest_api.limiter.reset()

    def tearDown(self):
        speedtest_api.limiter.reset()

    def make_client(self):
        app = FastAPI()
        app.state.limiter = speedtest_api.limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.dependency_overrides[verify_session] = lambda: True
        app.include_router(speedtest_api.router, prefix="/api/speedtest")
        return TestClient(app)

    def test_single_speedtest_route_returns_result(self):
        node = {"name": "Demo", "type": "http", "server": "127.0.0.1", "port": 8080}

        with (
            patch.object(speedtest_api, "get_proxy_node_by_id", return_value=node),
            patch.object(speedtest_api, "_run_go_speedtest", return_value={"latency": 123, "latency_status": "ok"}),
        ):
            response = self.make_client().post("/api/speedtest/single", json={"node_id": "sub_demo_0", "timeout": 5})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["node_id"], "sub_demo_0")
        self.assertEqual(body["name"], "Demo")
        self.assertEqual(body["result"]["latency"], 123)

    def test_single_speedtest_route_requires_session(self):
        app = FastAPI()
        app.state.limiter = speedtest_api.limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.include_router(speedtest_api.router, prefix="/api/speedtest")
        client = TestClient(app)

        with patch.object(
            core_dependencies,
            "load_config",
            return_value={"auth": {"password_hash": "set", "sessions": {}}},
        ):
            response = client.post("/api/speedtest/single", json={"node_id": "sub_demo_0"})

        self.assertEqual(response.status_code, 401)

    def test_single_speedtest_route_rejects_invalid_timeout(self):
        response = self.make_client().post("/api/speedtest/single", json={"node_id": "sub_demo_0", "timeout": 0})

        self.assertEqual(response.status_code, 422)

    def test_batch_speedtest_route_rejects_empty_batch(self):
        response = self.make_client().post(
            "/api/speedtest/batch",
            json={"node_ids": [], "concurrency": 10, "timeout": 10},
        )

        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
