"""Route-level tests for the system management endpoints."""

import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.system as system_api
import core.dependencies as core_dependencies
from core.dependencies import verify_session


class SystemRoutesTest(unittest.TestCase):
    def make_client(self):
        app = FastAPI()
        app.dependency_overrides[verify_session] = lambda: True
        app.include_router(system_api.router, prefix="/api/system")
        return TestClient(app)

    def test_log_level_route_reports_current_level(self):
        response = self.make_client().get("/api/system/log-level")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn(body["current_level"], body["available_levels"])
        self.assertIsInstance(body["loggers"], dict)

    def test_backups_route_lists_backups(self):
        backups = [{"filename": "backup_20260913.zip", "created_at": "2026-09-13"}]

        with patch.object(system_api, "backup_list", return_value=backups):
            response = self.make_client().get("/api/system/backups")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["backups"], backups)
        self.assertEqual(response.json()["count"], 1)

    def test_log_level_route_rejects_unknown_level(self):
        response = self.make_client().post("/api/system/log-level", json={"level": "LOUD"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid log level", response.json()["detail"])

    def test_system_routes_require_session(self):
        app = FastAPI()
        app.include_router(system_api.router, prefix="/api/system")
        client = TestClient(app)

        with patch.object(
            core_dependencies,
            "load_config",
            return_value={"auth": {"password_hash": "set", "sessions": {}}},
        ):
            response = client.get("/api/system/log-level")

        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
