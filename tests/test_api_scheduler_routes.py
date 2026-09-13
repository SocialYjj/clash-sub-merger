"""Route-level tests for the subscription scheduler endpoints."""

import copy
import unittest
from contextlib import contextmanager
from datetime import datetime
from unittest.mock import Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.scheduler as scheduler_api
import core.dependencies as core_dependencies
from core.dependencies import verify_session


@contextmanager
def _unlocked_write_slot(_subscription_id):
    yield


class SchedulerRoutesTest(unittest.TestCase):
    def make_client(self):
        app = FastAPI()
        app.dependency_overrides[verify_session] = lambda: True
        app.include_router(scheduler_api.router, prefix="/api/scheduler")
        return TestClient(app)

    def test_get_presets_returns_cron_presets(self):
        presets = [{"name": "Daily 3am", "value": "0 3 * * *"}]

        with patch("scheduler_service.CRON_PRESETS", presets):
            response = self.make_client().get("/api/scheduler/presets")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["presets"], presets)

    def test_validate_cron_returns_next_run_time(self):
        response = self.make_client().post("/api/scheduler/validate-cron", json={"cron_expr": "0 3 * * *"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["valid"])
        self.assertRegex(body["next_run"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        self.assertIsInstance(body["timestamp"], int)

    def test_validate_cron_reports_invalid_expression(self):
        response = self.make_client().post("/api/scheduler/validate-cron", json={"cron_expr": "not a cron"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["valid"])
        self.assertTrue(body["error"])

    def test_get_subscription_schedule_returns_saved_cron(self):
        config = {
            "auth": {},
            "subscriptions": [{"id": "sub_1", "name": "Demo", "cron_expr": "0 3 * * *", "next_update": 123}],
        }

        with patch.object(scheduler_api, "load_config", return_value=copy.deepcopy(config)):
            response = self.make_client().get("/api/scheduler/subscriptions/sub_1")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["cron_expr"], "0 3 * * *")
        self.assertEqual(body["next_update"], 123)
        self.assertTrue(body["description"])

    def test_get_subscription_schedule_returns_404_for_unknown_subscription(self):
        with patch.object(scheduler_api, "load_config", return_value={"auth": {}, "subscriptions": []}):
            response = self.make_client().get("/api/scheduler/subscriptions/sub_missing")

        self.assertEqual(response.status_code, 404)

    def test_update_schedule_registers_job_and_persists_cron(self):
        config = {"auth": {}, "subscriptions": [{"id": "sub_1", "name": "Demo", "enabled": True}]}

        def update_config(mutator):
            return mutator(config)

        scheduler = Mock()
        scheduler.add_job.return_value = "sub_refresh_sub_1"
        next_run = datetime(2026, 9, 14, 3, 0, 0)
        scheduler.get_job_info.return_value = {"next_run": next_run}

        with (
            patch.object(scheduler_api, "load_config", return_value=copy.deepcopy(config)),
            patch.object(scheduler_api, "update_config", side_effect=update_config),
            patch.object(scheduler_api, "subscription_write_slot", _unlocked_write_slot),
            patch("scheduler_service.get_scheduler", return_value=scheduler),
        ):
            response = self.make_client().put("/api/scheduler/subscriptions/sub_1", json={"cron_expr": "0 3 * * *"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["cron_expr"], "0 3 * * *")
        self.assertEqual(response.json()["next_update"], int(next_run.timestamp()))
        scheduler.add_job.assert_called_once()
        self.assertEqual(config["subscriptions"][0]["cron_expr"], "0 3 * * *")

    def test_scheduler_routes_require_session(self):
        app = FastAPI()
        app.include_router(scheduler_api.router, prefix="/api/scheduler")
        client = TestClient(app)

        with patch.object(
            core_dependencies,
            "load_config",
            return_value={"auth": {"password_hash": "set", "sessions": {}}},
        ):
            response = client.get("/api/scheduler/presets")

        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
