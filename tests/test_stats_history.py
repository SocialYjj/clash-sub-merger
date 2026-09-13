"""Tests for the daily dashboard statistics snapshot service and its API route."""

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.stats as stats_api
import core.dependencies as core_dependencies
import services.stats_history as stats_history
from core.dependencies import verify_session


def _proxy(name: str, server: str, latency=None, enabled=True) -> dict:
    node = {
        "name": name,
        "type": "trojan",
        "server": server,
        "port": 443,
        "password": "secret",
    }
    if latency is not None:
        node["last_latency"] = latency
    if enabled is not True:
        node["enabled"] = enabled
    return node


class StatsHistoryTestBase(unittest.TestCase):
    """Isolates the SQLite-backed history document in a temporary directory."""

    def setUp(self):
        _tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(_tempdir.cleanup)
        root = Path(_tempdir.name)
        patches = (
            patch("core.config.DATA_DIR", str(root)),
            patch("core.config.DATABASE_FILE", str(root / "app.db")),
        )
        for item in patches:
            item.start()
            self.addCleanup(item.stop)


class RecordStatsSnapshotTests(StatsHistoryTestBase):
    def test_snapshot_counts_effective_nodes_and_min_latency(self):
        config = {
            "subscriptions": [
                {"id": "sub_a", "name": "A", "enabled": True},
                {"id": "sub_b", "name": "B", "enabled": False},
            ],
            "custom_nodes": [
                {
                    "name": "Custom US 01",
                    "type": "vmess",
                    "server": "custom.example.com",
                    "port": 443,
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "last_latency": 30,
                },
                {
                    "name": "已禁用节点",
                    "type": "vmess",
                    "server": "off.example.com",
                    "port": 443,
                    "uuid": "2",
                    "enabled": False,
                },
            ],
            "users": [{"id": "u1", "enabled": True}, {"id": "u2", "enabled": False}],
        }
        subscription = {
            "proxies": [
                _proxy("🇯🇵 Japan 01", "a.example.com", latency=42),
                _proxy("🇺🇸 US 01", "b.example.com", latency=88),
                _proxy("防丢失官网:https://example.com", "info.example.com", latency=1),
                _proxy("Disabled 01", "c.example.com", latency=5, enabled=False),
            ]
        }

        with (
            patch.object(stats_history, "load_config", return_value=config),
            patch.object(stats_history, "load_subscription_yaml", return_value=subscription),
        ):
            snapshot = stats_history.record_stats_snapshot()

        self.assertEqual(snapshot["date"], time.strftime("%Y-%m-%d"))
        # Info nodes and disabled nodes are excluded, disabled subscription skipped.
        self.assertEqual(snapshot["total_nodes"], 2)
        self.assertEqual(snapshot["subscription_count"], 1)
        self.assertEqual(snapshot["custom_node_count"], 1)
        self.assertEqual(snapshot["user_count"], 1)
        self.assertEqual(snapshot["min_latency_ms"], 30)
        self.assertGreater(snapshot["recorded_at"], 0)
        self.assertEqual(stats_history.load_stats_history(), [snapshot])

    def test_snapshot_without_latency_data_stores_null(self):
        config = {"subscriptions": [{"id": "sub_a", "name": "A"}], "custom_nodes": [], "users": []}
        subscription = {"proxies": [_proxy("Japan 01", "a.example.com")]}

        with (
            patch.object(stats_history, "load_config", return_value=config),
            patch.object(stats_history, "load_subscription_yaml", return_value=subscription),
        ):
            snapshot = stats_history.record_stats_snapshot()

        self.assertIsNone(snapshot["min_latency_ms"])

    def test_same_date_snapshot_replaces_existing_entry(self):
        first = {"subscriptions": [{"id": "sub_a", "name": "A"}], "custom_nodes": [], "users": []}
        second = {"subscriptions": [], "custom_nodes": [], "users": []}
        subscription = {"proxies": [_proxy("Japan 01", "a.example.com")]}

        with (
            patch.object(stats_history, "load_subscription_yaml", return_value=subscription),
            patch.object(stats_history, "load_config", return_value=first),
        ):
            stats_history.record_stats_snapshot()
        with patch.object(stats_history, "load_config", return_value=second):
            stats_history.record_stats_snapshot()

        history = stats_history.load_stats_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["total_nodes"], 0)

    def test_history_is_pruned_to_newest_entries_ascending(self):
        dates = [f"2026-01-{day:02d}" for day in range(1, 8)]
        config = {"subscriptions": [], "custom_nodes": [], "users": []}

        with (
            patch.object(stats_history, "STATS_HISTORY_MAX_ENTRIES", 5),
            patch.object(stats_history, "load_config", return_value=config),
            patch.object(stats_history, "_local_today", side_effect=iter(dates)),
        ):
            for _ in dates:
                stats_history.record_stats_snapshot()

        history = stats_history.load_stats_history()
        self.assertEqual([entry["date"] for entry in history], dates[-5:])

    def test_snapshot_failure_never_raises(self):
        with patch.object(stats_history, "load_config", side_effect=RuntimeError("boom")):
            snapshot = stats_history.record_stats_snapshot()

        self.assertEqual(snapshot, {})
        self.assertEqual(stats_history.load_stats_history(), [])


class StaleSnapshotBackfillTests(StatsHistoryTestBase):
    def test_backfills_when_history_is_missing(self):
        with patch.object(
            stats_history, "load_config", return_value={"subscriptions": [], "custom_nodes": [], "users": []}
        ):
            snapshot = stats_history.record_stats_snapshot_if_stale()

        self.assertEqual(snapshot["date"], time.strftime("%Y-%m-%d"))
        self.assertEqual(len(stats_history.load_stats_history()), 1)

    def test_skips_backfill_when_latest_snapshot_is_fresh(self):
        now = time.time()
        stats_history._upsert_snapshot(
            {
                "date": "2026-01-01",
                "total_nodes": 7,
                "subscription_count": 1,
                "custom_node_count": 0,
                "user_count": 0,
                "min_latency_ms": None,
                "recorded_at": int(now - 3600),
            }
        )

        with patch.object(stats_history, "record_stats_snapshot") as record:
            result = stats_history.record_stats_snapshot_if_stale(max_age_hours=20)

        self.assertEqual(result, {})
        record.assert_not_called()
        self.assertEqual(stats_history.load_stats_history()[0]["total_nodes"], 7)

    def test_backfills_when_latest_snapshot_is_older_than_limit(self):
        now = time.time()
        stats_history._upsert_snapshot(
            {
                "date": "2000-01-01",
                "total_nodes": 7,
                "subscription_count": 1,
                "custom_node_count": 0,
                "user_count": 0,
                "min_latency_ms": None,
                "recorded_at": int(now - 21 * 3600),
            }
        )

        with patch.object(
            stats_history, "load_config", return_value={"subscriptions": [], "custom_nodes": [], "users": []}
        ):
            result = stats_history.record_stats_snapshot_if_stale(max_age_hours=20)

        self.assertEqual(result["date"], time.strftime("%Y-%m-%d"))
        history = stats_history.load_stats_history()
        self.assertEqual(history[0]["date"], "2000-01-01")
        self.assertEqual(history[-1]["date"], time.strftime("%Y-%m-%d"))


class StatsHistoryRouteTests(unittest.TestCase):
    def make_client(self, override_session: bool = False):
        app = FastAPI()
        if override_session:
            app.dependency_overrides[verify_session] = lambda: True
        app.include_router(stats_api.router, prefix="/api/stats")
        return TestClient(app)

    def test_history_route_returns_ascending_entries(self):
        stored = [
            {
                "date": "2026-01-01",
                "total_nodes": 3,
                "subscription_count": 1,
                "custom_node_count": 0,
                "user_count": 1,
                "min_latency_ms": 120,
                "recorded_at": 1,
            },
            {
                "date": "2026-01-02",
                "total_nodes": 5,
                "subscription_count": 2,
                "custom_node_count": 1,
                "user_count": 1,
                "min_latency_ms": 90,
                "recorded_at": 2,
            },
        ]

        with patch.object(stats_api, "load_stats_history", return_value=stored):
            response = self.make_client(override_session=True).get("/api/stats/history")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"history": stored})

    def test_history_route_requires_session(self):
        app = FastAPI()
        app.include_router(stats_api.router, prefix="/api/stats")
        client = TestClient(app)

        with patch.object(
            core_dependencies,
            "load_config",
            return_value={"auth": {"password_hash": "set", "sessions": {}}},
        ):
            response = client.get("/api/stats/history")

        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
