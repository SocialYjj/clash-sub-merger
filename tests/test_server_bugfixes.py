"""Regression tests for server-side bug fixes."""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

import api.health as health_api
import api.subscriptions as subscriptions_api
import server
from services.node_identity import subscription_node_id, subscription_node_ids
from services.node_manager import find_subscription_node, get_proxy_node_by_id
from services.subscription_node_count import count_effective_subscription_nodes


class ServerBugfixTests(unittest.TestCase):
    def test_effective_subscription_count_excludes_info_and_disabled_nodes(self):
        nodes = [
            {
                "name": "US 01",
                "type": "http",
                "server": "us.example.com",
                "port": 8080,
            },
            {
                "name": "US 02",
                "type": "http",
                "server": "disabled.example.com",
                "port": 8080,
                "enabled": False,
            },
            {
                "name": "加入频道获取更多节点",
                "type": "http",
                "server": "info.example.com",
                "port": 8080,
            },
        ]

        self.assertEqual(count_effective_subscription_nodes(nodes), 1)

    def test_subscription_list_does_not_return_persisted_count_when_yaml_is_unavailable(self):
        config = {
            "subscriptions": [{
                "id": "sub_missing",
                "name": "Missing",
                "enabled": True,
                "node_count": 54,
            }],
        }

        with (
            patch.object(subscriptions_api, "load_config", return_value=config),
            patch.object(subscriptions_api, "load_subscription_yaml", side_effect=FileNotFoundError),
        ):
            response = subscriptions_api.list_subscriptions.__wrapped__(True)

        subscription = response["subscriptions"][0]
        self.assertEqual(subscription["node_count"], 0)
        self.assertTrue(subscription["node_count_stale"])
        self.assertEqual(subscription["node_count_error"], "Subscription data unavailable")

    def test_subscription_node_count_migration_updates_once_and_preserves_fields(self):
        config = {
            "subscriptions": [
                {
                    "id": "sub_demo",
                    "name": "Demo",
                    "node_count": 99,
                    "enabled": True,
                    "last_success": 123,
                },
            ],
        }
        source_nodes = [
            {
                "name": "US 01",
                "type": "http",
                "server": "us.example.com",
                "port": 8080,
            },
            {
                "name": "US 02",
                "type": "http",
                "server": "disabled.example.com",
                "port": 8080,
                "enabled": False,
            },
        ]

        with (
            patch.object(server, "load_config", return_value=config),
            patch.object(server, "load_subscription_yaml", return_value={"proxies": source_nodes}),
            patch.object(server, "save_config") as save_config,
        ):
            server.migrate_subscription_node_counts()

        self.assertEqual(config["subscriptions"][0]["node_count"], 1)
        self.assertEqual(config["subscriptions"][0]["last_success"], 123)
        self.assertTrue(config["migration_versions"]["subscription_node_counts_v1"])
        save_config.assert_called_once_with(config)

        with (
            patch.object(server, "load_config", return_value=config),
            patch.object(server, "load_subscription_yaml") as load_yaml,
            patch.object(server, "save_config") as save_config,
        ):
            server.migrate_subscription_node_counts()

        load_yaml.assert_not_called()
        save_config.assert_not_called()

    def test_subscription_node_count_migration_waits_for_missing_enabled_source(self):
        config = {
            "subscriptions": [
                {"id": "sub_missing", "name": "Missing", "node_count": 4, "enabled": True},
            ],
        }

        with (
            patch.object(server, "load_config", return_value=config),
            patch.object(server, "load_subscription_yaml", side_effect=FileNotFoundError),
            patch.object(server, "save_config") as save_config,
        ):
            server.migrate_subscription_node_counts()

        self.assertNotIn("migration_versions", config)
        save_config.assert_not_called()

    def test_subscription_node_count_migration_skips_source_without_proxy_list(self):
        config = {
            "subscriptions": [
                {"id": "sub_partial", "name": "Partial", "node_count": 7, "enabled": True},
            ],
        }

        with (
            patch.object(server, "load_config", return_value=config),
            patch.object(server, "load_subscription_yaml", return_value={"dns": {"enable": True}}),
            patch.object(server, "save_config") as save_config,
        ):
            server.migrate_subscription_node_counts()

        self.assertEqual(config["subscriptions"][0]["node_count"], 7)
        self.assertNotIn("migration_versions", config)
        save_config.assert_not_called()

    def test_subscription_node_count_migration_preserves_positive_count_for_empty_source(self):
        config = {
            "subscriptions": [
                {"id": "sub_empty", "name": "Empty", "node_count": 12, "enabled": True},
            ],
        }

        with (
            patch.object(server, "load_config", return_value=config),
            patch.object(server, "load_subscription_yaml", return_value={"proxies": []}),
            patch.object(server, "save_config") as save_config,
        ):
            server.migrate_subscription_node_counts()

        self.assertEqual(config["subscriptions"][0]["node_count"], 12)
        self.assertNotIn("migration_versions", config)
        save_config.assert_not_called()

    def test_subscription_node_count_migration_accepts_already_empty_source(self):
        config = {
            "subscriptions": [
                {"id": "sub_empty", "name": "Empty", "node_count": 0, "enabled": True},
            ],
        }

        with (
            patch.object(server, "load_config", return_value=config),
            patch.object(server, "load_subscription_yaml", return_value={"proxies": []}),
            patch.object(server, "save_config") as save_config,
        ):
            server.migrate_subscription_node_counts()

        self.assertTrue(config["migration_versions"]["subscription_node_counts_v1"])
        save_config.assert_called_once_with(config)

    def test_filter_underscore_fields_removes_all_management_metadata(self):
        node = {
            "name": "🇯🇵 Node",
            "type": "http",
            "server": "example.com",
            "port": 8080,
            "source": "provider",
            "sourceId": "sub_1",
            "sourceType": "subscription",
            "idx": 3,
            "nodeKey": "internal-key",
            "final_name": "internal-name",
            "flag": "🇯🇵",
            "country": "Japan",
            "region": "Tokyo",
            "city": "Tokyo",
            "last_latency": 42,
            "last_speed": 1024,
            "_source_id": "sub_1",
        }

        cleaned = server.filter_underscore_fields(node)

        self.assertEqual(cleaned, {
            "name": "🇯🇵 Node",
            "type": "http",
            "server": "example.com",
            "port": 8080,
        })

    def test_base64_padding_adds_only_missing_padding(self):
        self.assertEqual(server._pad_base64("abcd"), "abcd")
        self.assertEqual(server._pad_base64("abc"), "abc=")
        self.assertEqual(server._pad_base64("ab"), "ab==")
        self.assertEqual(server._pad_base64("a"), "a===")

    def test_extract_country_from_full_flag_emoji(self):
        info = server.extract_country_from_name("🇯🇵 Tokyo 01")

        self.assertIsNotNone(info)
        self.assertEqual(info["country_code"], "JP")

    def test_subscription_node_id_allows_underscores_in_subscription_id(self):
        expected_node = {
            "name": "second",
            "type": "http",
            "server": "second.example.com",
            "port": 8080,
        }
        with tempfile.TemporaryDirectory() as tempdir:
            sub_file = Path(tempdir) / "my_sub_name.yaml"
            sub_file.write_text("proxies: []\n", encoding="utf-8")

            with (
                patch("services.node_manager.load_config", return_value={
                    "custom_nodes": [],
                    "subscriptions": [{"id": "my_sub_name", "name": "Provider"}],
                }),
                patch("services.node_manager.load_subscription_yaml", return_value={
                    "proxies": [
                        {"name": "first", "type": "http", "server": "first.example.com", "port": 8080},
                        expected_node,
                    ]
                }),
            ):
                node = get_proxy_node_by_id(
                    subscription_node_id("my_sub_name", expected_node),
                    yaml_source_dir=tempdir,
                )

        self.assertEqual(node, expected_node)

    def test_invalid_stable_id_does_not_fall_back_to_name_or_position(self):
        nodes = [
            {"name": "first", "type": "http", "server": "first.example.com", "port": 8080},
            {"name": "second", "type": "http", "server": "second.example.com", "port": 8080},
        ]
        with tempfile.TemporaryDirectory() as tempdir:
            sub_file = Path(tempdir) / "my_sub_1.yaml"
            sub_file.write_text("proxies: []\n", encoding="utf-8")

            with (
                patch("services.node_manager.load_config", return_value={
                    "subscriptions": [{"id": "my_sub_1", "name": "Provider"}],
                }),
                patch("services.node_manager.load_subscription_yaml", return_value={"proxies": nodes}),
            ):
                node = find_subscription_node(
                    "my_sub_1",
                    node_index=1,
                    node_name="second",
                    node_id="node_invalid",
                    yaml_source_dir=tempdir,
                )

        self.assertIsNone(node)

    def test_subscription_lookup_accepts_ui_id_for_duplicate_endpoint(self):
        nodes = [
            {"name": "CF 01", "type": "http", "server": "edge.example.com", "port": 8080},
            {"name": "CF 02", "type": "http", "server": "edge.example.com", "port": 8080},
        ]
        ui_ids = subscription_node_ids("my_sub_1", nodes)

        with tempfile.TemporaryDirectory() as tempdir:
            sub_file = Path(tempdir) / "my_sub_1.yaml"
            sub_file.write_text("proxies: []\n", encoding="utf-8")

            with (
                patch("services.node_manager.load_config", return_value={
                    "subscriptions": [{"id": "my_sub_1", "name": "Provider"}],
                }),
                patch("services.node_manager.load_subscription_yaml", return_value={"proxies": nodes}),
            ):
                node = find_subscription_node(
                    "my_sub_1",
                    node_id=ui_ids[1],
                    yaml_source_dir=tempdir,
                )

        self.assertEqual(node["server"], "edge.example.com")
        self.assertEqual(node["_allocation_id"], subscription_node_id("my_sub_1", nodes[1]))

    def test_sync_fetch_wrapper_rejects_running_event_loop(self):
        async def call_sync_wrapper():
            with self.assertRaisesRegex(RuntimeError, "async context"):
                server.fetch_subscription("https://example.test/sub")

        asyncio.run(call_sync_wrapper())

    def test_frontend_static_resolver_blocks_path_traversal(self):
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir) / "dist"
            root.mkdir()
            safe_file = root / "favicon.ico"
            safe_file.write_text("icon", encoding="utf-8")
            data_dir = Path(tempdir) / "data"
            data_dir.mkdir()
            secret = data_dir / "config.json"
            secret.write_text('{"token":"secret"}', encoding="utf-8")

            with patch.object(server, "frontend_dist_path", root.resolve()):
                self.assertEqual(server._resolve_frontend_static_file("favicon.ico"), safe_file.resolve())
                self.assertIsNone(server._resolve_frontend_static_file("../data/config.json"))

    def test_security_headers_are_added_to_http_responses(self):
        with patch.object(health_api.AppConfig, "GO_SPEEDTEST_ENABLED", False):
            response = TestClient(server.app).get("/health")

        self.assertIn("default-src 'self'", response.headers.get("content-security-policy", ""))
        self.assertEqual(response.headers.get("x-content-type-options"), "nosniff")

    def test_default_cors_wildcard_disables_credentials(self):
        self.assertEqual(server._cors_origins, ["*"])
        self.assertFalse(server._cors_allow_credentials)

    def test_speedtest_start_fails_if_process_exits_during_startup(self):
        fake_process = Mock()
        fake_process.pid = 12345
        fake_process.poll.return_value = 1

        with tempfile.TemporaryDirectory() as tempdir:
            executable = Path(tempdir) / "speedtest"
            executable.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            executable.chmod(0o755)

            with (
                patch.object(server.AppConfig, "GO_SPEEDTEST_BIN", str(executable)),
                patch.object(server.subprocess, "Popen", return_value=fake_process),
                patch.object(server.time, "sleep", return_value=None),
            ):
                server.GO_SPEEDTEST_PROCESS = None
                started = server.start_go_speedtest_service()

        self.assertFalse(started)
        self.assertIsNone(server.GO_SPEEDTEST_PROCESS)


if __name__ == "__main__":
    unittest.main()
