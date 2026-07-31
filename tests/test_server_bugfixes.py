"""Regression tests for server-side bug fixes."""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

import api.health as health_api
import server
from services.node_identity import subscription_node_id
from services.node_manager import find_subscription_node, get_proxy_node_by_id


class ServerBugfixTests(unittest.TestCase):
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
