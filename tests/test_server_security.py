"""Regression tests for server security and speedtest startup hardening."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

import server


class ServerSecurityTests(unittest.TestCase):
    def test_frontend_static_resolver_blocks_path_traversal(self):
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir) / "dist"
            root.mkdir()
            safe_file = root / "favicon.ico"
            safe_file.write_text("icon", encoding="utf-8")
            data_dir = Path(tempdir) / "data"
            data_dir.mkdir()
            (data_dir / "config.json").write_text('{"token":"secret"}', encoding="utf-8")

            with patch.object(server, "frontend_dist_path", root.resolve()):
                self.assertEqual(server._resolve_frontend_static_file("favicon.ico"), safe_file.resolve())
                self.assertIsNone(server._resolve_frontend_static_file("../data/config.json"))

    def test_security_headers_are_added_to_http_responses(self):
        response = TestClient(server.app).get("/health")

        self.assertIn("default-src 'self'", response.headers.get("content-security-policy", ""))
        self.assertEqual(response.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(response.headers.get("x-frame-options"), "DENY")

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
