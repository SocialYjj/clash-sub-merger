"""Regression tests for server security and speedtest startup hardening."""

import asyncio
import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import api.auth as auth_api
import api.health as health_api
import services.backup as backup_service
import server
from core.dependencies import verify_session
from core.security import generate_session_token, hash_password, session_storage_key
from core.token_utils import constant_time_equal
from helpers import load_subscription_yaml


class ServerSecurityTests(unittest.TestCase):
    def test_yaml_python_object_tags_are_not_executed(self):
        malicious = (
            "proxies:\n"
            "  - name: evil\n"
            "    type: ss\n"
            "    server: !!python/object/apply:os.system [\"echo pwned\"]\n"
            "    port: 443\n"
        )

        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "evil.yaml").write_text(malicious, encoding="utf-8")

            with patch("os.system") as system_call:
                with self.assertRaises(Exception):
                    load_subscription_yaml("evil", tempdir, use_cache=False)

        system_call.assert_not_called()

        with patch("os.system") as system_call:
            server._process_subscription_content_str(malicious)

        system_call.assert_not_called()

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
        with patch.object(health_api.AppConfig, "GO_SPEEDTEST_ENABLED", False):
            response = TestClient(server.app).get("/health")

        self.assertIn("default-src 'self'", response.headers.get("content-security-policy", ""))
        self.assertEqual(response.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(response.headers.get("x-frame-options"), "DENY")

    def test_api_docs_are_disabled_by_default(self):
        self.assertIsNone(server.app.docs_url)
        self.assertIsNone(server.app.redoc_url)
        self.assertIsNone(server.app.openapi_url)

    def test_builtin_access_log_is_disabled_to_protect_subscription_tokens(self):
        source = Path(server.__file__).read_text(encoding="utf-8")

        self.assertIn("uvicorn.run(app, host=host, port=port, access_log=False)", source)

    def test_container_healthchecks_do_not_depend_on_curl(self):
        repo_root = Path(__file__).resolve().parents[1]
        dockerfile = (repo_root / "Dockerfile").read_text(encoding="utf-8")
        compose = (repo_root / "docker-compose.yml").read_text(encoding="utf-8")

        self.assertNotIn("CMD curl -f", dockerfile)
        self.assertNotIn('"curl", "-f"', compose)
        self.assertIn("urllib.request", dockerfile)
        self.assertIn("urllib.request", compose)

    def test_runtime_container_uses_unprivileged_user(self):
        repo_root = Path(__file__).resolve().parents[1]
        dockerfile = (repo_root / "Dockerfile").read_text(encoding="utf-8")
        entrypoint = (repo_root / "docker-entrypoint.sh").read_text(encoding="utf-8")

        self.assertIn("useradd --create-home --uid 1000", dockerfile)
        self.assertIn("chown -R appuser:appuser /app", dockerfile)
        self.assertIn("gosu", dockerfile)
        self.assertIn('ENTRYPOINT ["docker-entrypoint.sh"]', dockerfile)
        self.assertIn('chown appuser:appuser "$data_dir"', entrypoint)
        self.assertIn('find "$data_dir" -maxdepth 1 -type f -exec chown appuser:appuser {} +', entrypoint)
        self.assertIn('gosu appuser touch "$write_probe"', entrypoint)
        self.assertIn('exec gosu appuser "$@"', entrypoint)

    def test_subscription_refresh_lock_uses_async_filelock_and_timeout_alias(self):
        content = (
            Path(__file__).resolve().parents[1]
            / "services"
            / "subscription_refresh_lock.py"
        ).read_text(encoding="utf-8")

        self.assertIn("AsyncFileLock", content)
        self.assertIn("Timeout as FileLockTimeout", content)
        self.assertIn("except FileLockTimeout:", content)
        self.assertIn("await file_lock.release(force=True)", content)

    def test_health_endpoint_returns_503_when_required_speedtest_is_down(self):
        class DownClient:
            async def get(self, *args, **kwargs):
                raise RuntimeError("down")

        async def run_check():
            with (
                patch.object(health_api, "_http_client", DownClient()),
                patch.object(health_api.AppConfig, "GO_SPEEDTEST_ENABLED", True),
                patch.object(health_api, "load_config", return_value={"auth": {"password_hash": "set"}}),
            ):
                return await health_api.health_check()

        response = asyncio.run(run_check())

        self.assertEqual(response.status_code, 503)
        self.assertIn(b'"status":"unhealthy"', response.body)

    def test_health_endpoint_uses_injected_http_client(self):
        class Response:
            status_code = 200

        class HealthyClient:
            def __init__(self):
                self.called = False

            async def get(self, *args, **kwargs):
                self.called = True
                return Response()

        async def run_check():
            client = HealthyClient()
            with (
                patch.object(health_api, "_http_client", client),
                patch.object(health_api.AppConfig, "GO_SPEEDTEST_ENABLED", True),
                patch.object(health_api, "load_config", return_value={"auth": {"password_hash": "set"}}),
            ):
                response = await health_api.health_check()
            return response, client

        response, client = asyncio.run(run_check())

        self.assertTrue(client.called)
        self.assertEqual(response.status_code, 200)

    def test_default_cors_wildcard_disables_credentials(self):
        self.assertEqual(server._cors_origins, ["*"])
        self.assertFalse(server._cors_allow_credentials)

    def test_backup_restore_and_delete_reject_path_traversal(self):
        with tempfile.TemporaryDirectory() as tempdir:
            outside = Path(tempdir).parent / "outside_backup_target.json"
            outside.write_text("{}", encoding="utf-8")
            self.addCleanup(lambda: outside.exists() and outside.unlink())

            with patch.object(backup_service, "BACKUP_DIR", tempdir):
                for action in (backup_service.restore_backup, backup_service.delete_backup):
                    with self.assertRaises(ValueError):
                        action("../outside_backup_target.json")
                    with self.assertRaises(ValueError):
                        action("..\\outside_backup_target.json")

            self.assertTrue(outside.exists())

    def test_backup_restore_uses_atomic_replace_and_creates_pre_restore_backup(self):
        with tempfile.TemporaryDirectory() as tempdir:
            data_dir = Path(tempdir)
            backup_dir = data_dir / "backups"
            backup_dir.mkdir()
            config_file = data_dir / "config.json"
            config_file.write_text(json.dumps({"auth": {"old": True}}), encoding="utf-8")
            backup_file = backup_dir / "config_20260101_restore.json"
            restored_config = {"auth": {"password_hash": "a" * 64, "restored": True}}
            backup_file.write_text(json.dumps(restored_config), encoding="utf-8")

            with (
                patch.object(backup_service, "CONFIG_FILE", str(config_file)),
                patch.object(backup_service, "BACKUP_DIR", str(backup_dir)),
            ):
                self.assertTrue(backup_service.restore_backup(backup_file.name))

            self.assertEqual(json.loads(config_file.read_text(encoding="utf-8")), restored_config)
            self.assertFalse(Path(f"{config_file}.restore.tmp").exists())
            pre_restore_backups = list(backup_dir.glob("config_*_pre_restore.json"))
            self.assertEqual(len(pre_restore_backups), 1)
            self.assertEqual(json.loads(pre_restore_backups[0].read_text(encoding="utf-8")), {"auth": {"old": True}})

    def test_subscription_token_comparison_helper_preserves_behavior(self):
        self.assertTrue(constant_time_equal("token-value", "token-value"))
        self.assertFalse(constant_time_equal("token-value", "other-value"))
        self.assertFalse(constant_time_equal(None, "token-value"))

    def test_verify_session_distinguishes_invalid_and_expired_tokens(self):
        config = {
            "auth": {
                "password_hash": "set",
                "sessions": {
                    "expired-token": 1,
                },
            }
        }

        with patch("core.dependencies.load_config", return_value=config):
            with self.assertRaises(HTTPException) as invalid_ctx:
                verify_session("bogus-token")
        self.assertEqual(invalid_ctx.exception.detail, "Invalid session")

        def update_config(mutator):
            return mutator(config)

        with (
            patch("core.dependencies.load_config", return_value=config),
            patch("core.dependencies.update_config", side_effect=update_config),
        ):
            with self.assertRaises(HTTPException) as expired_ctx:
                verify_session("expired-token")
        self.assertEqual(expired_ctx.exception.detail, "Session expired")

    def test_verify_session_accepts_and_migrates_legacy_plaintext_session_keys(self):
        config = {
            "auth": {
                "password_hash": "set",
                "sessions": {
                    "legacy-token": 9999999999,
                },
            }
        }

        def update_config(mutator):
            return mutator(config)

        with (
            patch("core.dependencies.load_config", return_value=config),
            patch("core.dependencies.update_config", side_effect=update_config),
        ):
            self.assertTrue(verify_session("legacy-token"))

        self.assertNotIn("legacy-token", config["auth"]["sessions"])
        self.assertIn(session_storage_key("legacy-token"), config["auth"]["sessions"])

    def test_session_secret_signs_new_sessions_when_configured(self):
        with patch("core.security.SESSION_SECRET", "test-secret"):
            token = generate_session_token()

        self.assertTrue(token.startswith("st_"))
        self.assertIn(".", token)

    def test_login_route_enforces_configured_rate_limit(self):
        auth_api.limiter.reset()
        config = {"auth": {"password_hash": hash_password("Correct123"), "sessions": {}}}

        def update_config(mutator):
            return mutator(config)

        app = FastAPI()
        app.state.limiter = auth_api.limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.include_router(auth_api.router, prefix="/api/auth")
        client = TestClient(app)

        with patch.object(auth_api, "update_config", side_effect=update_config):
            responses = [
                client.post("/api/auth/login", json={"password": "wrong-password"})
                for _ in range(11)
            ]

        self.assertEqual([r.status_code for r in responses[:10]], [401] * 10)
        self.assertEqual(responses[10].status_code, 429)

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

    def test_async_startup_does_not_block_event_loop_with_speedtest_sleep(self):
        source = Path(server.__file__).read_text(encoding="utf-8")

        self.assertIn("await asyncio.to_thread(start_go_speedtest_service)", source)


if __name__ == "__main__":
    unittest.main()
