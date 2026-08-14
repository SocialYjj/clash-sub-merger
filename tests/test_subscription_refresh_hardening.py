"""Regression tests for subscription refresh, scheduling, and public auth hardening."""

import asyncio
import base64
import copy
import inspect
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import api.admin_tokens as admin_tokens_api
import api.auth as auth_api
import api.proxy_chains as proxy_chains_api
import api.scheduler as scheduler_api
import api.subscriptions as subscriptions_api
import api.users as users_api
import server
from core.dependencies import verify_session
from services.subscription_fetcher import FetchError, SubscriptionFetcher
from services.subscription_state import refresh_failure_fields
import services.subscription_refresh_lock as refresh_lock_service


@asynccontextmanager
async def _unlocked_refresh(_subscription_id: str):
    yield


class AuthAndRouteRegressionTests(unittest.TestCase):
    def test_public_auth_status_does_not_return_subscription_credentials(self):
        config = {
            "auth": {
                "password_hash": "set",
                "sub_token": "must-not-leak",
                "sub_filename": "private.yaml",
                "sub_name": "private",
            }
        }

        with patch.object(auth_api, "load_config", return_value=config):
            response = auth_api.get_auth_status()

        self.assertEqual(response, {"has_password": True})

    def test_public_initial_setup_route_is_not_registered(self):
        app = FastAPI()
        app.include_router(auth_api.router, prefix="/api/auth")

        response = TestClient(app).post(
            "/api/auth/setup",
            json={"password": "Password123"},
        )

        self.assertIn(response.status_code, {404, 405})

    def test_deprecated_global_subscription_token_routes_are_not_registered(self):
        registered_paths = {route.path for route in auth_api.router.routes}

        self.assertNotIn("/regenerate-token", registered_paths)
        self.assertNotIn("/sub-token", registered_paths)
        self.assertNotIn("/sub-filename", registered_paths)
        self.assertNotIn("/sub-name", registered_paths)

    def test_user_and_admin_group_read_and_preview_routes_exist(self):
        template = {
            "id": "tpl_custom",
            "name": "自定义模板",
            "header": "",
            "suffix": "",
            "proxy_groups": [{"name": "节点选择", "type": "select", "_editable": True}],
        }
        config = {
            "subscriptions": [],
            "custom_nodes": [],
            "templates": [template],
            "users": [{
                "id": "user_1",
                "name": "User",
                "template_id": "tpl_custom",
                "allocations": {},
                "group_config": {"节点选择": ["DIRECT"]},
            }],
            "admin_tokens": [{
                "id": "admin_1",
                "name": "Admin",
                "template_id": "tpl_custom",
                "group_config": {"节点选择": ["REJECT"]},
            }],
        }

        app = FastAPI()
        app.include_router(users_api.router, prefix="/api/users")
        app.include_router(admin_tokens_api.router, prefix="/api/admin-tokens")
        app.dependency_overrides[verify_session] = lambda: True
        client = TestClient(app)

        with (
            patch.object(users_api, "load_config", return_value=copy.deepcopy(config)),
            patch.object(admin_tokens_api, "load_config", return_value=copy.deepcopy(config)),
            patch("api.templates.get_builtin_template", return_value={"proxy_groups": []}),
        ):
            user_view = client.get("/api/users/user_1/group-config")
            user_preview = client.get("/api/users/user_1/preview-yaml")
            admin_view = client.get("/api/admin-tokens/admin_1/group-config")
            admin_preview = client.get("/api/admin-tokens/admin_1/preview-yaml")

        self.assertEqual(user_view.status_code, 200)
        self.assertEqual(user_view.json()["groups"][0]["current_nodes"], ["DIRECT"])
        self.assertIn("DIRECT", user_preview.json()["yaml"])
        self.assertEqual(admin_view.status_code, 200)
        self.assertEqual(admin_view.json()["groups"][0]["current_nodes"], ["REJECT"])
        self.assertIn("REJECT", admin_preview.json()["yaml"])

    def test_proxy_chain_reorder_matches_static_route(self):
        config = {
            "proxy_chains": [
                {"id": "chain_1", "name": "one"},
                {"id": "chain_2", "name": "two"},
            ]
        }

        def update_config(mutator):
            return mutator(config)

        app = FastAPI()
        app.include_router(proxy_chains_api.router, prefix="/api/proxy-chains")
        app.dependency_overrides[verify_session] = lambda: True

        with patch.object(proxy_chains_api, "update_config", side_effect=update_config):
            response = TestClient(app).put(
                "/api/proxy-chains/reorder",
                json={"order": ["chain_2", "chain_1"]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [chain["id"] for chain in config["proxy_chains"]],
            ["chain_2", "chain_1"],
        )


class SubscriptionRefreshRegressionTests(unittest.TestCase):
    @staticmethod
    def _valid_subscription_response(url: str) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            text=(
                "proxies:\n"
                "  - name: Test Node\n"
                "    type: http\n"
                "    server: 127.0.0.1\n"
                "    port: 8080\n"
            ),
        )

    def test_transient_fetch_retries_without_exposing_subscription_url(self):
        secret_url = "https://provider.example/sub/account-secret?token=query-secret"
        responses = [
            httpx.Response(503, request=httpx.Request("GET", secret_url)),
            self._valid_subscription_response(secret_url),
        ]

        class SequenceClient:
            def __init__(self):
                self.calls = 0

            @asynccontextmanager
            async def stream(self, *_args, **_kwargs):
                response = responses[self.calls]
                self.calls += 1
                yield response

        http_client = SequenceClient()
        fetcher = SubscriptionFetcher(http_client)

        with (
            patch.object(subscriptions_api.AppConfig, "SUBSCRIPTION_FETCH_RETRIES", 1),
            patch.object(subscriptions_api.AppConfig, "SUBSCRIPTION_FETCH_RETRY_DELAY_SECONDS", 0),
            patch("services.subscription_fetcher.logger.warning") as warning_log,
        ):
            _content, _usage, node_count = asyncio.run(
                fetcher.fetch(secret_url, "test-agent")
            )

        self.assertEqual(http_client.calls, 2)
        self.assertEqual(node_count, 1)
        self.assertNotIn("account-secret", repr(warning_log.call_args_list))
        self.assertNotIn("query-secret", repr(warning_log.call_args_list))

    def test_empty_html_and_zero_node_responses_are_rejected(self):
        fetcher = SubscriptionFetcher(Mock())
        request = httpx.Request("GET", "https://provider.example/redacted")
        invalid_responses = [
            httpx.Response(200, request=request, content=b""),
            httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/html"},
                text="<html><body>upstream error</body></html>",
            ),
            httpx.Response(
                200,
                request=request,
                headers={"content-type": "application/octet-stream"},
                text="<!doctype html><html><body>upstream error</body></html>",
            ),
            httpx.Response(200, request=request, text="proxies: []\n"),
        ]

        for response in invalid_responses:
            with self.subTest(content=response.text[:20]):
                with self.assertRaises(FetchError):
                    fetcher._process_response(response)

    def test_valid_base64_response_with_html_content_type_is_accepted(self):
        fetcher = SubscriptionFetcher(Mock())
        yaml_content = (
            "proxies:\n"
            "  - name: Test Node\n"
            "    type: http\n"
            "    server: 127.0.0.1\n"
            "    port: 8080\n"
        )
        encoded_content = base64.b64encode(yaml_content.encode()).decode()
        response = httpx.Response(
            200,
            request=httpx.Request("GET", "https://provider.example/redacted"),
            headers={"content-type": "text/html; charset=utf-8"},
            text=encoded_content,
        )

        parsed_content, _usage, node_count = fetcher._process_response(response)

        self.assertEqual(node_count, 1)
        self.assertIn("Test Node", parsed_content)

    def test_fetch_failure_message_does_not_expose_subscription_url(self):
        secret_url = "https://provider.example/account-secret?token=query-secret"

        class NotFoundClient:
            @asynccontextmanager
            async def stream(self, *_args, **_kwargs):
                yield httpx.Response(
                    404,
                    request=httpx.Request("GET", secret_url),
                )

        with self.assertRaises(FetchError) as error_context:
            asyncio.run(
                SubscriptionFetcher(NotFoundClient()).fetch(secret_url, "test-agent")
            )

        error_message = str(error_context.exception)
        self.assertIn("HTTP 404", error_message)
        self.assertNotIn("account-secret", error_message)
        self.assertNotIn("query-secret", error_message)

    def test_failed_refresh_keeps_existing_yaml_unchanged(self):
        with tempfile.TemporaryDirectory() as tempdir:
            yaml_path = Path(tempdir) / "sub_1.yaml"
            old_content = "proxies:\n  - name: Existing Node\n    type: http\n    server: 127.0.0.1\n    port: 8080\n"
            yaml_path.write_text(old_content, encoding="utf-8")
            subscription = {
                "id": "sub_1",
                "name": "Provider",
                "url": "https://provider.example/private-token",
                "type": "url",
                "enabled": True,
            }
            config = {"subscriptions": [subscription]}

            class FailedFetcher:
                async def fetch(self, *_args, **_kwargs):
                    raise FetchError("Direct subscription fetch failed: HTTP 503")

            status_updates = []

            def record_failure(failed_subscription, exc, attempted_at=None):
                status_updates.append(
                    refresh_failure_fields(
                        failed_subscription,
                        exc,
                        attempted_at,
                    )
                )

            with (
                patch.object(subscriptions_api.AppConfig, "YAML_SOURCE_DIR", tempdir),
                patch.object(subscriptions_api, "load_config", return_value=config),
                patch.object(subscriptions_api, "_get_fetcher", return_value=FailedFetcher()),
                patch.object(subscriptions_api, "reject_concurrent_refresh", _unlocked_refresh),
                patch.object(subscriptions_api, "record_refresh_attempt"),
                patch.object(subscriptions_api, "record_refresh_failure", side_effect=record_failure),
            ):
                with self.assertRaises(FetchError):
                    asyncio.run(subscriptions_api._refresh_remote_subscription(subscription))

            self.assertEqual(yaml_path.read_text(encoding="utf-8"), old_content)
            self.assertEqual(status_updates[-1]["update_status"], "error")
            self.assertIn("HTTP 503", status_updates[-1]["last_error"])

    def test_batch_refresh_reports_partial_failure_counts(self):
        config = {
            "subscriptions": [
                {"id": "sub_ok", "name": "OK", "type": "url", "enabled": True},
                {"id": "sub_bad", "name": "Bad", "type": "url", "enabled": True},
                {"id": "sub_disabled", "name": "Disabled", "type": "url", "enabled": False},
            ]
        }

        async def refresh_one(subscription):
            if subscription["id"] == "sub_bad":
                raise FetchError("Direct subscription fetch failed: HTTP 503")
            return subscription

        with (
            patch.object(subscriptions_api, "load_config", return_value=config),
            patch.object(subscriptions_api, "_refresh_remote_subscription", side_effect=refresh_one),
        ):
            endpoint = inspect.unwrap(subscriptions_api.refresh_all_subscriptions)
            response = asyncio.run(endpoint(request=None, _=True))

        self.assertEqual(response["status"], "partial")
        self.assertEqual(response["success_count"], 1)
        self.assertEqual(response["failure_count"], 1)
        self.assertEqual(response["total_count"], 2)

    def test_refresh_lock_rejects_only_while_held_and_then_recovers(self):
        async def exercise_lock():
            conflict = None
            async with refresh_lock_service.reject_concurrent_refresh("sub_1"):
                try:
                    async with refresh_lock_service.reject_concurrent_refresh("sub_1"):
                        self.fail("a concurrent refresh unexpectedly acquired the lock")
                except HTTPException as exc:
                    conflict = exc

            # The lock file may remain on disk, but an unlocked file must not
            # prevent the next refresh from acquiring the operating-system lock.
            async with refresh_lock_service.reject_concurrent_refresh("sub_1"):
                pass
            return conflict

        with tempfile.TemporaryDirectory() as tempdir:
            with patch.object(refresh_lock_service, "REFRESH_LOCK_DIR", tempdir):
                conflict = asyncio.run(exercise_lock())

        self.assertIsNotNone(conflict)
        self.assertEqual(conflict.status_code, 409)
        self.assertIn("Retry-After", conflict.headers)

    def test_disabling_subscription_removes_scheduled_job(self):
        config = {
            "subscriptions": [{
                "id": "sub_1",
                "name": "Provider",
                "type": "url",
                "enabled": True,
                "cron_expr": "0 0 * * *",
                "next_update": 123,
            }]
        }

        def update_config(mutator):
            return mutator(config)

        scheduler = Mock()
        with (
            patch.object(subscriptions_api, "update_config", side_effect=update_config),
            patch.object(subscriptions_api, "reject_concurrent_refresh", _unlocked_refresh),
            patch.object(subscriptions_api, "invalidate_stats_cache"),
            patch("scheduler_service.get_scheduler", return_value=scheduler),
        ):
            response = asyncio.run(
                subscriptions_api.toggle_subscription("sub_1", _=True)
            )

        self.assertFalse(response["enabled"])
        self.assertFalse(config["subscriptions"][0]["enabled"])
        self.assertIsNone(config["subscriptions"][0]["next_update"])
        scheduler.remove_job.assert_called_once_with("sub_refresh_sub_1")

    def test_deleting_subscription_removes_yaml_and_scheduled_job(self):
        config = {
            "subscriptions": [{
                "id": "sub_1",
                "name": "Provider",
                "type": "url",
                "enabled": True,
                "cron_expr": "0 0 * * *",
            }]
        }

        def update_config(mutator):
            return mutator(config)

        scheduler = Mock()
        with tempfile.TemporaryDirectory() as tempdir:
            yaml_path = Path(tempdir) / "sub_1.yaml"
            yaml_path.write_text("proxies: []\n", encoding="utf-8")
            with (
                patch.object(subscriptions_api.AppConfig, "YAML_SOURCE_DIR", tempdir),
                patch.object(subscriptions_api, "load_config", return_value=config),
                patch.object(subscriptions_api, "update_config", side_effect=update_config),
                patch.object(subscriptions_api, "reject_concurrent_refresh", _unlocked_refresh),
                patch.object(subscriptions_api, "invalidate_stats_cache"),
                patch("scheduler_service.get_scheduler", return_value=scheduler),
            ):
                response = asyncio.run(
                    subscriptions_api.delete_subscription("sub_1", _=True)
                )

            self.assertFalse(yaml_path.exists())

        self.assertEqual(response["status"], "success")
        self.assertEqual(config["subscriptions"], [])
        scheduler.remove_job.assert_called_once_with("sub_refresh_sub_1")


class SchedulerConsistencyRegressionTests(unittest.TestCase):
    def test_failed_job_registration_does_not_persist_new_cron(self):
        config = {
            "subscriptions": [{
                "id": "sub_1",
                "type": "url",
                "enabled": True,
                "cron_expr": "0 6 * * *",
            }]
        }

        class FailedScheduler:
            def __init__(self):
                self.added_crons = []
                self.removed_jobs = []

            def add_job(self, task_id, cron_expr, *_args):
                self.added_crons.append((task_id, cron_expr))
                return None if cron_expr == "0 12 * * *" else "restored-job"

            def remove_job(self, task_id):
                self.removed_jobs.append(task_id)

            def get_job_info(self, _task_id):
                return None

        scheduler = FailedScheduler()
        save_config = Mock()
        server_module = SimpleNamespace(refresh_subscription_job=lambda _sub_id: None)

        with (
            patch.object(scheduler_api, "load_config", return_value=config),
            patch.object(scheduler_api, "update_config", save_config),
            patch.object(scheduler_api, "_get_server", return_value=server_module),
            patch("scheduler_service.get_scheduler", return_value=scheduler),
        ):
            with self.assertRaises(HTTPException):
                scheduler_api._set_subscription_schedule("sub_1", "0 12 * * *")

        save_config.assert_not_called()
        self.assertEqual(
            scheduler.added_crons,
            [
                ("sub_refresh_sub_1", "0 12 * * *"),
                ("sub_refresh_sub_1", "0 6 * * *"),
            ],
        )

    def test_startup_persists_failed_schedule_as_not_pending(self):
        config = {
            "subscriptions": [{
                "id": "sub_1",
                "name": "Provider",
                "type": "url",
                "enabled": True,
                "cron_expr": "0 0 * * *",
                "next_update": 123,
            }]
        }
        scheduler = Mock()
        scheduler.jobs = {}
        scheduler.add_job.return_value = None
        scheduler.get_job_info.return_value = None
        update_fields = Mock()

        with (
            patch.object(server, "load_config", return_value=config),
            patch.object(server, "get_scheduler", return_value=scheduler),
            patch.object(server, "update_subscription_fields", update_fields),
        ):
            server._restore_scheduled_jobs()

        update_fields.assert_called_once_with("sub_1", {"next_update": None})

    def test_scheduled_lock_conflict_does_not_persist_refresh_failure(self):
        lock_conflict = server.SubscriptionRefreshInProgress(
            "Subscription sub_1 is already being updated"
        )
        record_failure = Mock()

        with (
            patch.object(server, "wait_for_scheduled_refresh_slot", side_effect=lock_conflict),
            patch.object(server, "record_refresh_failure", record_failure),
        ):
            server.refresh_subscription_job("sub_1")

        record_failure.assert_not_called()

    def test_scheduled_refresh_recounts_processed_valid_nodes(self):
        content = """proxies:
  - name: US-01
    type: socks5
    server: us.example.com
    port: 443
  - name: "机场公告: 请更新订阅"
    type: socks5
    server: notice.example.com
    port: 443
  - name: JP-01
    type: socks5
    server: jp.example.com
    port: 443
"""
        subscription = {"id": "sub_1", "url": "https://example.com/sub"}

        with (
            patch.object(server, "_load_existing_nodes", return_value=[]),
            patch.object(
                server.asyncio,
                "run",
                side_effect=lambda coroutine: (coroutine.close(), (content, {"upload": 0}, 3))[1],
            ),
            patch.object(
                server,
                "apply_region_history_to_yaml_content",
                side_effect=lambda value, **_: (value, False, False),
            ),
            patch.object(
                server,
                "apply_node_test_metadata_to_yaml_content",
                side_effect=lambda value, **_: (value, False),
            ),
            patch.object(
                server,
                "apply_node_visibility_to_yaml_content",
                side_effect=lambda value, **_: (value, False),
            ),
        ):
            _content, _usage, node_count, *_rest = server._fetch_and_process_subscription(
                subscription
            )

        self.assertEqual(node_count, 2)


if __name__ == "__main__":
    unittest.main()
