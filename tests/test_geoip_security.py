"""Security regressions for custom GeoIP APIs and their persisted secrets."""

import asyncio
import inspect
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import api.geoip as geoip_api
import geoip_service
from core.dependencies import verify_session


class _ChunkedAsyncStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self._chunks = chunks

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk


class GeoIPDestinationSecurityTests(unittest.TestCase):
    def test_custom_api_url_rejects_local_hosts_credentials_and_private_addresses(self):
        invalid_urls = (
            "http://localhost/lookup/{ip}",
            "http://127.0.0.1/lookup/{ip}",
            "http://[::1]/lookup/{ip}",
            "https://user:password@example.com/lookup/{ip}",
            "file:///etc/passwd",
        )
        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    geoip_api._validate_geoip_api_url(url)

    def test_dns_resolution_rejects_any_private_destination(self):
        mixed_resolution = [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("10.0.0.8", 443)),
        ]
        with patch("geoip_service.socket.getaddrinfo", return_value=mixed_resolution):
            allowed = asyncio.run(
                geoip_service._is_public_custom_api_url("https://geo.example/lookup")
            )

        self.assertFalse(allowed)

    def test_custom_api_client_disables_redirects_and_environment_proxies(self):
        client_options = {}

        class RedirectResponse:
            status_code = 302

        class StreamContext:
            async def __aenter__(self):
                return RedirectResponse()

            async def __aexit__(self, *_args):
                return False

        class FakeClient:
            def __init__(self, **kwargs):
                client_options.update(kwargs)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def stream(self, *_args, **_kwargs):
                return StreamContext()

        with (
            patch.object(geoip_service, "_is_public_custom_api_url", return_value=True),
            patch.object(geoip_service.httpx, "AsyncClient", FakeClient),
        ):
            lookup = asyncio.run(
                geoip_service._lookup_custom_api(
                    "8.8.8.8",
                    {"url": "https://geo.example/{ip}", "method": "GET"},
                )
            )

        self.assertIsNone(lookup)
        self.assertFalse(client_options["follow_redirects"])
        self.assertFalse(client_options["trust_env"])

    def test_custom_api_response_is_rejected_after_size_limit(self):
        response = httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=_ChunkedAsyncStream([b'{"countryCode":"US",', b'"padding":"0123456789"}']),
        )
        with patch.object(geoip_service, "CUSTOM_GEOIP_MAX_RESPONSE_BYTES", 16):
            decoded = asyncio.run(geoip_service._read_limited_json_response(response))

        self.assertIsNone(decoded)


class GeoIPConfigurationSecurityTests(unittest.TestCase):
    def _update_config(self, config):
        def update(config_mutator):
            return config_mutator(config)

        return update

    def test_historical_invalid_url_does_not_break_new_api_creation(self):
        config = {
            "geoip_config": {
                "custom_apis": [{"id": "custom_old", "name": "Old", "url": "http://[broken"}],
            }
        }
        endpoint = inspect.unwrap(geoip_api.create_custom_api)
        with (
            patch.object(geoip_api, "update_config", side_effect=self._update_config(config)),
            patch.object(geoip_api, "_apply_persisted_geoip_config"),
        ):
            response = endpoint(
                geoip_api.CustomApiConfig(name="New", url="https://geo.example/{ip}"),
                _=True,
            )

        self.assertEqual(response["status"], "success")
        self.assertEqual(len(config["geoip_config"]["custom_apis"]), 2)

    def test_duplicate_name_and_url_are_rejected(self):
        existing = {
            "id": "custom_1",
            "name": "Provider",
            "url": "https://geo.example/lookup/{ip}",
            "enabled": True,
        }
        for candidate in (
            geoip_api.CustomApiConfig(name="provider", url="https://other.example/{ip}"),
            geoip_api.CustomApiConfig(name="Other", url="https://GEO.EXAMPLE/lookup/{ip}"),
        ):
            config = {"geoip_config": {"custom_apis": [dict(existing)]}}
            with patch.object(geoip_api, "update_config", side_effect=self._update_config(config)):
                with self.assertRaises(HTTPException) as error_context:
                    inspect.unwrap(geoip_api.create_custom_api)(candidate, _=True)
            self.assertEqual(error_context.exception.status_code, 409)

    def test_custom_api_token_omission_preserves_and_empty_string_clears(self):
        config = {
            "geoip_config": {
                "custom_apis": [{
                    "id": "custom_1",
                    "name": "Provider",
                    "url": "https://geo.example/{ip}",
                    "token": "stored-secret-token",
                    "enabled": True,
                }],
            }
        }
        endpoint = inspect.unwrap(geoip_api.update_custom_api)
        with (
            patch.object(geoip_api, "update_config", side_effect=self._update_config(config)),
            patch.object(geoip_api, "_apply_persisted_geoip_config"),
        ):
            endpoint(
                "custom_1",
                geoip_api.CustomApiConfig(name="Provider", url="https://geo.example/{ip}"),
                _=True,
            )
            self.assertEqual(config["geoip_config"]["custom_apis"][0]["token"], "stored-secret-token")
            endpoint(
                "custom_1",
                geoip_api.CustomApiConfig(name="Provider", url="https://geo.example/{ip}", token=""),
                _=True,
            )

        self.assertEqual(config["geoip_config"]["custom_apis"][0]["token"], "")

    def test_deleting_preferred_api_selects_an_enabled_fallback(self):
        config = {
            "geoip_config": {
                "preferred_api": "custom_1",
                "api_settings": {
                    "ip-api.com": {"enabled": False},
                    "ipwhois": {"enabled": True},
                    "ipinfo": {"enabled": False},
                },
                "custom_apis": [{
                    "id": "custom_1",
                    "name": "Provider",
                    "url": "https://geo.example/{ip}",
                    "enabled": True,
                }],
            }
        }
        with (
            patch.object(geoip_api, "update_config", side_effect=self._update_config(config)),
            patch.object(geoip_api, "_apply_persisted_geoip_config"),
        ):
            inspect.unwrap(geoip_api.delete_custom_api)("custom_1", _=True)

        self.assertEqual(config["geoip_config"]["preferred_api"], "ipwhois")

    def test_geoip_lookup_endpoint_enforces_rate_limit(self):
        geoip_api.limiter.reset()
        app = FastAPI()
        app.state.limiter = geoip_api.limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.include_router(geoip_api.router, prefix="/api/geoip")
        app.dependency_overrides[verify_session] = lambda: True

        async def no_lookup(_ip):
            return None

        with patch.object(geoip_service, "lookup_ip_online", side_effect=no_lookup):
            client = TestClient(app)
            responses = [
                client.post("/api/geoip/lookup", json={"ip": "8.8.8.8"})
                for _ in range(31)
            ]
        geoip_api.limiter.reset()

        self.assertEqual([response.status_code for response in responses[:30]], [200] * 30)
        self.assertEqual(responses[30].status_code, 429)

    def test_failed_cache_replace_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as tempdir:
            cache_path = Path(tempdir) / "geoip_cache.json"
            with (
                patch.object(geoip_service, "GEOIP_CACHE_FILE", str(cache_path)),
                patch.object(geoip_service, "_online_geoip_cache", {"8.8.8.8": {"timestamp": 1}}),
                patch.object(geoip_service.os, "replace", side_effect=OSError("replace failed")),
            ):
                asyncio.run(geoip_service.save_geoip_cache_to_disk())

            self.assertEqual(list(Path(tempdir).glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
