"""Regression tests for the backend-only Cloudflare Radar integration."""

import asyncio
import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import api.geoip as geoip_api
import services.cloudflare_radar as radar


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class _FakeClient:
    calls = []
    payload = {
        "success": True,
        "result": {
            "summary_0": {
                "LIKELY_HUMAN": "62.3",
                "LIKELY_AUTOMATED": "37.7",
            }
        },
    }

    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _FakeResponse(self.payload)


class _RateLimitedClient(_FakeClient):
    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _FakeResponse({}, status_code=429)


class CloudflareRadarTests(unittest.TestCase):
    def setUp(self):
        radar._radar_cache.clear()
        radar._radar_inflight.clear()
        radar._configured_radar_token = ""
        _FakeClient.calls = []

    def test_normalizes_asn_and_parses_current_bot_class_keys(self):
        self.assertEqual(radar.normalize_radar_asn("AS15169 Google"), "15169")
        self.assertEqual(radar.normalize_radar_asn("15169"), "15169")
        self.assertIsNone(radar.normalize_radar_asn("Google"))

        result = radar.parse_radar_bot_class_response(_FakeClient.payload)

        self.assertEqual(result["radar_human_ratio"], 62.3)
        self.assertEqual(result["radar_bot_ratio"], 37.7)
        self.assertEqual(result["radar_source"], "cloudflare_radar")

    def test_parses_legacy_human_bot_keys_and_fraction_values(self):
        result = radar.parse_radar_bot_class_response({
            "success": True,
            "result": {"summary_0": {"human": 0.625, "bot": 0.375}},
        })

        self.assertEqual(result["radar_human_ratio"], 62.5)
        self.assertEqual(result["radar_bot_ratio"], 37.5)

    def test_preserves_explicit_no_data_state(self):
        result = radar.parse_radar_bot_class_response({
            "success": True,
            "result": {
                "summary_0": {},
                "meta": {"confidenceInfo": {"level": 0}},
            },
        })

        self.assertEqual(result["radar_status"], "no_data")
        self.assertEqual(result["radar_confidence_level"], 0)
        self.assertNotIn("radar_human_ratio", result)

    def test_missing_token_skips_network_request(self):
        async def run_lookup():
            with patch.dict("os.environ", {"CLOUDFLARE_RADAR_API_TOKEN": ""}, clear=False), \
                 patch.object(radar.httpx, "AsyncClient", side_effect=AssertionError("network call")):
                return await radar.lookup_radar_for_asn("AS15169")

        self.assertIsNone(asyncio.run(run_lookup()))

    def test_persisted_admin_token_enables_runtime_lookup(self):
        with patch.dict("os.environ", {"CLOUDFLARE_RADAR_API_TOKEN": ""}, clear=False):
            radar.apply_cloudflare_radar_runtime_config({
                "geoip_config": {"cloudflare_radar_token": "admin-token"},
            })
            self.assertTrue(radar.is_radar_enabled())

        radar._configured_radar_token = ""

    def test_concurrent_same_asn_uses_one_request_and_cache_persists(self):
        async def run_lookup():
            with tempfile.TemporaryDirectory() as tempdir, \
                 patch.dict("os.environ", {"CLOUDFLARE_RADAR_API_TOKEN": "test-token"}, clear=False), \
                 patch.object(radar, "RADAR_CACHE_FILE", str(Path(tempdir) / "radar.json")), \
                 patch.object(radar.httpx, "AsyncClient", _FakeClient):
                results = await asyncio.gather(*[
                    radar.lookup_radar_for_asn("AS15169")
                    for _ in range(8)
                ])
                return results

        results = asyncio.run(run_lookup())

        self.assertEqual(len(_FakeClient.calls), 1)
        self.assertEqual({result["radar_human_ratio"] for result in results}, {62.3})
        self.assertEqual(_FakeClient.calls[0][1]["params"]["asn"], "15169")
        self.assertEqual(_FakeClient.calls[0][1]["headers"]["Authorization"], "Bearer test-token")

    def test_cache_file_never_contains_api_token(self):
        with tempfile.TemporaryDirectory() as tempdir:
            cache_file = Path(tempdir) / "radar.json"
            radar._radar_cache["15169|7d"] = {
                "radar_human_ratio": 60,
                "radar_bot_ratio": 40,
                "timestamp": 9999999999,
            }

            async def save():
                with patch.object(radar, "RADAR_CACHE_FILE", str(cache_file)):
                    await radar.save_radar_cache_to_disk()

            asyncio.run(save())
            self.assertNotIn("test-token", cache_file.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(cache_file.read_text(encoding="utf-8"))["version"], 1)

    def test_rate_limit_failure_is_short_lived_negative_cached(self):
        async def run_lookup():
            with patch.dict("os.environ", {"CLOUDFLARE_RADAR_API_TOKEN": "test-token"}, clear=False), \
                 patch.object(radar.httpx, "AsyncClient", _RateLimitedClient):
                first = await radar.lookup_radar_for_asn("AS15169")
                second = await radar.lookup_radar_for_asn("AS15169")
                return first, second

        self.assertEqual(asyncio.run(run_lookup()), (None, None))
        self.assertEqual(len(_RateLimitedClient.calls), 1)


class CloudflareRadarConfigurationApiTests(unittest.TestCase):
    def test_online_config_reports_status_without_returning_token(self):
        persisted = {
            "geoip_config": {
                "preferred_api": "ip-api.com",
                "cloudflare_radar_token": "admin-token",
            },
        }
        endpoint = inspect.unwrap(geoip_api.get_online_geoip_config)
        with patch.object(geoip_api, "load_config", return_value=persisted), \
             patch("geoip_service.get_all_geoip_apis", return_value=[]), \
             patch("services.cloudflare_radar.is_radar_enabled", return_value=True):
            response = endpoint(_=True)

        self.assertTrue(response["radar_enabled"])
        self.assertTrue(response["has_radar_token"])
        self.assertNotIn("cloudflare_radar_token", response)

    def test_online_config_saves_and_clears_admin_token(self):
        persisted = {"geoip_config": {}}

        def apply_update(mutator):
            return mutator(persisted)

        endpoint = inspect.unwrap(geoip_api.update_online_geoip_config)
        with patch.object(geoip_api, "update_config", side_effect=apply_update), \
             patch.object(geoip_api, "_apply_persisted_geoip_config"):
            endpoint(geoip_api.OnlineGeoIPConfig(cloudflare_radar_token="  admin-token  "), _=True)
            self.assertEqual(persisted["geoip_config"]["cloudflare_radar_token"], "admin-token")
            endpoint(geoip_api.OnlineGeoIPConfig(cloudflare_radar_token=""), _=True)

        self.assertEqual(persisted["geoip_config"]["cloudflare_radar_token"], "")


if __name__ == "__main__":
    unittest.main()
