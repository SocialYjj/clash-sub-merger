"""Regression tests for GeoIP concurrency guards."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import geoip_service


class GeoIPConcurrencyTests(unittest.TestCase):
    def setUp(self):
        geoip_service._online_geoip_cache.clear()
        geoip_service._online_geoip_inflight.clear()

    def test_concurrent_same_ip_uses_single_online_lookup_task(self):
        calls = 0

        async def fake_lookup(ip, timeout):
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.01)
            return {"countryCode": "JP", "country": "Japan", "city": "Tokyo"}

        async def run_lookup():
            with patch.object(geoip_service, "_lookup_ip_api_com", side_effect=fake_lookup):
                return await asyncio.gather(*[
                    geoip_service.lookup_ip_online("203.0.113.1")
                    for _ in range(8)
                ])

        results = asyncio.run(run_lookup())

        self.assertEqual(calls, 1)
        self.assertEqual({result["iso_code"] for result in results}, {"JP"})

    def test_cache_save_uses_atomic_replace(self):
        with tempfile.TemporaryDirectory() as tempdir:
            cache_file = str(Path(tempdir) / "geoip_cache.json")
            geoip_service._online_geoip_cache["203.0.113.2:default"] = {
                "timestamp": 1,
                "iso_code": "US",
            }

            async def run_save():
                with patch.object(geoip_service, "GEOIP_CACHE_FILE", cache_file):
                    await geoip_service.save_geoip_cache_to_disk()

            asyncio.run(run_save())

            self.assertFalse(Path(f"{cache_file}.tmp").exists())
            self.assertEqual(
                json.loads(Path(cache_file).read_text(encoding="utf-8")),
                geoip_service._online_geoip_cache,
            )


if __name__ == "__main__":
    unittest.main()
