"""Regression tests for Python speedtest service hardening."""

import asyncio
import pathlib
import unittest
from unittest.mock import patch

from speedtest_service import SpeedTestConfig, SpeedTestResult, SpeedTestService


class SpeedtestServiceHardeningTests(unittest.TestCase):
    def test_source_does_not_disable_aiohttp_tls_verification(self):
        source = pathlib.Path("speedtest_service.py").read_text(encoding="utf-8")

        self.assertNotIn("TCPConnector(ssl=False", source)
        self.assertNotIn("ssl=False", source)

    def test_concurrent_duplicate_node_tests_share_single_task(self):
        async def run_test():
            service = SpeedTestService(SpeedTestConfig(test_speed=False))
            calls = 0

            async def fake_uncached(*args, **kwargs):
                nonlocal calls
                calls += 1
                await asyncio.sleep(0.01)
                return SpeedTestResult(node_id="n1", node_name="Node 1", latency=10, latency_status="success")

            with patch.object(service, "_test_node_uncached", side_effect=fake_uncached):
                first, second = await asyncio.gather(
                    service.test_node({"id": "n1", "name": "Node 1"}, "http://127.0.0.1:7890"),
                    service.test_node({"id": "n1", "name": "Node 1"}, "http://127.0.0.1:7890"),
                )
            await service.close()
            return calls, first, second

        calls, first, second = asyncio.run(run_test())

        self.assertEqual(calls, 1)
        self.assertIs(first, second)

    def test_requests_reuse_single_aiohttp_session(self):
        async def run_test():
            service = SpeedTestService()
            first = await service._get_session()
            second = await service._get_session()
            reused = first is second
            await service.close()
            return reused

        self.assertTrue(asyncio.run(run_test()))


if __name__ == "__main__":
    unittest.main()
