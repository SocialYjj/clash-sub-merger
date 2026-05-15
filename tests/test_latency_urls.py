"""Tests to keep default latency-test URLs on Cloudflare."""

import unittest
from pathlib import Path

import speedtest_service


CLOUDFLARE_204_URL = "https://cp.cloudflare.com/generate_204"
FORBIDDEN_LATENCY_URLS = [
    "http://" + "www.gstatic.com" + "/generate_204",
    "https://" + "www.gstatic.com" + "/generate_204",
    "http://" + "cp.cloudflare.com" + "/generate_204",
    "http://" + "www.google.com" + "/generate_204",
]
SOURCE_FILES_WITH_LATENCY_DEFAULTS = [
    Path("api/nodes.py"),
    Path("api/templates.py"),
    Path("services/config_merger.py"),
    Path("services/proxy_chain_utils.py"),
    Path("speedtest_service.py"),
    Path("speedtest/main.go"),
    Path("speedtest/README.md"),
    Path("submerger/src/pages/Templates.jsx"),
]


class LatencyUrlDefaultsTests(unittest.TestCase):
    def test_python_speedtest_defaults_use_cloudflare(self):
        self.assertEqual(speedtest_service.DEFAULT_LATENCY_URL, CLOUDFLARE_204_URL)
        self.assertEqual(speedtest_service.ALTERNATIVE_LATENCY_URLS, [CLOUDFLARE_204_URL])

    def test_source_defaults_do_not_use_old_generate_204_urls(self):
        for source_file in SOURCE_FILES_WITH_LATENCY_DEFAULTS:
            with self.subTest(source_file=str(source_file)):
                content = source_file.read_text(encoding="utf-8")
                self.assertIn(CLOUDFLARE_204_URL, content)
                for url in FORBIDDEN_LATENCY_URLS:
                    self.assertNotIn(url, content)


if __name__ == "__main__":
    unittest.main()
