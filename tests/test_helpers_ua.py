"""Regression tests for FlClash User-Agent version caching."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import helpers_ua


class HelpersUATests(unittest.TestCase):
    def test_failed_github_lookup_caches_fallback_version(self):
        with tempfile.TemporaryDirectory() as tempdir:
            cache_file = Path(tempdir) / ".flclash_version_cache"

            with (
                patch.object(helpers_ua, "_cached_version", None),
                patch.object(helpers_ua, "_cache_file", str(cache_file)),
                patch.object(helpers_ua.httpx, "Client", side_effect=RuntimeError("offline")) as client_factory,
            ):
                first = helpers_ua.get_flclash_latest_version()
                second = helpers_ua.get_flclash_latest_version()

            self.assertEqual(first, helpers_ua.DEFAULT_FLCLASH_VERSION)
            self.assertEqual(second, helpers_ua.DEFAULT_FLCLASH_VERSION)
            self.assertEqual(client_factory.call_count, 1)
            self.assertEqual(cache_file.read_text(encoding="utf-8"), helpers_ua.DEFAULT_FLCLASH_VERSION)


if __name__ == "__main__":
    unittest.main()
