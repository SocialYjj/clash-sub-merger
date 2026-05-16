"""Regression tests for node region history pruning."""

import unittest
from unittest.mock import patch

import services.region_history as region_history


class RegionHistoryTests(unittest.TestCase):
    def test_legacy_entries_without_updated_at_are_not_immortal(self):
        entries = {
            "legacy": {
                "region": {"country_code": "US", "country": "United States", "flag": "🇺🇸"},
                "server": "example.com",
                "port": "443",
            },
            "fresh": {
                "updated_at": 2_000_000,
                "region": {"country_code": "JP", "country": "Japan", "flag": "🇯🇵"},
                "server": "example.jp",
                "port": "443",
            },
        }

        with (
            patch.object(region_history, "REGION_HISTORY_MAX_AGE_DAYS", 1),
            patch.object(region_history.time, "time", return_value=2_000_000),
        ):
            trimmed = region_history._trim_entries(entries)

        self.assertNotIn("legacy", trimmed)
        self.assertIn("fresh", trimmed)


if __name__ == "__main__":
    unittest.main()
