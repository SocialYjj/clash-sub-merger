"""Regression tests for node region history pruning and country detection."""

import unittest
from unittest.mock import patch

import services.region_history as region_history
from services.country_data import detect_country


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


class CountryDataRegionMappingTests(unittest.TestCase):
    """地名→国家映射测试，避免节点分组错乱。"""

    def _detect_code(self, name: str):
        result = detect_country(name)
        return result['country_code'] if result else None

    # ---- 用户报告的漏网地名 ----
    def test_falkenstein_maps_to_germany(self):
        self.assertEqual(self._detect_code('德国 Falkenstein 01'), 'DE')

    def test_falkenstein_english_only_maps_to_germany(self):
        self.assertEqual(self._detect_code('Falkenstein 01'), 'DE')

    def test_mejiro_maps_to_japan(self):
        self.assertEqual(self._detect_code('日本 Mejiro 01'), 'JP')

    def test_mejiro_english_only_maps_to_japan(self):
        self.assertEqual(self._detect_code('Mejiro 01'), 'JP')

    # ---- 补充的日本地名 ----
    def test_tokyo_maps_to_japan(self):
        self.assertEqual(self._detect_code('Tokyo Premium 01'), 'JP')

    def test_osaka_maps_to_japan(self):
        self.assertEqual(self._detect_code('Osaka 01'), 'JP')

    def test_yokohama_maps_to_japan(self):
        self.assertEqual(self._detect_code('Yokohama IEPL 01'), 'JP')

    # ---- 补充的德国地名 ----
    def test_berlin_maps_to_germany(self):
        self.assertEqual(self._detect_code('Berlin 01'), 'DE')

    def test_munich_maps_to_germany(self):
        self.assertEqual(self._detect_code('Munich 01'), 'DE')

    # ---- 不误伤已有逻辑 ----
    def test_hongkong_still_works(self):
        self.assertEqual(self._detect_code('香港 01'), 'HK')

    def test_us_still_works(self):
        self.assertEqual(self._detect_code('Los Angeles 01'), 'US')

    def test_short_code_jp_boundary(self):
        # JP 作为短拉丁码应整体匹配，不被随机子串误伤
        self.assertEqual(self._detect_code('JP 01'), 'JP')
        # 但不应误匹配 "ajps" 中的 "jp"
        self.assertIsNone(self._detect_code('ajps_xyz_node'))


if __name__ == "__main__":
    unittest.main()
