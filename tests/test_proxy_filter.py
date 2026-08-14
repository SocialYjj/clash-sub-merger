import unittest

from services.proxy_filter import ProxyFilter


class ProxyFilterTargetCompatibilityTests(unittest.TestCase):
    def test_account_status_banners_are_filtered_as_info_nodes(self):
        banners = [
            "2026-08-19 11:28:10 (UTC+8)",
            "Balance: 20.00 GiB",
            "Website: wpku.org",
        ]

        for name in banners:
            with self.subTest(name=name):
                self.assertTrue(ProxyFilter.get_invalid_reason({"name": name}))
                self.assertFalse(ProxyFilter.is_minimally_valid_proxy({
                    "name": name,
                    "type": "ss",
                    "server": "example.com",
                    "port": 443,
                    "cipher": "aes-128-gcm",
                    "password": "secret",
                }))

    @staticmethod
    def _reality_spider_node() -> dict:
        return {
            "name": "Reality spider",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
            "network": "tcp",
            "reality-opts": {
                "public-key": "public-key",
                "short-id": "abcd",
                "spider-x": "/spider",
            },
        }

    def test_reality_spider_is_structurally_valid_but_not_clash_compatible(self):
        node = self._reality_spider_node()

        self.assertTrue(ProxyFilter.is_minimally_valid_proxy(node))
        self.assertFalse(ProxyFilter.is_valid_proxy(node))
        self.assertEqual(
            ProxyFilter.get_target_invalid_reason(node, "clash"),
            "unsupported-reality-option",
        )
        self.assertIsNone(ProxyFilter.get_target_invalid_reason(node, "v2ray"))

        retained = ProxyFilter.filter_minimally_valid_proxies([node])
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0]["reality-opts"]["spider-x"], "/spider")
        self.assertEqual(ProxyFilter.filter_proxies([node]), [])


if __name__ == "__main__":
    unittest.main()
