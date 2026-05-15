import unittest

from core.proxy_compat import (
    normalize_config_nodes,
    normalize_subscription_data,
    normalize_xhttp_proxy,
)


class ProxyCompatTests(unittest.TestCase):
    def test_normalize_xhttp_proxy_moves_legacy_fields_to_xhttp_opts(self):
        proxy = {
            "name": "legacy-xhttp",
            "type": "vless",
            "network": "xhttp",
            "xhttp-mode": "stream-up",
            "path": "/xhttp",
            "host": "www.apple.com",
        }

        changed = normalize_xhttp_proxy(proxy)

        self.assertTrue(changed)
        self.assertEqual(
            proxy["xhttp-opts"],
            {"mode": "stream-up", "path": "/xhttp", "host": "www.apple.com"},
        )
        self.assertNotIn("xhttp-mode", proxy)
        self.assertNotIn("path", proxy)
        self.assertNotIn("host", proxy)

    def test_normalize_xhttp_proxy_preserves_existing_xhttp_opts(self):
        proxy = {
            "network": "xhttp",
            "xhttp-mode": "auto",
            "path": "/legacy",
            "xhttp-opts": {"mode": "stream-up", "path": "/current"},
        }

        changed = normalize_xhttp_proxy(proxy)

        self.assertTrue(changed)
        self.assertEqual(proxy["xhttp-opts"], {"mode": "stream-up", "path": "/current"})

    def test_non_xhttp_proxy_keeps_top_level_path(self):
        proxy = {"network": "ws", "path": "/ws", "host": "example.com"}

        changed = normalize_xhttp_proxy(proxy)

        self.assertFalse(changed)
        self.assertEqual(proxy["path"], "/ws")
        self.assertEqual(proxy["host"], "example.com")

    def test_normalize_config_nodes_updates_custom_nodes(self):
        config = {
            "custom_nodes": [
                {"network": "xhttp", "xhttp-mode": "auto", "path": "/custom"},
                {"network": "ws", "path": "/ws"},
            ]
        }

        changed_count = normalize_config_nodes(config)

        self.assertEqual(changed_count, 1)
        self.assertEqual(config["custom_nodes"][0]["xhttp-opts"], {"mode": "auto", "path": "/custom"})
        self.assertEqual(config["custom_nodes"][1]["path"], "/ws")

    def test_normalize_subscription_data_updates_proxies(self):
        data = {
            "proxies": [
                {"network": "xhttp", "xhttp-mode": "auto", "path": "/sub"},
            ]
        }

        changed_count = normalize_subscription_data(data)

        self.assertEqual(changed_count, 1)
        self.assertEqual(data["proxies"][0]["xhttp-opts"], {"mode": "auto", "path": "/sub"})


if __name__ == "__main__":
    unittest.main()
