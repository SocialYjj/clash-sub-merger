import unittest

from services.node_parser import parse_vless_link
from services.proxy_filter import ProxyFilter


class XHTTPCompatibilityTests(unittest.TestCase):
    def test_vless_xhttp_link_uses_xhttp_opts(self):
        proxy = parse_vless_link(
            "vless://11111111-1111-1111-1111-111111111111@example.com:443"
            "?type=xhttp&security=reality&mode=stream-up&path=%2Ffoo&host=www.apple.com"
            "&flow=xtls-rprx-vision#xhttp"
        )

        self.assertEqual(proxy["network"], "xhttp")
        self.assertEqual(
            proxy["xhttp-opts"],
            {"mode": "stream-up", "path": "/foo", "host": "www.apple.com"},
        )
        self.assertNotIn("xhttp-mode", proxy)
        self.assertNotIn("path", proxy)
        self.assertNotIn("host", proxy)

    def test_legacy_xhttp_fields_are_migrated(self):
        proxy = {
            "name": "legacy-xhttp",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "xhttp",
            "xhttp-mode": "auto",
            "path": "/bar",
            "host": "www.apple.com",
        }

        sanitized = ProxyFilter.sanitize_proxy(proxy)

        self.assertEqual(
            sanitized["xhttp-opts"],
            {"mode": "auto", "path": "/bar", "host": "www.apple.com"},
        )
        self.assertNotIn("xhttp-mode", sanitized)
        self.assertNotIn("path", sanitized)
        self.assertNotIn("host", sanitized)


if __name__ == "__main__":
    unittest.main()
