import unittest
from urllib.parse import parse_qs, urlparse

from services.link_exporter import proxy_to_link


class LinkExporterTests(unittest.TestCase):
    def test_vless_xhttp_export_uses_xhttp_opts(self):
        link = proxy_to_link({
            "name": "xhttp node",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "xhttp",
            "tls": True,
            "servername": "www.apple.com",
            "xhttp-opts": {
                "mode": "stream-up",
                "path": "/xhttp",
                "host": "www.apple.com",
            },
        })

        parsed = urlparse(link)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, "vless")
        self.assertEqual(params["type"], ["xhttp"])
        self.assertEqual(params["security"], ["tls"])
        self.assertEqual(params["mode"], ["stream-up"])
        self.assertEqual(params["path"], ["/xhttp"])
        self.assertEqual(params["host"], ["www.apple.com"])

    def test_vless_ipv6_server_is_bracketed(self):
        link = proxy_to_link({
            "name": "ipv6",
            "type": "vless",
            "server": "2001:db8::1",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "tcp",
        })

        self.assertIn("@[2001:db8::1]:443", link)

    def test_unsupported_proxy_type_returns_empty_string(self):
        self.assertEqual(proxy_to_link({"type": "unknown"}), "")


if __name__ == "__main__":
    unittest.main()
