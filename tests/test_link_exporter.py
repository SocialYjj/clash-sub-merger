import unittest
from urllib.parse import parse_qs, urlparse

from services.link_exporter import proxy_to_link
from services.node_parser import parse_node_link


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

    def test_vless_reality_query_values_are_url_encoded(self):
        link = proxy_to_link({
            "name": "reality",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "network": "tcp",
            "tls": True,
            "reality-opts": {
                "public-key": "abc+def/ghi=",
                "short-id": "sid+/=",
            },
        })

        self.assertIn("pbk=abc%2Bdef%2Fghi%3D", link)
        self.assertIn("sid=sid%2B%2F%3D", link)
        params = parse_qs(urlparse(link).query)
        self.assertEqual(params["pbk"], ["abc+def/ghi="])
        self.assertEqual(params["sid"], ["sid+/="])

    def test_hysteria2_obfs_password_is_url_encoded(self):
        link = proxy_to_link({
            "name": "hy2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "sni": "sni.example.com",
            "obfs": "salamander",
            "obfs-password": "pa ss+/=",
        })

        self.assertIn("obfs-password=pa%20ss%2B%2F%3D", link)
        params = parse_qs(urlparse(link).query)
        self.assertEqual(params["obfs-password"], ["pa ss+/="])

    def test_hysteria_auth_str_is_url_encoded(self):
        link = proxy_to_link({
            "name": "hy",
            "type": "hysteria",
            "server": "example.com",
            "port": 443,
            "auth-str": "token+/= space",
            "sni": "peer.example.com",
        })

        self.assertIn("auth=token%2B%2F%3D%20space", link)
        params = parse_qs(urlparse(link).query)
        self.assertEqual(params["auth"], ["token+/= space"])

    def test_unsupported_proxy_type_returns_empty_string(self):
        self.assertEqual(proxy_to_link({"type": "unknown"}), "")

    def test_anytls_export_does_not_disappear_from_base64_output(self):
        link = proxy_to_link({
            "name": "AnyTLS Reality",
            "type": "anytls",
            "server": "example.com",
            "port": 443,
            "password": "pass:word",
            "tls": True,
            "servername": "www.apple.com",
            "client-fingerprint": "chrome",
            "alpn": ["h2", "http/1.1"],
            "network": "xhttp",
            "xhttp-opts": {
                "mode": "stream-up",
                "path": "/xhttp",
                "host": "cdn.example.com",
            },
        })

        self.assertTrue(link.startswith("anytls://"))
        parsed = parse_node_link(link)
        self.assertEqual(parsed["type"], "anytls")
        self.assertEqual(parsed["password"], "pass:word")
        self.assertEqual(parsed["client-fingerprint"], "chrome")
        self.assertEqual(parsed["alpn"], ["h2", "http/1.1"])
        self.assertEqual(parsed["network"], "xhttp")
        self.assertEqual(parsed["xhttp-opts"]["mode"], "stream-up")

    def test_wireguard_export_does_not_disappear_from_base64_output(self):
        link = proxy_to_link({
            "name": "WG",
            "type": "wireguard",
            "server": "2001:db8::2",
            "port": 51820,
            "private-key": "private/key=",
            "public-key": "public/key=",
            "preshared-key": "psk/key=",
            "reserved": [1, 2, 3],
            "address": ["10.0.0.2/32", "fd00::2/128"],
            "mtu": 1280,
        })

        self.assertTrue(link.startswith("wireguard://"))
        self.assertIn("@[2001:db8::2]:51820", link)
        parsed = parse_node_link(link)
        self.assertEqual(parsed["type"], "wireguard")
        self.assertEqual(parsed["private-key"], "private/key=")
        self.assertEqual(parsed["public-key"], "public/key=")
        self.assertEqual(parsed["preshared-key"], "psk/key=")
        self.assertEqual(parsed["reserved"], "1,2,3")
        self.assertEqual(parsed["address"], "10.0.0.2/32,fd00::2/128")
        self.assertEqual(parsed["mtu"], 1280)


if __name__ == "__main__":
    unittest.main()
