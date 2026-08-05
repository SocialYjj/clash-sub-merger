"""Regression tests for subscription data-flow integrity."""

import base64
import unittest
from urllib.parse import quote

from services.subscription import SubscriptionParser


class SubscriptionParserDataIntegrityTests(unittest.TestCase):
    def test_base64_uri_list_uses_canonical_vless_parser(self):
        link = (
            "vless://11111111-1111-1111-1111-111111111111@example.com:443"
            "?security=reality"
            "&type=xhttp"
            "&mode=stream-up"
            "&path=%2Fxhttp"
            "&host=cdn.example.com"
            "&sni=www.apple.com"
            "&fp=chrome"
            "&alpn=h2,http/1.1"
            "&pbk=PUBLICKEY"
            "&sid=bb05e72e"
            "&spx=%2Fspider"
            "&flow=xtls-rprx-vision"
            "&encryption=none"
            "&ech=ech-config"
            "&pqv=pqv-value"
            "&pcs=certsha"
            "#" + quote("VLESS XHTTP Reality")
        )
        content = base64.b64encode(link.encode()).decode()

        parsed = SubscriptionParser.parse_content(content)
        proxy = parsed["proxies"][0]

        self.assertEqual(proxy["name"], "VLESS XHTTP Reality")
        self.assertEqual(proxy["network"], "xhttp")
        self.assertEqual(proxy["xhttp-opts"], {
            "mode": "stream-up",
            "path": "/xhttp",
            "host": "cdn.example.com",
        })
        self.assertEqual(proxy["servername"], "www.apple.com")
        self.assertEqual(proxy["client-fingerprint"], "chrome")
        self.assertEqual(proxy["alpn"], ["h2", "http/1.1"])
        self.assertEqual(proxy["reality-opts"], {
            "public-key": "PUBLICKEY",
            "short-id": "bb05e72e",
            "spider-x": "/spider",
        })
        self.assertEqual(proxy["flow"], "xtls-rprx-vision")
        self.assertEqual(proxy["encryption"], "none")
        self.assertEqual(proxy["ech"], "ech-config")
        self.assertEqual(proxy["pqv"], "pqv-value")
        self.assertEqual(proxy["cert-sha"], "certsha")

    def test_trojan_does_not_force_skip_cert_verify(self):
        parsed = SubscriptionParser.parse_content(
            "trojan://password@example.com:443?sni=example.com#trojan"
        )
        proxy = parsed["proxies"][0]

        self.assertNotIn("skip-cert-verify", proxy)
        self.assertEqual(proxy["sni"], "example.com")
        self.assertNotIn("servername", proxy)

    def test_trojan_preserves_explicit_allow_insecure(self):
        parsed = SubscriptionParser.parse_content(
            "trojan://password@example.com:443?sni=example.com&allowInsecure=1#trojan"
        )
        proxy = parsed["proxies"][0]

        self.assertTrue(proxy["skip-cert-verify"])


if __name__ == "__main__":
    unittest.main()
