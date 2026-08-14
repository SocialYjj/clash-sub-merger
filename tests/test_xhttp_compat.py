import unittest
from urllib.parse import quote

from services.node_parser import parse_node_link, parse_vless_link
from services.proxy_filter import ProxyFilter
from services.xhttp_compat import (
    XHTTPCompatibilityError,
    parse_xhttp_extra,
    xhttp_opts_to_extra,
)


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

    def test_trojan_servername_is_migrated_to_sni(self):
        proxy = {
            "name": "legacy-trojan",
            "type": "trojan",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "tls": True,
            "servername": "cdn.example.com",
        }

        sanitized = ProxyFilter.sanitize_proxy(proxy)

        self.assertEqual(sanitized["sni"], "cdn.example.com")
        self.assertNotIn("servername", sanitized)

    def test_complete_xhttp_extra_round_trip_is_lossless(self):
        extra = {
            "xPaddingBytes": {"from": 100, "to": 200},
            "xPaddingPlacement": "queryInHeader",
            "xPaddingMethod": "tokenish",
            "uplinkHTTPMethod": "POST",
            "sessionIDPlacement": "cookie",
            "sessionIDKey": "session",
            "seqPlacement": "header",
            "seqKey": "X-Seq",
            "noGRPCHeader": True,
            "headers": {"User-Agent": "custom-agent"},
            "xmux": {"maxConnections": {"from": 2, "to": 4}},
            "downloadSettings": {
                "address": "download.example.com",
                "port": 8443,
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "download.example.com",
                    "fingerprint": "chrome",
                    "alpn": ["h2"],
                    "allowInsecure": False,
                    "pinnedPeerCertSha256": "certificate-pin",
                },
                "xhttpSettings": {
                    "path": "/download",
                    "host": "cdn.example.com",
                    "xPaddingBytes": 64,
                },
            },
        }

        opts = parse_xhttp_extra(extra)

        exported = xhttp_opts_to_extra(opts)

        # Xray accepts integer ranges as numbers or ``from-to`` strings; the
        # project deliberately emits the canonical string representation.
        self.assertEqual(exported["xPaddingBytes"], "100-200")
        self.assertEqual(exported["xmux"]["maxConnections"], "2-4")
        self.assertEqual(parse_xhttp_extra(exported), opts)

    def test_invalid_xhttp_extra_is_preserved_for_structural_rejection(self):
        link = (
            "vless://11111111-1111-1111-1111-111111111111@example.com:443"
            f"?type=xhttp&extra={quote('{bad json}')}#invalid-xhttp"
        )

        proxy = parse_node_link(link)

        self.assertIsNotNone(proxy)
        self.assertEqual(proxy["xhttp-opts"]["extra"], "{bad json}")
        self.assertEqual(
            ProxyFilter.get_structural_invalid_reason(proxy),
            "invalid-xhttp-options",
        )

    def test_xhttp_modes_and_stream_one_download_conflict_are_rejected(self):
        cases = (
            {"mode": "unsupported"},
            {"mode": "stream-one", "download-settings": {"server": "example.com"}},
        )
        for opts in cases:
            with self.subTest(opts=opts):
                with self.assertRaises(XHTTPCompatibilityError):
                    xhttp_opts_to_extra(opts)

    def test_xhttp_invalid_ranges_are_rejected(self):
        cases = ("-1", "10-2", {"from": -1, "to": 2}, {"from": 3, "to": 2})
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(XHTTPCompatibilityError):
                    parse_xhttp_extra({"xPaddingBytes": value})

    def test_xhttp_placement_and_method_values_are_validated(self):
        cases = (
            {"mode": "stream-up", "session-placement": "body"},
            {"mode": "stream-up", "seq-placement": "auto"},
            {"mode": "stream-up", "x-padding-placement": "path"},
            {"mode": "stream-up", "x-padding-method": "random"},
            {"mode": "stream-up", "uplink-data-placement": "header"},
            {"mode": "stream-up", "uplink-http-method": "GET"},
        )
        for opts in cases:
            with self.subTest(opts=opts):
                with self.assertRaises(XHTTPCompatibilityError):
                    xhttp_opts_to_extra(opts)

    def test_xhttp_reuse_settings_cannot_set_both_connection_limits(self):
        with self.assertRaises(XHTTPCompatibilityError):
            parse_xhttp_extra({
                "xmux": {"maxConcurrency": 2, "maxConnections": 3},
            })

    def test_hysteria2_conflicting_certificate_pins_are_structurally_invalid(self):
        proxy = {
            "name": "hy2",
            "type": "hysteria2",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "fingerprint": "new-pin",
            "ca-sha256": "old-pin",
        }

        self.assertEqual(
            ProxyFilter.get_structural_invalid_reason(proxy),
            "conflicting-hysteria2-certificate-pin",
        )


class ProxyFilterInfoNodeTests(unittest.TestCase):
    """机场广告/信息节点过滤测试。"""

    def _invalid(self, name: str):
        return ProxyFilter.get_invalid_reason({'name': name})

    # ---- 用户报告的漏网节点 ----
    def test_anti_loss_official_website_with_url_is_filtered(self):
        # 用户报告：防丢失官网:https://love.p6m6.com 未被过滤
        self.assertIsNotNone(self._invalid('防丢失官网:https://love.p6m6.com'))

    def test_anti_loss_official_website_without_protocol(self):
        self.assertIsNotNone(self._invalid('防丢失官网:love.p6m6.com'))

    def test_typo_variant_still_filtered(self):
        # 机场可能用谐音/错字"放丢失"，语义判断仍能兜底
        self.assertIsNotNone(self._invalid('放丢失官网:https://love.p6m6.com'))

    # ---- 其他官网类信息节点变体 ----
    def test_permanent_official_website_with_url_is_filtered(self):
        self.assertIsNotNone(self._invalid('永久官网 https://x.com'))

    def test_anti_disconnect_official_website_is_filtered(self):
        self.assertIsNotNone(self._invalid('防失联官网:https://example.com'))

    def test_url_publish_info_node_is_filtered(self):
        self.assertIsNotNone(self._invalid('网址发布:https://foo.bar.com'))

    # ---- 不误伤真实节点 ----
    def test_real_node_with_region_prefix_is_kept(self):
        # "官网香港01" 有地区提示，应保留
        self.assertIsNone(self._invalid('官网香港01'))

    def test_real_node_with_region_and_index_is_kept(self):
        self.assertIsNone(self._invalid('官网美国-01'))

    def test_real_node_with_url_but_has_identity_is_kept(self):
        # 含节点身份（地区+序号）的不应被新规则误伤
        self.assertIsNone(self._invalid('美国官网01 https://x.com'))

    def test_normal_node_is_kept(self):
        self.assertIsNone(self._invalid('香港 IEPL 01'))


if __name__ == "__main__":
    unittest.main()
