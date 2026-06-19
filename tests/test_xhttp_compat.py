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
