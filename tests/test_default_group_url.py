"""Tests for default Clash/Mihomo proxy-group health-check URLs."""

import unittest

from api.templates import get_builtin_template
from services.config_merger import ProxyGroupGenerator
from services.proxy_chain_utils import DEFAULT_GROUP_URL


class DefaultGroupUrlTests(unittest.TestCase):
    def test_default_group_url_uses_cloudflare_generate_204(self):
        self.assertEqual(DEFAULT_GROUP_URL, "https://cp.cloudflare.com/generate_204")

    def test_builtin_template_uses_default_group_url(self):
        template = get_builtin_template()

        url_test_groups = [
            group for group in template["proxy_groups"]
            if group.get("type") == "url-test"
        ]

        self.assertEqual(len(url_test_groups), 1)
        self.assertEqual(url_test_groups[0].get("url"), DEFAULT_GROUP_URL)

    def test_generated_proxy_groups_use_default_group_url(self):
        groups = ProxyGroupGenerator.generate_groups(
            proxies=[{"name": "节点A"}],
            country_groups={"🇺🇸 美国": ["节点A"]},
        )
        groups_by_name = {group["name"]: group for group in groups}

        self.assertEqual(groups_by_name["♻️ 自动选择(测速)"]["url"], DEFAULT_GROUP_URL)
        self.assertEqual(groups_by_name["🔯 故障转移"]["url"], DEFAULT_GROUP_URL)


if __name__ == "__main__":
    unittest.main()
