"""Tests for default Clash/Mihomo proxy-group health-check URLs."""

import unittest

import yaml

from api.templates import get_builtin_template
from services.config_merger import ConfigMerger, ProxyGroupGenerator
from services.proxy_chain_utils import DEFAULT_GROUP_URL


class DefaultGroupUrlTests(unittest.TestCase):
    def test_default_group_url_uses_cloudflare_generate_204(self):
        self.assertEqual(DEFAULT_GROUP_URL, "https://cp.cloudflare.com/generate_204")

    def test_builtin_template_uses_default_group_url(self):
        template = get_builtin_template()

        url_test_groups = [group for group in template["proxy_groups"] if group.get("type") == "url-test"]

        self.assertEqual(len(url_test_groups), 1)
        self.assertEqual(url_test_groups[0].get("url"), DEFAULT_GROUP_URL)

    def test_builtin_editor_uses_the_same_template_as_subscription_output(self):
        template = get_builtin_template()
        generated_groups = ProxyGroupGenerator.generate_groups([], {})

        self.assertEqual(template["header"], ConfigMerger.DEFAULT_HEADER)
        self.assertEqual(template["suffix"], ConfigMerger.DEFAULT_SUFFIX)
        self.assertEqual(
            [group["name"] for group in template["proxy_groups"]],
            [group["name"] for group in generated_groups],
        )

    def test_builtin_template_routes_academic_databases_before_general_rules(self):
        template = get_builtin_template()
        rules = yaml.safe_load(template["suffix"])["rules"]

        for rule in (
            "DOMAIN-SUFFIX, ieee.org, DIRECT",
            "DOMAIN-SUFFIX, sciencedirect.com, DIRECT",
            "DOMAIN-SUFFIX, scopus.com, DIRECT",
            "DOMAIN-SUFFIX, webofscience.com, DIRECT",
            "DOMAIN-SUFFIX, lib.hfut.edu.cn, DIRECT",
            "IP-CIDR, 210.45.242.0/24, DIRECT, no-resolve",
        ):
            self.assertIn(rule, rules)

        first_general_rule = rules.index("RULE-SET, ChinaMax, DIRECT")
        self.assertLess(rules.index("DOMAIN-SUFFIX, ieee.org, DIRECT"), first_general_rule)
        self.assertLess(rules.index("DOMAIN-SUFFIX, webofscience.com, DIRECT"), first_general_rule)
        self.assertLess(rules.index("IP-CIDR, 210.45.242.0/24, DIRECT, no-resolve"), first_general_rule)
        self.assertLess(first_general_rule, rules.index("RULE-SET, Global, 🚀 手动选择"))
        self.assertLess(rules.index("RULE-SET, Global, 🚀 手动选择"), rules.index("MATCH, GLOBAL"))

    def test_custom_suffix_remains_independent_from_builtin_academic_rules(self):
        custom_suffix = "rules:\n  - MATCH, DIRECT\n"
        merger = ConfigMerger(yaml_dir="", output_file="", custom_suffix=custom_suffix)

        self.assertEqual(merger.suffix, custom_suffix)
        self.assertNotIn("sciencedirect.com", merger.suffix)

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
