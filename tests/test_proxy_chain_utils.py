import unittest

from services.proxy_chain_utils import (
    MAX_PROXY_NAME_LENGTH,
    coerce_group_strategy,
    group_id_suffix,
    unique_group_name,
    unique_name,
)


class ProxyChainUtilsTests(unittest.TestCase):
    def test_group_id_suffix_keeps_last_four_alnum_chars(self):
        self.assertEqual(group_id_suffix("grp_bb05-e72e"), "e72e")
        self.assertEqual(group_id_suffix("----"), "")
        self.assertEqual(group_id_suffix(None), "")

    def test_unique_name_appends_numeric_suffix(self):
        existing = {"🔗 A", "🔗 A (2)"}

        name = unique_name("🔗 A", existing)

        self.assertEqual(name, "🔗 A (3)")
        self.assertIn("🔗 A (3)", existing)

    def test_unique_name_keeps_numeric_suffix_within_max_length(self):
        base = "A" * MAX_PROXY_NAME_LENGTH
        existing = {base}

        name = unique_name(base, existing)

        self.assertEqual(len(name), MAX_PROXY_NAME_LENGTH)
        self.assertTrue(name.endswith(" (2)"))
        self.assertIn(name, existing)

    def test_unique_group_name_prefers_stable_group_id_suffix(self):
        existing = {"🔀 落地池"}

        name = unique_group_name("🔀 落地池", existing, "grp_bb05e72e")

        self.assertEqual(name, "🔀 落地池 (e72e)")
        self.assertIn("🔀 落地池 (e72e)", existing)

    def test_unique_group_name_keeps_id_suffix_within_max_length(self):
        base = "池" * MAX_PROXY_NAME_LENGTH
        existing = {base}

        name = unique_group_name(base, existing, "grp_bb05e72e")

        self.assertEqual(len(name), MAX_PROXY_NAME_LENGTH)
        self.assertTrue(name.endswith(" (e72e)"))
        self.assertIn(name, existing)

    def test_unique_group_name_falls_back_to_numeric_suffix(self):
        existing = {"🔀 落地池", "🔀 落地池 (e72e)"}

        name = unique_group_name("🔀 落地池", existing, "grp_bb05e72e")

        self.assertEqual(name, "🔀 落地池 (2)")
        self.assertIn("🔀 落地池 (2)", existing)

    def test_coerce_group_strategy_defaults_invalid_strategy_to_load_balance(self):
        self.assertEqual(
            coerce_group_strategy({"group_strategy": "bad", "lb_strategy": "bad"}),
            {"type": "load-balance", "strategy": "round-robin"},
        )

    def test_coerce_group_strategy_keeps_url_test_options(self):
        self.assertEqual(
            coerce_group_strategy({
                "group_strategy": "url-test",
                "group_url": "https://example.com/204",
                "group_interval": "120",
                "group_tolerance": "20",
            }),
            {
                "type": "url-test",
                "url": "https://example.com/204",
                "interval": 120,
                "tolerance": 20,
            },
        )


if __name__ == "__main__":
    unittest.main()
