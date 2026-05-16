"""Regression tests for subscription YAML atomic update helpers."""

import tempfile
import unittest
from pathlib import Path

import yaml

from helpers import load_subscription_yaml, update_subscription_yaml


class SubscriptionYamlSafetyTests(unittest.TestCase):
    def test_update_subscription_yaml_preserves_non_proxy_sections(self):
        with tempfile.TemporaryDirectory() as tempdir:
            sub_file = Path(tempdir) / "sub_demo.yaml"
            sub_file.write_text(
                "proxies:\n"
                "  - name: Old\n"
                "    type: http\n"
                "    server: 127.0.0.1\n"
                "    port: 8080\n"
                "rules:\n"
                "  - MATCH,DIRECT\n",
                encoding="utf-8",
            )

            def rename(cfg):
                cfg["proxies"][0]["name"] = "New"

            update_subscription_yaml("sub_demo", tempdir, rename)

            saved = yaml.safe_load(sub_file.read_text(encoding="utf-8"))

        self.assertEqual(saved["proxies"][0]["name"], "New")
        self.assertEqual(saved["rules"], ["MATCH,DIRECT"])

    def test_update_subscription_yaml_rejects_path_traversal_id(self):
        with tempfile.TemporaryDirectory() as tempdir:
            with self.assertRaises(Exception):
                update_subscription_yaml("../outside", tempdir, lambda cfg: None)

    def test_load_subscription_yaml_preserves_yaml_that_starts_with_mixed_port(self):
        with tempfile.TemporaryDirectory() as tempdir:
            sub_file = Path(tempdir) / "sub_demo.yaml"
            sub_file.write_text(
                "mixed-port: 7890\n"
                "dns:\n"
                "  enable: true\n"
                "proxies:\n"
                "  - name: Demo\n"
                "    type: http\n"
                "    server: 127.0.0.1\n"
                "    port: 8080\n",
                encoding="utf-8",
            )

            loaded = load_subscription_yaml("sub_demo", tempdir, use_cache=False)

        self.assertEqual(loaded["mixed-port"], 7890)
        self.assertTrue(loaded["dns"]["enable"])
        self.assertEqual(loaded["proxies"][0]["name"], "Demo")


if __name__ == "__main__":
    unittest.main()
