"""Regression tests for config merge naming and source metadata."""

import tempfile
import unittest
from pathlib import Path

from services.config_merger import ConfigMerger
from services.country_grouper import CountryGrouper
from services.proxy_chain_utils import MAX_PROXY_NAME_LENGTH


class ConfigMergerBugfixTests(unittest.TestCase):
    def write_yaml(self, folder, filename, node_name):
        Path(folder, filename).write_text(
            "proxies:\n"
            f"  - name: {node_name}\n"
            "    type: http\n"
            "    server: 127.0.0.1\n"
            "    port: 8080\n",
            encoding="utf-8",
        )

    def test_duplicate_transformed_proxy_names_are_made_unique(self):
        with tempfile.TemporaryDirectory() as tempdir:
            self.write_yaml(tempdir, "sub_a.yaml", "US 01")
            self.write_yaml(tempdir, "sub_b.yaml", "US 01")

            merger = ConfigMerger(
                yaml_dir=tempdir,
                output_file=str(Path(tempdir) / "out.yaml"),
                file_aliases={"sub_a.yaml": "Provider", "sub_b.yaml": "Provider"},
            )
            cfg = merger.merge_and_generate()
            names = [proxy["name"] for proxy in cfg["proxies"]]

        self.assertEqual(len(names), 2)
        self.assertEqual(len(set(names)), 2)
        self.assertTrue(names[1].endswith("(2)"))

    def test_duplicate_long_proxy_names_keep_suffix_within_limit(self):
        long_name = "A" * MAX_PROXY_NAME_LENGTH
        with tempfile.TemporaryDirectory() as tempdir:
            self.write_yaml(tempdir, "sub_a.yaml", long_name)
            self.write_yaml(tempdir, "sub_b.yaml", long_name)

            merger = ConfigMerger(
                yaml_dir=tempdir,
                output_file=str(Path(tempdir) / "out.yaml"),
                file_aliases={"sub_a.yaml": "", "sub_b.yaml": ""},
            )
            names = [proxy["name"] for proxy in merger.merge_and_generate()["proxies"]]

        self.assertEqual(len(names), 2)
        self.assertTrue(all(len(name) <= MAX_PROXY_NAME_LENGTH for name in names))
        self.assertTrue(names[1].endswith("(2)"))

    def test_source_metadata_is_optional_and_internal(self):
        with tempfile.TemporaryDirectory() as tempdir:
            self.write_yaml(tempdir, "sub_demo.yaml", "JP 01")

            plain = ConfigMerger(
                yaml_dir=tempdir,
                output_file=str(Path(tempdir) / "plain.yaml"),
                file_aliases={"sub_demo.yaml": "Demo"},
            ).merge_and_generate()["proxies"][0]
            annotated = ConfigMerger(
                yaml_dir=tempdir,
                output_file=str(Path(tempdir) / "annotated.yaml"),
                file_aliases={"sub_demo.yaml": "Demo"},
                include_source_metadata=True,
            ).merge_and_generate()["proxies"][0]

        self.assertNotIn("_source_id", plain)
        self.assertEqual(annotated["_source_id"], "sub_demo")
        self.assertEqual(annotated["_source_file"], "sub_demo.yaml")

    def test_country_group_deduplicates_proxy_names(self):
        groups = CountryGrouper.group_by_country([
            {"name": "🇯🇵 Demo JP"},
            {"name": "🇯🇵 Demo JP"},
        ])

        self.assertEqual(groups["🇯🇵 日本"], ["🇯🇵 Demo JP"])


if __name__ == "__main__":
    unittest.main()
