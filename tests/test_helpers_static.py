"""Static guardrails for helper module cleanup."""

import ast
import pathlib
import unittest
from collections import Counter


HELPERS_PATH = pathlib.Path(__file__).resolve().parents[1] / "helpers.py"


class HelpersStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(HELPERS_PATH.read_text(encoding="utf-8"))

    def test_top_level_function_names_are_unique(self):
        function_names = [
            node.name
            for node in self.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        duplicates = sorted(name for name, count in Counter(function_names).items() if count > 1)

        self.assertEqual(duplicates, [])

    def test_legacy_unused_helpers_are_removed(self):
        top_level_names = {
            node.name
            for node in self.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }

        self.assertTrue(
            {
                "get_subscription_node",
                "load_yaml_file_cached",
                "save_custom_nodes_yaml",
                "find_item_by_id",
                "Validators",
            }.isdisjoint(top_level_names)
        )


if __name__ == "__main__":
    unittest.main()
