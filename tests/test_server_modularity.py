"""Static guardrails for the modular FastAPI entrypoint."""

import ast
import pathlib
import unittest


SERVER_PATH = pathlib.Path(__file__).resolve().parents[1] / "server.py"


class ServerModularityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(SERVER_PATH.read_text(encoding="utf-8"))

    def test_server_uses_canonical_config_database(self):
        function_names = {
            node.name
            for node in self.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        self.assertNotIn("load_config", function_names)
        self.assertNotIn("save_config", function_names)

        imports = [
            node for node in self.tree.body
            if isinstance(node, ast.ImportFrom) and node.module == "core.database"
        ]
        imported_names = {alias.name for node in imports for alias in node.names}
        self.assertIn("load_config", imported_names)
        self.assertIn("save_config", imported_names)

    def test_server_does_not_keep_duplicate_database_find_helpers(self):
        function_names = {
            node.name
            for node in self.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        self.assertTrue(
            {
                "find_subscription_by_id",
                "find_custom_node_by_id",
                "find_user_by_id",
                "find_template_by_id",
                "find_admin_token_by_id",
                "find_proxy_chain_by_id",
            }.isdisjoint(function_names)
        )

    def test_server_keeps_only_spa_app_routes(self):
        app_route_lines = []
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and isinstance(decorator.func.value, ast.Name)
                    and decorator.func.value.id == "app"
                    and decorator.func.attr in {"get", "post", "put", "delete", "patch"}
                ):
                    app_route_lines.append((decorator.func.attr, decorator.lineno))
                    include_in_schema = next(
                        (
                            keyword.value.value
                            for keyword in decorator.keywords
                            if keyword.arg == "include_in_schema"
                            and isinstance(keyword.value, ast.Constant)
                        ),
                        None,
                    )
                    self.assertIs(include_in_schema, False)

        self.assertEqual(len(app_route_lines), 2)
