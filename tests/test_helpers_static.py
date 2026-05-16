"""Static guardrails for helper module cleanup."""

import ast
import pathlib
import re
import unittest
from collections import Counter


HELPERS_PATH = pathlib.Path(__file__).resolve().parents[1] / "helpers.py"
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


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

    def test_timeout_environment_variables_are_not_cross_wired(self):
        content = HELPERS_PATH.read_text(encoding="utf-8")

        self.assertIn("TIMEOUT_GEOIP_LOOKUP = env_int('GEOIP_LOOKUP_TIMEOUT', 10, minimum=1)", content)
        self.assertIn("TIMEOUT_SPEEDTEST_PROXY = env_int('SPEEDTEST_TIMEOUT', 10, minimum=1)", content)
        self.assertNotIn("TIMEOUT_GEOIP_LOOKUP = int(os.getenv('HEALTH_CHECK_TIMEOUT'", content)

    def test_environment_integer_reads_use_safe_parser(self):
        for path in (
            "core/config.py",
            "helpers.py",
            "services/region_history.py",
            "geoip_service.py",
            "server.py",
        ):
            with self.subTest(file=path):
                content = (REPO_ROOT / path).read_text(encoding="utf-8")
                self.assertNotIn("int(os.environ.get(", content)
                self.assertNotIn("int(os.getenv(", content)

        config_content = (REPO_ROOT / "core" / "config.py").read_text(encoding="utf-8")
        self.assertIn("def env_int(", config_content)

    def test_env_example_documents_session_and_region_history_settings(self):
        content = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")

        for key in (
            "SESSION_SECRET=",
            "HTTP_VERIFY_SSL=true",
            "NODE_REGION_HISTORY_MAX_AGE_DAYS=180",
            "NODE_REGION_HISTORY_MAX_ENTRIES=20000",
        ):
            self.assertIn(key, content)

    def test_sync_version_validates_semver_before_writing_package_files(self):
        content = (REPO_ROOT / "submerger" / "scripts" / "sync-version.cjs").read_text(encoding="utf-8")

        self.assertIn("semverPattern", content)
        self.assertIn("process.exit(1)", content)

    def test_services_init_does_not_create_orphan_http_client(self):
        services_init = (REPO_ROOT / "services" / "__init__.py").read_text(encoding="utf-8")
        http_client = (REPO_ROOT / "services" / "http_client.py").read_text(encoding="utf-8")

        self.assertNotIn("from .http_client import", services_init)
        self.assertIsNone(re.search(r"^http_client\s*=\s*httpx\.AsyncClient", http_client, re.MULTILINE))
        self.assertIn("def get_http_client()", http_client)
        self.assertIn("verify=AppConfig.HTTP_VERIFY_SSL", http_client)

    def test_config_cache_is_guarded_by_lock(self):
        content = (REPO_ROOT / "core" / "database.py").read_text(encoding="utf-8")

        self.assertIn("_config_cache_lock = threading.RLock()", content)
        self.assertIn("with _config_cache_lock:", content)

    def test_core_metrics_does_not_export_dead_zero_metrics(self):
        metrics_content = (REPO_ROOT / "core" / "metrics.py").read_text(encoding="utf-8")
        core_init = (REPO_ROOT / "core" / "__init__.py").read_text(encoding="utf-8")

        for name in (
            "subscription_refresh_total",
            "subscription_refresh_duration_seconds",
            "subscription_node_count",
            "speedtest_total",
            "speedtest_latency_milliseconds",
            "config_operations_total",
            "nodes_total",
        ):
            self.assertNotIn(name, metrics_content)
            self.assertNotIn(name, core_init)

    def test_pydantic_models_use_v2_field_validator(self):
        for relative_path in (
            "api/auth.py",
            "api/nodes.py",
            "api/subscriptions.py",
            "api/users.py",
            "core/models.py",
        ):
            with self.subTest(file=relative_path):
                content = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn("field_validator", content)
                self.assertNotIn("from pydantic import BaseModel, Field, validator", content)
                self.assertNotIn("@validator(", content)


if __name__ == "__main__":
    unittest.main()
