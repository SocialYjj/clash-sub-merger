"""Static guardrails for frontend async cleanup patterns."""

import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "submerger" / "src"


class FrontendAbortStaticTests(unittest.TestCase):
    def read_src(self, relative_path: str) -> str:
        return (SRC_ROOT / relative_path).read_text(encoding="utf-8")

    def test_request_interceptor_does_not_retry_canceled_requests(self):
        content = self.read_src("utils/request.js")

        self.assertIn("const isRequestCanceled", content)
        self.assertIn("if (isRequestCanceled(error))", content)
        self.assertIn("ERR_CANCELED", content)

    def test_node_map_guards_world_json_loader_after_unmount(self):
        content = self.read_src("pages/NodeMap.jsx")

        self.assertIn("const mountedRef = useRef(false)", content)
        self.assertIn("loadWorldJson().then", content)
        self.assertIn("if (!mountedRef.current || controller.signal.aborted) return", content)
        self.assertIn("countryDataAbortRef.current?.abort()", content)
        self.assertIn("countryNodesAbortRef.current?.abort()", content)

    def test_sidebar_health_fetch_is_abortable(self):
        content = self.read_src("components/Sidebar.jsx")

        self.assertIn("const controller = new AbortController()", content)
        self.assertIn("fetch('/health', { signal: controller.signal })", content)
        self.assertIn("return () => controller.abort()", content)

    def test_schedule_modal_cleans_debounce_and_inflight_validation(self):
        content = self.read_src("components/ScheduleModal.jsx")

        self.assertIn("const validateCronDebounced = useRef(null)", content)
        self.assertIn("const cronAbortRef = useRef(null)", content)
        self.assertIn("clearTimeout(validateCronDebounced.current)", content)
        self.assertIn("cronAbortRef.current?.abort()", content)
        self.assertIn("{ signal }", content)

    def test_removed_unused_dnd_kit_dependency_references(self):
        for relative_path in (
            "package.json",
            "package-lock.json",
            "vite.config.mjs",
            "README.md",
        ):
            with self.subTest(file=relative_path):
                content = (REPO_ROOT / "submerger" / relative_path).read_text(encoding="utf-8")
                self.assertNotIn("@dnd-kit", content)
                self.assertNotIn("dnd-kit", content)


if __name__ == "__main__":
    unittest.main()
