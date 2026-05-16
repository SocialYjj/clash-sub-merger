"""Regression tests for template preview route."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.templates as templates_api
from core.dependencies import verify_session


class TemplatePreviewTests(unittest.TestCase):
    def test_preview_uses_merge_and_generate_result(self):
        with tempfile.TemporaryDirectory() as tempdir:
            Path(tempdir, "sub_demo.yaml").write_text(
                "proxies:\n"
                "  - name: JP 01\n"
                "    type: http\n"
                "    server: 127.0.0.1\n"
                "    port: 8080\n",
                encoding="utf-8",
            )

            app = FastAPI()
            app.dependency_overrides[verify_session] = lambda: True
            app.include_router(templates_api.router, prefix="/api/template")
            client = TestClient(app)

            with (
                patch.object(templates_api, "YAML_SOURCE_DIR", tempdir),
                patch.object(templates_api, "OUTPUT_FILE", str(Path(tempdir) / "out.yaml")),
            ):
                response = client.post("/api/template/preview", json={
                    "content": "mixed-port: 7890\n",
                    "file_aliases": {"sub_demo.yaml": "Demo"},
                })

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("proxies:", data["preview"])
        self.assertIn("proxy-groups:", data["preview"])


if __name__ == "__main__":
    unittest.main()
