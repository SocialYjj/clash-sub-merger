"""Tests for the extracted single-template compatibility routes."""

import copy
import logging
import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.template_compat import create_template_router, split_template
from core.dependencies import verify_session


class TemplateCompatRoutesTest(unittest.TestCase):
    def make_client(self, config):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        output_file = str(Path(tempdir.name) / "myconfig.yaml")
        app = FastAPI()
        app.dependency_overrides[verify_session] = lambda: True

        def load_config():
            return copy.deepcopy(config)

        def update_config(mutator):
            result = mutator(config)
            return result

        app.include_router(create_template_router(
            yaml_source_dir=tempdir.name,
            output_file=output_file,
            load_config=load_config,
            update_config=update_config,
            logger=logging.getLogger("test.template_compat"),
        ))
        return TestClient(app), config

    def test_split_template_removes_proxy_sections(self):
        header, suffix = split_template(
            "mixed-port: 7890\n"
            "proxies:\n"
            "  - name: should-drop\n"
            "proxy-groups:\n"
            "  - name: group-drop\n"
            "rules:\n"
            "  - MATCH,DIRECT\n"
        )

        self.assertIn("mixed-port: 7890", header)
        self.assertNotIn("should-drop", header)
        self.assertNotIn("group-drop", suffix)
        self.assertIn("rules:", suffix)

    def test_default_template_route_is_registered(self):
        client, _ = self.make_client({"auth": {}, "subscriptions": [], "custom_nodes": []})

        response = client.get("/api/template/default")

        self.assertEqual(response.status_code, 200)
        self.assertIn("proxies: []", response.json()["content"])
        self.assertIn("proxy-groups: []", response.json()["content"])

    def test_save_template_updates_config(self):
        client, config = self.make_client({"auth": {}, "subscriptions": [], "custom_nodes": []})

        response = client.post("/api/template/save", json={
            "content": "mixed-port: 7890\n\nproxies: []\n\nproxy-groups: []\n\nrules:\n  - MATCH,DIRECT"
        })

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        self.assertEqual(config["template"]["header"], "mixed-port: 7890")
        self.assertIn("MATCH,DIRECT", config["template"]["suffix"])
