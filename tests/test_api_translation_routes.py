"""Route-level tests for the translation configuration endpoints."""

import copy
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.translation as translation_api
import core.dependencies as core_dependencies
import translation_service
from core.dependencies import verify_session


class TranslationRoutesTest(unittest.TestCase):
    def make_client(self):
        app = FastAPI()
        app.dependency_overrides[verify_session] = lambda: True
        app.include_router(translation_api.router, prefix="/api/translation")
        return TestClient(app)

    def test_get_config_returns_public_translation_config(self):
        public_config = {
            "preferred_provider": "google",
            "provider_order": ["google", "openai"],
            "providers": [],
        }

        with patch.object(translation_service, "get_public_translation_config", return_value=public_config):
            response = self.make_client().get("/api/translation/config")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["preferred_provider"], "google")
        self.assertEqual(response.json()["provider_order"], ["google", "openai"])

    def test_update_config_normalizes_and_persists_settings(self):
        config = {"auth": {}, "translation_config": {}}

        def update_config(mutator):
            return mutator(config)

        with (
            patch.object(translation_api, "update_config", side_effect=update_config),
            patch.object(translation_api, "load_config", return_value=copy.deepcopy(config)),
            patch.object(translation_service, "update_translation_runtime_config", return_value={}) as runtime_update,
            patch.object(translation_service, "apply_translation_runtime_config", return_value={}),
            patch.object(
                translation_service,
                "get_public_translation_config",
                return_value={"preferred_provider": "google", "provider_order": ["google"], "providers": []},
            ),
        ):
            response = self.make_client().post(
                "/api/translation/config",
                json={"preferred_provider": "Google ", "provider_order": ["GOOGLE"], "providers": {}},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")
        runtime_update.assert_called_once_with(preferred_provider="google", provider_order=["google"], providers={})
        self.assertEqual(config["translation_config"]["preferred_provider"], "google")
        self.assertEqual(config["translation_config"]["provider_order"], ["google"])

    def test_update_config_rejects_unknown_provider(self):
        response = self.make_client().post(
            "/api/translation/config",
            json={"providers": {"definitely_not_a_provider": {"enabled": True}}},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("Unknown translation provider", response.json()["detail"])

    def test_provider_test_rejects_empty_text(self):
        response = self.make_client().post("/api/translation/providers/google/test", json={"text": ""})

        self.assertEqual(response.status_code, 422)

    def test_config_route_requires_session(self):
        app = FastAPI()
        app.include_router(translation_api.router, prefix="/api/translation")
        client = TestClient(app)

        with patch.object(
            core_dependencies,
            "load_config",
            return_value={"auth": {"password_hash": "set", "sessions": {}}},
        ):
            response = client.get("/api/translation/config")

        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
