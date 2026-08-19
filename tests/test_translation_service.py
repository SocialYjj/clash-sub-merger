"""Tests for provider-independent location translation."""

import asyncio
import copy
import json
import unittest
from unittest.mock import AsyncMock, patch

import translation_service


class TranslationServiceTests(unittest.TestCase):
    def setUp(self):
        self.runtime_snapshot = translation_service.get_translation_runtime_config()
        with translation_service._translation_cache_lock:
            self.cache_snapshot = copy.deepcopy(translation_service._translation_cache)
            translation_service._translation_cache.clear()

    def tearDown(self):
        with translation_service._translation_config_lock:
            translation_service._translation_runtime_config = self.runtime_snapshot
        with translation_service._translation_cache_lock:
            translation_service._translation_cache.clear()
            translation_service._translation_cache.update(self.cache_snapshot)

    def test_google_translation_is_cached_without_repeating_provider_call(self):
        async def run_test():
            with (
                patch.object(
                    translation_service,
                    "_translate_google",
                    new=AsyncMock(return_value="山景城"),
                ) as google_call,
                patch.object(translation_service, "_save_translation_cache"),
            ):
                first_translation = await translation_service.translate_to_simplified_chinese(
                    "Mountain View"
                )
                second_translation = await translation_service.translate_to_simplified_chinese(
                    "Mountain View"
                )
                return first_translation, second_translation, google_call.await_count

        first_translation, second_translation, call_count = asyncio.run(run_test())
        self.assertEqual(first_translation, "山景城")
        self.assertEqual(second_translation, "山景城")
        self.assertEqual(call_count, 1)

    def test_google_endpoint_accepts_base_url_or_full_translate_path(self):
        self.assertEqual(
            translation_service._get_google_translate_endpoint(
                {"endpoint": "https://translate.googleapis.com/"}
            ),
            "https://translate.googleapis.com/translate_a/single",
        )
        self.assertEqual(
            translation_service._get_google_translate_endpoint(
                {"endpoint": "https://mirror.example/translate_a/single"}
            ),
            "https://mirror.example/translate_a/single",
        )

    def test_microsoft_endpoint_accepts_base_url_or_full_web_path(self):
        self.assertEqual(
            translation_service._get_microsoft_translate_endpoint(
                {"endpoint": "https://edge.microsoft.com/translate"}
            ),
            "https://edge.microsoft.com/translate/translatetext",
        )

    def test_openai_endpoint_accepts_base_url_or_full_chat_path(self):
        self.assertEqual(
            translation_service._openai_endpoint(
                {"endpoint": "https://api.openai.com/v1"}
            ),
            "https://api.openai.com/v1/chat/completions",
        )
        self.assertEqual(
            translation_service._openai_endpoint(
                {"endpoint": "https://gateway.example/v1/chat/completions"}
            ),
            "https://gateway.example/v1/chat/completions",
        )
        self.assertEqual(
            translation_service._get_microsoft_translate_endpoint(
                {"endpoint": "https://edge.microsoft.com/translate/translatetext"}
            ),
            "https://edge.microsoft.com/translate/translatetext",
        )

    def test_provider_fallback_uses_next_configured_provider(self):
        translation_service.update_translation_runtime_config(
            preferred_provider="microsoft",
            providers={
                "google": {"enabled": False},
                "microsoft": {"enabled": True, "endpoint": "https://translation.test"},
            },
        )

        async def run_test():
            with (
                patch.object(
                    translation_service,
                    "_translate_microsoft",
                    new=AsyncMock(return_value="加利福尼亚州"),
                ) as microsoft_call,
                patch.object(translation_service, "_save_translation_cache"),
            ):
                translated = await translation_service.translate_to_simplified_chinese(
                    "California",
                    context="region",
                )
                return translated, microsoft_call.await_count

        translated, call_count = asyncio.run(run_test())
        self.assertEqual(translated, "加利福尼亚州")
        self.assertEqual(call_count, 1)

    def test_public_config_does_not_expose_credentials(self):
        translation_service.update_translation_runtime_config(
            providers={
                "tencent": {
                    "enabled": True,
                    "secret_id": "public-id",
                    "secret_key": "private-secret",
                },
                "openai": {
                    "enabled": True,
                    "api_key": "openai-private-key",
                    "model": "gpt-4o-mini",
                }
            }
        )

        public_config = translation_service.get_public_translation_config()
        tencent = next(provider for provider in public_config["providers"] if provider["id"] == "tencent")
        self.assertTrue(tencent["configured"])
        self.assertEqual(tencent["fields"], ["secret_id", "secret_key"])
        self.assertNotIn("endpoint", tencent)
        self.assertNotIn("region", tencent)
        self.assertNotIn("description", tencent)
        self.assertNotIn("private-secret", str(tencent))
        self.assertNotIn("public-id", str(tencent))
        openai = next(provider for provider in public_config["providers"] if provider["id"] == "openai")
        self.assertTrue(openai["configured"])
        self.assertEqual(openai["model"], "gpt-4o-mini")
        self.assertNotIn("openai-private-key", str(openai))

    def test_chinese_source_is_not_sent_to_a_provider(self):
        async def run_test():
            with patch.object(
                translation_service,
                "_translate_google",
                new=AsyncMock(),
            ) as google_call:
                translated = await translation_service.translate_to_simplified_chinese("美国")
                return translated, google_call.await_count

        translated, call_count = asyncio.run(run_test())
        self.assertEqual(translated, "美国")
        self.assertEqual(call_count, 0)

    def test_provider_response_parsers_cover_all_configured_services(self):
        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def raise_for_status(self):
                return None

            def json(self):
                return self.payload

            @property
            def text(self):
                if isinstance(self.payload, str):
                    return self.payload
                return json.dumps(self.payload)

        class FakeAsyncClient:
            payload = None
            post_payload = None
            post_calls = []

            def __init__(self, *args, **kwargs):
                del args, kwargs

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                del args

            async def get(self, *args, **kwargs):
                del args, kwargs
                return FakeResponse(self.payload)

            async def post(self, *args, **kwargs):
                FakeAsyncClient.post_calls.append((args, kwargs))
                payload = self.post_payload if self.post_payload is not None else self.payload
                return FakeResponse(payload)

        provider_cases = {
            "google": ({"endpoint": "https://translation.test"}, [[['阿什本']]]),
            "microsoft": ({"endpoint": "https://translation.test"}, [{"translations": [{"text": "微软"}]}]),
            "tencent": ({"secret_id": "id", "secret_key": "secret"}, {"Response": {"TargetText": "腾讯"}}),
            "openai": (
                {
                    "endpoint": "https://translation.test",
                    "api_key": "test-key",
                    "model": "gpt-4o-mini",
                },
                {"choices": [{"message": {"content": "OpenAI"}}]},
            ),
        }

        async def run_tests():
            parsed_values = {}
            FakeAsyncClient.post_calls = []
            with patch.object(translation_service.httpx, "AsyncClient", FakeAsyncClient):
                for provider_id, (provider_config, response_payload) in provider_cases.items():
                    FakeAsyncClient.payload = response_payload
                    FakeAsyncClient.post_payload = response_payload if provider_id == "microsoft" else None
                    parsed_values[provider_id] = await translation_service._translate_with_provider(
                        provider_id,
                        "source",
                        "city",
                        provider_config,
                    )
            return parsed_values, FakeAsyncClient.post_calls

        parsed_values, post_calls = asyncio.run(run_tests())
        self.assertEqual(
            parsed_values,
            {
                "google": "阿什本",
                "microsoft": "微软",
                "tencent": "腾讯",
                "openai": "OpenAI",
            },
        )
        microsoft_url, microsoft_options = next(
            call for call in post_calls if "translatetext" in call[0][0]
        )
        self.assertEqual(microsoft_url, ("https://translation.test/translatetext",))
        self.assertEqual(
            microsoft_options["params"],
            {"from": "", "to": "zh-Hans", "isEnterpriseClient": "false"},
        )
        self.assertEqual(microsoft_options["json"], ["source"])
        self.assertNotIn("Authorization", microsoft_options["headers"])
        openai_url, openai_options = next(
            call for call in post_calls if "chat/completions" in call[0][0]
        )
        self.assertEqual(openai_url, ("https://translation.test/chat/completions",))
        self.assertEqual(openai_options["headers"]["Authorization"], "Bearer test-key")
        self.assertEqual(openai_options["json"]["model"], "gpt-4o-mini")
        self.assertEqual(openai_options["json"]["messages"][-1], {"role": "user", "content": "source"})


if __name__ == "__main__":
    unittest.main()
