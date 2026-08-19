import os
import unittest
import uuid

from core import storage


@unittest.skipUnless(
    os.environ.get("RUN_EXTERNAL_STORAGE_TESTS") == "1",
    "Set RUN_EXTERNAL_STORAGE_TESTS=1 to run PostgreSQL/MySQL integration tests",
)
class ExternalStorageTests(unittest.TestCase):
    def setUp(self):
        storage.initialize_database()

    def test_document_and_cache_round_trip(self):
        original_config = storage.read_app_document("config", default=None)
        self.assertIsInstance(original_config, dict)

        round_trip_config = {
            "backend": storage.backend_name(),
            "unicode": "山景城",
            "nodes": ["n1", "n2"],
        }
        storage.write_app_document("config", round_trip_config)
        self.assertTrue(storage.has_app_document("config"))
        self.assertEqual(storage.read_app_document("config"), round_trip_config)
        storage.write_app_document("config", original_config)

        namespace = f"__external_storage_test__{uuid.uuid4().hex}"
        cache_payload = {"value": "缓存", "items": [1, 2, 3]}
        storage.write_cache_document(namespace, cache_payload, expires_at=123.5)
        self.assertEqual(storage.read_cache_document(namespace), cache_payload)
        self.assertEqual(
            storage.read_cache_document_record(namespace),
            {"payload": cache_payload, "expires_at": 123.5},
        )
        storage.delete_cache_document(namespace)
        self.assertIsNone(storage.read_cache_document(namespace, default=None))


if __name__ == "__main__":
    unittest.main()
