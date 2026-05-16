import hashlib
import importlib
import os
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.auth as auth_api
from core.dependencies import verify_session
import core.security as security


class SecurityTests(unittest.TestCase):
    def test_pbkdf2_password_hash_round_trip(self):
        password_hash = security.hash_password("StrongPass123")

        self.assertTrue(password_hash.startswith("pbkdf2_sha256$"))
        self.assertTrue(security.verify_password("StrongPass123", password_hash))
        self.assertFalse(security.verify_password("WrongPass123", password_hash))
        self.assertFalse(security.needs_password_rehash(password_hash))

    def test_legacy_sha256_password_hash_is_supported_and_marked_for_rehash(self):
        legacy_hash = hashlib.sha256("OldPass123".encode("utf-8")).hexdigest()

        self.assertTrue(security.verify_password("OldPass123", legacy_hash))
        self.assertFalse(security.verify_password("WrongPass123", legacy_hash))
        self.assertTrue(security.needs_password_rehash(legacy_hash))

    def test_password_policy_default_rules(self):
        original_env = os.environ.copy()
        try:
            with patch.dict(os.environ, {}, clear=True):
                default_security = importlib.reload(security)
                self.assertEqual(default_security.validate_password_policy(" StrongPass123 "), "StrongPass123")
                with self.assertRaisesRegex(ValueError, "at least"):
                    default_security.validate_password_policy("A1")
                with self.assertRaisesRegex(ValueError, "letter"):
                    default_security.validate_password_policy("12345678")
                with self.assertRaisesRegex(ValueError, "number"):
                    default_security.validate_password_policy("Password")
        finally:
            os.environ.clear()
            os.environ.update(original_env)
            importlib.reload(security)

    def test_password_policy_can_be_relaxed_by_environment(self):
        original_env = os.environ.copy()
        try:
            with patch.dict(os.environ, {
                "PASSWORD_MIN_LENGTH": "4",
                "PASSWORD_REQUIRE_LETTER": "false",
                "PASSWORD_REQUIRE_NUMBER": "false",
            }, clear=False):
                relaxed_security = importlib.reload(security)
                self.assertEqual(relaxed_security.PASSWORD_MIN_LENGTH, 4)
                self.assertEqual(relaxed_security.validate_password_policy("1234"), "1234")
        finally:
            os.environ.clear()
            os.environ.update(original_env)
            importlib.reload(security)

    def test_change_password_requires_current_password(self):
        config = {
            "auth": {
                "password_hash": security.hash_password("OldPass123"),
                "sessions": {"session": 9999999999},
            }
        }

        def update_config(mutator):
            return mutator(config)

        app = FastAPI()
        app.dependency_overrides[verify_session] = lambda: True
        app.include_router(auth_api.router, prefix="/api/auth")
        client = TestClient(app)

        with patch.object(auth_api, "update_config", side_effect=update_config):
            missing_current = client.post("/api/auth/change-password", json={
                "new_password": "NewPass123",
            })
            wrong_current = client.post("/api/auth/change-password", json={
                "current_password": "WrongPass123",
                "new_password": "NewPass123",
            })
            ok = client.post("/api/auth/change-password", json={
                "current_password": "OldPass123",
                "new_password": "NewPass123",
            })

        self.assertEqual(missing_current.status_code, 422)
        self.assertEqual(wrong_current.status_code, 401)
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(security.verify_password("NewPass123", config["auth"]["password_hash"]))
        self.assertFalse(security.verify_password("OldPass123", config["auth"]["password_hash"]))


if __name__ == "__main__":
    unittest.main()
