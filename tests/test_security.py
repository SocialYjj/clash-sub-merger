import hashlib
import unittest

from core.security import hash_password, needs_password_rehash, verify_password


class SecurityTests(unittest.TestCase):
    def test_pbkdf2_password_hash_round_trip(self):
        password_hash = hash_password("StrongPass123")

        self.assertTrue(password_hash.startswith("pbkdf2_sha256$"))
        self.assertTrue(verify_password("StrongPass123", password_hash))
        self.assertFalse(verify_password("WrongPass123", password_hash))
        self.assertFalse(needs_password_rehash(password_hash))

    def test_legacy_sha256_password_hash_is_supported_and_marked_for_rehash(self):
        legacy_hash = hashlib.sha256("OldPass123".encode("utf-8")).hexdigest()

        self.assertTrue(verify_password("OldPass123", legacy_hash))
        self.assertFalse(verify_password("WrongPass123", legacy_hash))
        self.assertTrue(needs_password_rehash(legacy_hash))


if __name__ == "__main__":
    unittest.main()
