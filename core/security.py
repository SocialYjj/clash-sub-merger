"""
Security helpers for password hashing and token generation.

The project historically stored passwords as plain SHA256 hex digests.  Keep
verification compatibility for existing installations, but write new/changed
passwords as salted PBKDF2-SHA256 hashes using only Python's standard library.
"""
import base64
import hashlib
import hmac
import secrets


PBKDF2_SCHEME = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 260_000


def generate_token() -> str:
    """Generate a URL-safe random token."""
    return secrets.token_urlsafe(24)


def hash_password(password: str) -> str:
    """Hash a password using salted PBKDF2-SHA256."""
    salt = secrets.token_urlsafe(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    digest_b64 = base64.b64encode(digest).decode("ascii")
    return f"{PBKDF2_SCHEME}${PBKDF2_ITERATIONS}${salt}${digest_b64}"


def _verify_pbkdf2(password: str, password_hash: str) -> bool:
    try:
        scheme, iterations_raw, salt, expected_b64 = password_hash.split("$", 3)
        if scheme != PBKDF2_SCHEME:
            return False
        iterations = int(iterations_raw)
        expected = base64.b64decode(expected_b64.encode("ascii"), validate=True)
    except Exception:
        return False

    actual = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return hmac.compare_digest(actual, expected)


def _verify_legacy_sha256(password: str, password_hash: str) -> bool:
    if len(password_hash) != 64:
        return False
    try:
        int(password_hash, 16)
    except ValueError:
        return False
    actual = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(actual, password_hash)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against either the new PBKDF2 hash or legacy SHA256."""
    if not password_hash:
        return False
    if password_hash.startswith(f"{PBKDF2_SCHEME}$"):
        return _verify_pbkdf2(password, password_hash)
    return _verify_legacy_sha256(password, password_hash)


def needs_password_rehash(password_hash: str) -> bool:
    """Return True when a stored password hash should be upgraded."""
    if not password_hash or not password_hash.startswith(f"{PBKDF2_SCHEME}$"):
        return True
    try:
        _, iterations_raw, _, _ = password_hash.split("$", 3)
        return int(iterations_raw) < PBKDF2_ITERATIONS
    except Exception:
        return True
