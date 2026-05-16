"""
Security helpers for password hashing and token generation.

The project historically stored passwords as plain SHA256 hex digests.  Keep
verification compatibility for existing installations, but write new/changed
passwords as salted PBKDF2-SHA256 hashes using only Python's standard library.
"""
import base64
import hashlib
import hmac
import os
import re
import secrets


PBKDF2_SCHEME = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 260_000


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


PASSWORD_MIN_LENGTH = _env_int("PASSWORD_MIN_LENGTH", 8, 1)
PASSWORD_MAX_LENGTH = _env_int("PASSWORD_MAX_LENGTH", 100, PASSWORD_MIN_LENGTH)
PASSWORD_REQUIRE_LETTER = _env_bool("PASSWORD_REQUIRE_LETTER", True)
PASSWORD_REQUIRE_NUMBER = _env_bool("PASSWORD_REQUIRE_NUMBER", True)
SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()


def validate_password_policy(password: str) -> str:
    """Validate and normalize an admin password according to environment policy."""
    password = (password or "").strip()
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password must be at most {PASSWORD_MAX_LENGTH} characters")
    if PASSWORD_REQUIRE_LETTER and not re.search(r"[A-Za-z]", password):
        raise ValueError("Password must contain at least one letter")
    if PASSWORD_REQUIRE_NUMBER and not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one number")
    return password


def generate_token() -> str:
    """Generate a URL-safe random token."""
    return secrets.token_urlsafe(24)


def _session_signature(raw_token: str) -> str:
    digest = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        raw_token.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def generate_session_token() -> str:
    """
    Generate a session token.

    When SESSION_SECRET is configured, new session tokens are signed so
    operators can pin a persistent server-side signing secret. Existing
    unsigned tokens stored in config remain readable for backwards
    compatibility.
    """
    raw_token = generate_token()
    if not SESSION_SECRET:
        return raw_token
    return f"st_{raw_token}.{_session_signature(raw_token)}"


def verify_session_token_signature(session_token: str) -> bool:
    """Validate signed session tokens. Unsigned legacy tokens are accepted."""
    if not SESSION_SECRET or not session_token.startswith("st_"):
        return True
    try:
        raw_token, signature = session_token[3:].rsplit(".", 1)
    except ValueError:
        return False
    expected = _session_signature(raw_token)
    return hmac.compare_digest(signature, expected)


def session_storage_key(session_token: str) -> str:
    """
    Return the config.json key used for storing a session.

    Session tokens are bearer credentials.  Store only a digest at rest so a
    leaked config file does not immediately become a live admin session dump.
    Legacy plaintext session keys remain readable during upgrade.
    """
    token = str(session_token or "")
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


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
