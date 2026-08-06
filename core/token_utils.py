"""Helpers for subscription token creation and uniqueness checks."""

import hmac
import re
from typing import Optional

from fastapi import HTTPException

from .security import generate_token


MIN_CUSTOM_TOKEN_LENGTH = 8
MAX_CUSTOM_TOKEN_LENGTH = 200
CUSTOM_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9._~-]+$")


def constant_time_equal(left: Optional[str], right: Optional[str]) -> bool:
    """Compare secret tokens without leaking useful timing information."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    if not left or not right:
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def normalize_custom_subscription_token(token: Optional[str]) -> Optional[str]:
    """Trim and validate a user-supplied subscription token."""
    if token is None:
        return None

    normalized = token.strip()
    if not normalized:
        return None
    if len(normalized) < MIN_CUSTOM_TOKEN_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Custom token must be at least {MIN_CUSTOM_TOKEN_LENGTH} characters",
        )
    if len(normalized) > MAX_CUSTOM_TOKEN_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Custom token must be at most {MAX_CUSTOM_TOKEN_LENGTH} characters",
        )
    if not CUSTOM_TOKEN_PATTERN.fullmatch(normalized):
        raise HTTPException(
            status_code=400,
            detail="Custom token may contain only letters, numbers, '.', '_', '-', or '~'",
        )
    return normalized


def find_subscription_token_conflict(
    config: dict,
    token: str,
    *,
    exclude_admin_id: Optional[str] = None,
    exclude_user_id: Optional[str] = None,
) -> Optional[dict]:
    """Return conflict metadata if a subscription token is already in use."""
    if not token:
        return None

    auth = config.get("auth", {})
    if constant_time_equal(auth.get("sub_token"), token):
        return {"type": "legacy_admin", "id": "auth.sub_token", "name": auth.get("sub_name", "legacy")}

    for admin_token in config.get("admin_tokens", []):
        if exclude_admin_id and admin_token.get("id") == exclude_admin_id:
            continue
        if constant_time_equal(admin_token.get("token"), token):
            return {
                "type": "admin",
                "id": admin_token.get("id"),
                "name": admin_token.get("name", ""),
            }

    for user in config.get("users", []):
        if exclude_user_id and user.get("id") == exclude_user_id:
            continue
        if constant_time_equal(user.get("token"), token):
            return {
                "type": "user",
                "id": user.get("id"),
                "name": user.get("name", ""),
            }

    return None


def ensure_subscription_token_unique(
    config: dict,
    token: str,
    *,
    exclude_admin_id: Optional[str] = None,
    exclude_user_id: Optional[str] = None,
) -> str:
    """Raise a 400 error when a subscription token would collide."""
    conflict = find_subscription_token_conflict(
        config,
        token,
        exclude_admin_id=exclude_admin_id,
        exclude_user_id=exclude_user_id,
    )
    if conflict:
        label = conflict.get("name") or conflict.get("id") or conflict.get("type")
        raise HTTPException(status_code=400, detail=f"Token already exists: {label}")
    return token


def generate_unique_subscription_token(
    config: dict,
    *,
    exclude_admin_id: Optional[str] = None,
    exclude_user_id: Optional[str] = None,
    attempts: int = 10,
) -> str:
    """Generate a random subscription token that is unique in the current config."""
    for _ in range(attempts):
        token = generate_token()
        if not find_subscription_token_conflict(
            config,
            token,
            exclude_admin_id=exclude_admin_id,
            exclude_user_id=exclude_user_id,
        ):
            return token

    raise HTTPException(status_code=500, detail="Failed to generate a unique token")
