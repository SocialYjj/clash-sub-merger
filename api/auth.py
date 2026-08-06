"""
Authentication API
Login, logout, password management
"""
import time
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from pydantic import BaseModel, Field, field_validator

from core.config import AppConfig
from core.database import load_config, update_config
from core.dependencies import verify_session
from core.security import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    generate_session_token,
    hash_password,
    needs_password_rehash,
    session_storage_key,
    validate_password_policy,
    verify_password,
)
from helpers import handle_api_errors
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()
from core.rate_limit import limiter


# ==================== Data Models ====================

class ChangePassword(BaseModel):
    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    new_password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)

    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        return validate_password_policy(v)


class Login(BaseModel):
    password: str = Field(max_length=PASSWORD_MAX_LENGTH)


# ==================== API Endpoints ====================

@router.get("/status")
@handle_api_errors
def get_auth_status():
    """Return only the public state needed by the login screen."""
    config = load_config()
    auth = config.get('auth', {})
    return {"has_password": bool(auth.get('password_hash'))}


@router.post("/login")
@limiter.limit(AppConfig.RATE_LIMIT_LOGIN)
@handle_api_errors
def login(data: Login, request: Request):
    """User login"""
    client_host = request.client.host if request.client else "unknown"

    def create_session(config: dict) -> str:
        auth = config.setdefault('auth', {})

        if not auth.get('password_hash'):
            raise HTTPException(status_code=400, detail="Please set password first")

        if not verify_password(data.password, auth['password_hash']):
            logger.warning("Failed login attempt from %s", client_host)
            raise HTTPException(status_code=401, detail="Wrong password")

        now = time.time()
        sessions = auth.setdefault('sessions', {})
        active_sessions = {
            key: expiry
            for key, expiry in sessions.items()
            if isinstance(expiry, (int, float)) and expiry > now
        }
        newest_sessions = sorted(
            active_sessions.items(),
            key=lambda item: item[1],
            reverse=True,
        )[: max(0, AppConfig.MAX_ACTIVE_SESSIONS - 1)]

        session_token = generate_session_token()
        if needs_password_rehash(auth['password_hash']):
            auth['password_hash'] = hash_password(data.password)
        auth['sessions'] = dict(newest_sessions)
        auth['sessions'][session_storage_key(session_token)] = now + AppConfig.SESSION_TTL_SECONDS
        return session_token

    session_token = update_config(create_session)

    logger.info("User logged in from %s", client_host)
    return {"status": "success", "session": session_token}


@router.post("/logout")
@handle_api_errors
def logout(authorization: Optional[str] = Header(None)):
    """User logout"""
    if not authorization:
        return {"status": "success"}

    def remove_session(config: dict):
        sessions = config.get('auth', {}).get('sessions', {})
        sessions.pop(authorization, None)
        sessions.pop(session_storage_key(authorization), None)
        config.setdefault('auth', {})['sessions'] = sessions

    update_config(remove_session)
    return {"status": "success"}


@router.post("/change-password")
@handle_api_errors
def change_password(data: ChangePassword, _: bool = Depends(verify_session)):
    """Change password after validating the current password."""
    def change_auth_password(config: dict) -> str:
        auth = config.setdefault('auth', {})
        password_hash = auth.get('password_hash')
        if not password_hash:
            raise HTTPException(status_code=400, detail="Password is not set")

        if not verify_password(data.current_password, password_hash):
            raise HTTPException(status_code=401, detail="Current password is incorrect")

        session_token = generate_session_token()
        auth['password_hash'] = hash_password(data.new_password)
        auth['sessions'] = {
            session_storage_key(session_token): time.time() + AppConfig.SESSION_TTL_SECONDS
        }
        return session_token

    session_token = update_config(change_auth_password)

    logger.info("Password changed")
    return {"status": "success", "session": session_token}
