"""
Shared dependencies for API endpoints
Authentication, rate limiting, etc.
"""
import time
from typing import Optional
from fastapi import Header, HTTPException

from .database import ConfigLoadError, load_config, update_config
from .security import session_storage_key, verify_session_token_signature
from .token_utils import constant_time_equal
from logger_config import get_logger

logger = get_logger(__name__)


def verify_session(authorization: Optional[str] = Header(None)) -> bool:
    """
    Verify user session from Authorization header.
    Returns True if session is valid, raises HTTPException otherwise.
    """
    try:
        config = load_config()
    except ConfigLoadError as exc:
        raise HTTPException(status_code=503, detail="Configuration is unavailable") from exc
    auth = config.get('auth', {})
    
    # An uninitialized or damaged instance must never expose the admin API.
    if not auth.get('password_hash'):
        raise HTTPException(status_code=503, detail="Administrator password is not initialized")
    
    # Require authorization header
    if not authorization:
        raise HTTPException(status_code=401, detail="Not logged in")
    
    # Check session validity
    sessions = auth.get('sessions', {})
    session_key = session_storage_key(authorization)
    stored_key = session_key if session_key in sessions else authorization
    if stored_key in sessions:
        if not verify_session_token_signature(authorization):
            raise HTTPException(status_code=401, detail="Invalid session")
        if sessions[stored_key] > time.time():
            if stored_key == authorization:
                # One-time migration for legacy plaintext session keys.
                def migrate_plaintext_session(latest_config: dict):
                    latest_sessions = latest_config.get('auth', {}).get('sessions', {})
                    expiry = latest_sessions.pop(authorization, None)
                    if expiry and expiry > time.time():
                        latest_sessions[session_key] = expiry
                    latest_config.setdefault('auth', {})['sessions'] = latest_sessions

                update_config(migrate_plaintext_session)
            return True
        # Session expired, clean it atomically without overwriting concurrent
        # config changes made by other requests.
        def remove_expired_session(latest_config: dict):
            latest_sessions = latest_config.get('auth', {}).get('sessions', {})
            if latest_sessions.get(stored_key, 0) <= time.time():
                latest_sessions.pop(stored_key, None)
                latest_config.setdefault('auth', {})['sessions'] = latest_sessions

        update_config(remove_expired_session)
        raise HTTPException(status_code=401, detail="Session expired")

    raise HTTPException(status_code=401, detail="Invalid session")


def verify_admin_or_user_token(token: str, config: Optional[dict] = None) -> dict:
    """
    Verify admin or user token.
    Returns dict with 'type' ('admin' or 'user') and relevant info.
    """
    if config is None:
        config = load_config()
    auth = config.get('auth', {})
    
    # Check legacy admin token
    if constant_time_equal(token, auth.get('sub_token')):
        return {'type': 'admin', 'legacy': True}
    
    # Check new admin tokens
    for admin_token in config.get('admin_tokens', []):
        if constant_time_equal(token, admin_token.get('token')):
            if not admin_token.get('enabled', True):
                raise HTTPException(status_code=403, detail="Token is disabled")
            return {'type': 'admin', 'token_info': admin_token}
    
    # Check user tokens
    for user in config.get('users', []):
        if constant_time_equal(token, user.get('token')):
            if not user.get('enabled', True):
                raise HTTPException(status_code=403, detail="User account is disabled")
            expire_time = user.get('expire_time', 0)
            if expire_time > 0 and expire_time < time.time():
                raise HTTPException(status_code=403, detail="Subscription expired")
            return {'type': 'user', 'user_info': user}
    
    raise HTTPException(status_code=401, detail="Invalid subscription token")
