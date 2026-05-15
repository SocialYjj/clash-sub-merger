"""
Shared dependencies for API endpoints
Authentication, rate limiting, etc.
"""
import time
from typing import Optional
from fastapi import Header, HTTPException

from .database import load_config, update_config
from logger_config import get_logger

logger = get_logger(__name__)


def verify_session(authorization: Optional[str] = Header(None)) -> bool:
    """
    Verify user session from Authorization header.
    Returns True if session is valid, raises HTTPException otherwise.
    """
    config = load_config()
    auth = config.get('auth', {})
    
    # If no password set, allow access
    if not auth.get('password_hash'):
        return True
    
    # Require authorization header
    if not authorization:
        raise HTTPException(status_code=401, detail="Not logged in")
    
    # Check session validity
    sessions = auth.get('sessions', {})
    if authorization in sessions:
        if sessions[authorization] > time.time():
            return True
        # Session expired, clean it atomically without overwriting concurrent
        # config changes made by other requests.
        def remove_expired_session(latest_config: dict):
            latest_sessions = latest_config.get('auth', {}).get('sessions', {})
            if latest_sessions.get(authorization, 0) <= time.time():
                latest_sessions.pop(authorization, None)
                latest_config.setdefault('auth', {})['sessions'] = latest_sessions

        update_config(remove_expired_session)
    
    raise HTTPException(status_code=401, detail="Session expired")


def verify_admin_or_user_token(token: str) -> dict:
    """
    Verify admin or user token.
    Returns dict with 'type' ('admin' or 'user') and relevant info.
    """
    config = load_config()
    auth = config.get('auth', {})
    
    # Check legacy admin token
    if auth.get('sub_token') and token == auth['sub_token']:
        return {'type': 'admin', 'legacy': True}
    
    # Check new admin tokens
    for admin_token in config.get('admin_tokens', []):
        if admin_token.get('token') == token:
            if not admin_token.get('enabled', True):
                raise HTTPException(status_code=403, detail="Token is disabled")
            return {'type': 'admin', 'token_info': admin_token}
    
    # Check user tokens
    for user in config.get('users', []):
        if user.get('token') == token:
            if not user.get('enabled', True):
                raise HTTPException(status_code=403, detail="User account is disabled")
            expire_time = user.get('expire_time', 0)
            if expire_time > 0 and expire_time < time.time():
                raise HTTPException(status_code=403, detail="Subscription expired")
            return {'type': 'user', 'user_info': user}
    
    raise HTTPException(status_code=401, detail="Invalid subscription token")
