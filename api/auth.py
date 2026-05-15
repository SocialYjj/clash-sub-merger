"""
Authentication API
Login, logout, password management
"""
import re
import time
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from pydantic import BaseModel, Field, validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.database import load_config, update_config
from core.dependencies import verify_session
from core.security import generate_token, hash_password, needs_password_rehash, verify_password
from helpers import handle_api_errors
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Rate limiter for auth endpoints
limiter = Limiter(key_func=get_remote_address)


# ==================== Data Models ====================

class SetPassword(BaseModel):
    password: str = Field(min_length=8, max_length=100)
    
    @validator('password')
    def validate_password(cls, v):
        v = v.strip()
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[A-Za-z]', v):
            raise ValueError('Password must contain at least one letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one number')
        return v


class Login(BaseModel):
    password: str = Field(max_length=100)


class UpdateSubFilename(BaseModel):
    filename: str = Field(min_length=1, max_length=100)
    
    @validator('filename')
    def validate_filename(cls, v):
        return v.strip()


class UpdateSubName(BaseModel):
    name: str = Field(min_length=1, max_length=100)


# ==================== API Endpoints ====================

@router.get("/status")
@handle_api_errors
def get_auth_status():
    """Get authentication status"""
    config = load_config()
    auth = config.get('auth', {})
    return {
        "has_password": bool(auth.get('password_hash')),
        "sub_token": auth.get('sub_token', ''),
        "sub_filename": auth.get('sub_filename', 'config.yaml'),
        "sub_name": auth.get('sub_name', 'Aggregated')
    }


@router.post("/setup")
@handle_api_errors
def setup_password(data: SetPassword):
    """Initial password setup"""
    def setup_auth(config: dict):
        auth = config.setdefault('auth', {})
        if auth.get('password_hash'):
            raise HTTPException(status_code=400, detail="Password already set, use change password")

        session_token = generate_token()
        sub_token = generate_token()
        config['auth'] = {
            'password_hash': hash_password(data.password),
            'sub_token': sub_token,
            'sessions': {session_token: time.time() + 86400}
        }
        return session_token, sub_token

    session_token, sub_token = update_config(setup_auth)
    logger.info("Password setup completed")
    return {"status": "success", "session": session_token, "sub_token": sub_token}


@router.post("/login")
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

        session_token = generate_token()
        if needs_password_rehash(auth['password_hash']):
            auth['password_hash'] = hash_password(data.password)
        auth.setdefault('sessions', {})[session_token] = time.time() + 86400
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
        if authorization in sessions:
            sessions.pop(authorization, None)
            config.setdefault('auth', {})['sessions'] = sessions

    update_config(remove_session)
    return {"status": "success"}


@router.post("/change-password")
@handle_api_errors
def change_password(data: SetPassword, _: bool = Depends(verify_session)):
    """Change password"""
    def change_auth_password(config: dict) -> str:
        auth = config.setdefault('auth', {})
        session_token = generate_token()
        auth['password_hash'] = hash_password(data.password)
        auth['sessions'] = {session_token: time.time() + 86400}
        return session_token

    session_token = update_config(change_auth_password)

    logger.info("Password changed")
    return {"status": "success", "session": session_token}


@router.post("/regenerate-token")
@handle_api_errors
def regenerate_sub_token(_: bool = Depends(verify_session)):
    """Regenerate subscription token"""
    def regenerate_token(config: dict) -> str:
        new_token = generate_token()
        config.setdefault('auth', {})['sub_token'] = new_token
        return new_token

    new_token = update_config(regenerate_token)

    logger.info("Subscription token regenerated")
    return {"sub_token": new_token}


@router.post("/sub-filename")
@handle_api_errors
def update_sub_filename(data: UpdateSubFilename, _: bool = Depends(verify_session)):
    """Update subscription filename"""
    filename = data.filename
    if not filename.endswith('.yaml') and not filename.endswith('.yml'):
        filename += '.yaml'

    def set_sub_filename(config: dict):
        config.setdefault('auth', {})['sub_filename'] = filename

    update_config(set_sub_filename)

    return {"status": "success", "sub_filename": filename}


@router.post("/sub-name")
@handle_api_errors
def update_sub_name(data: UpdateSubName, _: bool = Depends(verify_session)):
    """Update subscription name"""
    name = data.name.strip()

    def set_sub_name(config: dict):
        config.setdefault('auth', {})['sub_name'] = name

    update_config(set_sub_name)

    return {"status": "success", "sub_name": name}


@router.get("/sub-token")
@handle_api_errors
def get_sub_token(_: bool = Depends(verify_session)):
    """Get subscription token"""
    config = load_config()
    return {"sub_token": config.get('auth', {}).get('sub_token', '')}
