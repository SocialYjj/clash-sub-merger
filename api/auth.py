"""
Authentication API
Login, logout, password management
"""
import re
import time
import secrets
import hashlib
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from pydantic import BaseModel, Field, validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.config import AppConfig
from core.database import load_config, save_config
from helpers import handle_api_errors, generate_timestamp_id
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


# ==================== Helper Functions ====================

def hash_password(password: str) -> str:
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()


def generate_token() -> str:
    """Generate secure token"""
    return secrets.token_urlsafe(24)


def verify_session(authorization: Optional[str] = Header(None)) -> bool:
    """Verify user session"""
    config = load_config()
    auth = config.get('auth', {})
    
    if not auth.get('password_hash'):
        return True
    
    if not authorization:
        raise HTTPException(status_code=401, detail="Not logged in")
    
    sessions = auth.get('sessions', {})
    if authorization in sessions:
        if sessions[authorization] > time.time():
            return True
        del sessions[authorization]
        config['auth']['sessions'] = sessions
        save_config(config)
    
    raise HTTPException(status_code=401, detail="Session expired")


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
    config = load_config()
    if config['auth'].get('password_hash'):
        raise HTTPException(status_code=400, detail="Password already set, use change password")
    
    session_token = generate_token()
    config['auth'] = {
        'password_hash': hash_password(data.password),
        'sub_token': generate_token(),
        'sessions': {session_token: time.time() + 86400}
    }
    save_config(config)
    logger.info("Password setup completed")
    return {"status": "success", "session": session_token, "sub_token": config['auth']['sub_token']}


@router.post("/login")
@handle_api_errors
def login(data: Login, request: Request):
    """User login"""
    config = load_config()
    auth = config.get('auth', {})
    
    if not auth.get('password_hash'):
        raise HTTPException(status_code=400, detail="Please set password first")
    
    if hash_password(data.password) != auth['password_hash']:
        logger.warning("Failed login attempt from %s", request.client.host)
        raise HTTPException(status_code=401, detail="Wrong password")
    
    session_token = generate_token()
    if 'sessions' not in config['auth']:
        config['auth']['sessions'] = {}
    config['auth']['sessions'][session_token] = time.time() + 86400
    save_config(config)
    
    logger.info("User logged in from %s", request.client.host)
    return {"status": "success", "session": session_token}


@router.post("/logout")
@handle_api_errors
def logout(authorization: Optional[str] = Header(None)):
    """User logout"""
    if not authorization:
        return {"status": "success"}
    
    config = load_config()
    sessions = config.get('auth', {}).get('sessions', {})
    
    if authorization in sessions:
        del sessions[authorization]
        config['auth']['sessions'] = sessions
        save_config(config)
    
    return {"status": "success"}


@router.post("/change-password")
@handle_api_errors
def change_password(data: SetPassword, _: bool = Depends(verify_session)):
    """Change password"""
    config = load_config()
    
    session_token = generate_token()
    config['auth']['password_hash'] = hash_password(data.password)
    config['auth']['sessions'] = {session_token: time.time() + 86400}
    save_config(config)
    
    logger.info("Password changed")
    return {"status": "success", "session": session_token}


@router.post("/regenerate-token")
@handle_api_errors
def regenerate_sub_token(_: bool = Depends(verify_session)):
    """Regenerate subscription token"""
    config = load_config()
    
    new_token = generate_token()
    config['auth']['sub_token'] = new_token
    save_config(config)
    
    logger.info("Subscription token regenerated")
    return {"sub_token": new_token}


@router.post("/sub-filename")
@handle_api_errors
def update_sub_filename(data: UpdateSubFilename, _: bool = Depends(verify_session)):
    """Update subscription filename"""
    config = load_config()
    
    filename = data.filename
    if not filename.endswith('.yaml') and not filename.endswith('.yml'):
        filename += '.yaml'
    
    config['auth']['sub_filename'] = filename
    save_config(config)
    
    return {"status": "success", "sub_filename": filename}


@router.post("/sub-name")
@handle_api_errors
def update_sub_name(data: UpdateSubName, _: bool = Depends(verify_session)):
    """Update subscription name"""
    config = load_config()
    
    name = data.name.strip()
    config['auth']['sub_name'] = name
    save_config(config)
    
    return {"status": "success", "sub_name": name}


@router.get("/sub-token")
@handle_api_errors
def get_sub_token(_: bool = Depends(verify_session)):
    """Get subscription token"""
    config = load_config()
    return {"sub_token": config.get('auth', {}).get('sub_token', '')}
