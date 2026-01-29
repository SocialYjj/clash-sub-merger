"""
Users API
User management endpoints
"""
import time
import secrets
from typing import Optional, Dict, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, validator

from core.dependencies import verify_session
from core.database import load_config, save_config
from helpers import handle_api_errors, generate_timestamp_id
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Lazy import server module
_server_module = None


def _get_server():
    global _server_module
    if _server_module is None:
        import server as srv
        _server_module = srv
    return _server_module


def generate_token() -> str:
    return secrets.token_urlsafe(24)


# ==================== Data Models ====================

class CreateUser(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    expire_time: Optional[int] = Field(0, ge=0)
    
    @validator('name')
    def validate_name(cls, v):
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError('Name contains invalid characters')
        return v.strip()


class UpdateUser(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    expire_time: Optional[int] = Field(None, ge=0)
    enabled: Optional[bool] = None
    template_id: Optional[str] = None
    sub_name: Optional[str] = Field(None, max_length=100)
    sub_filename: Optional[str] = Field(None, max_length=100)
    
    @validator('name', 'sub_name', 'sub_filename')
    def validate_names(cls, v):
        if v and ('/' in v or '\\' in v or '..' in v):
            raise ValueError('Name contains invalid characters')
        return v.strip() if v else v


class UserNodeAllocation(BaseModel):
    subscriptions: Dict[str, List[str]]


class UpdateUserGroupConfig(BaseModel):
    group_config: Dict[str, List[str]]


class RegenerateTokenRequest(BaseModel):
    custom_token: Optional[str] = None


# ==================== API Endpoints ====================

@router.get("")
@handle_api_errors
def list_users(_: bool = Depends(verify_session)):
    """List all users"""
    config = load_config()
    users = config.get('users', [])
    # Mask tokens in list view
    return {"users": [{**u, 'token': u['token'][:8] + '...'} for u in users]}


@router.get("/{user_id}")
@handle_api_errors
def get_user(user_id: str, _: bool = Depends(verify_session)):
    """Get user details including full token"""
    config = load_config()
    for user in config.get('users', []):
        if user['id'] == user_id:
            return {"user": user}
    raise HTTPException(status_code=404, detail="User not found")


@router.post("")
@handle_api_errors
def create_user(data: CreateUser, _: bool = Depends(verify_session)):
    """Create a new user"""
    config = load_config()
    
    user_id = generate_timestamp_id('user_')
    user = {
        'id': user_id,
        'name': data.name,
        'token': generate_token(),
        'enabled': True,
        'expire_time': data.expire_time,
        'created_at': int(time.time()),
        'allocations': {},
        'template_id': 'builtin',
        'group_config': {}
    }
    
    if 'users' not in config:
        config['users'] = []
    config['users'].append(user)
    save_config(config)
    
    return {"status": "success", "user": user}


@router.put("/{user_id}")
@handle_api_errors
def update_user(user_id: str, data: UpdateUser, _: bool = Depends(verify_session)):
    """Update user info"""
    config = load_config()
    
    for user in config.get('users', []):
        if user['id'] == user_id:
            if data.name is not None:
                user['name'] = data.name
            if data.expire_time is not None:
                user['expire_time'] = data.expire_time
            if data.enabled is not None:
                user['enabled'] = data.enabled
            if data.template_id is not None:
                if data.template_id != 'builtin':
                    templates = config.get('templates', [])
                    if not any(t['id'] == data.template_id for t in templates):
                        raise HTTPException(status_code=400, detail="Template not found")
                user['template_id'] = data.template_id
            if data.sub_name is not None:
                user['sub_name'] = data.sub_name
            if data.sub_filename is not None:
                user['sub_filename'] = data.sub_filename
            if 'sub_cache' in user:
                del user['sub_cache']
            save_config(config)
            return {"status": "success", "user": user}
    
    raise HTTPException(status_code=404, detail="User not found")


@router.delete("/{user_id}")
@handle_api_errors
def delete_user(user_id: str, _: bool = Depends(verify_session)):
    """Delete a user"""
    config = load_config()
    users = config.get('users', [])
    config['users'] = [u for u in users if u['id'] != user_id]
    save_config(config)
    return {"status": "success"}


@router.post("/{user_id}/regenerate-token")
@handle_api_errors
def regenerate_user_token(user_id: str, data: RegenerateTokenRequest = None, _: bool = Depends(verify_session)):
    """Regenerate user's subscription token"""
    config = load_config()
    
    for user in config.get('users', []):
        if user['id'] == user_id:
            if data and data.custom_token and len(data.custom_token.strip()) >= 8:
                user['token'] = data.custom_token.strip()
            else:
                user['token'] = generate_token()
            save_config(config)
            return {"status": "success", "token": user['token']}
    
    raise HTTPException(status_code=404, detail="User not found")


@router.post("/{user_id}/reset-group-config")
@handle_api_errors
def reset_user_group_config(user_id: str, _: bool = Depends(verify_session)):
    """Reset user's group configuration"""
    config = load_config()
    
    for user in config.get('users', []):
        if user['id'] == user_id:
            user['group_config'] = {}
            if 'sub_cache' in user:
                del user['sub_cache']
            save_config(config)
            return {"status": "success", "message": "Group config reset"}
    
    raise HTTPException(status_code=404, detail="User not found")


@router.get("/{user_id}/allocations")
@handle_api_errors
def get_user_allocations(user_id: str, _: bool = Depends(verify_session)):
    """Get user's node allocations"""
    config = load_config()
    
    for user in config.get('users', []):
        if user['id'] == user_id:
            return {"allocations": user.get('allocations', {})}
    
    raise HTTPException(status_code=404, detail="User not found")


@router.put("/{user_id}/allocations")
@handle_api_errors
def update_user_allocations(user_id: str, data: UserNodeAllocation, _: bool = Depends(verify_session)):
    """Update user's node allocations"""
    config = load_config()
    
    for user in config.get('users', []):
        if user['id'] == user_id:
            user['allocations'] = data.subscriptions
            if 'sub_cache' in user:
                del user['sub_cache']
            save_config(config)
            return {"status": "success", "allocations": user['allocations']}
    
    raise HTTPException(status_code=404, detail="User not found")


@router.put("/{user_id}/group-config")
@handle_api_errors
def update_user_group_config(user_id: str, data: UpdateUserGroupConfig, _: bool = Depends(verify_session)):
    """Update user's group configuration"""
    config = load_config()
    
    for user in config.get('users', []):
        if user['id'] == user_id:
            user['group_config'] = data.group_config
            if 'sub_cache' in user:
                del user['sub_cache']
            save_config(config)
            return {"status": "success", "group_config": user['group_config']}
    
    raise HTTPException(status_code=404, detail="User not found")
