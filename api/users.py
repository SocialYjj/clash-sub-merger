"""
Users API
User management endpoints
"""
import time
from typing import Optional, Dict, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from core.dependencies import verify_session
from core.database import load_config, update_config
from core.token_utils import (
    ensure_subscription_token_unique,
    generate_unique_subscription_token,
    normalize_custom_subscription_token,
)
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


# ==================== Data Models ====================

class CreateUser(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    expire_time: Optional[int] = Field(0, ge=0)
    
    @field_validator('name')
    @classmethod
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
    
    @field_validator('name', 'sub_name', 'sub_filename')
    @classmethod
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
    def add_user(config: dict) -> dict:
        user_id = generate_timestamp_id('user_')
        user = {
            'id': user_id,
            'name': data.name,
            'token': generate_unique_subscription_token(config),
            'enabled': True,
            'expire_time': data.expire_time,
            'created_at': int(time.time()),
            'allocations': {},
            'template_id': 'builtin',
            'group_config': {}
        }
        config.setdefault('users', []).append(user)
        return dict(user)

    user = update_config(add_user)
    
    return {"status": "success", "user": user}


@router.put("/{user_id}")
@handle_api_errors
def update_user(user_id: str, data: UpdateUser, _: bool = Depends(verify_session)):
    """Update user info"""
    def apply_user_update(config: dict) -> dict:
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
                user.pop('sub_cache', None)
                return dict(user)

        raise HTTPException(status_code=404, detail="User not found")

    user = update_config(apply_user_update)
    return {"status": "success", "user": user}


@router.delete("/{user_id}")
@handle_api_errors
def delete_user(user_id: str, _: bool = Depends(verify_session)):
    """Delete a user"""
    def remove_user(config: dict):
        users = config.get('users', [])
        config['users'] = [u for u in users if u['id'] != user_id]

    update_config(remove_user)
    return {"status": "success"}


@router.post("/{user_id}/regenerate-token")
@handle_api_errors
def regenerate_user_token(user_id: str, data: RegenerateTokenRequest = None, _: bool = Depends(verify_session)):
    """Regenerate user's subscription token"""
    def regenerate_token(config: dict) -> str:
        for user in config.get('users', []):
            if user['id'] == user_id:
                custom_token = normalize_custom_subscription_token(data.custom_token if data else None)
                if custom_token:
                    user['token'] = ensure_subscription_token_unique(
                        config,
                        custom_token,
                        exclude_user_id=user_id,
                    )
                else:
                    user['token'] = generate_unique_subscription_token(
                        config,
                        exclude_user_id=user_id,
                    )
                return user['token']

        raise HTTPException(status_code=404, detail="User not found")

    token = update_config(regenerate_token)
    return {"status": "success", "token": token}


@router.post("/{user_id}/reset-group-config")
@handle_api_errors
def reset_user_group_config(user_id: str, _: bool = Depends(verify_session)):
    """Reset user's group configuration"""
    def reset_group_config(config: dict):
        for user in config.get('users', []):
            if user['id'] == user_id:
                user['group_config'] = {}
                user.pop('sub_cache', None)
                return

        raise HTTPException(status_code=404, detail="User not found")

    update_config(reset_group_config)
    return {"status": "success", "message": "Group config reset"}


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
    def update_allocations(config: dict) -> dict:
        for user in config.get('users', []):
            if user['id'] == user_id:
                user['allocations'] = data.subscriptions
                user.pop('sub_cache', None)
                return dict(user['allocations'])

        raise HTTPException(status_code=404, detail="User not found")

    allocations = update_config(update_allocations)
    return {"status": "success", "allocations": allocations}


@router.put("/{user_id}/group-config")
@handle_api_errors
def update_user_group_config(user_id: str, data: UpdateUserGroupConfig, _: bool = Depends(verify_session)):
    """Update user's group configuration"""
    def update_group_config(config: dict) -> dict:
        for user in config.get('users', []):
            if user['id'] == user_id:
                user['group_config'] = data.group_config
                user.pop('sub_cache', None)
                return dict(user['group_config'])

        raise HTTPException(status_code=404, detail="User not found")

    group_config = update_config(update_group_config)
    return {"status": "success", "group_config": group_config}
