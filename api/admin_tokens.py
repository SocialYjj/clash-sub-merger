"""
Admin Tokens API
Admin token management endpoints
"""
import time
import secrets
from typing import Optional, Dict, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.dependencies import verify_session
from core.database import load_config, save_config
from helpers import handle_api_errors, generate_timestamp_id
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()


def generate_token() -> str:
    return secrets.token_urlsafe(24)


# ==================== Data Models ====================

class CreateAdminToken(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    template_id: str = "builtin"
    sub_filename: Optional[str] = ""
    sub_name: Optional[str] = ""


class UpdateAdminToken(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    template_id: Optional[str] = None
    sub_filename: Optional[str] = None
    sub_name: Optional[str] = None
    enabled: Optional[bool] = None


class UpdateAdminTokenGroupConfig(BaseModel):
    group_config: Dict[str, List[str]]


class RegenerateAdminTokenRequest(BaseModel):
    custom_token: Optional[str] = None


# ==================== API Endpoints ====================

@router.get("")
@handle_api_errors
def list_admin_tokens(_: bool = Depends(verify_session)):
    """List all admin tokens"""
    config = load_config()
    tokens = config.get('admin_tokens', [])
    # Mask tokens in list view
    return {"tokens": [{**t, 'token': t['token'][:8] + '...'} for t in tokens]}


@router.get("/{token_id}")
@handle_api_errors
def get_admin_token(token_id: str, _: bool = Depends(verify_session)):
    """Get admin token details"""
    config = load_config()
    for token in config.get('admin_tokens', []):
        if token['id'] == token_id:
            return {"token": token}
    raise HTTPException(status_code=404, detail="Token not found")


@router.post("")
@handle_api_errors
def create_admin_token(data: CreateAdminToken, _: bool = Depends(verify_session)):
    """Create a new admin token"""
    config = load_config()
    
    # Validate template exists
    if data.template_id != 'builtin':
        templates = config.get('templates', [])
        if not any(t['id'] == data.template_id for t in templates):
            raise HTTPException(status_code=400, detail="Template not found")
    
    token_id = generate_timestamp_id('tpl_')
    token = {
        'id': token_id,
        'name': data.name,
        'token': generate_token(),
        'template_id': data.template_id,
        'sub_filename': data.sub_filename,
        'sub_name': data.sub_name,
        'enabled': True,
        'created_at': int(time.time()),
        'group_config': {}
    }
    
    if 'admin_tokens' not in config:
        config['admin_tokens'] = []
    config['admin_tokens'].append(token)
    save_config(config)
    
    return {"status": "success", "token": token}


@router.put("/{token_id}")
@handle_api_errors
def update_admin_token(token_id: str, data: UpdateAdminToken, _: bool = Depends(verify_session)):
    """Update admin token"""
    config = load_config()
    
    for token in config.get('admin_tokens', []):
        if token['id'] == token_id:
            if data.name is not None:
                token['name'] = data.name
            if data.template_id is not None:
                if data.template_id != 'builtin':
                    templates = config.get('templates', [])
                    if not any(t['id'] == data.template_id for t in templates):
                        raise HTTPException(status_code=400, detail="Template not found")
                token['template_id'] = data.template_id
            if data.sub_filename is not None:
                token['sub_filename'] = data.sub_filename
            if data.sub_name is not None:
                token['sub_name'] = data.sub_name
            if data.enabled is not None:
                token['enabled'] = data.enabled
            save_config(config)
            return {"status": "success", "token": token}
    
    raise HTTPException(status_code=404, detail="Token not found")


@router.delete("/{token_id}")
@handle_api_errors
def delete_admin_token(token_id: str, _: bool = Depends(verify_session)):
    """Delete admin token"""
    config = load_config()
    tokens = config.get('admin_tokens', [])
    config['admin_tokens'] = [t for t in tokens if t['id'] != token_id]
    save_config(config)
    return {"status": "success"}


@router.post("/{token_id}/regenerate")
@handle_api_errors
def regenerate_admin_token(token_id: str, data: RegenerateAdminTokenRequest = None, _: bool = Depends(verify_session)):
    """Regenerate admin token value"""
    config = load_config()
    
    for token in config.get('admin_tokens', []):
        if token['id'] == token_id:
            if data and data.custom_token and len(data.custom_token.strip()) >= 8:
                token['token'] = data.custom_token.strip()
            else:
                token['token'] = generate_token()
            save_config(config)
            return {"status": "success", "token": token['token']}
    
    raise HTTPException(status_code=404, detail="Token not found")


@router.put("/{token_id}/group-config")
@handle_api_errors
def update_admin_token_group_config(token_id: str, data: UpdateAdminTokenGroupConfig, _: bool = Depends(verify_session)):
    """Update admin token's group configuration"""
    config = load_config()
    
    for token in config.get('admin_tokens', []):
        if token['id'] == token_id:
            token['group_config'] = data.group_config
            save_config(config)
            return {"status": "success", "group_config": token['group_config']}
    
    raise HTTPException(status_code=404, detail="Token not found")


@router.post("/{token_id}/reset-group-config")
@handle_api_errors
def reset_admin_token_group_config(token_id: str, _: bool = Depends(verify_session)):
    """Reset admin token's group configuration"""
    config = load_config()
    
    for token in config.get('admin_tokens', []):
        if token['id'] == token_id:
            token['group_config'] = {}
            save_config(config)
            return {"status": "success", "message": "Group config reset"}
    
    raise HTTPException(status_code=404, detail="Token not found")
