"""
Admin Tokens API
Admin token management endpoints
"""
import time
from typing import Optional, Dict, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.dependencies import verify_session
from core.database import load_config, update_config
from core.token_utils import (
    ensure_subscription_token_unique,
    generate_unique_subscription_token,
    normalize_custom_subscription_token,
)
from helpers import handle_api_errors, generate_timestamp_id
from logger_config import get_logger
from services.group_config_builder import build_group_config_view, render_group_config_preview
from services.user_configuration_validation import (
    MAX_EDITABLE_GROUPS,
    MAX_GROUP_NODES,
    MAX_REFERENCE_LENGTH,
    normalize_group_config,
)

logger = get_logger(__name__)
router = APIRouter()


# ==================== Data Models ====================

class CreateAdminToken(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    template_id: str = "builtin"
    custom_token: Optional[str] = None
    sub_filename: Optional[str] = ""
    sub_name: Optional[str] = ""

    @field_validator('name')
    @classmethod
    def normalize_name(cls, value):
        normalized = value.strip()
        if not normalized:
            raise ValueError('Name cannot be empty')
        return normalized

    @field_validator('sub_filename', 'sub_name')
    @classmethod
    def normalize_optional_names(cls, value):
        if value is None:
            return value
        normalized = value.strip()
        if '/' in normalized or '\\' in normalized or '..' in normalized:
            raise ValueError('Name contains invalid characters')
        return normalized


class UpdateAdminToken(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    template_id: Optional[str] = None
    sub_filename: Optional[str] = None
    sub_name: Optional[str] = None
    enabled: Optional[bool] = None

    @field_validator('name')
    @classmethod
    def normalize_name(cls, value):
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError('Name cannot be empty')
        return normalized

    @field_validator('sub_filename', 'sub_name')
    @classmethod
    def normalize_optional_names(cls, value):
        if value is None:
            return None
        normalized = value.strip()
        if '/' in normalized or '\\' in normalized or '..' in normalized:
            raise ValueError('Name contains invalid characters')
        return normalized


class UpdateAdminTokenGroupConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')

    group_config: Dict[str, List[str]] = Field(max_length=MAX_EDITABLE_GROUPS)

    @field_validator('group_config')
    @classmethod
    def validate_group_config_shape(cls, group_config):
        for group_name, references in group_config.items():
            if not isinstance(group_name, str) or not group_name.strip() or len(group_name) > 200:
                raise ValueError('Invalid proxy group name')
            if len(references) > MAX_GROUP_NODES:
                raise ValueError('Too many nodes in proxy group')
            if any(not isinstance(reference, str) or len(reference) > MAX_REFERENCE_LENGTH for reference in references):
                raise ValueError('Invalid proxy group reference')
        return group_config


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


def _get_admin_token_group_view(token_id: str) -> dict:
    config = load_config()
    admin_token = next(
        (candidate for candidate in config.get('admin_tokens', []) if candidate['id'] == token_id),
        None,
    )
    if not admin_token:
        raise HTTPException(status_code=404, detail="Token not found")

    from api.templates import get_builtin_template

    return build_group_config_view(
        config,
        admin_token,
        allocations=None,
        builtin_template=get_builtin_template(),
    )


@router.get("/{token_id}/group-config")
@handle_api_errors
def get_admin_token_group_config(token_id: str, _: bool = Depends(verify_session)):
    """Get the visual proxy-group configuration for an admin token."""
    return _get_admin_token_group_view(token_id)


@router.get("/{token_id}/preview-yaml")
@handle_api_errors
def preview_admin_token_group_config(token_id: str, _: bool = Depends(verify_session)):
    """Render the admin token's visual proxy-group configuration as YAML."""
    return {"yaml": render_group_config_preview(_get_admin_token_group_view(token_id))}


@router.post("")
@handle_api_errors
def create_admin_token(data: CreateAdminToken, _: bool = Depends(verify_session)):
    """Create a new admin token"""
    def add_admin_token(config: dict) -> dict:
        # Validate template exists against the latest config while holding lock.
        if data.template_id != 'builtin':
            templates = config.get('templates', [])
            if not any(t['id'] == data.template_id for t in templates):
                raise HTTPException(status_code=400, detail="Template not found")

        token_value = normalize_custom_subscription_token(data.custom_token)
        if token_value:
            ensure_subscription_token_unique(config, token_value)
        else:
            token_value = generate_unique_subscription_token(config)

        token_id = generate_timestamp_id('adm_')
        token = {
            'id': token_id,
            'name': data.name,
            'token': token_value,
            'template_id': data.template_id,
            'sub_filename': data.sub_filename,
            'sub_name': data.sub_name,
            'enabled': True,
            'created_at': int(time.time()),
            'group_config': {}
        }
        config.setdefault('admin_tokens', []).append(token)
        return dict(token)

    token = update_config(add_admin_token)
    
    return {"status": "success", "token": token}


@router.put("/{token_id}")
@handle_api_errors
def update_admin_token(token_id: str, data: UpdateAdminToken, _: bool = Depends(verify_session)):
    """Update admin token"""
    def apply_token_update(config: dict) -> dict:
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
                return dict(token)

        raise HTTPException(status_code=404, detail="Token not found")

    token = update_config(apply_token_update)
    return {"status": "success", "token": token}


@router.delete("/{token_id}")
@handle_api_errors
def delete_admin_token(token_id: str, _: bool = Depends(verify_session)):
    """Delete admin token"""
    def remove_admin_token(config: dict):
        tokens = config.get('admin_tokens', [])
        config['admin_tokens'] = [t for t in tokens if t['id'] != token_id]

    update_config(remove_admin_token)
    return {"status": "success"}


@router.post("/{token_id}/regenerate")
@handle_api_errors
def regenerate_admin_token(token_id: str, data: RegenerateAdminTokenRequest = None, _: bool = Depends(verify_session)):
    """Regenerate admin token value"""
    def regenerate_token(config: dict) -> str:
        for token in config.get('admin_tokens', []):
            if token['id'] == token_id:
                custom_token = normalize_custom_subscription_token(data.custom_token if data else None)
                if custom_token:
                    token['token'] = ensure_subscription_token_unique(
                        config,
                        custom_token,
                        exclude_admin_id=token_id,
                    )
                else:
                    token['token'] = generate_unique_subscription_token(
                        config,
                        exclude_admin_id=token_id,
                    )
                return token['token']

        raise HTTPException(status_code=404, detail="Token not found")

    token = update_config(regenerate_token)
    return {"status": "success", "token": token}


@router.put("/{token_id}/group-config")
@handle_api_errors
def update_admin_token_group_config(token_id: str, data: UpdateAdminTokenGroupConfig, _: bool = Depends(verify_session)):
    """Update admin token's group configuration"""
    def update_group_config(config: dict) -> dict:
        for token in config.get('admin_tokens', []):
            if token['id'] == token_id:
                from api.templates import get_builtin_template

                token['group_config'] = normalize_group_config(
                    config,
                    token,
                    data.group_config,
                    allocations=None,
                    builtin_template=get_builtin_template(),
                )
                return dict(token['group_config'])

        raise HTTPException(status_code=404, detail="Token not found")

    group_config = update_config(update_group_config)
    return {"status": "success", "group_config": group_config}


@router.post("/{token_id}/reset-group-config")
@handle_api_errors
def reset_admin_token_group_config(token_id: str, _: bool = Depends(verify_session)):
    """Reset admin token's group configuration"""
    def reset_group_config(config: dict):
        for token in config.get('admin_tokens', []):
            if token['id'] == token_id:
                token['group_config'] = {}
                return

        raise HTTPException(status_code=404, detail="Token not found")

    update_config(reset_group_config)
    return {"status": "success", "message": "Group config reset"}
