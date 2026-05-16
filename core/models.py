"""
Pydantic Data Models
Shared data models for API validation
"""
from typing import Optional, Dict, List
from pydantic import BaseModel, HttpUrl, Field, field_validator
from core.security import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, validate_password_policy


# ==================== Authentication Models ====================

class SetPassword(BaseModel):
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        return validate_password_policy(v)


class Login(BaseModel):
    password: str = Field(max_length=100)


# ==================== Subscription Models ====================

class AddSubscription(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: HttpUrl
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError('Name contains invalid characters')
        return v.strip()


class AddLocalSubscription(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=10*1024*1024)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError('Name contains invalid characters')
        return v.strip()


class UpdateSubscription(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    url: Optional[HttpUrl] = None
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v and ('/' in v or '\\' in v or '..' in v):
            raise ValueError('Name contains invalid characters')
        return v.strip() if v else v


class UpdateLocalSubscription(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    content: Optional[str] = Field(None, max_length=10*1024*1024)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v and ('/' in v or '\\' in v or '..' in v):
            raise ValueError('Name contains invalid characters')
        return v.strip() if v else v


class ReorderSubscriptions(BaseModel):
    order: List[str]


# ==================== Template Models ====================

class TemplateContent(BaseModel):
    content: str
    file_aliases: Optional[Dict[str, str]] = None


class FinalContent(BaseModel):
    content: str
    save_path: Optional[str] = None


# ==================== Node Models ====================

class CustomNode(BaseModel):
    link: str = Field(min_length=1, max_length=2000)
    name: Optional[str] = Field(None, max_length=200)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v and ('/' in v or '\\' in v or '..' in v):
            raise ValueError('Name contains invalid characters')
        return v


class UpdateNodeName(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError('Name contains invalid characters')
        return v


class UpdateNodeFull(BaseModel):
    node: dict


class UpdateSubNode(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError('Name contains invalid characters')
        return v


class UpdateSubNodeFull(BaseModel):
    node: dict


# ==================== User Models ====================

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


# ==================== Port Mapping Models ====================

class PortMappingCreate(BaseModel):
    final_name: str = Field(min_length=1, max_length=200)
    port: int = Field(ge=1024, le=65535)
    
    @field_validator('final_name')
    @classmethod
    def validate_name(cls, v):
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError('Name contains invalid characters')
        return v


class PortMappingUpdate(BaseModel):
    port: int = Field(ge=1024, le=65535)
