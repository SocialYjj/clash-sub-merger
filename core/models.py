"""
Pydantic Data Models
Shared data models for API validation
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl, RootModel, field_validator

from core.security import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, validate_password_policy

# ==================== Authentication Models ====================


class SetPassword(BaseModel):
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        return validate_password_policy(v)


class Login(BaseModel):
    password: str = Field(max_length=100)


# ==================== Subscription Models ====================


class AddSubscription(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: HttpUrl

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if "/" in v or "\\" in v or ".." in v:
            raise ValueError("Name contains invalid characters")
        return v.strip()


class AddLocalSubscription(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=10 * 1024 * 1024)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if "/" in v or "\\" in v or ".." in v:
            raise ValueError("Name contains invalid characters")
        return v.strip()


class UpdateSubscription(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    url: Optional[HttpUrl] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if v and ("/" in v or "\\" in v or ".." in v):
            raise ValueError("Name contains invalid characters")
        return v.strip() if v else v


class UpdateLocalSubscription(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    content: Optional[str] = Field(None, max_length=10 * 1024 * 1024)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if v and ("/" in v or "\\" in v or ".." in v):
            raise ValueError("Name contains invalid characters")
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

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if v and ("/" in v or "\\" in v or ".." in v):
            raise ValueError("Name contains invalid characters")
        return v


class UpdateNodeName(BaseModel):
    name: str = Field(min_length=1, max_length=200)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if "/" in v or "\\" in v or ".." in v:
            raise ValueError("Name contains invalid characters")
        return v


class NodePayload(RootModel[Dict[str, Any]]):
    """Free-form node configuration mapping (Clash proxy schema).

    Node payloads come from arbitrary subscription providers, so the shape is
    intentionally a pass-through ``dict``: there is no strict field schema that
    could reject previously-accepted payloads. The commonly required fields are
    exposed as typed accessors instead.
    """

    @property
    def name(self) -> str:
        return str(self.root.get("name") or "")

    @property
    def proxy_type(self) -> str:
        return str(self.root.get("type") or "")

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain-dict copy of the payload."""
        return dict(self.root)


class UpdateNodeFull(BaseModel):
    """Full node update payload.

    The validated route-level variants live in ``api/nodes.py``; this model
    keeps the shared contract: ``node`` must be a mapping, nothing stricter.
    """

    node: NodePayload

    @property
    def node_data(self) -> Dict[str, Any]:
        return self.node.to_dict()


class UpdateSubNode(BaseModel):
    name: str = Field(min_length=1, max_length=200)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if "/" in v or "\\" in v or ".." in v:
            raise ValueError("Name contains invalid characters")
        return v


class UpdateSubNodeFull(BaseModel):
    node: NodePayload

    @property
    def node_data(self) -> Dict[str, Any]:
        return self.node.to_dict()


# ==================== User Models ====================


class CreateUser(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    expire_time: Optional[int] = Field(0, ge=0)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if "/" in v or "\\" in v or ".." in v:
            raise ValueError("Name contains invalid characters")
        return v.strip()


class UpdateUser(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    expire_time: Optional[int] = Field(None, ge=0)
    enabled: Optional[bool] = None
    template_id: Optional[str] = None
    sub_name: Optional[str] = Field(None, max_length=100)
    sub_filename: Optional[str] = Field(None, max_length=100)

    @field_validator("name", "sub_name", "sub_filename")
    @classmethod
    def validate_names(cls, v):
        if v and ("/" in v or "\\" in v or ".." in v):
            raise ValueError("Name contains invalid characters")
        return v.strip() if v else v


class UserNodeAllocation(BaseModel):
    subscriptions: Dict[str, List[str]]


class UpdateUserGroupConfig(BaseModel):
    group_config: Dict[str, List[str]]


# ==================== Port Mapping Models ====================


class PortMappingCreate(BaseModel):
    final_name: str = Field(min_length=1, max_length=200)
    port: int = Field(ge=1024, le=65535)

    @field_validator("final_name")
    @classmethod
    def validate_name(cls, v):
        if "/" in v or "\\" in v or ".." in v:
            raise ValueError("Name contains invalid characters")
        return v


class PortMappingUpdate(BaseModel):
    port: int = Field(ge=1024, le=65535)
