"""Token resolution for the subscription output endpoint.

Phase (a) of the ``/sub`` pipeline: map the request token onto the user or
admin-token subject that drives allocations, templates and profile naming.
"""

from dataclasses import dataclass
from typing import Optional

from fastapi import HTTPException

from core.dependencies import verify_admin_or_user_token


@dataclass
class AuthContext:
    """Resolved token/auth subject for a subscription request."""

    user_info: Optional[dict] = None
    user_allocations: Optional[dict] = None
    admin_token_info: Optional[dict] = None
    template_id: str = "builtin"

    @property
    def group_config_subject(self) -> Optional[dict]:
        """Subject whose saved ``group_config`` applies to this request."""
        return self.user_info or self.admin_token_info


def resolve_auth(token: Optional[str], config: dict) -> AuthContext:
    """Resolve the request token into a user/admin subject and template id."""
    user_info = None
    user_allocations = None
    template_id = "builtin"  # Default template
    admin_token_info = None  # Store matched admin token for its settings

    token_result = verify_admin_or_user_token(token, config=config)
    if token_result.get("type") == "admin":
        if token_result.get("legacy"):
            # Legacy admin uses current saved template (if any)
            if "template" in config:
                template_id = "legacy"  # Special marker for legacy template
        else:
            admin_token_info = token_result.get("token_info") or {}
            template_id = admin_token_info.get("template_id", "builtin")
    elif token_result.get("type") == "user":
        user_info = token_result.get("user_info") or {}
        user_allocations = user_info.get("allocations", {})
        template_id = user_info.get("template_id", "builtin")
    else:
        raise HTTPException(status_code=401, detail="Invalid subscription token") from None

    return AuthContext(
        user_info=user_info,
        user_allocations=user_allocations,
        admin_token_info=admin_token_info,
        template_id=template_id,
    )


def resolve_sub_name(*, auth: dict, user_info: Optional[dict], admin_token_info: Optional[dict]) -> str:
    """Resolve the profile title (user's sub_name > admin token's > global)."""
    if user_info:
        # User subscription - use user's sub_name if set
        if user_info.get("sub_name"):
            return f"{user_info['sub_name']} - {user_info['name']}"
        # Fallback to global sub_name
        return f"{auth.get('sub_name', 'Aggregated')} - {user_info['name']}"
    # Admin token subscription - use admin token's sub_name or global sub_name
    if admin_token_info and admin_token_info.get("sub_name"):
        return admin_token_info["sub_name"]
    return auth.get("sub_name", "Aggregated")
