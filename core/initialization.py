"""Secure first-start initialization for the administrator account."""

import time

from core.config import AppConfig
from core.database import load_config, update_config
from core.security import hash_password, validate_password_policy
from core.token_utils import generate_unique_subscription_token
from helpers import generate_timestamp_id
from logger_config import get_logger


logger = get_logger(__name__)


def initialize_administrator() -> bool:
    """Initialize a fresh instance from the environment, or fail closed."""
    config = load_config()
    if config.get("auth", {}).get("password_hash"):
        return False

    initial_password = AppConfig.INITIAL_ADMIN_PASSWORD
    if not initial_password:
        raise RuntimeError(
            "Administrator password is not initialized. Set INITIAL_ADMIN_PASSWORD "
            "for the first successful startup."
        )
    validated_password = validate_password_policy(initial_password)

    def initialize(latest_config: dict) -> bool:
        auth = latest_config.setdefault("auth", {})
        if auth.get("password_hash"):
            return False

        auth["password_hash"] = hash_password(validated_password)
        auth["sessions"] = {}
        if not latest_config.get("admin_tokens"):
            latest_config.setdefault("admin_tokens", []).append({
                "id": generate_timestamp_id("adm_"),
                "name": "默认",
                "token": generate_unique_subscription_token(latest_config),
                "template_id": "builtin",
                "sub_filename": "",
                "sub_name": "",
                "enabled": True,
                "created_at": int(time.time()),
                "group_config": {},
            })
        return True

    initialized = update_config(initialize)
    if initialized:
        logger.info("Administrator account initialized from INITIAL_ADMIN_PASSWORD")
    return initialized
