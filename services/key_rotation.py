"""
API Key rotation reminder service
"""
import time
from typing import List

from core.config import AppConfig
from core.database import load_config
from logger_config import get_logger

logger = get_logger(__name__)


def check_key_rotation_needed() -> List[dict]:
    """
    Check which API keys need rotation
    
    Returns:
        List of keys needing rotation with details
    """
    config = load_config()
    now = int(time.time())
    rotation_threshold = AppConfig.KEY_ROTATION_DAYS * 24 * 60 * 60
    
    keys_needing_rotation = []
    
    # Check admin tokens
    for token in config.get('admin_tokens', []):
        created_at = token.get('created_at', 0)
        age_days = (now - created_at) // (24 * 60 * 60)
        
        if now - created_at > rotation_threshold:
            keys_needing_rotation.append({
                'type': 'admin_token',
                'id': token['id'],
                'name': token.get('name', 'Unknown'),
                'created_at': created_at,
                'age_days': age_days,
                'recommended_action': 'regenerate'
            })
    
    # Check user tokens
    for user in config.get('users', []):
        created_at = user.get('created_at', 0)
        age_days = (now - created_at) // (24 * 60 * 60)
        
        if now - created_at > rotation_threshold:
            keys_needing_rotation.append({
                'type': 'user_token',
                'id': user['id'],
                'name': user.get('name', 'Unknown'),
                'created_at': created_at,
                'age_days': age_days,
                'recommended_action': 'regenerate'
            })
    
    return keys_needing_rotation


def log_rotation_reminder():
    """Log reminder for keys needing rotation"""
    keys = check_key_rotation_needed()
    if keys:
        logger.warning(f"API key rotation reminder: {len(keys)} keys are older than {AppConfig.KEY_ROTATION_DAYS} days")
        for key in keys:
            logger.warning(f"  - {key['type']}: {key['name']} (age: {key['age_days']} days)")
