"""
Configuration database module
Handles loading, saving, and caching of config.json
"""
import json
import os
import time
from typing import Optional
from filelock import FileLock, Timeout
from fastapi import HTTPException

from logger_config import get_logger
from .config import AppConfig, CONFIG_FILE

logger = get_logger(__name__)

# Config cache for performance
_config_cache: Optional[dict] = None
_config_mtime: Optional[float] = None


def get_default_config() -> dict:
    """Get default configuration structure"""
    return {
        'auth': {},
        'subscriptions': [],
        'custom_nodes': [],
        'source_order': [],
        'users': [],
        'templates': [],
        'admin_tokens': [],
        'proxy_chains': [],
    }


def load_config() -> dict:
    """Load unified config with caching"""
    global _config_cache, _config_mtime
    
    default = get_default_config()
    
    if not os.path.exists(CONFIG_FILE):
        logger.debug("Config file not found: %s, using default config", CONFIG_FILE)
        return default
    
    try:
        current_mtime = os.path.getmtime(CONFIG_FILE)
        
        if _config_cache is not None and _config_mtime == current_mtime:
            return _config_cache.copy()
        
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        for key in default:
            if key not in config:
                config[key] = default[key]
        
        _config_cache = config
        _config_mtime = current_mtime
        
        logger.debug("Config loaded successfully from %s", CONFIG_FILE)
        return config.copy()
    except json.JSONDecodeError as e:
        logger.error("Config file is corrupted (invalid JSON): %s, error: %s", CONFIG_FILE, e)
        backup_file = f"{CONFIG_FILE}.corrupted.{int(time.time())}"
        try:
            import shutil
            shutil.copy(CONFIG_FILE, backup_file)
            logger.info("Corrupted config backed up to: %s", backup_file)
        except Exception as backup_error:
            logger.error("Failed to backup corrupted config: %s", backup_error)
        return default
    except Exception as e:
        logger.error("Unexpected error loading config: %s", e, exc_info=True)
        return default


def save_config(config: dict):
    """Save unified config with file locking"""
    global _config_cache, _config_mtime
    
    lock_file = f"{CONFIG_FILE}.lock"
    lock = FileLock(lock_file, timeout=AppConfig.FILE_LOCK_TIMEOUT)
    
    try:
        with lock:
            temp_file = f"{CONFIG_FILE}.tmp"
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            
            if os.path.exists(CONFIG_FILE):
                backup_file = f"{CONFIG_FILE}.backup"
                import shutil
                shutil.copy(CONFIG_FILE, backup_file)
            
            os.replace(temp_file, CONFIG_FILE)
            
            _config_cache = None
            _config_mtime = None
            
            logger.debug("Config saved successfully to %s", CONFIG_FILE)
    except Timeout:
        logger.error("Timeout waiting for config file lock")
        raise HTTPException(status_code=503, detail="Configuration is being updated, please try again")
    except Exception as e:
        logger.error("Failed to save config: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to save configuration: {str(e)}")


def invalidate_config_cache():
    """Invalidate config cache"""
    global _config_cache, _config_mtime
    _config_cache = None
    _config_mtime = None


# Helper functions for finding items
def find_subscription_by_id(config: dict, sub_id: str) -> Optional[dict]:
    """Fast subscription lookup by ID"""
    for s in config.get('subscriptions', []):
        if s['id'] == sub_id:
            return s
    return None


def find_custom_node_by_id(config: dict, node_id: str) -> Optional[dict]:
    """Fast custom node lookup by ID"""
    for node in config.get('custom_nodes', []):
        if node['id'] == node_id:
            return node
    return None


def find_user_by_id(config: dict, user_id: str) -> Optional[dict]:
    """Fast user lookup by ID"""
    for user in config.get('users', []):
        if user['id'] == user_id:
            return user
    return None


def find_template_by_id(config: dict, template_id: str) -> Optional[dict]:
    """Fast template lookup by ID"""
    for template in config.get('templates', []):
        if template['id'] == template_id:
            return template
    return None


def find_admin_token_by_id(config: dict, token_id: str) -> Optional[dict]:
    """Fast admin token lookup by ID"""
    for token in config.get('admin_tokens', []):
        if token['id'] == token_id:
            return token
    return None
