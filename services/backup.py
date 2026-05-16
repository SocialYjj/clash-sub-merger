"""
Backup service module
Handles config backup, restore, and cleanup
"""
import os
import json
import shutil
from pathlib import Path
from datetime import datetime as dt
from typing import Optional, List

from filelock import FileLock, Timeout

from core.config import AppConfig, CONFIG_FILE, BACKUP_DIR
from core.database import load_config, save_config, invalidate_config_cache
from logger_config import get_logger

logger = get_logger(__name__)


def _config_file_lock() -> FileLock:
    """Return the same config lock used by core.database writes."""
    return FileLock(f"{CONFIG_FILE}.lock", timeout=AppConfig.FILE_LOCK_TIMEOUT)


def _resolve_backup_path(filename: str) -> Path:
    """Resolve a user-supplied backup filename inside BACKUP_DIR only."""
    if not filename or '/' in filename or '\\' in filename or filename in ('.', '..'):
        raise ValueError("Invalid backup filename")

    backup_dir = Path(BACKUP_DIR).resolve()
    raw_backup_path = backup_dir / filename
    if raw_backup_path.exists() and raw_backup_path.is_symlink():
        raise ValueError("Invalid backup file")

    backup_path = raw_backup_path.resolve()

    if backup_path.parent != backup_dir or backup_path.name != filename:
        raise ValueError("Invalid backup filename")
    if not backup_path.name.startswith('config_') or backup_path.suffix != '.json':
        raise ValueError("Invalid backup filename")

    return backup_path


def _backup_filename(reason: str) -> str:
    timestamp = dt.now().strftime('%Y%m%d_%H%M%S_%f')
    return f"config_{timestamp}_{reason}.json"


def _create_backup_locked(reason: str = 'manual') -> Optional[str]:
    """Create a backup while the caller holds the config file lock."""
    if not os.path.exists(CONFIG_FILE):
        return None

    backup_filename = _backup_filename(reason)
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    shutil.copy2(CONFIG_FILE, backup_path)
    logger.info(f"Backup created: {backup_filename}")
    return backup_filename


def _atomic_restore_config_locked(config_data: dict):
    """Atomically replace config.json while the caller holds the config lock."""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    tmp_file = f"{CONFIG_FILE}.restore.tmp"
    try:
        with open(tmp_file, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, ensure_ascii=False, indent=2)

        os.replace(tmp_file, CONFIG_FILE)
        invalidate_config_cache()
    finally:
        if os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                logger.debug("Failed to remove restore temp file: %s", tmp_file, exc_info=True)


def create_backup(reason: str = 'manual') -> Optional[str]:
    """
    Create a backup of config.json
    
    Args:
        reason: Reason for backup (manual, auto, pre_restore, pre_import)
    
    Returns:
        Backup filename or None if failed
    """
    try:
        with _config_file_lock():
            backup_filename = _create_backup_locked(reason)
        
        cleanup_old_backups()
        
        return backup_filename
    except Timeout:
        logger.error("Timeout waiting for config file lock while creating backup")
        return None
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        return None


def cleanup_old_backups():
    """Keep only the most recent backups"""
    try:
        backups = sorted(
            [f for f in os.listdir(BACKUP_DIR) if f.startswith('config_') and f.endswith('.json')],
            reverse=True
        )
        
        for old_backup in backups[AppConfig.AUTO_BACKUP_KEEP_COUNT:]:
            try:
                os.remove(os.path.join(BACKUP_DIR, old_backup))
                logger.info(f"Deleted old backup: {old_backup}")
            except Exception as e:
                logger.error(f"Failed to delete old backup {old_backup}: {e}")
    except Exception as e:
        logger.error(f"Failed to cleanup backups: {e}")


def list_backups() -> List[dict]:
    """List all available backups"""
    backups = []
    
    try:
        for f in os.listdir(BACKUP_DIR):
            if f.startswith('config_') and f.endswith('.json'):
                filepath = os.path.join(BACKUP_DIR, f)
                stat = os.stat(filepath)
                backups.append({
                    'filename': f,
                    'size': stat.st_size,
                    'created_at': int(stat.st_mtime)
                })
        
        backups.sort(key=lambda x: x['created_at'], reverse=True)
    except Exception as e:
        logger.error(f"Failed to list backups: {e}")
    
    return backups


def restore_backup(filename: str) -> bool:
    """
    Restore config from a backup
    
    Args:
        filename: Backup filename
    
    Returns:
        True if successful
    """
    backup_path = _resolve_backup_path(filename)
    
    if not backup_path.exists():
        raise FileNotFoundError(f"Backup not found: {filename}")
    
    # Validate and load backup file before taking the config write lock.
    try:
        with open(backup_path, 'r', encoding='utf-8') as f:
            backup_config = json.load(f)
    except json.JSONDecodeError:
        raise ValueError("Invalid backup file")
    if not isinstance(backup_config, dict):
        raise ValueError("Invalid backup file")
    
    try:
        with _config_file_lock():
            # Create backup before restore under the same lock used for the
            # atomic replacement, so concurrent readers/writers never observe a
            # partially copied config file.
            _create_backup_locked('pre_restore')
            _atomic_restore_config_locked(backup_config)
    except Timeout:
        raise TimeoutError("Configuration is being updated, please try again")
    
    logger.info(f"Config restored from backup: {filename}")
    return True


def delete_backup(filename: str) -> bool:
    """Delete a backup file"""
    backup_path = _resolve_backup_path(filename)
    
    if not backup_path.exists():
        raise FileNotFoundError(f"Backup not found: {filename}")
    
    os.remove(backup_path)
    logger.info(f"Backup deleted: {filename}")
    return True


def export_config() -> dict:
    """Export full configuration for migration"""
    import time
    config = load_config()
    
    return {
        'version': AppConfig.VERSION,
        'exported_at': int(time.time()),
        'config': config
    }


def import_config(import_data: dict, merge: bool = False) -> str:
    """
    Import configuration from export file
    
    Args:
        import_data: Exported data dict
        merge: If True, merge with existing; if False, replace
    
    Returns:
        'merge' or 'replace' indicating mode used
    """
    if 'config' not in import_data:
        raise ValueError("Invalid import data: missing 'config' field")
    
    new_config = import_data['config']
    
    # Create backup before import
    create_backup('pre_import')
    
    if merge:
        current_config = load_config()
        
        # Merge subscriptions
        existing_urls = {s['url'] for s in current_config.get('subscriptions', [])}
        for sub in new_config.get('subscriptions', []):
            if sub.get('url') and sub['url'] not in existing_urls:
                current_config.setdefault('subscriptions', []).append(sub)
        
        # Merge custom nodes
        existing_names = {n['name'] for n in current_config.get('custom_nodes', [])}
        for node in new_config.get('custom_nodes', []):
            if node.get('name') and node['name'] not in existing_names:
                current_config.setdefault('custom_nodes', []).append(node)
        
        # Merge users
        existing_user_names = {u['name'] for u in current_config.get('users', [])}
        for user in new_config.get('users', []):
            if user.get('name') and user['name'] not in existing_user_names:
                current_config.setdefault('users', []).append(user)
        
        # Merge templates
        existing_template_names = {t['name'] for t in current_config.get('templates', [])}
        for template in new_config.get('templates', []):
            if template.get('name') and template['name'] not in existing_template_names:
                current_config.setdefault('templates', []).append(template)
        
        save_config(current_config)
        logger.info("Config merged from import")
        return 'merge'
    else:
        save_config(new_config)
        logger.info("Config replaced from import")
        return 'replace'
