"""
Backup service module
Handles config backup, restore, and cleanup
"""
import os
import json
import shutil
from datetime import datetime as dt
from typing import Optional, List

from core.config import AppConfig, CONFIG_FILE, BACKUP_DIR
from core.database import load_config, save_config, invalidate_config_cache
from logger_config import get_logger

logger = get_logger(__name__)


def create_backup(reason: str = 'manual') -> Optional[str]:
    """
    Create a backup of config.json
    
    Args:
        reason: Reason for backup (manual, auto, pre_restore, pre_import)
    
    Returns:
        Backup filename or None if failed
    """
    if not os.path.exists(CONFIG_FILE):
        return None
    
    timestamp = dt.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"config_{timestamp}_{reason}.json"
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    
    try:
        shutil.copy2(CONFIG_FILE, backup_path)
        logger.info(f"Backup created: {backup_filename}")
        
        cleanup_old_backups()
        
        return backup_filename
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
    backup_path = os.path.join(BACKUP_DIR, filename)
    
    if not os.path.exists(backup_path):
        raise FileNotFoundError(f"Backup not found: {filename}")
    
    # Validate backup file
    try:
        with open(backup_path, 'r', encoding='utf-8') as f:
            json.load(f)
    except json.JSONDecodeError:
        raise ValueError("Invalid backup file")
    
    # Create backup before restore
    create_backup('pre_restore')
    
    # Restore
    shutil.copy2(backup_path, CONFIG_FILE)
    invalidate_config_cache()
    
    logger.info(f"Config restored from backup: {filename}")
    return True


def delete_backup(filename: str) -> bool:
    """Delete a backup file"""
    backup_path = os.path.join(BACKUP_DIR, filename)
    
    if not os.path.exists(backup_path):
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
