"""
Backup service module
Handles config backup, restore, and cleanup
"""
import os
import json
import shutil
import base64
import tempfile
from copy import deepcopy
from pathlib import Path
from datetime import datetime as dt
from typing import Optional, List

from filelock import FileLock, Timeout

from core.config import AppConfig, CONFIG_FILE, BACKUP_DIR
from core.database import load_config, invalidate_config_cache
from logger_config import get_logger
from services.configuration_validation import (
    remove_legacy_stale_references,
    validate_configuration_node_references,
    validate_and_normalize_configuration,
)

logger = get_logger(__name__)

_MIGRATION_ROOTS = ("uploads",)
_MIGRATION_FILES = ("node_region_history.json", "geoip_cache.json", "myconfig.yaml")


def _apply_geoip_runtime_config(config: dict) -> None:
    from geoip_service import apply_geoip_runtime_config

    apply_geoip_runtime_config(config)


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


def _data_root() -> Path:
    return Path(CONFIG_FILE).resolve().parent


def _iter_migration_files() -> list[Path]:
    root = _data_root()
    files: list[Path] = []
    for relative_name in _MIGRATION_FILES:
        candidate = root / relative_name
        if candidate.is_file():
            files.append(candidate)
    for relative_root in _MIGRATION_ROOTS:
        directory = root / relative_root
        if not directory.is_dir():
            continue
        files.extend(path for path in directory.rglob('*') if path.is_file())
    return files


def _backup_sidecar_path(backup_path: str | Path) -> Path:
    return Path(f"{backup_path}.files")


def _snapshot_migration_files(backup_path: str) -> None:
    sidecar = _backup_sidecar_path(backup_path)
    temporary = Path(f"{sidecar}.tmp")
    if temporary.is_dir():
        shutil.rmtree(temporary)
    elif temporary.exists():
        temporary.unlink()
    temporary.mkdir(parents=True, exist_ok=True)
    root = _data_root()
    for source in _iter_migration_files():
        relative = source.relative_to(root)
        target = temporary / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    if sidecar.exists():
        shutil.rmtree(sidecar)
    os.replace(temporary, sidecar)


def _restore_migration_files(sidecar: Path) -> None:
    if not sidecar.is_dir():
        return
    root = _data_root()
    restore_items: list[tuple[Path, Path]] = []
    allowed_prefixes = tuple(Path(name) for name in _MIGRATION_ROOTS)
    allowed_files = set(_MIGRATION_FILES)
    for source in sidecar.rglob('*'):
        if not source.is_file():
            continue
        relative = source.relative_to(sidecar)
        relative_text = relative.as_posix()
        if relative_text not in allowed_files and not any(
            relative == prefix or prefix in relative.parents for prefix in allowed_prefixes
        ):
            raise ValueError("Backup contains an unsupported migration file")
        target = root / relative
        restore_items.append((source, target))

    _clear_migration_targets()
    for source, target in restore_items:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(f"{target}.restore.tmp")
        shutil.copy2(source, temporary)
        os.replace(temporary, target)


def _clear_migration_targets() -> None:
    """Remove only files owned by the migration boundary before replacement."""
    root = _data_root()
    for relative_name in _MIGRATION_FILES:
        target = root / relative_name
        if target.is_file() or target.is_symlink():
            target.unlink()
    uploads = root / "uploads"
    if uploads.is_dir():
        for child in uploads.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        uploads.mkdir(parents=True, exist_ok=True)


def _export_migration_files() -> dict[str, str]:
    root = _data_root()
    exported: dict[str, str] = {}
    for source in _iter_migration_files():
        relative = source.relative_to(root).as_posix()
        exported[relative] = base64.b64encode(source.read_bytes()).decode('ascii')
    return exported


def _decode_migration_files(files: object) -> dict[str, bytes]:
    if files is None:
        return {}
    if not isinstance(files, dict):
        raise ValueError("Imported migration files must be an object")
    decoded: dict[str, bytes] = {}
    allowed_prefixes = tuple(Path(name) for name in _MIGRATION_ROOTS)
    allowed_files = set(_MIGRATION_FILES)
    for relative_text, encoded in files.items():
        if not isinstance(relative_text, str) or not isinstance(encoded, str):
            raise ValueError("Imported migration file entry is invalid")
        relative = Path(relative_text)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError("Imported migration file path is invalid")
        if relative_text not in allowed_files and not any(
            relative == prefix or prefix in relative.parents for prefix in allowed_prefixes
        ):
            raise ValueError("Imported migration file path is unsupported")
        try:
            decoded[relative_text] = base64.b64decode(encoded.encode('ascii'), validate=True)
        except (ValueError, UnicodeEncodeError):
            raise ValueError("Imported migration file content is invalid") from None
    return decoded


def _restore_encoded_files(files: dict[str, bytes]) -> list[Path]:
    root = _data_root()
    restored: list[Path] = []
    for relative_text, content in files.items():
        target = root / Path(relative_text)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(f"{target}.restore.tmp")
        temporary.write_bytes(content)
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, target)
        restored.append(target)
    return restored


def _merge_encoded_files(files: dict[str, bytes], added_subscription_ids: set[str]) -> list[Path]:
    """Restore only files belonging to newly imported objects during merge.

    Existing uploads, generated output and GeoIP/cache files belong to the
    destination instance and must never be silently replaced by a merge import.
    """
    root = _data_root()
    selected: dict[str, bytes] = {}
    for relative_text, content in files.items():
        relative = Path(relative_text)
        if relative.parts and relative.parts[0] == "uploads":
            if len(relative.parts) != 2 or relative.suffix != ".yaml":
                continue
            if relative.stem in added_subscription_ids:
                selected[relative_text] = content
            continue

        # Root migration files are copied only when the destination does not
        # have one yet. This preserves the active instance's output and caches.
        if relative_text in _MIGRATION_FILES and not (root / relative).exists():
            selected[relative_text] = content

    return _restore_encoded_files(selected)


def _create_backup_locked(reason: str = 'manual') -> Optional[str]:
    """Create a backup while the caller holds the config file lock."""
    if not os.path.exists(CONFIG_FILE):
        return None

    backup_filename = _backup_filename(reason)
    backup_path = Path(BACKUP_DIR) / backup_filename
    os.makedirs(BACKUP_DIR, exist_ok=True)
    # Write to a hidden same-directory temporary file first. A backup must
    # never become visible to list/restore while config.json is only partially
    # copied (especially on network filesystems).
    temporary_fd, temporary_name = tempfile.mkstemp(
        prefix=f".{backup_filename}.",
        suffix='.tmp',
        dir=BACKUP_DIR,
    )
    os.close(temporary_fd)
    temporary = Path(temporary_name)
    try:
        shutil.copyfile(CONFIG_FILE, temporary)
        os.replace(temporary, backup_path)
        _snapshot_migration_files(str(backup_path))
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)
    try:
        os.chmod(backup_path, 0o600)
    except OSError:
        logger.warning("Could not restrict backup file permissions")
    logger.info(f"Backup created: {backup_filename}")
    return backup_filename


def _atomic_restore_config_locked(config_data: dict):
    """Atomically replace config.json while the caller holds the config lock."""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    tmp_file = f"{CONFIG_FILE}.restore.tmp"
    try:
        with open(tmp_file, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp_file, 0o600)
        except OSError:
            logger.warning("Could not restrict restored configuration permissions")

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
                sidecar = _backup_sidecar_path(os.path.join(BACKUP_DIR, old_backup))
                if sidecar.exists():
                    shutil.rmtree(sidecar)
                logger.info(f"Deleted old backup: {old_backup}")
            except Exception as e:
                logger.error(f"Failed to delete old backup {old_backup}: {e}")
    except Exception as e:
        logger.error(f"Failed to cleanup backups: {e}")


def list_backups() -> List[dict]:
    """List all available backups"""
    backups = []
    
    try:
        with _config_file_lock():
            filenames = list(os.listdir(BACKUP_DIR))
        for f in filenames:
            if f.startswith('config_') and f.endswith('.json'):
                filepath = os.path.join(BACKUP_DIR, f)
                stat = os.stat(filepath)
                backups.append({
                    'filename': f,
                    'size': stat.st_size,
                    'created_at': int(stat.st_mtime),
                    'complete': _backup_sidecar_path(filepath).is_dir(),
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
    remove_legacy_stale_references(backup_config)
    backup_config = validate_and_normalize_configuration(backup_config)
    backup_config.setdefault('auth', {}).pop('sessions', None)
    
    try:
        with _config_file_lock():
            # Create backup before restore under the same lock used for the
            # atomic replacement, so concurrent readers/writers never observe a
            # partially copied config file.
            _create_backup_locked('pre_restore')
            _atomic_restore_config_locked(backup_config)
            sidecar = _backup_sidecar_path(backup_path)
            if sidecar.is_dir():
                _restore_migration_files(sidecar)
    except Timeout:
        raise TimeoutError("Configuration is being updated, please try again")

    _apply_geoip_runtime_config(backup_config)
    logger.info(f"Config restored from backup: {filename}")
    return True


def delete_backup(filename: str) -> bool:
    """Delete a backup file"""
    backup_path = _resolve_backup_path(filename)
    
    if not backup_path.exists():
        raise FileNotFoundError(f"Backup not found: {filename}")
    
    with _config_file_lock():
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {filename}")
        os.remove(backup_path)
        sidecar = _backup_sidecar_path(backup_path)
        if sidecar.exists():
            shutil.rmtree(sidecar)
    logger.info(f"Backup deleted: {filename}")
    return True


def export_config() -> dict:
    """Export full configuration for migration"""
    import time
    config = deepcopy(load_config())
    # Login sessions are runtime credentials, not migration data. Password
    # hashes and subscription tokens remain because this is a full migration.
    config.setdefault('auth', {}).pop('sessions', None)
    # Radar tokens are administrator API credentials. They can be supplied
    # again through the destination instance's settings or environment and
    # must never be included in a downloadable migration file.
    geoip_config = config.get('geoip_config')
    if isinstance(geoip_config, dict):
        geoip_config.pop('cloudflare_radar_token', None)
    translation_config = config.get('translation_config')
    if isinstance(translation_config, dict):
        providers = translation_config.get('providers')
        if isinstance(providers, dict):
            sensitive_provider_fields = {
                'api_key', 'secret_key', 'secret_id',
            }
            for provider_record in providers.values():
                if isinstance(provider_record, dict):
                    for field_name in sensitive_provider_fields:
                        provider_record.pop(field_name, None)
    remove_legacy_stale_references(config)
    
    return {
        'version': AppConfig.VERSION,
        'exported_at': int(time.time()),
        'config': config,
        'files': _export_migration_files(),
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
    if not isinstance(new_config, dict):
        raise ValueError("Invalid import data: config must be an object")
    new_config = validate_and_normalize_configuration(new_config)
    migration_files = _decode_migration_files(import_data.get('files'))
    files_field_present = 'files' in import_data

    try:
        with _config_file_lock():
            _create_backup_locked('pre_import')
            rollback_config: dict | None = None
            if merge:
                if os.path.exists(CONFIG_FILE):
                    with open(CONFIG_FILE, 'r', encoding='utf-8') as config_file:
                        merged_config = json.load(config_file)
                    if not isinstance(merged_config, dict):
                        raise ValueError("Existing configuration is invalid")
                else:
                    merged_config = {}
                rollback_config = deepcopy(merged_config)
                remove_legacy_stale_references(merged_config)

                # Merge by persisted IDs first.  The old implementation used
                # URL/name-only keys, which skipped local subscriptions and
                # silently left related references behind.  A conflicting ID
                # is deliberately kept as the destination object: changing an
                # ID would require rewriting every allocation/chain reference.
                merge_specs = (
                    'subscriptions',
                    'custom_nodes',
                    'users',
                    'templates',
                    'admin_tokens',
                    'proxy_chains',
                )
                added_subscription_ids: set[str] = set()
                for collection_name in merge_specs:
                    destination = merged_config.setdefault(collection_name, [])
                    if not isinstance(destination, list):
                        raise ValueError(f"Existing {collection_name} configuration is invalid")
                    known_ids = {
                        str(item.get('id'))
                        for item in destination
                        if isinstance(item, dict) and item.get('id')
                    }
                    known_tokens = {
                        str(item.get('token'))
                        for item in destination
                        if isinstance(item, dict) and item.get('token')
                    }
                    incoming = new_config.get(collection_name, [])
                    if not isinstance(incoming, list):
                        raise ValueError(f"Imported {collection_name} must be a list")
                    for item in incoming:
                        if not isinstance(item, dict):
                            raise ValueError(f"Imported {collection_name} contains an invalid item")
                        item_id = str(item.get('id') or '')
                        item_token = str(item.get('token') or '')
                        if item_id and item_id in known_ids:
                            continue
                        if item_token and item_token in known_tokens:
                            continue
                        destination.append(deepcopy(item))
                        if collection_name == 'subscriptions' and item_id:
                            added_subscription_ids.add(item_id)
                        if item_id:
                            known_ids.add(item_id)
                        if item_token:
                            known_tokens.add(item_token)

                # Preserve imported non-collection settings without replacing
                # operator-specific runtime values.  Mapping keys are stable
                # node/chain references, so a shallow union is safe here.
                for key in ('settings', 'geoip_config', 'translation_config', 'port_mappings', 'speedtest_profiles'):
                    incoming_value = new_config.get(key)
                    if incoming_value is None:
                        continue
                    if key in ('settings', 'geoip_config', 'translation_config'):
                        existing_value = merged_config.setdefault(key, {})
                        if not isinstance(existing_value, dict) or not isinstance(incoming_value, dict):
                            raise ValueError(f"Imported {key} configuration is invalid")
                        for setting_key, setting_value in incoming_value.items():
                            existing_value.setdefault(setting_key, deepcopy(setting_value))
                    elif key == 'port_mappings':
                        existing_value = merged_config.setdefault(key, {})
                        if not isinstance(existing_value, dict) or not isinstance(incoming_value, dict):
                            raise ValueError("Imported port mappings are invalid")
                        for reference, port in incoming_value.items():
                            existing_value.setdefault(reference, port)
                    else:
                        existing_value = merged_config.setdefault(key, [])
                        if not isinstance(existing_value, list) or not isinstance(incoming_value, list):
                            raise ValueError("Imported speedtest profiles are invalid")
                        known_profile_ids = {
                            str(item.get('id')) for item in existing_value
                            if isinstance(item, dict) and item.get('id')
                        }
                        for item in incoming_value:
                            if isinstance(item, dict) and str(item.get('id') or '') not in known_profile_ids:
                                existing_value.append(deepcopy(item))
                                if item.get('id'):
                                    known_profile_ids.add(str(item['id']))

                incoming_order = new_config.get('source_order', [])
                merged_order = merged_config.setdefault('source_order', [])
                if isinstance(incoming_order, list) and isinstance(merged_order, list):
                    for source_id in incoming_order:
                        if source_id not in merged_order:
                            merged_order.append(source_id)
                final_config = validate_and_normalize_configuration(merged_config)
                if files_field_present:
                    missing_subscription_files = {
                        subscription_id
                        for subscription_id in added_subscription_ids
                        if next(
                            (
                                subscription.get('enabled', True)
                                for subscription in final_config.get('subscriptions', [])
                                if subscription.get('id') == subscription_id
                            ),
                            True,
                        )
                        if not (Path(_data_root()) / 'uploads' / f'{subscription_id}.yaml').exists()
                        and f'uploads/{subscription_id}.yaml' not in migration_files
                    }
                    if missing_subscription_files:
                        raise ValueError(
                            'Merge import is missing subscription files: '
                            + ', '.join(sorted(missing_subscription_files))
                        )
                mode = 'merge'
            else:
                if os.path.exists(CONFIG_FILE):
                    with open(CONFIG_FILE, 'r', encoding='utf-8') as config_file:
                        rollback_config = json.load(config_file)
                else:
                    rollback_config = {}
                final_config = new_config
                final_config.setdefault('auth', {}).pop('sessions', None)
                mode = 'replace'

            previous_migration_files = _export_migration_files()
            restored_merge_files: list[Path] = []
            if migration_files and mode == 'merge':
                restored_merge_files = _merge_encoded_files(migration_files, added_subscription_ids)
            elif mode == 'replace':
                _clear_migration_targets()
                if migration_files:
                    _restore_encoded_files(migration_files)
            try:
                _atomic_restore_config_locked(final_config)
                if files_field_present:
                    validate_configuration_node_references(
                        final_config,
                        str(_data_root() / 'uploads'),
                    )
            except BaseException:
                for restored_path in restored_merge_files:
                    try:
                        restored_path.unlink(missing_ok=True)
                    except OSError:
                        logger.error("Failed to remove staged merge file %s", restored_path, exc_info=True)
                if rollback_config is not None:
                    _atomic_restore_config_locked(rollback_config)
                if mode == 'replace' and files_field_present:
                    _clear_migration_targets()
                    _restore_encoded_files(previous_migration_files)
                raise
    except Timeout:
        raise TimeoutError("Configuration is being updated, please try again")

    _apply_geoip_runtime_config(final_config)
    logger.info("Config %sd from import", 'merge' if mode == 'merge' else 'replace')
    return mode


def restore_config_snapshot(config_snapshot: dict) -> None:
    """Restore a trusted in-memory snapshot after a runtime reload failure."""
    if not isinstance(config_snapshot, dict):
        raise ValueError("Configuration snapshot must be an object")
    try:
        with _config_file_lock():
            _atomic_restore_config_locked(deepcopy(config_snapshot))
    except Timeout as exc:
        raise TimeoutError("Configuration is being updated, please try again") from exc
    _apply_geoip_runtime_config(config_snapshot)
