"""Migrate legacy data files into the configured database backend.

The command is intentionally explicit: source files are deleted only after
every logical file has been written and read back successfully.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import storage
from core.config import DATA_DIR


ROOT_JSON_CACHES = {
    "geoip_cache.json": "geoip",
    "cloudflare_radar_cache.json": "radar",
    "node_region_history.json": "region_history",
}
ROOT_LEGACY_FILES = (
    "config.json.backup",
    "migrations.log",
    ".flclash_version_cache",
)


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _write_and_verify(logical_path: str, content: str) -> None:
    storage.write_stored_file(logical_path, content)
    stored = storage.read_stored_file(logical_path, default=None)
    if stored is None or _digest(stored) != _digest(content):
        raise RuntimeError(f"Stored file verification failed: {logical_path}")


def _legacy_config_matches_database(legacy_value: object, database_value: object) -> bool:
    """Check that legacy persistent values are still present in the database.

    The database may contain fields introduced after the legacy JSON copy was
    written; those database-only dictionary keys are intentionally preserved.
    Lists remain exact because silently accepting a changed subscription/user
    list could hide real data divergence.
    """
    if isinstance(legacy_value, dict) and isinstance(database_value, dict):
        return all(
            key in database_value and _legacy_config_matches_database(value, database_value[key])
            for key, value in legacy_value.items()
            if key != "sessions"
        )
    if isinstance(legacy_value, list) and isinstance(database_value, list):
        return len(legacy_value) == len(database_value) and all(
            _legacy_config_matches_database(left, right)
            for left, right in zip(legacy_value, database_value)
        )
    return legacy_value == database_value


def _migrate_tree(source_root: Path, logical_prefix: str) -> list[Path]:
    migrated: list[Path] = []
    if not source_root.is_dir():
        return migrated
    for source in sorted(path for path in source_root.rglob("*") if path.is_file()):
        relative_path = source.relative_to(source_root).as_posix()
        logical_path = f"{logical_prefix}/{relative_path}"
        content = source.read_text(encoding="utf-8")
        _write_and_verify(logical_path, content)
        migrated.append(source)
    return migrated


def _migrate_root_files(data_root: Path) -> list[Path]:
    migrated: list[Path] = []
    config_path = data_root / "config.json"
    if config_path.is_file():
        expected_config = json.loads(config_path.read_text(encoding="utf-8"))
        stored_config = storage.read_app_document("config", default=None)
        comparable_file_config = copy.deepcopy(expected_config)
        comparable_db_config = copy.deepcopy(stored_config)
        if isinstance(comparable_file_config, dict):
            comparable_file_config.get("auth", {}).pop("sessions", None)
        if isinstance(comparable_db_config, dict):
            comparable_db_config.get("auth", {}).pop("sessions", None)
        if not _legacy_config_matches_database(comparable_file_config, comparable_db_config):
            raise RuntimeError("Database config does not match data/config.json")
        migrated.append(config_path)

    for filename, namespace in ROOT_JSON_CACHES.items():
        source = data_root / filename
        if not source.is_file():
            continue
        expected_cache = json.loads(source.read_text(encoding="utf-8"))
        stored_cache = storage.read_cache_document(namespace, default=None)
        if stored_cache != expected_cache:
            raise RuntimeError(f"Database cache does not match data/{filename}")
        migrated.append(source)

    for filename in ROOT_LEGACY_FILES:
        source = data_root / filename
        if source.is_file():
            _write_and_verify(f"legacy/{filename}", source.read_text(encoding="utf-8"))
            migrated.append(source)
    return migrated


def _remove_empty_directories(directory: Path) -> None:
    if not directory.is_dir():
        return
    for child in sorted(directory.rglob("*"), reverse=True):
        if child.is_dir():
            try:
                child.rmdir()
            except OSError:
                pass


def migrate(*, delete_source: bool) -> dict[str, object]:
    data_root = Path(DATA_DIR).resolve()
    storage.initialize_database()

    root_files = _migrate_root_files(data_root)
    upload_files = _migrate_tree(data_root / "uploads", "uploads")
    backup_files = _migrate_tree(data_root / "backups", "backups")

    # The SQLite database file is an old backend artifact. It is safe to
    # remove only after switching to a server database; in SQLite mode it is
    # the active source of truth and must be kept.
    sqlite_file = data_root / "app.db"
    if delete_source and storage.backend_name() in {"postgres", "postgresql", "mysql"} and sqlite_file.is_file():
        sqlite_file.unlink()

    if delete_source:
        for source in [*root_files, *upload_files, *backup_files]:
            source.unlink(missing_ok=True)
        _remove_empty_directories(data_root / "uploads")
        _remove_empty_directories(data_root / "backups")

    return {
        "data_root": str(data_root),
        "backend": storage.backend_name(),
        "root_files": len(root_files),
        "upload_files": len(upload_files),
        "backup_files": len(backup_files),
        "source_deleted": delete_source,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate legacy data files into the configured database")
    parser.add_argument(
        "--delete-source",
        action="store_true",
        help="Delete legacy files after successful write/read verification",
    )
    arguments = parser.parse_args()
    print(json.dumps(migrate(delete_source=arguments.delete_source), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
