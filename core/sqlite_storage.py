"""SQLite persistence for configuration, caches, and logical application files.

The application historically persisted its state in several JSON files and
directories.  JSON documents and logical application files now share one
transactional persistence boundary.  Operational artifacts such as logs and
runtime locks remain on the filesystem.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


_SCHEMA_VERSION = 2
_init_lock = threading.RLock()
_initialized_paths: set[str] = set()


def _paths() -> tuple[Path, Path]:
    # Import lazily to avoid a config -> storage import cycle.
    from .config import DATABASE_FILE

    database_path = Path(DATABASE_FILE)
    return database_path, Path(f"{database_path}.lock")


def database_path() -> str:
    return str(_paths()[0])


def database_lock_path() -> str:
    return str(_paths()[1])


def _connect() -> sqlite3.Connection:
    database_file, _ = _paths()
    database_file.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(
        database_file,
        timeout=30,
        isolation_level=None,
        check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def initialize_database() -> None:
    """Create the schema and import legacy JSON files once, if present."""
    database_file, _ = _paths()
    cache_key = str(database_file.resolve())
    with _init_lock:
        connection = _connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS app_documents (
                    document_name TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cache_documents (
                    namespace TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    expires_at REAL
                );
                CREATE TABLE IF NOT EXISTS stored_files (
                    file_path TEXT PRIMARY KEY,
                    content_text TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (_SCHEMA_VERSION, time.time()),
            )
            try:
                os.chmod(database_file, 0o600)
            except OSError:
                pass
            if cache_key not in _initialized_paths:
                _migrate_legacy_documents(connection)
                _initialized_paths.add(cache_key)
        finally:
            connection.close()


def _read_json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None


def _write_document_row(connection: sqlite3.Connection, table: str, key: str, payload: Any) -> None:
    now = time.time()
    if table == "app_documents":
        connection.execute(
            "INSERT INTO app_documents(document_name, payload_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(document_name) DO UPDATE SET payload_json=excluded.payload_json, updated_at=excluded.updated_at",
            (key, json.dumps(payload, ensure_ascii=False, separators=(",", ":")), now),
        )
        return
    connection.execute(
        "INSERT INTO cache_documents(namespace, payload_json, updated_at, expires_at) VALUES (?, ?, ?, NULL) "
        "ON CONFLICT(namespace) DO UPDATE SET payload_json=excluded.payload_json, updated_at=excluded.updated_at, expires_at=NULL",
        (key, json.dumps(payload, ensure_ascii=False, separators=(",", ":")), now),
    )


def _migrate_legacy_documents(connection: sqlite3.Connection) -> None:
    from .config import CONFIG_FILE, DATA_DIR

    legacy_documents = {
        "config": Path(CONFIG_FILE),
    }
    legacy_caches = {
        "geoip": Path(DATA_DIR) / "geoip_cache.json",
        "radar": Path(DATA_DIR) / "cloudflare_radar_cache.json",
        "translation": Path(DATA_DIR) / "translation_cache.json",
        "region_history": Path(DATA_DIR) / "node_region_history.json",
    }
    with connection:
        for document_name, path in legacy_documents.items():
            if connection.execute(
                "SELECT 1 FROM app_documents WHERE document_name = ?", (document_name,)
            ).fetchone():
                continue
            payload = _read_json_file(path)
            if isinstance(payload, dict):
                _write_document_row(connection, "app_documents", document_name, payload)

        for namespace, path in legacy_caches.items():
            if connection.execute(
                "SELECT 1 FROM cache_documents WHERE namespace = ?", (namespace,)
            ).fetchone():
                continue
            payload = _read_json_file(path)
            if payload is not None:
                _write_document_row(connection, "cache_documents", namespace, payload)


def read_app_document(document_name: str, default: Any = None) -> Any:
    initialize_database()
    connection = _connect()
    try:
        row = connection.execute(
            "SELECT payload_json FROM app_documents WHERE document_name = ?", (document_name,)
        ).fetchone()
        if row is None:
            return default
        return json.loads(row["payload_json"])
    finally:
        connection.close()


def write_app_document(document_name: str, payload: Any) -> None:
    initialize_database()
    connection = _connect()
    try:
        with connection:
            connection.execute(
                "INSERT INTO app_documents(document_name, payload_json, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(document_name) DO UPDATE SET payload_json=excluded.payload_json, updated_at=excluded.updated_at",
                (document_name, json.dumps(payload, ensure_ascii=False, separators=(",", ":")), time.time()),
            )
        try:
            os.chmod(_paths()[0], 0o600)
        except OSError:
            pass
    finally:
        connection.close()


def read_cache_document(namespace: str, default: Any = None) -> Any:
    initialize_database()
    connection = _connect()
    try:
        row = connection.execute(
            "SELECT payload_json FROM cache_documents WHERE namespace = ?", (namespace,)
        ).fetchone()
        if row is None:
            return default
        return json.loads(row["payload_json"])
    finally:
        connection.close()


def read_cache_document_record(namespace: str, default: Any = None) -> Any:
    """Read a cache payload together with its expiration metadata."""
    initialize_database()
    connection = _connect()
    try:
        row = connection.execute(
            "SELECT payload_json, expires_at FROM cache_documents WHERE namespace = ?",
            (namespace,),
        ).fetchone()
        if row is None:
            return default
        return {"payload": json.loads(row["payload_json"]), "expires_at": row["expires_at"]}
    finally:
        connection.close()


def write_cache_document(namespace: str, payload: Any, *, expires_at: float | None = None) -> None:
    initialize_database()
    connection = _connect()
    try:
        with connection:
            connection.execute(
                "INSERT INTO cache_documents(namespace, payload_json, updated_at, expires_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(namespace) DO UPDATE SET payload_json=excluded.payload_json, updated_at=excluded.updated_at, expires_at=excluded.expires_at",
                (
                    namespace,
                    json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                    time.time(),
                    expires_at,
                ),
            )
        try:
            os.chmod(_paths()[0], 0o600)
        except OSError:
            pass
    finally:
        connection.close()


def delete_cache_document(namespace: str) -> None:
    initialize_database()
    connection = _connect()
    try:
        with connection:
            connection.execute("DELETE FROM cache_documents WHERE namespace = ?", (namespace,))
    finally:
        connection.close()


def has_app_document(document_name: str) -> bool:
    initialize_database()
    connection = _connect()
    try:
        return connection.execute(
            "SELECT 1 FROM app_documents WHERE document_name = ?", (document_name,)
        ).fetchone() is not None
    finally:
        connection.close()


def read_stored_file(file_path: str, default: str | None = None) -> str | None:
    initialize_database()
    connection = _connect()
    try:
        row = connection.execute(
            "SELECT content_text FROM stored_files WHERE file_path = ?", (file_path,)
        ).fetchone()
        return default if row is None else str(row[0])
    finally:
        connection.close()


def write_stored_file(file_path: str, content: str) -> None:
    initialize_database()
    connection = _connect()
    try:
        with connection:
            connection.execute(
                "INSERT INTO stored_files(file_path, content_text, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(file_path) DO UPDATE SET content_text=excluded.content_text, updated_at=excluded.updated_at",
                (file_path, content, time.time()),
            )
    finally:
        connection.close()


def delete_stored_file(file_path: str) -> None:
    initialize_database()
    connection = _connect()
    try:
        with connection:
            connection.execute("DELETE FROM stored_files WHERE file_path = ?", (file_path,))
    finally:
        connection.close()


def delete_stored_files(prefix: str) -> None:
    initialize_database()
    connection = _connect()
    try:
        with connection:
            connection.execute(
                "DELETE FROM stored_files WHERE file_path = ? OR file_path LIKE ?",
                (prefix, f"{prefix}/%"),
            )
    finally:
        connection.close()


def list_stored_files(prefix: str | None = None) -> list[dict[str, Any]]:
    initialize_database()
    connection = _connect()
    try:
        if prefix:
            rows = connection.execute(
                "SELECT file_path, content_text, updated_at FROM stored_files "
                "WHERE file_path = ? OR file_path LIKE ? ORDER BY file_path",
                (prefix, f"{prefix}/%"),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT file_path, content_text, updated_at FROM stored_files ORDER BY file_path"
            ).fetchall()
        return [
            {"file_path": str(row[0]), "content": str(row[1]), "updated_at": float(row[2])}
            for row in rows
        ]
    finally:
        connection.close()
