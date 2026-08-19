"""MySQL persistence for application JSON documents and caches."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


_SCHEMA_VERSION = 1
_INITIALIZATION_LOCK = threading.RLock()
_INITIALIZED_DATABASES: set[str] = set()


def _connection_settings() -> dict[str, Any]:
    url = os.environ.get("MYSQL_URL", "").strip()
    if url:
        parsed = urlparse(url)
        if parsed.scheme not in {"mysql", "mysql+pymysql"}:
            raise ValueError("MYSQL_URL must use mysql:// or mysql+pymysql://")
        return {
            "host": parsed.hostname or "127.0.0.1",
            "port": parsed.port or 3306,
            "user": unquote(parsed.username or ""),
            "password": unquote(parsed.password or ""),
            "database": parsed.path.lstrip("/"),
        }
    return {
        "host": os.environ.get("MYSQL_HOST", "127.0.0.1").strip(),
        "port": int(os.environ.get("MYSQL_PORT", "3306")),
        "user": os.environ.get("MYSQL_USER", "clash_sub_merger").strip(),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "database": os.environ.get("MYSQL_DATABASE", "clash_sub_merger").strip(),
    }


def _database_identity() -> str:
    settings = _connection_settings()
    return "|".join(
        (
            str(settings["host"]),
            str(settings["port"]),
            str(settings["database"]),
            str(settings["user"]),
        )
    )


def _connect():
    try:
        import pymysql
    except ImportError as exc:  # pragma: no cover - exercised only without optional dependency
        raise RuntimeError("MySQL backend requires PyMySQL. Install project requirements first.") from exc

    settings = _connection_settings()
    return pymysql.connect(
        **settings,
        charset="utf8mb4",
        autocommit=False,
        connect_timeout=int(os.environ.get("MYSQL_CONNECT_TIMEOUT", "10")),
    )


def database_path() -> str:
    """Return a non-secret identifier used in diagnostics."""
    return f"mysql://{_database_identity()}"


def database_lock_path() -> str:
    from .config import DATA_DIR

    return str(Path(DATA_DIR) / "mysql_storage.lock")


def initialize_database() -> None:
    identity = _database_identity()
    with _INITIALIZATION_LOCK:
        if identity in _INITIALIZED_DATABASES:
            return
        connection = _connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INT PRIMARY KEY,
                        applied_at DOUBLE NOT NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS app_documents (
                        document_name VARCHAR(255) PRIMARY KEY,
                        payload_json LONGTEXT NOT NULL,
                        updated_at DOUBLE NOT NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cache_documents (
                        namespace VARCHAR(255) PRIMARY KEY,
                        payload_json LONGTEXT NOT NULL,
                        updated_at DOUBLE NOT NULL,
                        expires_at DOUBLE NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """
                )
                cursor.execute(
                    """
                    INSERT INTO schema_migrations(version, applied_at)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE version = VALUES(version)
                    """,
                    (_SCHEMA_VERSION, time.time()),
                )
            connection.commit()
            _INITIALIZED_DATABASES.add(identity)
        finally:
            connection.close()


def _decode_payload(payload_json: str, default: Any) -> Any:
    if payload_json is None:
        return default
    return json.loads(payload_json)


def read_app_document(document_name: str, default: Any = None) -> Any:
    initialize_database()
    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT payload_json FROM app_documents WHERE document_name = %s", (document_name,))
            row = cursor.fetchone()
        if row is None:
            return default
        return _decode_payload(row[0], default)
    finally:
        connection.close()


def write_app_document(document_name: str, payload: Any) -> None:
    initialize_database()
    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO app_documents(document_name, payload_json, updated_at)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    payload_json = VALUES(payload_json),
                    updated_at = VALUES(updated_at)
                """,
                (document_name, json.dumps(payload, ensure_ascii=False, separators=(",", ":")), time.time()),
            )
        connection.commit()
    finally:
        connection.close()


def has_app_document(document_name: str) -> bool:
    initialize_database()
    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM app_documents WHERE document_name = %s", (document_name,))
            return cursor.fetchone() is not None
    finally:
        connection.close()


def read_cache_document(namespace: str, default: Any = None) -> Any:
    initialize_database()
    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT payload_json FROM cache_documents WHERE namespace = %s", (namespace,))
            row = cursor.fetchone()
        if row is None:
            return default
        return _decode_payload(row[0], default)
    finally:
        connection.close()


def read_cache_document_record(namespace: str, default: Any = None) -> Any:
    """Read a cache payload together with its expiration metadata."""
    initialize_database()
    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT payload_json, expires_at FROM cache_documents WHERE namespace = %s", (namespace,))
            row = cursor.fetchone()
        if row is None:
            return default
        return {"payload": _decode_payload(row[0], default), "expires_at": row[1]}
    finally:
        connection.close()


def write_cache_document(namespace: str, payload: Any, *, expires_at: float | None = None) -> None:
    initialize_database()
    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO cache_documents(namespace, payload_json, updated_at, expires_at)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    payload_json = VALUES(payload_json),
                    updated_at = VALUES(updated_at),
                    expires_at = VALUES(expires_at)
                """,
                (
                    namespace,
                    json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                    time.time(),
                    expires_at,
                ),
            )
        connection.commit()
    finally:
        connection.close()


def delete_cache_document(namespace: str) -> None:
    initialize_database()
    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM cache_documents WHERE namespace = %s", (namespace,))
        connection.commit()
    finally:
        connection.close()
