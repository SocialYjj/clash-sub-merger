"""PostgreSQL persistence for application JSON documents and caches.

The project stores structured application state as JSON payloads, but the
transactional boundary is provided by PostgreSQL tables.  Keeping the payload
shape unchanged lets existing services share the SQLite and PostgreSQL
backends without duplicating business logic.
"""

from __future__ import annotations

import json
import os
import threading
import time
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


_SCHEMA_VERSION = 1
_INITIALIZATION_LOCK = threading.RLock()
_INITIALIZED_DATABASES: set[str] = set()


def _database_identity() -> str:
    dsn = os.environ.get("POSTGRES_DSN", "").strip()
    if dsn:
        parsed = urlparse(dsn)
        if parsed.scheme in {"postgres", "postgresql"} and parsed.hostname:
            return "|".join(
                (
                    parsed.hostname,
                    str(parsed.port or 5432),
                    parsed.path.lstrip("/"),
                    parsed.username or "",
                )
            )
        return f"dsn-sha256:{sha256(dsn.encode('utf-8')).hexdigest()[:16]}"
    return "|".join(
        (
            os.environ.get("POSTGRES_HOST", "127.0.0.1").strip(),
            os.environ.get("POSTGRES_PORT", "5432").strip(),
            os.environ.get("POSTGRES_DATABASE", "clash_sub_merger").strip(),
            os.environ.get("POSTGRES_USER", "clash_sub_merger").strip(),
        )
    )


def _connect():
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - exercised only without optional dependency
        raise RuntimeError(
            "PostgreSQL backend requires psycopg[binary]. Install project requirements first."
        ) from exc

    dsn = os.environ.get("POSTGRES_DSN", "").strip()
    if dsn:
        return psycopg.connect(dsn)

    return psycopg.connect(
        host=os.environ.get("POSTGRES_HOST", "127.0.0.1").strip(),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        dbname=os.environ.get("POSTGRES_DATABASE", "clash_sub_merger").strip(),
        user=os.environ.get("POSTGRES_USER", "clash_sub_merger").strip(),
        password=os.environ.get("POSTGRES_PASSWORD", ""),
        connect_timeout=int(os.environ.get("POSTGRES_CONNECT_TIMEOUT", "10")),
    )


def database_path() -> str:
    """Return a non-secret identifier used in diagnostics."""
    return f"postgresql://{_database_identity()}"


def database_lock_path() -> str:
    from .config import DATA_DIR

    return str(Path(DATA_DIR) / "postgresql_storage.lock")


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
                        version INTEGER PRIMARY KEY,
                        applied_at DOUBLE PRECISION NOT NULL
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS app_documents (
                        document_name VARCHAR(255) PRIMARY KEY,
                        payload_json TEXT NOT NULL,
                        updated_at DOUBLE PRECISION NOT NULL
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cache_documents (
                        namespace VARCHAR(255) PRIMARY KEY,
                        payload_json TEXT NOT NULL,
                        updated_at DOUBLE PRECISION NOT NULL,
                        expires_at DOUBLE PRECISION NULL
                    )
                    """
                )
                cursor.execute(
                    """
                    INSERT INTO schema_migrations(version, applied_at)
                    VALUES (%s, %s)
                    ON CONFLICT(version) DO NOTHING
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
            cursor.execute(
                "SELECT payload_json FROM app_documents WHERE document_name = %s",
                (document_name,),
            )
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
                ON CONFLICT(document_name) DO UPDATE SET
                    payload_json = EXCLUDED.payload_json,
                    updated_at = EXCLUDED.updated_at
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
            cursor.execute(
                "SELECT 1 FROM app_documents WHERE document_name = %s",
                (document_name,),
            )
            return cursor.fetchone() is not None
    finally:
        connection.close()


def read_cache_document(namespace: str, default: Any = None) -> Any:
    initialize_database()
    connection = _connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload_json FROM cache_documents WHERE namespace = %s",
                (namespace,),
            )
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
            cursor.execute(
                "SELECT payload_json, expires_at FROM cache_documents WHERE namespace = %s",
                (namespace,),
            )
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
                ON CONFLICT(namespace) DO UPDATE SET
                    payload_json = EXCLUDED.payload_json,
                    updated_at = EXCLUDED.updated_at,
                    expires_at = EXCLUDED.expires_at
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
