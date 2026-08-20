"""Backend-neutral persistence facade.

SQLite remains the default.  PostgreSQL and MySQL can be selected with
``STORAGE_BACKEND=postgresql`` or ``STORAGE_BACKEND=mysql`` and their matching
connection environment variables.  The public operations deliberately mirror
the existing SQLite storage API so service code keeps one persistence path.
"""

from __future__ import annotations

import importlib
import os
from types import ModuleType
from typing import Any


_BACKEND_MODULES = {
    "sqlite": "core.sqlite_storage",
    "postgres": "core.postgresql_storage",
    "postgresql": "core.postgresql_storage",
    "mysql": "core.mysql_storage",
}


def backend_name() -> str:
    value = os.environ.get("STORAGE_BACKEND", "sqlite").strip().lower().replace("-", "_")
    if value not in _BACKEND_MODULES:
        raise ValueError(
            f"Unsupported STORAGE_BACKEND={value!r}; expected sqlite, postgresql, or mysql"
        )
    return value


def _backend_module() -> ModuleType:
    return importlib.import_module(_BACKEND_MODULES[backend_name()])


def database_path() -> str:
    return _backend_module().database_path()


def database_lock_path() -> str:
    return _backend_module().database_lock_path()


def initialize_database() -> None:
    _backend_module().initialize_database()


def read_app_document(document_name: str, default: Any = None) -> Any:
    return _backend_module().read_app_document(document_name, default)


def write_app_document(document_name: str, payload: Any) -> None:
    _backend_module().write_app_document(document_name, payload)


def has_app_document(document_name: str) -> bool:
    return _backend_module().has_app_document(document_name)


def _validate_stored_file_path(file_path: str) -> str:
    """Validate a logical stored-file key before it reaches a database backend."""
    if not isinstance(file_path, str):
        raise TypeError("Stored file path must be a string")
    normalized = file_path.replace("\\", "/").strip("/")
    if not normalized or normalized in {".", ".."} or any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise ValueError("Invalid stored file path")
    if len(normalized) > 500:
        raise ValueError("Stored file path is too long")
    return normalized


def read_stored_file(file_path: str, default: str | None = None) -> str | None:
    return _backend_module().read_stored_file(_validate_stored_file_path(file_path), default)


def write_stored_file(file_path: str, content: str) -> None:
    if not isinstance(content, str):
        raise TypeError("Stored file content must be text")
    _backend_module().write_stored_file(_validate_stored_file_path(file_path), content)


def delete_stored_file(file_path: str) -> None:
    _backend_module().delete_stored_file(_validate_stored_file_path(file_path))


def delete_stored_files(prefix: str) -> None:
    normalized_prefix = _validate_stored_file_path(prefix).rstrip("/")
    _backend_module().delete_stored_files(normalized_prefix)


def list_stored_files(prefix: str | None = None) -> list[dict[str, Any]]:
    normalized_prefix = None if prefix is None else _validate_stored_file_path(prefix).rstrip("/")
    return _backend_module().list_stored_files(normalized_prefix)


def has_stored_file(file_path: str) -> bool:
    return read_stored_file(file_path, default=None) is not None


def read_cache_document(namespace: str, default: Any = None) -> Any:
    return _backend_module().read_cache_document(namespace, default)


def read_cache_document_record(namespace: str, default: Any = None) -> Any:
    return _backend_module().read_cache_document_record(namespace, default)


def write_cache_document(namespace: str, payload: Any, *, expires_at: float | None = None) -> None:
    _backend_module().write_cache_document(namespace, payload, expires_at=expires_at)


def delete_cache_document(namespace: str) -> None:
    _backend_module().delete_cache_document(namespace)
