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


def read_cache_document(namespace: str, default: Any = None) -> Any:
    return _backend_module().read_cache_document(namespace, default)


def read_cache_document_record(namespace: str, default: Any = None) -> Any:
    return _backend_module().read_cache_document_record(namespace, default)


def write_cache_document(namespace: str, payload: Any, *, expires_at: float | None = None) -> None:
    _backend_module().write_cache_document(namespace, payload, expires_at=expires_at)


def delete_cache_document(namespace: str) -> None:
    _backend_module().delete_cache_document(namespace)
