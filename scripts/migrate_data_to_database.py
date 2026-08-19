"""Copy the current SQLite documents and caches into PostgreSQL or MySQL.

Examples (PowerShell):

    $env:STORAGE_BACKEND = 'postgresql'
    $env:POSTGRES_HOST = '127.0.0.1'
    $env:POSTGRES_DATABASE = 'clash_sub_merger_pg'
    $env:POSTGRES_USER = 'clash_sub_merger_test'
    $env:POSTGRES_PASSWORD = '<test-password>'
    python scripts/migrate_data_to_database.py --backend postgresql

The source SQLite database is read-only.  Target rows with the same document
or namespace are replaced, while unrelated target rows are left untouched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any


TARGET_MODULES = {
    "postgres": "core.postgresql_storage",
    "postgresql": "core.postgresql_storage",
    "mysql": "core.mysql_storage",
}


def _read_sqlite_documents(source_path: Path) -> tuple[dict[str, Any], dict[str, tuple[Any, float | None]]]:
    if not source_path.exists():
        raise FileNotFoundError(f"SQLite source database does not exist: {source_path}")

    connection = sqlite3.connect(source_path)
    try:
        app_documents = {
            row[0]: json.loads(row[1])
            for row in connection.execute(
                "SELECT document_name, payload_json FROM app_documents ORDER BY document_name"
            )
        }
        cache_documents = {
            row[0]: (json.loads(row[1]), row[2])
            for row in connection.execute(
                "SELECT namespace, payload_json, expires_at FROM cache_documents ORDER BY namespace"
            )
        }
        integrity_result = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity_result != "ok":
            raise RuntimeError(f"SQLite source integrity check failed: {integrity_result}")
        return app_documents, cache_documents
    finally:
        connection.close()


def _payload_digest(app_documents: dict[str, Any], cache_documents: dict[str, Any]) -> str:
    cache_payloads = {
        namespace: record[0] if isinstance(record, tuple) else record
        for namespace, record in cache_documents.items()
    }
    normalized = json.dumps(
        {"app_documents": app_documents, "cache_documents": cache_payloads},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backend",
        required=True,
        choices=("postgres", "postgresql", "mysql"),
        help="Target database backend",
    )
    parser.add_argument(
        "--source-sqlite",
        default=None,
        help="SQLite app.db path (defaults to DATA_DIR/app.db)",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    if args.source_sqlite:
        source_path = Path(args.source_sqlite).expanduser().resolve()
    else:
        data_dir = Path(os.environ.get("DATA_DIR", project_root / "data")).expanduser().resolve()
        source_path = data_dir / "app.db"

    target_backend = args.backend
    os.environ["STORAGE_BACKEND"] = target_backend
    from importlib import import_module

    target_storage = import_module(TARGET_MODULES[target_backend])
    app_documents, cache_documents = _read_sqlite_documents(source_path)
    target_storage.initialize_database()

    for document_name, payload in app_documents.items():
        target_storage.write_app_document(document_name, payload)
    for namespace, (payload, expires_at) in cache_documents.items():
        target_storage.write_cache_document(namespace, payload, expires_at=expires_at)

    migrated_app_documents = {
        name: target_storage.read_app_document(name)
        for name in app_documents
    }
    migrated_cache_documents = {
        name: target_storage.read_cache_document_record(name)
        for name in cache_documents
    }
    migrated_cache_payloads = {
        name: record["payload"]
        for name, record in migrated_cache_documents.items()
    }

    source_digest = _payload_digest(app_documents, cache_documents)
    target_digest = _payload_digest(migrated_app_documents, migrated_cache_payloads)
    if source_digest != target_digest:
        raise RuntimeError(
            "Migration verification failed: source and target JSON payload digests differ"
        )

    print(f"source_sqlite={source_path}")
    print(f"target_backend={target_backend}")
    print(f"app_documents={len(app_documents)}")
    print(f"cache_documents={len(cache_documents)}")
    print(
        "cache_expirations_preserved="
        + str(
            all(
                migrated_cache_documents[name]["expires_at"] == cache_documents[name][1]
                for name in cache_documents
            )
        ).lower()
    )
    print(f"payload_sha256={source_digest}")
    print("migration_verified=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
