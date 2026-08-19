"""Migrate legacy data JSON documents into ``DATA_DIR/app.db``.

Usage (PowerShell):
    $env:DATA_DIR = 'G:\\clash-sub-merger\\data'
    python scripts/migrate_data_to_sqlite.py

The command is idempotent. Existing SQLite documents are never overwritten;
the first migration only imports missing documents from the legacy files.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", help="DATA_DIR to migrate (defaults to the environment)")
    args = parser.parse_args()
    if args.data_dir:
        os.environ["DATA_DIR"] = str(Path(args.data_dir).expanduser().resolve())

    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from core.config import DATA_DIR, DATABASE_FILE
    from core.database import load_config
    from core.sqlite_storage import read_cache_document, initialize_database

    initialize_database()
    config = load_config()
    data_dir = Path(DATA_DIR)
    print(f"DATA_DIR={data_dir}")
    print(f"DATABASE_FILE={DATABASE_FILE}")
    print(
        "config collections: "
        + json.dumps(
            {
                key: len(config.get(key, []))
                for key in (
                    "subscriptions",
                    "custom_nodes",
                    "users",
                    "templates",
                    "admin_tokens",
                    "proxy_chains",
                )
            },
            ensure_ascii=False,
        )
    )
    for namespace in ("geoip", "radar", "translation", "region_history"):
        payload = read_cache_document(namespace, default=None)
        if isinstance(payload, dict) and isinstance(payload.get("entries"), dict):
            size = len(payload["entries"])
        elif isinstance(payload, dict):
            size = len(payload)
        else:
            size = 0
        print(f"{namespace} cache entries: {size}")
    print(f"SQLite ready: {Path(DATABASE_FILE).exists()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
