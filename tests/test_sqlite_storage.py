import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import sqlite_storage


class SQLiteStorageTests(unittest.TestCase):
    def test_legacy_documents_and_caches_are_imported_once(self):
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            config_path = root / "config.json"
            config_path.write_text(json.dumps({"users": [{"id": "u1"}]}), encoding="utf-8")
            (root / "geoip_cache.json").write_text(
                json.dumps({"version": 1, "entries": {"1.1.1.1": {"country": "US"}}}),
                encoding="utf-8",
            )
            database_path = root / "app.db"
            with (
                patch("core.config.DATA_DIR", str(root)),
                patch("core.config.CONFIG_FILE", str(config_path)),
                patch("core.config.DATABASE_FILE", str(database_path)),
            ):
                sqlite_storage._initialized_paths.clear()
                sqlite_storage.initialize_database()
                self.assertEqual(
                    sqlite_storage.read_app_document("config")["users"][0]["id"],
                    "u1",
                )
                self.assertEqual(
                    sqlite_storage.read_cache_document("geoip")["entries"]["1.1.1.1"]["country"],
                    "US",
                )

                # Existing SQLite documents are authoritative on subsequent
                # initialization and are not overwritten by changed JSON.
                config_path.write_text(json.dumps({"users": [{"id": "changed"}]}), encoding="utf-8")
                sqlite_storage.initialize_database()
                self.assertEqual(
                    sqlite_storage.read_app_document("config")["users"][0]["id"],
                    "u1",
                )

            connection = sqlite3.connect(database_path)
            try:
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
            finally:
                connection.close()

    def test_cache_document_round_trip(self):
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            database_path = root / "app.db"
            with (
                patch("core.config.DATA_DIR", str(root)),
                patch("core.config.CONFIG_FILE", str(root / "config.json")),
                patch("core.config.DATABASE_FILE", str(database_path)),
            ):
                sqlite_storage._initialized_paths.clear()
                sqlite_storage.write_cache_document("translation", {"key": {"translation": "山景城"}})
                self.assertEqual(
                    sqlite_storage.read_cache_document("translation")["key"]["translation"],
                    "山景城",
                )
                sqlite_storage.delete_cache_document("translation")
                self.assertIsNone(sqlite_storage.read_cache_document("translation", None))

    def test_stored_file_round_trip_and_prefix_cleanup(self):
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            database_path = root / "app.db"
            with (
                patch("core.config.DATA_DIR", str(root)),
                patch("core.config.CONFIG_FILE", str(root / "config.json")),
                patch("core.config.DATABASE_FILE", str(database_path)),
            ):
                sqlite_storage._initialized_paths.clear()
                sqlite_storage.write_stored_file("uploads/source.yaml", "proxies: []\n")
                sqlite_storage.write_stored_file("backups/config.json", "{}")
                self.assertEqual(
                    sqlite_storage.read_stored_file("uploads/source.yaml"),
                    "proxies: []\n",
                )
                self.assertEqual(
                    [row["file_path"] for row in sqlite_storage.list_stored_files("uploads")],
                    ["uploads/source.yaml"],
                )
                sqlite_storage.delete_stored_files("uploads")
                self.assertIsNone(sqlite_storage.read_stored_file("uploads/source.yaml"))
                self.assertEqual(
                    sqlite_storage.read_stored_file("backups/config.json"),
                    "{}",
                )


if __name__ == "__main__":
    unittest.main()
