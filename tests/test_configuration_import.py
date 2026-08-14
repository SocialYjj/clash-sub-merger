"""Regression tests for configuration migration validation and rollback."""

import copy
import json
import tempfile
import unittest
from unittest.mock import Mock, patch

import api.system as system_api
import services.backup as backup_service
from services.configuration_validation import (
    remove_legacy_stale_references,
    validate_configuration_node_references,
    validate_and_normalize_configuration,
)
from services.proxy_chain_references import list_proxy_chain_virtual_references


def _valid_configuration() -> dict:
    return {
        "auth": {"password_hash": "a" * 64, "sessions": {"runtime-session": 9999999999}},
        "subscriptions": [{
            "id": "sub_1",
            "name": "Provider",
            "url": "https://provider.example/subscription",
            "type": "url",
        }],
        "custom_nodes": [{
            "id": "custom_1",
            "name": "Custom",
            "type": "ss",
            "server": "custom.example",
            "port": 443,
            "cipher": "aes-128-gcm",
            "password": "test-password",
        }],
        "users": [{
            "id": "user_1",
            "name": "User",
            "token": "user-token-value",
            "allocations": {"sub_1": ["*"], "custom_nodes": ["*"]},
            "group_config": {},
        }],
        "templates": [],
        "admin_tokens": [{
            "id": "admin_1",
            "name": "Admin",
            "token": "admin-token-value",
            "group_config": {},
        }],
        "proxy_chains": [],
        "source_order": ["sub_1", "custom_nodes"],
        "settings": {},
    }


class ConfigurationValidationTests(unittest.TestCase):
    def test_import_rejects_path_ids_duplicate_tokens_and_unknown_chain_sources(self):
        path_id_config = _valid_configuration()
        path_id_config["subscriptions"][0]["id"] = "../private"
        with self.assertRaisesRegex(ValueError, "ID is invalid"):
            validate_and_normalize_configuration(path_id_config)

        duplicate_token_config = _valid_configuration()
        duplicate_token_config["users"][0]["token"] = duplicate_token_config["admin_tokens"][0]["token"]
        with self.assertRaisesRegex(ValueError, "duplicate subscription tokens"):
            validate_and_normalize_configuration(duplicate_token_config)

        bad_chain_config = _valid_configuration()
        bad_chain_config["proxy_chains"] = [{
            "id": "chain_1",
            "name": "Chain",
            "rows": [{
                "row_id": "row_1",
                "nodes": [
                    {"type": "node", "sub_id": "missing", "node_id": "node_1"},
                    {"type": "node", "sub_id": "sub_1", "node_id": "node_2"},
                ],
            }],
        }]
        with self.assertRaisesRegex(ValueError, "unknown subscription"):
            validate_and_normalize_configuration(bad_chain_config)

    def test_import_rejects_missing_or_malformed_administrator_password_hash(self):
        missing_hash = _valid_configuration()
        missing_hash["auth"] = {}
        with self.assertRaisesRegex(ValueError, "no administrator password hash"):
            validate_and_normalize_configuration(missing_hash)

        excessive_work_factor = _valid_configuration()
        excessive_work_factor["auth"]["password_hash"] = (
            "pbkdf2_sha256$999999999$12345678$" + "YQ=="
        )
        with self.assertRaisesRegex(ValueError, "password hash is invalid"):
            validate_and_normalize_configuration(excessive_work_factor)

    def test_untrusted_import_rejects_unknown_allocations_and_source_order(self):
        unknown_allocation = _valid_configuration()
        unknown_allocation["users"][0]["allocations"]["deleted_sub"] = ["*"]
        with self.assertRaisesRegex(ValueError, "unknown source"):
            validate_and_normalize_configuration(unknown_allocation)

        unknown_order = _valid_configuration()
        unknown_order["source_order"].append("deleted_sub")
        with self.assertRaisesRegex(ValueError, "unknown source"):
            validate_and_normalize_configuration(unknown_order)

    def test_import_validates_chain_allocation_stable_and_legacy_references(self):
        config = _valid_configuration()
        config["proxy_chains"] = [{
            "id": "chain_1",
            "name": "Chain",
            "rows": [{
                "row_id": "row_1",
                "nodes": [
                    {"type": "node", "sub_id": "sub_1", "node_id": "node_a"},
                    {"type": "node", "sub_id": "sub_1", "node_id": "node_b"},
                ],
            }],
        }]
        references = list_proxy_chain_virtual_references(
            config,
            base_node_names=set(),
            reserved_group_names=set(),
        )
        chain_reference = references[0]

        config["users"][0]["allocations"] = {"chain_nodes": [chain_reference.stable_id]}
        normalized = validate_and_normalize_configuration(config)
        self.assertEqual(
            normalized["users"][0]["allocations"]["chain_nodes"],
            [chain_reference.stable_id],
        )

        legacy_config = copy.deepcopy(config)
        legacy_config["users"][0]["allocations"] = {"chain_nodes": [chain_reference.legacy_id]}
        validate_and_normalize_configuration(legacy_config)

        missing_config = copy.deepcopy(config)
        missing_config["users"][0]["allocations"] = {"chain_nodes": ["virtual_deleted_chain"]}
        with self.assertRaisesRegex(ValueError, "unknown chain component"):
            validate_and_normalize_configuration(missing_config)

    def test_restored_configuration_rejects_missing_chain_allocation_reference(self):
        config = _valid_configuration()
        config["subscriptions"] = []
        config["source_order"] = ["custom_nodes"]
        config["proxy_chains"] = [{
            "id": "chain_1",
            "name": "Chain",
            "rows": [{
                "row_id": "row_1",
                "nodes": [
                    {"type": "node", "sub_id": "custom", "node_id": "custom_1"},
                    {"type": "node", "sub_id": "custom", "node_id": "custom_1"},
                ],
            }],
        }]
        config["users"][0]["allocations"] = {"chain_nodes": ["virtual_deleted_chain"]}

        with tempfile.TemporaryDirectory() as tempdir:
            with self.assertRaisesRegex(ValueError, "missing chain component"):
                validate_configuration_node_references(config, tempdir)

    def test_trusted_legacy_cleanup_removes_stale_sources_before_validation(self):
        legacy_config = _valid_configuration()
        legacy_config["users"][0]["allocations"] = {
            "custom": ["*"],
            "deleted_sub": ["obsolete-node"],
        }
        legacy_config["source_order"] = ["deleted_sub", "sub_1", "sub_1", "custom_nodes"]

        changed = remove_legacy_stale_references(legacy_config)
        normalized = validate_and_normalize_configuration(legacy_config)

        self.assertGreaterEqual(changed, 2)
        self.assertEqual(normalized["users"][0]["allocations"], {"custom_nodes": ["*"]})
        self.assertEqual(normalized["source_order"], ["sub_1", "custom_nodes"])


class ConfigurationExportAndRollbackTests(unittest.TestCase):
    def test_export_omits_login_sessions_and_cleans_legacy_stale_references(self):
        config = _valid_configuration()
        config["users"][0]["allocations"]["deleted_sub"] = ["obsolete-node"]
        config["source_order"].insert(0, "deleted_sub")
        config["geoip_config"] = {"cloudflare_radar_token": "radar-secret"}

        with patch.object(backup_service, "load_config", return_value=copy.deepcopy(config)):
            exported = backup_service.export_config()

        exported_config = exported["config"]
        self.assertNotIn("sessions", exported_config["auth"])
        self.assertNotIn("cloudflare_radar_token", exported_config["geoip_config"])
        self.assertNotIn("deleted_sub", exported_config["users"][0]["allocations"])
        self.assertNotIn("deleted_sub", exported_config["source_order"])
        validate_and_normalize_configuration(exported_config)

    def test_export_response_is_never_cacheable(self):
        exported = {"version": "test", "exported_at": 1, "config": _valid_configuration()}
        with patch.object(system_api, "config_export", return_value=exported):
            response = system_api.export_configuration(_=True)

        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["pragma"], "no-cache")
        decoded = json.loads(response.body)
        self.assertEqual(decoded["version"], "test")

    def test_runtime_reload_failure_restores_previous_configuration(self):
        previous_config = _valid_configuration()
        restore_snapshot = Mock()

        with (
            patch.object(
                system_api,
                "_reload_runtime_configuration",
                side_effect=[RuntimeError("new runtime failed"), None],
            ),
            patch.object(system_api, "restore_config_snapshot", restore_snapshot),
        ):
            with self.assertRaisesRegex(RuntimeError, "Runtime configuration reload failed"):
                system_api._reload_or_restore(previous_config, "Configuration import")

        restore_snapshot.assert_called_once_with(previous_config)


if __name__ == "__main__":
    unittest.main()
