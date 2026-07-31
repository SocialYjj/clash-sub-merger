"""Boundary validation regressions for allocations and editable groups."""

import unittest
from unittest.mock import patch

from fastapi import HTTPException

from services.group_config_builder import build_group_config_view
from services.proxy_chain_references import list_proxy_chain_virtual_references
from services.user_configuration_validation import (
    normalize_group_config,
    normalize_user_allocations,
)


def _custom_node() -> dict:
    return {
        "id": "custom_1",
        "name": "Custom Exit",
        "type": "ss",
        "server": "custom.example",
        "port": 443,
        "cipher": "aes-128-gcm",
        "password": "test-password",
    }


class UserAllocationValidationTests(unittest.TestCase):
    def test_unknown_source_missing_node_and_mixed_wildcard_are_rejected(self):
        config = {
            "subscriptions": [],
            "custom_nodes": [_custom_node()],
            "proxy_chains": [],
        }
        invalid_allocations = (
            {"missing_source": ["*"]},
            {"custom_nodes": ["garbage-node-id"]},
            {"custom_nodes": ["*", "custom_1"]},
        )
        for allocations in invalid_allocations:
            with self.subTest(allocations=allocations):
                with self.assertRaises(HTTPException):
                    normalize_user_allocations(config, allocations)

    def test_unavailable_subscription_keeps_only_existing_references(self):
        config = {
            "subscriptions": [{"id": "sub_1", "name": "Provider"}],
            "custom_nodes": [],
            "proxy_chains": [],
        }
        with patch(
            "services.user_configuration_validation.load_subscription_yaml",
            side_effect=HTTPException(status_code=500, detail="Invalid YAML format"),
        ):
            retained = normalize_user_allocations(
                config,
                {"sub_1": ["previous-stable-id"]},
                existing_allocations={"sub_1": ["previous-stable-id"]},
            )
            with self.assertRaises(HTTPException):
                normalize_user_allocations(
                    config,
                    {"sub_1": ["injected-new-id"]},
                    existing_allocations={"sub_1": ["previous-stable-id"]},
                )

        self.assertEqual(retained, {"sub_1": ["previous-stable-id"]})


class GroupConfigurationValidationTests(unittest.TestCase):
    def setUp(self):
        self.builtin_template = {
            "id": "builtin",
            "name": "Builtin",
            "proxy_groups": [
                {"name": "Editable", "type": "select", "_editable": True},
                {"name": "Read Only", "type": "select", "_editable": False},
            ],
        }

    def test_read_only_group_and_unavailable_node_are_rejected(self):
        config = {
            "subscriptions": [],
            "custom_nodes": [_custom_node()],
            "proxy_chains": [],
            "templates": [],
        }
        subject = {"template_id": "builtin"}

        for group_config in (
            {"Read Only": ["DIRECT"]},
            {"Editable": ["not-available"]},
        ):
            with self.subTest(group_config=group_config):
                with self.assertRaises(HTTPException):
                    normalize_group_config(
                        config,
                        subject,
                        group_config,
                        allocations={"custom_nodes": ["*"]},
                        builtin_template=self.builtin_template,
                    )

    def test_allocated_proxy_chain_node_is_available_to_editable_group(self):
        config = {
            "subscriptions": [],
            "custom_nodes": [],
            "proxy_chains": [{
                "id": "chain_1",
                "name": "Chain",
                "enabled": True,
                "rows": [{
                    "row_id": "row_1",
                    "nodes": [
                        {"type": "node", "sub_id": "sub_1", "node_id": "node_1", "node_name": "One"},
                        {"type": "node", "sub_id": "sub_1", "node_id": "node_2", "node_name": "Two"},
                    ],
                }],
            }],
            "templates": [],
        }
        subject = {"template_id": "builtin"}

        normalized = normalize_group_config(
            config,
            subject,
            {"Editable": ["DIRECT", "🔗 Chain"]},
            allocations={"chain_nodes": ["*"]},
            builtin_template=self.builtin_template,
        )

        chain_reference = list_proxy_chain_virtual_references(
            config,
            base_node_names=set(),
            reserved_group_names={"Editable", "Read Only"},
        )[0]
        self.assertEqual(
            normalized,
            {"Editable": ["DIRECT", chain_reference.stable_id]},
        )

        subject["group_config"] = normalized
        group_view = build_group_config_view(
            config,
            subject,
            allocations={"chain_nodes": ["*"]},
            builtin_template=self.builtin_template,
        )
        editable_group = next(
            group for group in group_view["groups"]
            if group["name"] == "Editable"
        )
        self.assertEqual(editable_group["current_nodes"], ["DIRECT", "🔗 Chain"])


if __name__ == "__main__":
    unittest.main()
