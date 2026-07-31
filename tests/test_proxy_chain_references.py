"""Regression tests for durable proxy-chain component identities."""

import copy
import unittest
from unittest.mock import patch

from api.proxy_chains import ProxyChainNode, ProxyChainRow, _serialize_chain_rows
from services.proxy_chain_references import (
    list_proxy_chain_virtual_references,
    reconcile_proxy_chain_references,
)


def _direct_reference(node_id: str) -> dict:
    return {
        "type": "node",
        "sub_id": "sub_1",
        "node_id": node_id,
        "node_name": node_id,
    }


def _two_row_chain_config() -> dict:
    return {
        "subscriptions": [],
        "custom_nodes": [],
        "proxy_chains": [{
            "id": "chain_1",
            "name": "Chain",
            "enabled": True,
            "rows": [
                {"row_id": "row_a", "nodes": [_direct_reference("node_a"), _direct_reference("node_b")]},
                {"row_id": "row_b", "nodes": [_direct_reference("node_c"), _direct_reference("node_d")]},
            ],
        }],
        "users": [],
        "admin_tokens": [],
        "port_mappings": {},
        "settings": {},
        "speedtest_results": {},
    }


class ProxyChainLifecycleTests(unittest.TestCase):
    def _references(self, config: dict):
        return {
            reference.component_id: reference
            for reference in list_proxy_chain_virtual_references(config, base_node_names=set())
        }

    def test_chain_rename_normalizes_persisted_references_to_stable_ids(self):
        config = _two_row_chain_config()
        old_references = self._references(config)
        config["users"] = [{
            "allocations": {"chain_nodes": [reference.stable_id for reference in old_references.values()]},
            "group_config": {"Select": [reference.name for reference in old_references.values()]},
        }]
        config["admin_tokens"] = [{
            "group_config": {"Select": [reference.name for reference in old_references.values()]},
        }]
        config["port_mappings"] = {
            reference.name: 12000 + index
            for index, reference in enumerate(old_references.values())
        }
        previous_config = copy.deepcopy(config)
        config["proxy_chains"][0]["name"] = "Renamed"

        with patch("services.proxy_chain_references._base_node_names", side_effect=lambda _config: set()):
            reconcile_proxy_chain_references(config, previous_config)

        new_references = self._references(config)
        self.assertEqual(
            config["users"][0]["allocations"]["chain_nodes"],
            [old_references["row_a"].stable_id, old_references["row_b"].stable_id],
        )
        self.assertEqual(
            config["users"][0]["group_config"]["Select"],
            [new_references["row_a"].stable_id, new_references["row_b"].stable_id],
        )
        self.assertEqual(
            config["admin_tokens"][0]["group_config"]["Select"],
            [new_references["row_a"].stable_id, new_references["row_b"].stable_id],
        )
        self.assertEqual(set(config["port_mappings"]), {ref.stable_id for ref in new_references.values()})

    def test_deleting_first_row_removes_only_that_rows_references(self):
        config = _two_row_chain_config()
        old_references = self._references(config)
        config["users"] = [{
            "allocations": {"chain_nodes": [old_references["row_a"].stable_id, old_references["row_b"].stable_id]},
            "group_config": {"Select": [old_references["row_a"].name, old_references["row_b"].name]},
        }]
        config["port_mappings"] = {
            old_references["row_a"].name: 12000,
            old_references["row_b"].name: 12001,
        }
        previous_config = copy.deepcopy(config)
        config["proxy_chains"][0]["rows"].pop(0)

        with patch("services.proxy_chain_references._base_node_names", side_effect=lambda _config: set()):
            reconcile_proxy_chain_references(config, previous_config)

        remaining_reference = self._references(config)["row_b"]
        self.assertEqual(
            config["users"][0]["allocations"]["chain_nodes"],
            [remaining_reference.stable_id],
        )
        self.assertEqual(config["users"][0]["group_config"]["Select"], [remaining_reference.stable_id])
        self.assertEqual(config["port_mappings"], {remaining_reference.stable_id: 12001})

    def test_row_reorder_keeps_component_ownership_while_migrating_display_names(self):
        config = _two_row_chain_config()
        old_references = self._references(config)
        config["users"] = [{
            "allocations": {"chain_nodes": [old_references["row_a"].stable_id]},
            "group_config": {"Select": [old_references["row_a"].name]},
        }]
        previous_config = copy.deepcopy(config)
        config["proxy_chains"][0]["rows"].reverse()

        with patch("services.proxy_chain_references._base_node_names", side_effect=lambda _config: set()):
            reconcile_proxy_chain_references(config, previous_config)

        new_references = self._references(config)
        self.assertEqual(config["users"][0]["allocations"]["chain_nodes"], [old_references["row_a"].stable_id])
        self.assertEqual(config["users"][0]["group_config"]["Select"], [new_references["row_a"].stable_id])
        self.assertNotEqual(old_references["row_a"].name, new_references["row_a"].name)

    def test_proxy_group_rename_preserves_group_identity(self):
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
                        _direct_reference("node_a"),
                        {
                            "type": "group",
                            "group_id": "group_1",
                            "group_name": "Old Pool",
                            "group_nodes": [_direct_reference("node_b")],
                        },
                    ],
                }],
            }],
            "users": [],
            "admin_tokens": [],
            "port_mappings": {},
            "settings": {},
            "speedtest_results": {},
        }
        old_reference = self._references(config)["group_1"]
        config["users"] = [{
            "allocations": {"chain_pools": [old_reference.stable_id]},
            "group_config": {"Select": [old_reference.name]},
        }]
        previous_config = copy.deepcopy(config)
        config["proxy_chains"][0]["rows"][0]["nodes"][1]["group_name"] = "New Pool"

        with patch("services.proxy_chain_references._base_node_names", side_effect=lambda _config: set()):
            reconcile_proxy_chain_references(config, previous_config)

        new_reference = self._references(config)["group_1"]
        self.assertEqual(config["users"][0]["allocations"]["chain_pools"], [old_reference.stable_id])
        self.assertEqual(config["users"][0]["group_config"]["Select"], [new_reference.stable_id])
        self.assertNotEqual(old_reference.name, new_reference.name)

    def test_template_group_names_are_reserved_for_chain_references(self):
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
                        _direct_reference("node_a"),
                        {
                            "type": "group",
                            "group_id": "grp_pool_abcd",
                            "group_name": "Exit Pool",
                            "group_nodes": [_direct_reference("node_b")],
                        },
                    ],
                }],
            }],
        }

        reference = list_proxy_chain_virtual_references(
            config,
            base_node_names=set(),
            reserved_group_names={"🔀 Exit Pool"},
        )[0]

        self.assertEqual(reference.name, "🔀 Exit Pool (abcd)")


class ProxyChainSerializationTests(unittest.TestCase):
    def test_deleting_first_row_preserves_second_row_id_and_drops_positional_fields(self):
        existing_rows = [
            {
                "row_id": "row_a",
                "nodes": [
                    {**_direct_reference("node_a"), "node_index": 0},
                    {**_direct_reference("node_b"), "node_index": 1},
                ],
            },
            {
                "row_id": "row_b",
                "nodes": [
                    {**_direct_reference("node_c"), "node_index": 2},
                    {
                        "type": "group",
                        "group_id": "group_b",
                        "group_name": "Pool",
                        "group_nodes": [{**_direct_reference("node_d"), "node_index": 3}],
                    },
                ],
            },
        ]
        retained_row = ProxyChainRow(nodes=[
            ProxyChainNode(**existing_rows[1]["nodes"][0]),
            ProxyChainNode(**existing_rows[1]["nodes"][1]),
        ])

        serialized_rows = _serialize_chain_rows([retained_row], existing_rows)

        self.assertEqual(serialized_rows[0]["row_id"], "row_b")
        self.assertNotIn("node_index", serialized_rows[0]["nodes"][0])
        self.assertNotIn("node_index", serialized_rows[0]["nodes"][1]["group_nodes"][0])


if __name__ == "__main__":
    unittest.main()
