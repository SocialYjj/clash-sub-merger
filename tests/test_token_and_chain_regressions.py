import unittest
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

import api.admin_tokens as admin_tokens_api
from api.admin_tokens import CreateAdminToken
from api.proxy_chains import ProxyChainNode
from core.dependencies import verify_admin_or_user_token
from core.token_utils import ensure_subscription_token_unique, normalize_custom_subscription_token
from helpers import generate_timestamp_id


class TokenAndChainRegressionTests(unittest.TestCase):
    def test_timestamp_ids_keep_time_prefix_but_add_entropy(self):
        with (
            patch("helpers.time.time", return_value=123.456789),
            patch("helpers.secrets.token_hex", side_effect=["aaaaaaaa", "bbbbbbbb"]),
        ):
            first = generate_timestamp_id("sub_")
            second = generate_timestamp_id("sub_")

        self.assertEqual(first, "sub_123456_aaaaaaaa")
        self.assertEqual(second, "sub_123456_bbbbbbbb")
        self.assertNotEqual(first, second)

    def test_proxy_chain_group_preserves_advanced_group_options(self):
        node = ProxyChainNode(
            type="group",
            group_id="grp_1",
            group_name="落地池",
            group_strategy="url-test",
            group_url="https://cp.cloudflare.com/generate_204",
            group_interval="120",
            group_tolerance="20",
            group_nodes=[{
                "type": "node",
                "sub_id": "sub_1",
                "node_id": "node_stable",
                "node_name": "Node",
            }],
        )

        dumped = node.model_dump(exclude_none=True)

        self.assertEqual(dumped["group_url"], "https://cp.cloudflare.com/generate_204")
        self.assertEqual(dumped["group_interval"], 120)
        self.assertEqual(dumped["group_tolerance"], 20)

    def test_vpngate_group_normalizes_country_code_and_rejects_it_for_static_groups(self):
        dynamic_group = ProxyChainNode(
            type="group",
            group_id="vpngate-jp",
            group_name="VPN Gate 日本池",
            group_source="vpngate",
            vpngate_country_code="jp",
        )

        self.assertEqual(dynamic_group.vpngate_country_code, "JP")

        with self.assertRaises(ValidationError):
            ProxyChainNode(
                type="group",
                group_id="static-group",
                group_name="静态池",
                group_source="nodes",
                vpngate_country_code="JP",
                group_nodes=[{
                    "type": "node",
                    "sub_id": "sub_1",
                    "node_id": "node_stable",
                    "node_name": "Node",
                }],
            )

    def test_proxy_chain_node_rejects_unknown_fields_instead_of_silently_dropping(self):
        with self.assertRaises(ValidationError):
            ProxyChainNode(type="group", unknown_field="will-not-be-silently-dropped")

    def test_create_admin_token_accepts_custom_token_field(self):
        data = CreateAdminToken(name="custom", custom_token="MY_CUSTOM_TOKEN")

        self.assertEqual(data.custom_token, "MY_CUSTOM_TOKEN")

    def test_admin_token_ids_do_not_reuse_template_prefix(self):
        config = {"auth": {}, "templates": [], "admin_tokens": [], "users": []}

        def update_config(mutator):
            return mutator(config)

        with (
            patch.object(admin_tokens_api, "update_config", side_effect=update_config),
            patch.object(admin_tokens_api, "generate_timestamp_id", return_value="adm_123_entropy") as gen_id,
            patch.object(admin_tokens_api, "generate_unique_subscription_token", return_value="sub-token-value"),
        ):
            response = admin_tokens_api.create_admin_token(CreateAdminToken(name="admin"), _=True)

        gen_id.assert_called_once_with("adm_")
        self.assertEqual(response["token"]["id"], "adm_123_entropy")
        self.assertFalse(response["token"]["id"].startswith("tpl_"))

    def test_custom_token_collision_checks_admin_user_and_legacy_tokens(self):
        config = {
            "auth": {"sub_token": "legacy-token"},
            "admin_tokens": [{"id": "admin_1", "name": "admin", "token": "admin-token"}],
            "users": [{"id": "user_1", "name": "user", "token": "user-token"}],
        }

        for token in ("legacy-token", "admin-token", "user-token"):
            with self.assertRaises(HTTPException):
                ensure_subscription_token_unique(config, token)

        self.assertEqual(ensure_subscription_token_unique(config, "new-token"), "new-token")

    def test_custom_token_validation_trims_and_enforces_minimum_length(self):
        self.assertEqual(normalize_custom_subscription_token("  abcdefgh  "), "abcdefgh")
        self.assertIsNone(normalize_custom_subscription_token("   "))

        with self.assertRaises(HTTPException):
            normalize_custom_subscription_token("short")

    def test_subscription_output_auth_can_use_shared_token_verifier_with_supplied_config(self):
        user = {"id": "u1", "name": "User", "token": "user-token", "enabled": True}
        config = {"auth": {}, "admin_tokens": [], "users": [user]}

        result = verify_admin_or_user_token("user-token", config=config)

        self.assertEqual(result["type"], "user")
        self.assertEqual(result["user_info"], user)


if __name__ == "__main__":
    unittest.main()
