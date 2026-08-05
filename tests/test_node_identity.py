import unittest

from services.node_identity import (
    find_subscription_node_index,
    subscription_node_id,
    subscription_node_ids,
)


class SubscriptionNodeIdentityTests(unittest.TestCase):
    def _node(self, name: str) -> dict:
        return {
            "name": name,
            "type": "vless",
            "server": "edge.example.com",
            "port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "tls": True,
        }

    def test_duplicate_technical_endpoints_get_unique_ui_ids(self):
        nodes = [self._node("CF官方优选1"), self._node("CF官方优选2")]

        node_ids = subscription_node_ids("sub_cf", nodes)

        self.assertEqual(len(set(node_ids)), 2)
        self.assertNotEqual(node_ids[0], subscription_node_id("sub_cf", nodes[0]))
        self.assertEqual(find_subscription_node_index(nodes, "sub_cf", node_ids[0]), 0)
        self.assertEqual(find_subscription_node_index(nodes, "sub_cf", node_ids[1]), 1)

    def test_exact_duplicate_names_are_disambiguated_by_occurrence(self):
        nodes = [self._node("CF官方优选"), self._node("CF官方优选")]

        node_ids = subscription_node_ids("sub_cf", nodes)

        self.assertEqual(len(set(node_ids)), 2)
        self.assertEqual(find_subscription_node_index(nodes, "sub_cf", node_ids[0]), 0)
        self.assertEqual(find_subscription_node_index(nodes, "sub_cf", node_ids[1]), 1)

    def test_unique_node_keeps_legacy_stable_id(self):
        nodes = [self._node("唯一节点")]

        self.assertEqual(
            subscription_node_ids("sub_cf", nodes),
            [subscription_node_id("sub_cf", nodes[0])],
        )

    def test_trojan_sni_aliases_keep_the_same_stable_id(self):
        sni_node = {
            "name": "Trojan",
            "type": "trojan",
            "server": "edge.example.com",
            "port": 443,
            "password": "secret",
            "sni": "cdn.example.com",
        }
        legacy_node = dict(sni_node)
        legacy_node.pop("sni")
        legacy_node["servername"] = "cdn.example.com"

        self.assertEqual(
            subscription_node_id("sub_cf", sni_node),
            subscription_node_id("sub_cf", legacy_node),
        )


if __name__ == "__main__":
    unittest.main()
