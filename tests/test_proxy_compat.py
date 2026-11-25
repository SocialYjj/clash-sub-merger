import unittest

from core.proxy_compat import (
    certificate_pin_fingerprint,
    certificate_pins_equal,
    normalize_config_nodes,
    normalize_subscription_data,
    normalize_xhttp_proxy,
    store_certificate_pin,
)


class ProxyCompatTests(unittest.TestCase):
    def test_store_certificate_pin_converts_base64_sha256_and_preserves_source(self):
        import base64

        digest = bytes(range(32))
        source = base64.b64encode(digest).decode()
        proxy = {}

        self.assertTrue(store_certificate_pin(proxy, source))
        self.assertEqual(proxy["fingerprint"], digest.hex())
        self.assertEqual(proxy["_v2rayn-certificate-pin"], source)
        self.assertEqual(certificate_pin_fingerprint(source), digest.hex())
        self.assertTrue(certificate_pins_equal(source, digest.hex()))

    def test_store_certificate_pin_keeps_opaque_value_out_of_mihomo_fields(self):
        proxy = {}

        self.assertTrue(store_certificate_pin(proxy, "opaque-pin+/="))
        self.assertNotIn("fingerprint", proxy)
        self.assertEqual(proxy["_v2rayn-certificate-pin"], "opaque-pin+/=")

    def test_normalize_xhttp_proxy_moves_legacy_fields_to_xhttp_opts(self):
        proxy = {
            "name": "legacy-xhttp",
            "type": "vless",
            "network": "xhttp",
            "xhttp-mode": "stream-up",
            "path": "/xhttp",
            "host": "www.apple.com",
        }

        changed = normalize_xhttp_proxy(proxy)

        self.assertTrue(changed)
        self.assertEqual(
            proxy["xhttp-opts"],
            {"mode": "stream-up", "path": "/xhttp", "host": "www.apple.com"},
        )
        self.assertNotIn("xhttp-mode", proxy)
        self.assertNotIn("path", proxy)
        self.assertNotIn("host", proxy)

    def test_normalize_xhttp_proxy_preserves_existing_xhttp_opts(self):
        proxy = {
            "network": "xhttp",
            "xhttp-mode": "auto",
            "path": "/legacy",
            "xhttp-opts": {"mode": "stream-up", "path": "/current"},
        }

        changed = normalize_xhttp_proxy(proxy)

        self.assertTrue(changed)
        self.assertEqual(proxy["xhttp-opts"], {"mode": "stream-up", "path": "/current"})

    def test_non_xhttp_proxy_keeps_top_level_path(self):
        proxy = {"network": "ws", "path": "/ws", "host": "example.com"}

        changed = normalize_xhttp_proxy(proxy)

        self.assertFalse(changed)
        self.assertEqual(proxy["path"], "/ws")
        self.assertEqual(proxy["host"], "example.com")

    def test_normalize_config_nodes_updates_custom_nodes(self):
        config = {
            "custom_nodes": [
                {"network": "xhttp", "xhttp-mode": "auto", "path": "/custom"},
                {"network": "ws", "path": "/ws"},
            ]
        }

        changed_count = normalize_config_nodes(config)

        self.assertEqual(changed_count, 1)
        self.assertEqual(config["custom_nodes"][0]["xhttp-opts"], {"mode": "auto", "path": "/custom"})
        self.assertEqual(config["custom_nodes"][1]["path"], "/ws")

    def test_normalize_subscription_data_updates_proxies(self):
        data = {
            "proxies": [
                {"network": "xhttp", "xhttp-mode": "auto", "path": "/sub"},
            ]
        }

        changed_count = normalize_subscription_data(data)

        self.assertEqual(changed_count, 1)
        self.assertEqual(data["proxies"][0]["xhttp-opts"], {"mode": "auto", "path": "/sub"})

    def test_normalize_subscription_data_migrates_trojan_servername(self):
        data = {
            "proxies": [
                {
                    "type": "trojan",
                    "server": "example.com",
                    "port": 443,
                    "password": "secret",
                    "servername": "cdn.example.com",
                }
            ]
        }

        changed = normalize_subscription_data(data)

        self.assertEqual(changed, 1)
        self.assertEqual(data["proxies"][0]["sni"], "cdn.example.com")
        self.assertNotIn("servername", data["proxies"][0])

    def test_normalize_subscription_data_infers_trojan_websocket_transport(self):
        proxy = {
            "name": "Trojan WS",
            "type": "trojan",
            "server": "example.com",
            "port": 443,
            "password": "secret",
            "ws-opts": {"path": "/ws", "headers": {"Host": "cdn.example.com"}},
        }
        data = {"proxies": [proxy]}

        changed = normalize_subscription_data(data)

        self.assertEqual(changed, 1)
        self.assertEqual(proxy["network"], "ws")

    def test_normalize_subscription_data_opts_reality_nodes_into_mlkem(self):
        vless = {
            "name": "reality",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "tls": True,
            "reality-opts": {"public-key": "public-key", "short-id": "6b33f269"},
        }
        trojan = {
            "name": "reality-trojan",
            "type": "trojan",
            "server": "example.com",
            "port": 443,
            "tls": True,
            "reality-opts": {"public-key": "public-key"},
        }
        data = {"proxies": [vless, trojan]}

        changed = normalize_subscription_data(data)

        self.assertEqual(changed, 2)
        self.assertIs(vless["reality-opts"]["support-x25519mlkem768"], True)
        self.assertIs(trojan["reality-opts"]["support-x25519mlkem768"], True)
        # Second pass is a no-op, so repeated imports do not churn the config.
        self.assertEqual(normalize_subscription_data(data), 0)

    def test_normalize_subscription_data_keeps_explicit_mlkem_opt_out(self):
        proxy = {
            "name": "reality-legacy",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "tls": True,
            "reality-opts": {
                "public-key": "public-key",
                "support-x25519mlkem768": False,
            },
        }
        data = {"proxies": [proxy]}

        self.assertEqual(normalize_subscription_data(data), 0)
        self.assertIs(proxy["reality-opts"]["support-x25519mlkem768"], False)

    def test_normalize_reality_mlkem_skips_nodes_without_usable_reality(self):
        proxies = [
            {
                "name": "plain-tls",
                "type": "vless",
                "server": "example.com",
                "port": 443,
                "tls": True,
            },
            {
                "name": "no-key",
                "type": "vless",
                "server": "example.com",
                "port": 443,
                "tls": True,
                "reality-opts": {"short-id": "6b33f269"},
            },
            {
                "name": "vmess-reality",
                "type": "vmess",
                "server": "example.com",
                "port": 443,
                "reality-opts": {"public-key": "public-key"},
            },
        ]
        data = {"proxies": proxies}

        self.assertEqual(normalize_subscription_data(data), 0)
        for proxy in proxies:
            self.assertNotIn("support-x25519mlkem768", proxy.get("reality-opts") or {})


class CoreDatabaseCompatibilityTests(unittest.TestCase):
    def test_load_config_normalizes_xhttp_nodes_and_returns_deepcopy(self):
        import json
        import tempfile
        from pathlib import Path

        import core.database as database

        original_config_file = database.CONFIG_FILE
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                config_file = Path(tmpdir) / "config.json"
                config_file.write_text(
                    json.dumps(
                        {
                            "auth": {},
                            "subscriptions": [],
                            "custom_nodes": [
                                {
                                    "name": "legacy-xhttp",
                                    "type": "vless",
                                    "network": "xhttp",
                                    "xhttp-mode": "stream-up",
                                    "path": "/xhttp",
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )

                database.CONFIG_FILE = str(config_file)
                database.invalidate_config_cache()

                config = database.load_config()
                self.assertIn("proxy_chains", config)
                self.assertEqual(
                    config["custom_nodes"][0]["xhttp-opts"],
                    {"mode": "stream-up", "path": "/xhttp"},
                )
                self.assertNotIn("xhttp-mode", config["custom_nodes"][0])
                self.assertNotIn("path", config["custom_nodes"][0])

                config["custom_nodes"][0]["name"] = "mutated"
                fresh_config = database.load_config()
                self.assertEqual(fresh_config["custom_nodes"][0]["name"], "legacy-xhttp")
        finally:
            database.CONFIG_FILE = original_config_file
            database.invalidate_config_cache()


if __name__ == "__main__":
    unittest.main()
