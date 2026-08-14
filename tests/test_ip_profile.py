import unittest

from geoip_service import _build_provider_result, _extract_provider_metadata, normalize_ippure_profile


class IPProfileNormalizationTests(unittest.TestCase):
    def test_extracts_ip_api_network_metadata(self):
        metadata = _extract_provider_metadata({
            "as": "AS15169",
            "asname": "Google LLC",
            "org": "Google LLC",
            "isp": "Google LLC",
            "hosting": True,
            "mobile": False,
            "proxy": False,
        })

        self.assertEqual(metadata["asn"], "AS15169")
        self.assertEqual(metadata["asn_org"], "Google LLC")
        self.assertEqual(metadata["isp"], "Google LLC")
        self.assertTrue(metadata["is_hosting"])
        self.assertFalse(metadata["is_mobile"])
        self.assertFalse(metadata["is_proxy"])

    def test_extracts_ipinfo_asn_from_org_string(self):
        metadata = _extract_provider_metadata({
            "org": "AS15169 Google LLC",
            "is_hosting": True,
            "is_mobile": False,
        })

        self.assertEqual(metadata["asn"], "AS15169")
        self.assertEqual(metadata["asn_org"], "Google LLC")
        self.assertTrue(metadata["is_hosting"])

    def test_normalizes_ippure_broadcast_and_residential_flags(self):
        profile = normalize_ippure_profile({
            "ip": "203.0.113.10",
            "isBroadcast": False,
            "isResidential": True,
            "fraudScore": 12,
        })

        self.assertEqual(profile["ip"], "203.0.113.10")
        self.assertFalse(profile["is_broadcast"])
        self.assertTrue(profile["is_residential"])
        self.assertEqual(profile["ip_source"], "native")
        self.assertEqual(profile["network_type"], "residential")
        self.assertEqual(profile["fraud_score"], 12)

    def test_missing_ippure_flags_remain_unknown(self):
        profile = normalize_ippure_profile({"ip": "203.0.113.10"})

        self.assertEqual(profile["ip"], "203.0.113.10")
        self.assertNotIn("ip_source", profile)
        self.assertNotIn("network_type", profile)

    def test_preserves_provider_region_for_ip_profile(self):
        result = _build_provider_result(
            {"as": "AS64500", "org": "Example"},
            "US",
            "美国",
            "纽约",
            "纽约州",
        )

        self.assertEqual(result["region"], "纽约州")
        self.assertEqual(result["asn"], "AS64500")


if __name__ == "__main__":
    unittest.main()
