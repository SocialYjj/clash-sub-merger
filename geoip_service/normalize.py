"""
Normalization helpers for GeoIP provider payloads, cached results and country
/ city labels.  Also hosts the Traditional-to-Simplified converter and the
:class:`GeoIPService` static utility class.
"""

import re
import time
from typing import Dict, Optional

import geoip_service as _PKG
from logger_config import get_logger
from translation_service import get_cached_translation

# Setup logger
logger = get_logger(__name__)

# Traditional to Simplified Chinese converter
try:
    from opencc import OpenCC

    _t2s_converter = OpenCC("t2s")  # Traditional to Simplified

    def convert_to_simplified(text: str) -> str:
        """Convert Traditional Chinese to Simplified Chinese"""
        if not text:
            return text
        return _t2s_converter.convert(text)
except ImportError:

    def convert_to_simplified(text: str) -> str:
        """Fallback: return text as-is if opencc not available"""
        return text


def _coerce_optional_bool(value) -> Optional[bool]:
    """Normalize provider boolean variants without turning missing into false."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value).strip().lower()
    if normalized in {"true", "yes", "y", "1", "on"}:
        return True
    if normalized in {"false", "no", "n", "0", "off"}:
        return False
    return None


def _coerce_optional_number(value):
    """Normalize numeric risk fields while preserving unavailable values."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return int(parsed) if parsed.is_integer() else parsed


def _normalize_asn_value(value) -> Optional[str]:
    """Extract a stable AS number from provider-specific values."""
    if isinstance(value, dict):
        value = value.get("asn") or value.get("as_number") or value.get("number") or value.get("name")
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    match = re.search(r"\bAS\s*\d+\b", text, flags=re.IGNORECASE)
    return match.group(0).replace(" ", "").upper() if match else text


def _strip_asn_prefix(value: Optional[str]) -> Optional[str]:
    """Remove a leading AS number from an organization string."""
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    return re.sub(r"^AS\s*\d+\s*[-:]?\s*", "", text, flags=re.IGNORECASE) or text


def _extract_provider_metadata(data: dict) -> Dict:
    """Extract stable ASN/network fields shared by GeoIP providers."""
    if not isinstance(data, dict):
        return {}

    raw_asn = _PKG._first_json_value(
        data,
        (
            "asn.as_number",
            "asn.number",
            "asn",
            "as",
            "asn_number",
            "network.asn",
        ),
    )
    raw_org = _PKG._first_json_value(
        data,
        (
            "asn.organization",
            "asn.org",
            "asname",
            "org",
            "organization",
            "company.name",
            "company.organization",
            "network.organization",
        ),
    )
    raw_isp = _PKG._first_json_value(
        data,
        (
            "isp",
            "company.name",
            "organization",
            "org",
        ),
    )

    asn = _normalize_asn_value(raw_asn)
    if not asn and raw_org is not None:
        asn = _normalize_asn_value(raw_org)
    metadata = {
        "asn": asn,
        "asn_org": _strip_asn_prefix(str(raw_org)) if raw_org is not None else None,
        "isp": str(raw_isp).strip() if raw_isp not in (None, "") else None,
        "is_hosting": _coerce_optional_bool(
            _PKG._first_json_value(
                data,
                (
                    "hosting",
                    "is_hosting",
                    "isHosting",
                    "is_datacenter",
                    "isDataCenter",
                    "security.is_cloud_provider",
                    "security.isCloudProvider",
                ),
            )
        ),
        "is_mobile": _coerce_optional_bool(
            _PKG._first_json_value(
                data,
                (
                    "mobile",
                    "is_mobile",
                    "isMobile",
                    "network.is_mobile",
                ),
            )
        ),
        "is_proxy": _coerce_optional_bool(
            _PKG._first_json_value(
                data,
                (
                    "proxy",
                    "is_proxy",
                    "isProxy",
                    "security.is_proxy",
                    "security.isProxy",
                ),
            )
        ),
        "is_vpn": _coerce_optional_bool(
            _PKG._first_json_value(
                data,
                (
                    "vpn",
                    "is_vpn",
                    "isVpn",
                    "security.is_vpn",
                    "security.isVpn",
                ),
            )
        ),
        "is_tor": _coerce_optional_bool(
            _PKG._first_json_value(
                data,
                (
                    "tor",
                    "is_tor",
                    "isTor",
                    "security.is_tor",
                    "security.isTor",
                ),
            )
        ),
        "fraud_score": _coerce_optional_number(
            _PKG._first_json_value(
                data,
                (
                    "fraudScore",
                    "fraud_score",
                    "security.fraud_score",
                    "security.threat_score",
                ),
            )
        ),
    }

    # Remove empty values so a failed/partial provider cannot overwrite a
    # successful value from another provider or an older cached result.
    return {key: value for key, value in metadata.items() if value is not None}


def _build_provider_result(
    data: dict,
    country_code: str,
    country: str,
    city: str,
    region: str = "",
) -> Dict:
    """Build the normalized provider payload consumed by the online lookup."""
    return {
        "countryCode": country_code or "",
        "country": country or "",
        "region": region or "",
        "city": city or "",
        **_extract_provider_metadata(data),
    }


def normalize_ippure_profile(data: dict, exit_ip: Optional[str] = None) -> Optional[Dict]:
    """Normalize the small IPPure response used by node IP intelligence."""
    if not isinstance(data, dict):
        return None

    is_broadcast = _coerce_optional_bool(data.get("isBroadcast", data.get("is_broadcast")))
    is_residential = _coerce_optional_bool(data.get("isResidential", data.get("is_residential")))
    fraud_score = _coerce_optional_number(data.get("fraudScore", data.get("fraud_score")))
    response_ip = str(data.get("ip") or exit_ip or "").strip()

    if not response_ip and is_broadcast is None and is_residential is None and fraud_score is None:
        return None

    profile = {
        "ip": response_ip or None,
        "is_broadcast": is_broadcast,
        "is_residential": is_residential,
        "fraud_score": fraud_score,
        "source": "ippure",
        "checked_at": time.time(),
    }
    if is_broadcast is not None:
        profile["ip_source"] = "broadcast" if is_broadcast else "native"
    if is_residential is not None:
        profile["network_type"] = "residential" if is_residential else "datacenter"
    return {key: value for key, value in profile.items() if value is not None}


def normalize_country_name(country_name: str, iso_code: str = "") -> str:
    """Normalize provider output to the canonical Chinese country label."""
    source_text = str(country_name or "").strip()
    normalized_code = str(iso_code or "").strip().upper()
    try:
        from services.name_transformer import NameTransformer

        normalized_code, canonical_name = NameTransformer.canonical_country_name(
            source_text,
            normalized_code,
        )
    except Exception:
        canonical_name = None
    if canonical_name and normalized_code != "XX":
        # A saved GeoIP result may contain an older alias such as ``香港``.
        # The ISO code is the stable identity, so prefer the canonical label
        # for that code whenever it is available.
        return canonical_name

    text = convert_to_simplified(get_cached_translation(source_text, "country") or source_text)
    return text or normalized_code


def _normalize_geo_result_fields(iso_code: str, country_name: str, city_name: str) -> Dict[str, Optional[str]]:
    """Apply unified country and city normalization to GeoIP results."""
    code = (iso_code or "").upper()
    display_country = normalize_country_name(country_name, code)
    translated_city = convert_to_simplified(str(city_name or "").strip())

    if translated_city and translated_city in display_country:
        translated_city = None

    return {
        "iso_code": code,
        "country_name": display_country,
        "city": translated_city or None,
        "flag": GeoIPService.iso_to_flag(code),
    }


class GeoIPService:
    """Static utility class for GeoIP-related functions (flag conversion, etc.)"""

    @staticmethod
    def iso_to_flag(iso_code: str) -> str:
        """
        Convert ISO 3166-1 alpha-2 country code to flag emoji
        Example: "US" -> "🇺🇸", "CN" -> "🇨🇳"

        Uses Unicode Regional Indicator Symbols:
        - 'A' (U+0041) maps to 🇦 (U+1F1E6)
        - 'Z' (U+005A) maps to 🇿 (U+1F1FF)
        """
        if not iso_code or len(iso_code) != 2:
            return "🌐"

        try:
            # Convert each letter to regional indicator symbol
            # Regional indicators start at U+1F1E6 for 'A'
            flag = ""
            for char in iso_code.upper():
                if "A" <= char <= "Z":
                    # Calculate offset from 'A' and add to base regional indicator
                    flag += chr(0x1F1E6 + ord(char) - ord("A"))
                else:
                    return "🌐"
            return flag
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid ISO code for flag conversion: {iso_code}, error: {e}")
            return "🌐"
        except Exception as e:
            logger.error(f"Error converting ISO to flag: {e}")
            return "🌐"

    @staticmethod
    def flag_to_iso(flag: str) -> Optional[str]:
        """
        Convert flag emoji back to ISO country code
        Example: "🇺🇸" -> "US"
        """
        if not flag or len(flag) < 1:
            return None

        try:
            # Each flag emoji is 2 regional indicator symbols
            # Regional indicator 🇦 (U+1F1E6) to 🇿 (U+1F1FF)
            iso = ""
            for char in flag:
                cp = ord(char)
                if 0x1F1E6 <= cp <= 0x1F1FF:
                    iso += chr(ord("A") + cp - 0x1F1E6)

            if len(iso) == 2:
                return iso
            return None
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid flag emoji for ISO conversion: {flag}, error: {e}")
            return None
        except Exception as e:
            logger.error(f"Error converting flag to ISO: {e}")
            return None
