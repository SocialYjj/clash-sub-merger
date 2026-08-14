"""
Proxy compatibility migrations.

Keep these helpers free of service-layer imports so they can be used while
loading both config.json and subscription YAML files.
"""
from __future__ import annotations

import base64
import re
from typing import Any, Iterable


XHTTP_LEGACY_FIELD_MAP = {
    "xhttp-mode": "mode",
    "path": "path",
    "host": "host",
}


def is_mihomo_certificate_fingerprint(value: Any) -> bool:
    """Return whether a value is a Mihomo-compatible SHA-256 fingerprint."""
    compact = str(value or "").strip().replace(":", "")
    return re.fullmatch(r"[0-9A-Fa-f]{64}", compact) is not None


def decode_certificate_pin(value: Any) -> bytes | None:
    """Decode a v2rayN SHA-256 pin when it is a 32-byte Base64 value.

    v2rayN accepts both standard and URL-safe Base64 spellings, sometimes
    without padding.  Mihomo wants the same digest as lowercase hexadecimal,
    so only an unambiguous 32-byte digest is converted; arbitrary opaque
    values remain available for V2Ray export but are not emitted to Mihomo.
    """
    text = str(value or "").strip()
    if not text:
        return None

    normalized = text.replace("-", "+").replace("_", "/")
    padding = "=" * ((4 - len(normalized) % 4) % 4)
    try:
        decoded = base64.b64decode(normalized + padding, validate=True)
    except (ValueError, TypeError, base64.binascii.Error):
        return None
    return decoded if len(decoded) == 32 else None


def certificate_pin_fingerprint(value: Any) -> str | None:
    """Return the Mihomo hexadecimal form for a supported certificate pin."""
    text = str(value or "").strip()
    if is_mihomo_certificate_fingerprint(text):
        return text.replace(":", "").lower()
    decoded = decode_certificate_pin(text)
    return decoded.hex() if decoded is not None else None


def certificate_pins_equal(left: Any, right: Any) -> bool:
    """Compare certificate pins without confusing hex and Base64 spellings."""
    if left in (None, "") or right in (None, ""):
        return left in (None, "") and right in (None, "")
    left_text = str(left).strip()
    right_text = str(right).strip()
    if left_text == right_text:
        return True
    left_fingerprint = certificate_pin_fingerprint(left_text)
    right_fingerprint = certificate_pin_fingerprint(right_text)
    return (
        left_fingerprint is not None
        and right_fingerprint is not None
        and left_fingerprint == right_fingerprint
    )


def store_certificate_pin(proxy: dict, value: Any) -> bool:
    """Store a URI certificate pin without emitting an invalid Mihomo field.

    v2rayN accepts an opaque ``pinSHA256``/``pcs`` string, while Mihomo's
    ``fingerprint`` parser accepts only a 64-character hexadecimal SHA-256
    digest.  Keep non-Mihomo values in an internal field so V2Ray export can
    reproduce them, and so generated Clash YAML never contains an unusable
    fingerprint.
    """
    if not isinstance(proxy, dict) or value in (None, ""):
        return False
    text = str(value).strip()
    fingerprint = certificate_pin_fingerprint(text)
    if fingerprint is not None:
        proxy["fingerprint"] = fingerprint
        if not is_mihomo_certificate_fingerprint(text):
            # Preserve the source spelling so V2Ray export can reproduce the
            # exact pin instead of replacing Base64 with hexadecimal text.
            proxy["_v2rayn-certificate-pin"] = text
        else:
            proxy.pop("_v2rayn-certificate-pin", None)
    else:
        proxy.pop("fingerprint", None)
        proxy["_v2rayn-certificate-pin"] = text
    return True


def normalize_certificate_pin(proxy: dict) -> bool:
    """Migrate legacy opaque URI pins away from Mihomo's strict field."""
    if not isinstance(proxy, dict):
        return False

    before = dict(proxy)
    preserved = proxy.get("_v2rayn-certificate-pin")
    fingerprint = proxy.get("fingerprint")
    legacy_pin = proxy.get("ca-sha256")
    if (
        fingerprint not in (None, "")
        and legacy_pin not in (None, "")
        and not certificate_pins_equal(fingerprint, legacy_pin)
    ):
        # Leave conflicting aliases untouched so the structural validator can
        # report the conflict instead of choosing one value silently.
        return False
    if preserved not in (None, ""):
        preserved_fingerprint = certificate_pin_fingerprint(preserved)
        for explicit in (fingerprint, legacy_pin):
            if explicit in (None, ""):
                continue
            normalized_explicit = certificate_pin_fingerprint(explicit)
            if not certificate_pins_equal(explicit, preserved) and (
                preserved_fingerprint is None
                or normalized_explicit != preserved_fingerprint
            ):
                return False
        store_certificate_pin(proxy, preserved)
        return proxy != before

    for field in ("fingerprint", "ca-sha256"):
        value = proxy.get(field)
        if value in (None, ""):
            continue
        if field == "ca-sha256":
            # Keep a conflicting explicit fingerprint visible to validation.
            if proxy.get("fingerprint") not in (None, "") and not certificate_pins_equal(proxy["fingerprint"], value):
                return False
            proxy.pop("ca-sha256", None)
        store_certificate_pin(proxy, value)
        break
    return proxy != before


def _has_value(value: Any) -> bool:
    return value is not None and value != ""


def normalize_xhttp_proxy(proxy: dict) -> bool:
    """
    Normalize one xhttp proxy in place.

    Older app versions stored xhttp options as top-level fields:
    `xhttp-mode`, `path`, and `host`. Mihomo expects these under
    `xhttp-opts`. Return True if the proxy was changed.
    """
    if not isinstance(proxy, dict):
        return False

    network = str(proxy.get("network", "") or "").strip().lower()
    if network != "xhttp":
        return False

    before = dict(proxy)
    existing_opts = proxy.get("xhttp-opts")
    if isinstance(existing_opts, dict):
        xhttp_opts = dict(existing_opts)
    else:
        xhttp_opts = {}

    for legacy_key, opts_key in XHTTP_LEGACY_FIELD_MAP.items():
        legacy_value = proxy.pop(legacy_key, None)
        current_value = xhttp_opts.get(opts_key)
        if _has_value(legacy_value) and not _has_value(current_value):
            xhttp_opts[opts_key] = legacy_value

    xhttp_opts = {key: value for key, value in xhttp_opts.items() if _has_value(value)}
    if xhttp_opts:
        proxy["xhttp-opts"] = xhttp_opts
    else:
        proxy.pop("xhttp-opts", None)

    return proxy != before


def normalize_trojan_proxy(proxy: dict) -> bool:
    """Normalize legacy Trojan aliases and implicit WebSocket transport."""
    if not isinstance(proxy, dict):
        return False

    if str(proxy.get("type", "") or "").strip().lower() != "trojan":
        return False

    before = dict(proxy)
    if not _has_value(proxy.get("sni")):
        for alias in ("servername", "peer"):
            if _has_value(proxy.get(alias)):
                proxy["sni"] = proxy[alias]
                break
    proxy.pop("servername", None)
    proxy.pop("peer", None)

    # Some Clash providers omit ``network: ws`` while still supplying a
    # complete ``ws-opts`` mapping. Normalize that implicit form at the import
    # boundary instead of later exporting it as an unrelated TCP profile.
    ws_opts = proxy.get("ws-opts")
    if not _has_value(proxy.get("network")) and isinstance(ws_opts, dict) and ws_opts:
        proxy["network"] = "ws"
    return proxy != before


def normalize_v2ray_transport_proxy(proxy: dict) -> bool:
    """Normalize URI transport aliases to Mihomo's outbound schema.

    Mihomo represents HTTP Upgrade as WebSocket with an explicit option, and
    represents TCP HTTP camouflage as the ``http`` network with ``http-opts``.
    Keeping those aliases in a generated YAML makes the node look valid while
    the outbound adapter silently falls back to plain TCP.
    """
    if not isinstance(proxy, dict):
        return False

    proxy_type = str(proxy.get("type", "") or "").strip().lower()
    if proxy_type not in {"vmess", "vless", "trojan"}:
        return False

    before = dict(proxy)
    network = str(proxy.get("network", "") or "").strip().lower()

    if network in {"raw", "none"}:
        proxy["network"] = "tcp"
        network = "tcp"

    if network == "httpupgrade":
        proxy["network"] = "ws"
        ws_opts = proxy.get("ws-opts")
        if not isinstance(ws_opts, dict):
            ws_opts = {}
        else:
            ws_opts = dict(ws_opts)
        ws_opts["v2ray-http-upgrade"] = True
        if ws_opts.get("max-early-data") not in (None, ""):
            ws_opts.pop("max-early-data", None)
            ws_opts["v2ray-http-upgrade-fast-open"] = True
        proxy["ws-opts"] = ws_opts

    network = str(proxy.get("network", "") or "").strip().lower()
    if network == "grpc":
        grpc_opts = proxy.get("grpc-opts")
        if isinstance(grpc_opts, dict):
            grpc_opts = dict(grpc_opts)
            for mode_key in ("mode", "grpc-mode"):
                mode = str(grpc_opts.get(mode_key, "") or "").strip().lower()
                if mode in {"", "gun"}:
                    grpc_opts.pop(mode_key, None)
            if grpc_opts:
                proxy["grpc-opts"] = grpc_opts
            else:
                proxy.pop("grpc-opts", None)

    network = str(proxy.get("network", "") or "").strip().lower()
    if network == "tcp" and str(proxy.get("header-type", "") or "").strip().lower() == "http":
        if proxy_type != "trojan":
            proxy["network"] = "http"
            http_opts = proxy.get("http-opts")
            if not isinstance(http_opts, dict):
                http_opts = {}
            else:
                http_opts = dict(http_opts)
            path = proxy.pop("path", None)
            host = proxy.pop("host", None)
            if path not in (None, ""):
                http_opts.setdefault("path", [path] if not isinstance(path, list) else path)
            else:
                http_opts.setdefault("path", ["/"])
            if host not in (None, ""):
                headers = http_opts.get("headers")
                if not isinstance(headers, dict):
                    headers = {}
                else:
                    headers = dict(headers)
                headers.setdefault("Host", [host] if not isinstance(host, list) else host)
                http_opts["headers"] = headers
            proxy["http-opts"] = http_opts
            proxy.pop("header-type", None)

    return proxy != before


def normalize_alpn(proxy: dict) -> bool:
    """Normalize a scalar ALPN value to Mihomo's list form.

    URI parsers commonly produce a single string for ``alpn=h3`` while
    Mihomo's outbound options are declared as ``[]string``.  Keeping both
    representations in stored YAML makes later adapters disagree about the
    node's TLS profile, so normalize once at the import boundary.
    """
    if not isinstance(proxy, dict):
        return False

    value = proxy.get("alpn")
    if isinstance(value, str):
        values = [item.strip() for item in value.split(",") if item.strip()]
        if values:
            proxy["alpn"] = values
        else:
            proxy.pop("alpn", None)
        return True
    return False


def normalize_proxy_list(proxies: Iterable[Any]) -> int:
    """Normalize compatibility fields in a proxy iterable in place."""
    changed = 0
    if not isinstance(proxies, list):
        return changed

    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        node_changed = normalize_xhttp_proxy(proxy)
        node_changed = normalize_trojan_proxy(proxy) or node_changed
        node_changed = normalize_v2ray_transport_proxy(proxy) or node_changed
        node_changed = normalize_alpn(proxy) or node_changed
        node_changed = normalize_certificate_pin(proxy) or node_changed
        if node_changed:
            changed += 1
    return changed


def normalize_config_nodes(config: dict) -> int:
    """Normalize xhttp nodes stored inside config.json-compatible data."""
    if not isinstance(config, dict):
        return 0
    return normalize_proxy_list(config.get("custom_nodes", []))


def normalize_subscription_data(data: dict) -> int:
    """Normalize xhttp nodes inside a parsed Clash subscription YAML dict."""
    if not isinstance(data, dict):
        return 0
    return normalize_proxy_list(data.get("proxies", []))
