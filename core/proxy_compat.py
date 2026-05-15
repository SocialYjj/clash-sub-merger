"""
Proxy compatibility migrations.

Keep these helpers free of service-layer imports so they can be used while
loading both config.json and subscription YAML files.
"""
from __future__ import annotations

from typing import Any, Iterable


XHTTP_LEGACY_FIELD_MAP = {
    "xhttp-mode": "mode",
    "path": "path",
    "host": "host",
}


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


def normalize_proxy_list(proxies: Iterable[Any]) -> int:
    """Normalize xhttp nodes in a proxy iterable in place; return change count."""
    changed = 0
    if not isinstance(proxies, list):
        return changed

    for proxy in proxies:
        if isinstance(proxy, dict) and normalize_xhttp_proxy(proxy):
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
