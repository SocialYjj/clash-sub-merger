"""Shared helpers for generated proxy-chain group names and strategies."""

import re
from collections.abc import MutableSet


VALID_GROUP_STRATEGIES = {"url-test", "fallback", "load-balance"}
VALID_LOAD_BALANCE_STRATEGIES = {"round-robin", "consistent-hashing", "sticky-sessions"}
DEFAULT_GROUP_URL = "https://cp.cloudflare.com/generate_204"
DEFAULT_GROUP_INTERVAL = 300
DEFAULT_GROUP_TOLERANCE = 50
DEFAULT_LOAD_BALANCE_STRATEGY = "round-robin"


def group_id_suffix(group_id: str | None) -> str:
    """Return a stable short suffix for a group id.

    Only alphanumeric characters are kept so generated Clash group names stay
    compact and safe, e.g. ``grp_ab-cd_1234`` -> ``1234``.
    """
    if not group_id:
        return ""
    clean = re.sub(r"[^A-Za-z0-9]", "", group_id)
    return clean[-4:] if clean else ""


def unique_name(base: str, existing_names: MutableSet[str]) -> str:
    """Return ``base`` or append ``(2)``, ``(3)`` ... while mutating the set."""
    if base not in existing_names:
        existing_names.add(base)
        return base

    idx = 2
    while f"{base} ({idx})" in existing_names:
        idx += 1

    name = f"{base} ({idx})"
    existing_names.add(name)
    return name


def unique_group_name(
    base: str,
    existing_group_names: MutableSet[str],
    group_id: str | None = None,
) -> str:
    """Return a unique proxy-chain group name.

    When the plain base name already exists and a stable ``group_id`` is
    available, prefer a short id suffix before falling back to numeric suffixes.
    This keeps regenerated chain pool names stable across settings,
    allocation-preview, and subscription-output code paths.
    """
    if base not in existing_group_names:
        existing_group_names.add(base)
        return base

    suffix = group_id_suffix(group_id)
    if suffix:
        candidate = f"{base} ({suffix})"
        if candidate not in existing_group_names:
            existing_group_names.add(candidate)
            return candidate

    return unique_name(base, existing_group_names)


def coerce_group_strategy(spec: dict) -> dict:
    """Normalize a proxy-chain group node's Clash/Mihomo group strategy."""
    strategy = (spec.get("group_strategy") or "load-balance").strip()
    strategy = strategy if strategy in VALID_GROUP_STRATEGIES else "load-balance"

    group_cfg = {"type": strategy}

    if strategy in {"url-test", "fallback"}:
        group_cfg["url"] = spec.get("group_url") or DEFAULT_GROUP_URL
        group_cfg["interval"] = int(spec.get("group_interval") or DEFAULT_GROUP_INTERVAL)

    if strategy == "url-test":
        group_cfg["tolerance"] = int(spec.get("group_tolerance") or DEFAULT_GROUP_TOLERANCE)

    if strategy == "load-balance":
        lb_strategy = (spec.get("lb_strategy") or DEFAULT_LOAD_BALANCE_STRATEGY).strip()
        if lb_strategy not in VALID_LOAD_BALANCE_STRATEGIES:
            lb_strategy = DEFAULT_LOAD_BALANCE_STRATEGY
        group_cfg["strategy"] = lb_strategy

    return group_cfg
