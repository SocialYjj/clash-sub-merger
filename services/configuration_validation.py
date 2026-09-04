"""Validation and normalization for complete configuration migration data."""

from __future__ import annotations

import base64
from copy import deepcopy
import re
from urllib.parse import urlsplit

from services.node_reference_migration import ensure_custom_node_ids
from services.proxy_chain_references import (
    CHAIN_NODE_SOURCE,
    CHAIN_POOL_SOURCE,
    ensure_proxy_chain_component_ids,
    list_proxy_chain_virtual_references,
)
from services.node_pool_references import (
    NODE_POOL_SOURCE,
    VALID_NODE_POOL_LOAD_BALANCE_STRATEGIES,
    VALID_NODE_POOL_STRATEGIES,
    ensure_node_pool_ids,
    list_node_pool_virtual_references,
)
from services.vpngate import (
    VPNGATE_MAX_INTERVAL_MINUTES,
    VPNGATE_MAX_MAX_NODES,
    VPNGATE_MIN_INTERVAL_MINUTES,
    VPNGATE_MIN_MAX_NODES,
    VPNGATE_SOURCE_ID,
)


_SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
_COLLECTIONS = (
    "subscriptions",
    "custom_nodes",
    "users",
    "templates",
    "admin_tokens",
    "proxy_chains",
    "node_pools",
    "source_order",
)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~-]{8,200}$")


def _require_list(config: dict, key: str) -> list:
    value = config.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"Imported {key} must be a list")
    return value


def _validate_identifier(value: object, field_name: str) -> str:
    identifier = str(value or "").strip()
    if not _SAFE_ID.fullmatch(identifier):
        raise ValueError(f"Imported {field_name} is invalid")
    return identifier


def _validate_unique_ids(items: list, collection_name: str, *, allow_missing: bool = False) -> set[str]:
    identifiers: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError(f"Imported {collection_name} contains an invalid item")
        raw_identifier = item.get("id")
        if allow_missing and not raw_identifier:
            continue
        identifier = _validate_identifier(raw_identifier, f"{collection_name} ID")
        if identifier in identifiers:
            raise ValueError(f"Imported {collection_name} contains duplicate IDs")
        item["id"] = identifier
        identifiers.add(identifier)
    return identifiers


def _validate_subscription_records(subscriptions: list) -> set[str]:
    identifiers = _validate_unique_ids(subscriptions, "subscriptions")
    names: set[str] = set()
    urls: set[str] = set()
    for subscription in subscriptions:
        name = str(subscription.get("name") or "").strip()
        if not name or len(name) > 200:
            raise ValueError("Imported subscription name is invalid")
        name_key = name.casefold()
        if name_key in names:
            raise ValueError("Imported subscriptions contain duplicate names")
        names.add(name_key)
        subscription["name"] = name

        subscription_type = subscription.get("type", "remote")
        if subscription_type not in {"remote", "url", "local"}:
            raise ValueError("Imported subscription type is invalid")
        if "enabled" in subscription and not isinstance(subscription.get("enabled"), bool):
            raise ValueError("Imported subscription enabled flag is invalid")
        if subscription_type == "local":
            continue
        url = str(subscription.get("url") or "").strip()
        if not url or len(url) > 4096:
            raise ValueError("Imported remote subscription URL is invalid")
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Imported remote subscription URL must use HTTP or HTTPS")
        if url in urls:
            raise ValueError("Imported subscriptions contain duplicate URLs")
        urls.add(url)
        subscription["url"] = url
    return identifiers


def _validate_auth(config: dict) -> None:
    auth = config.get("auth", {})
    password_hash = auth.get("password_hash")
    if not isinstance(password_hash, str) or not password_hash:
        raise ValueError("Imported configuration has no administrator password hash")
    if re.fullmatch(r"[0-9a-fA-F]{64}", password_hash):
        return
    try:
        scheme, iterations_raw, salt, digest_b64 = password_hash.split("$", 3)
        iterations = int(iterations_raw)
        digest = base64.b64decode(digest_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        raise ValueError("Imported administrator password hash is invalid") from None
    if (
        scheme != "pbkdf2_sha256"
        or not 1 <= iterations <= 2_000_000
        or not 8 <= len(salt) <= 256
        or len(digest) != 32
    ):
        raise ValueError("Imported administrator password hash is invalid")


def _validate_tokens(config: dict, users: list, admin_tokens: list) -> None:
    tokens: set[str] = set()
    legacy_token = config.get("auth", {}).get("sub_token") if isinstance(config.get("auth"), dict) else None
    if legacy_token:
        tokens.add(str(legacy_token))
    for collection_name, items in (("users", users), ("admin tokens", admin_tokens)):
        for item in items:
            token = str(item.get("token") or "").strip()
            if not _TOKEN_RE.fullmatch(token):
                raise ValueError(f"Imported {collection_name} contains an invalid token")
            if token in tokens:
                raise ValueError("Imported configuration contains duplicate subscription tokens")
            tokens.add(token)
            item["token"] = token


def _validate_subject_templates(config: dict, users: list, admin_tokens: list) -> None:
    template_ids = {"builtin"}
    template_ids.update(
        str(template.get("id"))
        for template in config.get("templates", [])
        if isinstance(template, dict) and template.get("id")
    )
    for collection_name, subjects in (("users", users), ("admin tokens", admin_tokens)):
        for subject in subjects:
            template_id = str(subject.get("template_id") or "builtin")
            if template_id not in template_ids:
                raise ValueError(f"Imported {collection_name} references an unknown template")
            subject["template_id"] = template_id


def _validate_port_mappings(config: dict) -> None:
    mappings = config.get("port_mappings", {})
    if mappings is None:
        config["port_mappings"] = {}
        return
    if not isinstance(mappings, dict) or len(mappings) > 5000:
        raise ValueError("Imported port mappings are invalid")
    ports: set[int] = set()
    for reference, port in mappings.items():
        if not isinstance(reference, str) or not reference or len(reference) > 500:
            raise ValueError("Imported port mapping reference is invalid")
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ValueError("Imported port mapping port is invalid")
        if port in ports:
            raise ValueError("Imported port mappings contain duplicate ports")
        ports.add(port)


def _validate_settings(config: dict) -> None:
    settings = config.get("settings", {})
    if not isinstance(settings, dict):
        raise ValueError("Imported settings configuration is invalid")
    proxy_node_id = settings.get("proxy_node_id")
    if proxy_node_id is not None and (not isinstance(proxy_node_id, str) or len(proxy_node_id) > 500):
        raise ValueError("Imported default proxy reference is invalid")
    proxy_url = settings.get("subscription_proxy_url")
    if proxy_url:
        parsed = urlsplit(str(proxy_url))
        if parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname:
            raise ValueError("Imported subscription proxy URL is invalid")
    ipv6_proxy = settings.get("ipv6_proxy")
    if ipv6_proxy is not None:
        if not isinstance(ipv6_proxy, dict):
            raise ValueError("Imported IPv6 proxy configuration is invalid")
        if ipv6_proxy.get("proxy_url"):
            parsed = urlsplit(str(ipv6_proxy["proxy_url"]))
            if parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname:
                raise ValueError("Imported IPv6 proxy URL is invalid")

    vpngate = settings.get(VPNGATE_SOURCE_ID)
    if vpngate is not None:
        if not isinstance(vpngate, dict):
            raise ValueError("Imported VPN Gate settings are invalid")
        if "enabled" in vpngate and not isinstance(vpngate.get("enabled"), bool):
            raise ValueError("Imported VPN Gate enabled flag is invalid")
        interval = vpngate.get("interval_minutes")
        if interval is not None and (
            isinstance(interval, bool)
            or not isinstance(interval, int)
            or not VPNGATE_MIN_INTERVAL_MINUTES <= interval <= VPNGATE_MAX_INTERVAL_MINUTES
        ):
            raise ValueError("Imported VPN Gate refresh interval is invalid")
        max_nodes = vpngate.get("max_nodes")
        if max_nodes is not None and (
            isinstance(max_nodes, bool)
            or not isinstance(max_nodes, int)
            or not VPNGATE_MIN_MAX_NODES <= max_nodes <= VPNGATE_MAX_MAX_NODES
        ):
            raise ValueError("Imported VPN Gate maximum node count is invalid")
        countries = vpngate.get("countries")
        if countries is not None and (
            not isinstance(countries, list)
            or any(
                not isinstance(country, str)
                or not re.fullmatch(r"[A-Za-z]{2}", country.strip())
                for country in countries
            )
        ):
            raise ValueError("Imported VPN Gate country filter is invalid")


def _validate_speedtest_profiles(config: dict) -> None:
    profiles = config.get("speedtest_profiles", [])
    if not isinstance(profiles, list):
        raise ValueError("Imported speedtest profiles are invalid")
    _validate_unique_ids(profiles, "speedtest profiles")
    for profile in profiles:
        name = str(profile.get("name") or "").strip()
        if not name or len(name) > 100:
            raise ValueError("Imported speedtest profile name is invalid")
        for key in ("subscription_ids",):
            values = profile.get(key)
            if values is not None and (
                not isinstance(values, list)
                or any(not isinstance(value, str) or len(value) > 200 for value in values)
            ):
                raise ValueError("Imported speedtest profile subscriptions are invalid")
            if values is not None:
                unknown_ids = {
                    value for value in values
                    if value not in {
                        str(subscription.get("id"))
                        for subscription in config.get("subscriptions", [])
                        if isinstance(subscription, dict) and subscription.get("id")
                    }
                }
                if unknown_ids:
                    raise ValueError("Imported speedtest profile references an unknown subscription")


def _validate_proxy_chain_reference(
    reference: dict,
    *,
    subscription_ids: set[str],
    custom_node_ids: set[str],
    group_ids: set[str],
) -> None:
    if not isinstance(reference, dict):
        raise ValueError("Imported proxy chain contains an invalid node reference")
    reference_type = reference.get("type", "node")
    if reference_type not in {"node", "group"}:
        raise ValueError("Imported proxy chain contains an unknown reference type")
    if reference_type == "group":
        group_id = _validate_identifier(reference.get("group_id"), "proxy group ID")
        if group_id in group_ids:
            raise ValueError("Imported proxy chains contain duplicate group IDs")
        group_ids.add(group_id)
        members = reference.get("group_nodes")
        if not isinstance(members, list) or not 1 <= len(members) <= 500:
            raise ValueError("Imported proxy group must contain 1 to 500 nodes")
        for member in members:
            if isinstance(member, dict) and member.get("type") == "group":
                raise ValueError("Imported proxy groups cannot be nested")
            _validate_proxy_chain_reference(
                member,
                subscription_ids=subscription_ids,
                custom_node_ids=custom_node_ids,
                group_ids=group_ids,
            )
        return

    source_id = str(reference.get("sub_id") or "").strip()
    node_id = str(reference.get("node_id") or "").strip()
    node_name = str(reference.get("node_name") or "").strip()
    if len(source_id) > 200 or len(node_id) > 500 or len(node_name) > 500:
        raise ValueError("Imported proxy chain node reference is too long")
    if source_id in {"custom", "custom_nodes"}:
        legacy_reference = isinstance(reference.get("node_index"), int) or bool(node_name)
        if node_id and node_id not in custom_node_ids:
            raise ValueError("Imported proxy chain references an unknown custom node")
        if not node_id and not legacy_reference:
            raise ValueError("Imported proxy chain custom-node reference is incomplete")
        return
    if source_id == VPNGATE_SOURCE_ID:
        if not node_id and not isinstance(reference.get("node_index"), int) and not node_name:
            raise ValueError("Imported proxy chain VPN Gate reference is incomplete")
        return
    if source_id not in subscription_ids:
        raise ValueError("Imported proxy chain references an unknown subscription")
    if not node_id and not isinstance(reference.get("node_index"), int) and not node_name:
        raise ValueError("Imported proxy chain node reference is incomplete")


def _validate_proxy_chains(
    proxy_chains: list,
    *,
    subscription_ids: set[str],
    custom_node_ids: set[str],
) -> None:
    _validate_unique_ids(proxy_chains, "proxy chains")
    names: set[str] = set()
    row_ids: set[str] = set()
    group_ids: set[str] = set()
    for chain in proxy_chains:
        name = str(chain.get("name") or "").strip()
        if not name or len(name) > 100:
            raise ValueError("Imported proxy chain name is invalid")
        name_key = name.casefold()
        if name_key in names:
            raise ValueError("Imported proxy chains contain duplicate names")
        names.add(name_key)
        rows = chain.get("rows")
        if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
            raise ValueError("Imported proxy chain must contain 1 to 100 rows")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Imported proxy chain contains an invalid row")
            row_id = _validate_identifier(row.get("row_id"), "proxy chain row ID")
            if row_id in row_ids:
                raise ValueError("Imported proxy chains contain duplicate row IDs")
            row_ids.add(row_id)
            nodes = row.get("nodes")
            if not isinstance(nodes, list) or not 2 <= len(nodes) <= 20:
                raise ValueError("Imported proxy chain row must contain 2 to 20 hops")
            for reference in nodes:
                _validate_proxy_chain_reference(
                    reference,
                    subscription_ids=subscription_ids,
                    custom_node_ids=custom_node_ids,
                    group_ids=group_ids,
                )


def _validate_node_pool_member(
    reference: dict,
    *,
    subscription_ids: set[str],
    custom_node_ids: set[str],
) -> None:
    if not isinstance(reference, dict):
        raise ValueError("Imported node pool contains an invalid node reference")
    source_id = str(reference.get("sub_id") or "").strip()
    if source_id in {"custom", "custom_nodes"}:
        source_id = "custom_nodes"
    if source_id != "custom_nodes" and source_id not in subscription_ids:
        raise ValueError("Imported node pool references an unknown subscription")
    node_id = str(reference.get("node_id") or "").strip()
    node_name = str(reference.get("node_name") or "").strip()
    node_index = reference.get("node_index")
    if len(source_id) > 200 or len(node_id) > 500 or len(node_name) > 500:
        raise ValueError("Imported node pool node reference is too long")
    if not node_id and not node_name and not isinstance(node_index, int):
        raise ValueError("Imported node pool node reference is incomplete")
    if source_id == "custom_nodes" and node_id and node_id not in custom_node_ids:
        # Legacy name/index references are resolved against the restored node
        # list at the second validation boundary.
        if not node_name and not isinstance(node_index, int):
            raise ValueError("Imported node pool references an unknown custom node")


def _validate_node_pools(
    node_pools: list,
    *,
    subscription_ids: set[str],
    custom_node_ids: set[str],
) -> None:
    ensure_node_pool_ids({"node_pools": node_pools})
    _validate_unique_ids(node_pools, "node pools")
    names: set[str] = set()
    for pool in node_pools:
        name = str(pool.get("name") or "").strip()
        if not name or len(name) > 100:
            raise ValueError("Imported node pool name is invalid")
        key = name.casefold()
        if key in names:
            raise ValueError("Imported node pools contain duplicate names")
        names.add(key)
        if "enabled" in pool and not isinstance(pool.get("enabled"), bool):
            raise ValueError("Imported node pool enabled flag is invalid")
        strategy = str(pool.get("group_strategy") or "select").strip()
        if strategy not in VALID_NODE_POOL_STRATEGIES:
            raise ValueError("Imported node pool strategy is invalid")
        pool["group_strategy"] = strategy
        lb_strategy = str(pool.get("lb_strategy") or "round-robin").strip()
        if lb_strategy not in VALID_NODE_POOL_LOAD_BALANCE_STRATEGIES:
            raise ValueError("Imported node pool load-balance strategy is invalid")
        pool["lb_strategy"] = lb_strategy
        nodes = pool.get("nodes")
        if not isinstance(nodes, list) or not 1 <= len(nodes) <= 500:
            raise ValueError("Imported node pool must contain 1 to 500 nodes")
        for member in nodes:
            _validate_node_pool_member(
                member,
                subscription_ids=subscription_ids,
                custom_node_ids=custom_node_ids,
            )


def _chain_allocation_aliases(config: dict) -> dict[str, set[str]]:
    """Return stable and legacy aliases for generated chain components."""
    aliases = {
        CHAIN_NODE_SOURCE: set(),
        CHAIN_POOL_SOURCE: set(),
    }
    for reference in list_proxy_chain_virtual_references(
        config,
        base_node_names=set(),
        reserved_group_names=set(),
    ):
        aliases.setdefault(reference.source_id, set()).update(
            {reference.stable_id, reference.legacy_id, reference.name}
        )
    return aliases


def _node_pool_allocation_aliases(config: dict) -> dict[str, set[str]]:
    aliases = {NODE_POOL_SOURCE: set()}
    if "node_pools" not in config:
        return aliases
    for reference in list_node_pool_virtual_references(
        config,
        base_node_names=set(),
        reserved_group_names=set(),
    ):
        aliases[NODE_POOL_SOURCE].update(
            {reference.stable_id, reference.legacy_id, reference.name}
        )
    return aliases


def _validate_allocations(
    users: list,
    known_sources: set[str],
    chain_aliases: dict[str, set[str]],
    node_pool_aliases: dict[str, set[str]],
) -> None:
    known_sources = known_sources | {"custom_nodes", "chain_nodes", "chain_pools", NODE_POOL_SOURCE}
    all_virtual_aliases = {**chain_aliases, **node_pool_aliases}
    for user in users:
        allocations = user.get("allocations", {})
        if not isinstance(allocations, dict) or len(allocations) > 500:
            raise ValueError("Imported user allocations are invalid")
        for source_id, references in allocations.items():
            if source_id not in known_sources:
                raise ValueError("Imported user allocation references an unknown source")
            if not isinstance(references, list) or len(references) > 5000:
                raise ValueError("Imported user allocation contains too many nodes")
            if "*" in references and references != ["*"]:
                raise ValueError("Imported wildcard allocation cannot be mixed with node IDs")
            if any(not isinstance(reference, str) or not reference or len(reference) > 500 for reference in references):
                raise ValueError("Imported user allocation contains an invalid node reference")
            if source_id in all_virtual_aliases and references != ["*"]:
                unknown_references = [
                    reference
                    for reference in references
                    if reference not in all_virtual_aliases[source_id]
                ]
                if unknown_references:
                    if source_id in chain_aliases:
                        raise ValueError(
                            f"Imported {source_id} allocation references an unknown chain component"
                        )
                    raise ValueError(
                        f"Imported {source_id} allocation references an unknown node pool component"
                    )


def _validate_source_order(config: dict, subscription_ids: set[str]) -> None:
    source_order_present = "source_order" in config
    source_order = config.get("source_order", [])
    if len(source_order) > 500 or any(not isinstance(source_id, str) for source_id in source_order):
        raise ValueError("Imported source order is invalid")
    if len(source_order) != len(set(source_order)):
        raise ValueError("Imported source order contains duplicate IDs")
    known_sources = set(subscription_ids)
    if config.get("custom_nodes"):
        known_sources.add("custom_nodes")
    if any(source_id not in known_sources for source_id in source_order):
        raise ValueError("Imported source order references an unknown source")
    if not source_order_present and not known_sources:
        return
    # A partial order silently drops sources in older merger implementations.
    # Preserve the requested order while appending every real source exactly
    # once, so imported configurations cannot lose nodes by omission.
    for source_id in sorted(known_sources):
        if source_id not in source_order:
            source_order.append(source_id)
    config["source_order"] = source_order


def remove_legacy_stale_references(config: dict) -> int:
    """Remove references left by sources deleted by releases before cleanup existed."""
    changed = 0
    subscription_ids = {
        str(subscription.get("id"))
        for subscription in config.get("subscriptions", [])
        if isinstance(subscription, dict) and subscription.get("id")
    }
    known_allocation_sources = subscription_ids | {
        "custom_nodes",
        "chain_nodes",
        "chain_pools",
        NODE_POOL_SOURCE,
    }
    for user in config.get("users", []):
        if not isinstance(user, dict) or not isinstance(user.get("allocations"), dict):
            continue
        allocations = user["allocations"]
        legacy_custom_values = allocations.pop("custom", None)
        if legacy_custom_values is not None:
            changed += 1
            if "custom_nodes" not in allocations:
                allocations["custom_nodes"] = legacy_custom_values
        for source_id in list(allocations):
            if source_id not in known_allocation_sources:
                allocations.pop(source_id, None)
                changed += 1

    known_order_sources = set(subscription_ids)
    if config.get("custom_nodes"):
        known_order_sources.add("custom_nodes")
    source_order = config.get("source_order", [])
    if isinstance(source_order, list):
        cleaned_order: list[str] = []
        seen_sources: set[str] = set()
        for source_id in source_order:
            if (
                isinstance(source_id, str)
                and source_id in known_order_sources
                and source_id not in seen_sources
            ):
                cleaned_order.append(source_id)
                seen_sources.add(source_id)
        if cleaned_order != source_order:
            config["source_order"] = cleaned_order
            changed += 1
    return changed


def _validate_group_config(subjects: list) -> None:
    for subject in subjects:
        group_config = subject.get("group_config", {})
        if not isinstance(group_config, dict) or len(group_config) > 200:
            raise ValueError("Imported proxy-group configuration is invalid")
        for group_name, references in group_config.items():
            if not isinstance(group_name, str) or not group_name.strip() or len(group_name) > 200:
                raise ValueError("Imported proxy-group name is invalid")
            if not isinstance(references, list) or len(references) > 5000:
                raise ValueError("Imported proxy-group contains too many nodes")
            if any(not isinstance(reference, str) or not reference or len(reference) > 500 for reference in references):
                raise ValueError("Imported proxy-group contains an invalid node reference")


def validate_and_normalize_configuration(config: dict) -> dict:
    """Return a detached configuration that satisfies persisted invariants."""
    if not isinstance(config, dict):
        raise ValueError("Imported configuration must be an object")
    normalized = deepcopy(config)
    for key in _COLLECTIONS:
        _require_list(normalized, key)
    if "auth" in normalized and not isinstance(normalized["auth"], dict):
        raise ValueError("Imported auth configuration must be an object")
    if "settings" in normalized and not isinstance(normalized["settings"], dict):
        raise ValueError("Imported settings configuration must be an object")
    if "translation_config" in normalized:
        translation_config = normalized["translation_config"]
        if not isinstance(translation_config, dict):
            raise ValueError("Imported translation configuration must be an object")
        providers = translation_config.get("providers", {})
        if not isinstance(providers, dict) or any(
            not isinstance(provider_settings, dict)
            for provider_settings in providers.values()
        ):
            raise ValueError("Imported translation providers must be objects")
    _validate_auth(normalized)

    subscriptions = normalized.get("subscriptions", [])
    custom_nodes = normalized.get("custom_nodes", [])
    users = normalized.get("users", [])
    templates = normalized.get("templates", [])
    admin_tokens = normalized.get("admin_tokens", [])
    proxy_chains = normalized.get("proxy_chains", [])

    subscription_ids = _validate_subscription_records(subscriptions)
    _validate_unique_ids(users, "users")
    _validate_unique_ids(templates, "templates")
    _validate_unique_ids(admin_tokens, "admin tokens")
    _validate_unique_ids(custom_nodes, "custom nodes", allow_missing=True)
    ensure_custom_node_ids(normalized)
    custom_node_ids = _validate_unique_ids(custom_nodes, "custom nodes")
    ensure_proxy_chain_component_ids(normalized)
    _validate_proxy_chains(
        proxy_chains,
        subscription_ids=subscription_ids,
        custom_node_ids=custom_node_ids,
    )
    _validate_node_pools(
        normalized.get("node_pools", []),
        subscription_ids=subscription_ids,
        custom_node_ids=custom_node_ids,
    )
    _validate_tokens(normalized, users, admin_tokens)
    _validate_subject_templates(normalized, users, admin_tokens)
    _validate_allocations(
        users,
        subscription_ids,
        _chain_allocation_aliases(normalized),
        _node_pool_allocation_aliases(normalized),
    )
    _validate_source_order(normalized, subscription_ids)
    _validate_group_config([*users, *admin_tokens])
    _validate_port_mappings(normalized)
    _validate_settings(normalized)
    _validate_speedtest_profiles(normalized)
    return normalized


def validate_configuration_node_references(config: dict, yaml_source_dir: str) -> None:
    """Validate references against the actual subscription YAML files.

    Structural import validation can prove that an ID has the right shape,
    but only the restored YAML can prove that a node ID or legacy name exists.
    This second boundary check prevents migrations from succeeding with a
    valid-looking config that later emits empty groups or drops allocations.
    """
    from helpers import load_subscription_yaml
    from services.name_transformer import NameTransformer
    from services.node_identity import custom_node_id, subscription_node_ids
    from services.proxy_chain_references import list_proxy_chain_virtual_references

    source_aliases: dict[str, set[str]] = {}
    all_aliases: set[str] = set()

    for subscription in config.get("subscriptions", []):
        subscription_id = str(subscription.get("id") or "")
        if not subscription.get("enabled", True):
            # Disabled sources are intentionally allowed to exist without a
            # restored YAML file; they cannot contribute nodes or references
            # until explicitly enabled and refreshed.
            source_aliases[subscription_id] = set()
            continue
        try:
            subscription_yaml = load_subscription_yaml(subscription_id, yaml_source_dir, use_cache=False)
        except Exception as exc:
            raise ValueError(
                f"Imported subscription {subscription_id} is missing or has invalid YAML"
            ) from exc
        nodes = subscription_yaml.get("proxies") if isinstance(subscription_yaml, dict) else None
        if not isinstance(nodes, list):
            raise ValueError(f"Imported subscription {subscription_id} has no proxy list")
        identities = subscription_node_ids(subscription_id, nodes)
        aliases: set[str] = set(identities)
        for index, node in enumerate(nodes):
            if not isinstance(node, dict):
                raise ValueError(f"Imported subscription {subscription_id} contains an invalid node")
            aliases.add(str(node.get("name") or "").strip())
            transformed_name = NameTransformer.transform_name(
                node,
                subscription.get("name", subscription_id),
            ).get("name")
            if transformed_name:
                aliases.add(str(transformed_name).strip())
            aliases.add(identities[index])
        aliases.discard("")
        source_aliases[subscription_id] = aliases
        all_aliases.update(aliases)

    custom_aliases: set[str] = set()
    for node in config.get("custom_nodes", []):
        if not isinstance(node, dict):
            continue
        custom_aliases.update(
            value for value in (
                custom_node_id(node),
                str(node.get("name") or "").strip(),
                str(NameTransformer.transform_name(node, "Custom").get("name") or "").strip(),
            ) if value
        )
    source_aliases["custom_nodes"] = custom_aliases
    all_aliases.update(custom_aliases)

    for virtual_reference in list_proxy_chain_virtual_references(config):
        source_aliases.setdefault(virtual_reference.source_id, set()).update(
            {virtual_reference.stable_id, virtual_reference.legacy_id, virtual_reference.name}
        )
        all_aliases.update({virtual_reference.stable_id, virtual_reference.legacy_id, virtual_reference.name})

    for pool_reference in list_node_pool_virtual_references(config):
        source_aliases.setdefault(NODE_POOL_SOURCE, set()).update(
            {pool_reference.stable_id, pool_reference.legacy_id, pool_reference.name}
        )
        all_aliases.update({pool_reference.stable_id, pool_reference.legacy_id, pool_reference.name})

    def validate_node_reference(reference: object) -> None:
        if not isinstance(reference, dict):
            raise ValueError("Imported node reference is invalid")
        source_id = str(reference.get("sub_id") or "")
        if source_id in {"custom", "custom_nodes"}:
            source_id = "custom_nodes"
        if source_id == VPNGATE_SOURCE_ID:
            # VPN Gate nodes live in a refreshable backend cache rather than
            # the imported configuration document.  The runtime resolver will
            # mark a missing/stale node unavailable after the cache is loaded.
            return
        aliases = source_aliases.get(source_id)
        if aliases is None:
            raise ValueError("Imported node reference points to an unknown source")
        node_id = str(reference.get("node_id") or "").strip()
        node_name = str(reference.get("node_name") or "").strip()
        node_index = reference.get("node_index")
        if node_id and node_id not in aliases:
            raise ValueError("Imported node reference points to a missing node")
        if node_name and node_name not in aliases and not isinstance(node_index, int):
            raise ValueError("Imported node reference points to a missing node name")
        if not node_id and not node_name and not isinstance(node_index, int):
            raise ValueError("Imported node reference is incomplete")

    for chain in config.get("proxy_chains", []):
        for row in chain.get("rows", []) if isinstance(chain, dict) else []:
            for reference in row.get("nodes", []) if isinstance(row, dict) else []:
                if not isinstance(reference, dict):
                    raise ValueError("Imported proxy chain contains an invalid reference")
                if reference.get("type") == "group":
                    for member in reference.get("group_nodes", []) or []:
                        validate_node_reference(member)
                else:
                    validate_node_reference(reference)

    for pool in config.get("node_pools", []):
        if not isinstance(pool, dict):
            continue
        for member in pool.get("nodes", []) or []:
            validate_node_reference(member)

    for user in [*config.get("users", []), *config.get("admin_tokens", [])]:
        allocations = user.get("allocations", {}) if isinstance(user, dict) else {}
        if isinstance(allocations, dict):
            for source_id, values in allocations.items():
                if values == ["*"]:
                    continue
                aliases = source_aliases.get("custom_nodes" if source_id == "custom" else source_id, set())
                if source_id in {"chain_nodes", "chain_pools", NODE_POOL_SOURCE}:
                    if any(value not in aliases for value in values):
                        raise ValueError("Imported allocation references a missing chain component")
                elif aliases and any(value not in aliases for value in values):
                    raise ValueError("Imported allocation references a missing node")

        group_config = user.get("group_config", {}) if isinstance(user, dict) else {}
        if isinstance(group_config, dict):
            for values in group_config.values():
                if isinstance(values, list) and any(
                    value not in all_aliases and value not in {"DIRECT", "REJECT"}
                    for value in values
                ):
                    raise ValueError("Imported proxy-group configuration references a missing node")

    settings = config.get("settings", {})
    default_proxy_id = settings.get("proxy_node_id") if isinstance(settings, dict) else None
    if default_proxy_id and default_proxy_id not in all_aliases:
        raise ValueError("Imported default proxy references a missing node")

    port_mappings = config.get("port_mappings", {})
    if isinstance(port_mappings, dict):
        for reference in port_mappings:
            if reference not in all_aliases:
                raise ValueError("Imported port mapping references a missing node")
