"""Historical configuration migrations and runtime reload routines."""

import os
import json
import time
import hashlib
from copy import deepcopy

from core.config import AppConfig
from core.database import load_config, save_config
from helpers import generate_timestamp_id, load_subscription_yaml
from logger_config import get_logger
from services.subscription_node_count import count_effective_subscription_nodes
from services.subscription_state import describe_refresh_error

logger = get_logger(__name__)

DATA_DIR = AppConfig.DATA_DIR
MIGRATIONS_LOG = os.path.join(DATA_DIR, "migrations.log")
YAML_SOURCE_DIR = os.path.join(DATA_DIR, "uploads")


def _resolve_load_config():
    try:
        import server
        return getattr(server, "load_config", load_config)
    except Exception:
        return load_config


def _resolve_save_config():
    try:
        import server
        return getattr(server, "save_config", save_config)
    except Exception:
        return save_config


def _resolve_load_subscription_yaml():
    try:
        import server
        return getattr(server, "load_subscription_yaml", load_subscription_yaml)
    except Exception:
        return load_subscription_yaml


def log_migration(message: str) -> None:
    """Write migration message to a separate log file."""
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(MIGRATIONS_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        logger.warning("Failed to write migrations log: %s", e)


def migrate_old_config() -> None:
    """Migrate pre-unified legacy files into the SQLite configuration document."""
    from core.storage import has_app_document

    if has_app_document("config"):
        return  # Already migrated

    _save_config = _resolve_save_config()

    config = {
        "auth": {},
        "subscriptions": [],
        "custom_nodes": [],
        "source_order": [],
        "node_pools": [],
    }

    # Migrate auth.json
    auth_file = os.path.join(DATA_DIR, "auth.json")
    if os.path.exists(auth_file):
        with open(auth_file, "r", encoding="utf-8") as f:
            config["auth"] = json.load(f)

    # Migrate subscriptions.json
    subs_file = os.path.join(DATA_DIR, "subscriptions.json")
    if os.path.exists(subs_file):
        with open(subs_file, "r", encoding="utf-8") as f:
            config["subscriptions"] = json.load(f)

    # Migrate custom_nodes.json
    nodes_file = os.path.join(DATA_DIR, "custom_nodes.json")
    if os.path.exists(nodes_file):
        with open(nodes_file, "r", encoding="utf-8") as f:
            config["custom_nodes"] = json.load(f)

    # Migrate source_order.json
    order_file = os.path.join(DATA_DIR, "source_order.json")
    if os.path.exists(order_file):
        with open(order_file, "r", encoding="utf-8") as f:
            config["source_order"] = json.load(f)

    _save_config(config)
    logger.info("Config migration completed")
    log_migration("migrate_old_config: legacy files merged into SQLite")


def migrate_legacy_sub_token() -> None:
    """Migrate legacy auth.sub_token to admin_tokens if not already migrated."""
    _load_config = _resolve_load_config()
    _save_config = _resolve_save_config()

    config = _load_config()
    auth = config.get("auth", {})
    admin_tokens = config.get("admin_tokens", [])

    # Check if legacy sub_token exists
    legacy_token = auth.get("sub_token")
    if not legacy_token:
        return  # No legacy token to migrate

    # Check if already migrated (token value exists in admin_tokens)
    already_migrated = any(t.get("token") == legacy_token for t in admin_tokens)
    if already_migrated:
        return  # Already migrated

    # Create new admin token from legacy settings
    migrated_token = {
        "id": generate_timestamp_id("adm_"),
        "name": auth.get("sub_name", "默认"),  # Use original config name
        "token": legacy_token,  # Keep the same token value for backward compatibility
        "template_id": "builtin",
        "sub_filename": auth.get("sub_filename", ""),
        "sub_name": auth.get("sub_name", ""),
        "enabled": True,
        "created_at": int(time.time()),
    }

    if "admin_tokens" not in config:
        config["admin_tokens"] = []
    config["admin_tokens"].insert(0, migrated_token)  # Add at beginning

    # Remove legacy fields after migration
    if "sub_token" in config["auth"]:
        del config["auth"]["sub_token"]
    if "sub_filename" in config["auth"]:
        del config["auth"]["sub_filename"]
    if "sub_name" in config["auth"]:
        del config["auth"]["sub_name"]

    _save_config(config)
    logger.info("Legacy sub_token migrated to admin_tokens")
    log_migration("migrate_legacy_sub_token: migrated legacy token")


def migrate_subscription_fields() -> None:
    """Migrate subscriptions to the structured refresh status schema."""
    _load_config = _resolve_load_config()
    _save_config = _resolve_save_config()

    config = _load_config()
    subs = config.get("subscriptions", [])

    updated = False
    for sub in subs:
        if "cron_expr" not in sub:
            sub["cron_expr"] = None
            updated = True

        if "next_update" not in sub:
            sub["next_update"] = None
            updated = True

        if "last_attempt" not in sub:
            sub["last_attempt"] = sub.get("last_update")
            updated = True

        if "last_success" not in sub:
            status = str(sub.get("update_status") or "")
            sub["last_success"] = None if status.startswith("error") else sub.get("last_update")
            updated = True

        if "last_error" not in sub:
            status = str(sub.get("update_status") or "")
            sub["last_error"] = (
                describe_refresh_error(RuntimeError(status.partition(":")[2].strip() or status))
                if status.startswith("error")
                else None
            )
            updated = True

    if updated:
        _save_config(config)
        logger.info("Subscription refresh fields migrated for %s subscriptions", len(subs))
        log_migration(f"migrate_subscription_fields: updated {len(subs)} subscriptions")


def migrate_subscription_node_counts() -> None:
    """Reconcile persisted subscription counts with the current effective nodes.

    Older configurations stored the upstream count before advertisement and
    compatibility filtering.  The UI and exports use the effective count, so
    keep the persisted value aligned without touching a subscription whose
    source file cannot currently be read.
    """
    _load_config = _resolve_load_config()
    _save_config = _resolve_save_config()
    _load_subscription_yaml = _resolve_load_subscription_yaml()

    config = _load_config()
    migration_versions = config.get("migration_versions")
    if not isinstance(migration_versions, dict):
        migration_versions = {}
    if migration_versions.get("subscription_node_counts_v1") is True:
        return

    subscriptions = config.get("subscriptions", [])
    updated = 0
    missing_required_source = False

    for subscription in subscriptions:
        subscription_id = subscription.get("id")
        if not subscription_id:
            continue
        try:
            source_config = _load_subscription_yaml(
                subscription_id,
                YAML_SOURCE_DIR,
                use_cache=False,
            )
            source_nodes = (
                source_config.get("proxies")
                if isinstance(source_config, dict)
                else None
            )
            if not isinstance(source_nodes, list):
                logger.warning(
                    "Skipping node-count migration for subscription %s: "
                    "source has no list-valued proxies field",
                    subscription_id,
                )
                if subscription.get("enabled", True):
                    missing_required_source = True
                continue

            if not source_nodes and int(subscription.get("node_count") or 0) > 0:
                logger.warning(
                    "Skipping node-count migration for subscription %s: "
                    "empty proxy list would erase persisted count %s",
                    subscription_id,
                    subscription.get("node_count"),
                )
                if subscription.get("enabled", True):
                    missing_required_source = True
                continue
            effective_count = count_effective_subscription_nodes(source_nodes)
        except Exception as exc:
            logger.warning(
                "Skipping node-count migration for subscription %s: %s",
                subscription_id,
                type(exc).__name__,
            )
            if subscription.get("enabled", True):
                missing_required_source = True
            continue

        if subscription.get("node_count") != effective_count:
            subscription["node_count"] = effective_count
            updated += 1

    if not missing_required_source:
        config["migration_versions"] = migration_versions
        migration_versions["subscription_node_counts_v1"] = True

    if updated or not missing_required_source:
        _save_config(config)
        logger.info(
            "Subscription node-count migration updated %s subscription(s)",
            updated,
        )
        log_migration(
            "migrate_subscription_node_counts: updated "
            f"{updated} subscriptions"
            + (" and marked complete" if not missing_required_source else "")
        )


def migrate_stable_node_references() -> None:
    """Assign missing custom-node IDs and migrate proxy chains off array indexes."""
    from services.node_reference_migration import ensure_custom_node_ids, migrate_proxy_chain_node_ids
    from services.proxy_chain_references import (
        ensure_proxy_chain_component_ids,
        reconcile_proxy_chain_references,
        snapshot_with_chain_component_ids,
    )

    _load_config = _resolve_load_config()
    _save_config = _resolve_save_config()

    config = _load_config()
    original_config = deepcopy(config)
    added_node_ids = ensure_custom_node_ids(config)
    added_chain_component_ids = ensure_proxy_chain_component_ids(config)
    migrated_references = migrate_proxy_chain_node_ids(config)
    stable_chain_snapshot = snapshot_with_chain_component_ids(config)
    reconcile_proxy_chain_references(config, stable_chain_snapshot)
    if config == original_config:
        return
    _save_config(config)
    logger.info(
        "Stable node reference migration completed: custom_ids=%s chain_components=%s chain_references=%s",
        added_node_ids,
        added_chain_component_ids,
        migrated_references,
    )
    log_migration(
        f"migrate_stable_node_references: custom_ids={added_node_ids} "
        f"chain_components={added_chain_component_ids} "
        f"chain_references={migrated_references}"
    )


def migrate_proxy_chain_group_ids() -> None:
    """Add missing group_id for proxy chain group nodes."""
    _load_config = _resolve_load_config()
    _save_config = _resolve_save_config()

    config = _load_config()
    chains = config.get("proxy_chains", [])
    if not chains:
        return

    updated = False
    added = 0
    for chain in chains:
        chain_id = chain.get("id") or chain.get("name", "")
        rows = chain.get("rows", [])
        for row_idx, row in enumerate(rows):
            nodes = row.get("nodes", [])
            for col_idx, node in enumerate(nodes):
                if isinstance(node, dict) and node.get("type") == "group":
                    if not node.get("group_id"):
                        seed = f"{chain_id}:{row_idx}:{col_idx}"
                        digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:8]
                        node["group_id"] = f"grp_{digest}"
                        updated = True
                        added += 1

    if updated:
        _save_config(config)
        logger.info("Proxy chain group_id migration completed")
        log_migration(f"migrate_proxy_chain_group_ids: added {added} group_id")


def migrate_node_pool_ids() -> None:
    """Assign stable IDs to node pools created by an older release."""
    from services.node_pool_references import ensure_node_pool_ids

    _load_config = _resolve_load_config()
    _save_config = _resolve_save_config()

    config = _load_config()
    if ensure_node_pool_ids(config):
        _save_config(config)
        logger.info("Node-pool identity migration completed")
        log_migration("migrate_node_pool_ids: assigned stable pool IDs")


def init_geoip_config() -> None:
    """Load GeoIP configuration from saved config on startup."""
    from geoip_service import apply_geoip_runtime_config

    _load_config = _resolve_load_config()
    config = _load_config()
    geoip_config = apply_geoip_runtime_config(config)

    if geoip_config:
        logger.info(
            "GeoIP config loaded: preferred_api=%s, custom_apis=%d",
            geoip_config.get("preferred_api", "ip-api.com"),
            len(geoip_config.get("custom_apis", [])),
        )


def reload_runtime_configuration() -> None:
    """Rebuild derived runtime state after a backup restore or config import."""
    from services.custom_node_storage import rebuild_custom_nodes_yaml
    from services.stats_cache import invalidate as invalidate_stats_cache

    migrate_subscription_fields()
    migrate_proxy_chain_group_ids()
    migrate_node_pool_ids()
    migrate_stable_node_references()
    init_geoip_config()
    rebuild_custom_nodes_yaml()

    # Import lifecycle schedulers without circular import
    try:
        import server
        server._restore_scheduled_jobs()
        server.reschedule_vpngate_refresh()
    except Exception as e:
        logger.warning("Could not refresh scheduled jobs via server: %s", e)

    invalidate_stats_cache()
