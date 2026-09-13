"""Persistent daily dashboard statistics snapshots.

One snapshot per local calendar day feeds the Dashboard node-trend chart.
Snapshots live in the shared key-value document storage (``core.storage``
cache documents) exactly like the GeoIP lookup cache and the node region
history: a single ``stats_history`` namespace holding a versioned document
with an ``entries`` list, keeping the most recent 90 days.
"""

import threading
import time
from datetime import datetime
from typing import Optional

from filelock import FileLock

from core.config import AppConfig, env_int
from core.database import load_config
from core.storage import database_lock_path, read_cache_document, write_cache_document
from helpers import load_subscription_yaml
from logger_config import get_logger
from services.node_visibility import is_node_enabled
from services.proxy_filter import ProxyFilter
from services.subscription_node_count import count_effective_subscription_nodes

logger = get_logger(__name__)

STATS_HISTORY_NAMESPACE = "stats_history"
STATS_HISTORY_VERSION = 1
STATS_HISTORY_MAX_ENTRIES = env_int("STATS_HISTORY_MAX_ENTRIES", 90, minimum=7, maximum=365)
# A fresh deployment should get a first trend point without waiting a full day
# for the cron job, so startup backfills when the latest snapshot is stale.
STATS_SNAPSHOT_MAX_AGE_HOURS = env_int("STATS_SNAPSHOT_MAX_AGE_HOURS", 20, minimum=1)

# Serializes the read-modify-write of the history document inside this process;
# ``database_lock_path()`` (same lock as configuration writes) covers replicas.
_snapshot_lock = threading.RLock()


def _local_today() -> str:
    """Local calendar date (local timezone) as ``YYYY-MM-DD``."""
    return datetime.now().astimezone().strftime("%Y-%m-%d")


def _is_countable_node(node: dict) -> bool:
    """Use the same counting rules as the stats overview."""
    return ProxyFilter.is_valid_proxy(node)


def _entry_recorded_at(entry: dict) -> int:
    """Return the stored epoch timestamp, or 0 for legacy/invalid entries."""
    try:
        value = int(entry.get("recorded_at") or 0)
    except (TypeError, ValueError):
        return 0
    return value if value > 0 else 0


def _lower_latency(current: Optional[float], nodes: list[dict]) -> Optional[float]:
    """Fold the lowest positive ``last_latency`` of ``nodes`` into ``current``."""
    for node in nodes:
        raw = node.get("last_latency")
        if raw is None:
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            continue
        if value > 0 and (current is None or value < current):
            current = value
    return current


def _collect_snapshot(config: dict | None = None) -> dict:
    """Compute one snapshot using the same counting seams as the overview."""
    if config is None:
        config = load_config()

    subscriptions = config.get("subscriptions", [])
    enabled_subs = [s for s in subscriptions if s.get("enabled", True)]

    total_nodes = 0
    min_latency: Optional[float] = None

    for sub in enabled_subs:
        try:
            sub_data = load_subscription_yaml(sub["id"], AppConfig.YAML_SOURCE_DIR, use_cache=True)
        except Exception as exc:
            logger.warning(
                "Failed to load subscription %s (%s) for stats snapshot: %s",
                sub.get("id", "<unknown>"),
                sub.get("name", "<unnamed>"),
                type(exc).__name__,
            )
            continue
        total_nodes += count_effective_subscription_nodes(sub_data.get("proxies", []))
        min_latency = _lower_latency(
            min_latency,
            [node for node in sub_data.get("proxies", []) if is_node_enabled(node) and _is_countable_node(node)],
        )

    custom_nodes = [
        node for node in config.get("custom_nodes", []) if is_node_enabled(node) and _is_countable_node(node)
    ]
    min_latency = _lower_latency(min_latency, custom_nodes)

    return {
        "date": _local_today(),
        "total_nodes": total_nodes,
        "subscription_count": len(enabled_subs),
        "custom_node_count": len(custom_nodes),
        "user_count": len([u for u in config.get("users", []) if u.get("enabled", True)]),
        "min_latency_ms": int(min_latency) if min_latency is not None else None,
        "recorded_at": int(time.time()),
    }


def load_stats_history() -> list[dict]:
    """Return stored snapshots ascending by date."""
    try:
        payload = read_cache_document(STATS_HISTORY_NAMESPACE, default=None)
    except Exception as exc:
        logger.error("Failed to read stats history: %s", type(exc).__name__, exc_info=True)
        return []
    if not isinstance(payload, dict):
        return []
    if payload.get("version") != STATS_HISTORY_VERSION:
        logger.info("Ignoring stats history with unsupported version %s", payload.get("version"))
        return []
    entries = payload.get("entries")
    if not isinstance(entries, list):
        return []
    return [dict(entry) for entry in entries if isinstance(entry, dict)]


def _upsert_snapshot(snapshot: dict) -> None:
    """Insert or replace today's entry, prune to the newest MAX_ENTRIES days."""
    today = str(snapshot.get("date", ""))
    with _snapshot_lock, FileLock(database_lock_path(), timeout=10):
        entries = [entry for entry in load_stats_history() if entry.get("date") != today]
        if today:
            entries.append(snapshot)
        entries.sort(key=lambda entry: str(entry.get("date", "")))
        entries = entries[-STATS_HISTORY_MAX_ENTRIES:]
        write_cache_document(
            STATS_HISTORY_NAMESPACE,
            {
                "version": STATS_HISTORY_VERSION,
                "updated_at": int(time.time()),
                "entries": entries,
            },
        )


def record_stats_snapshot(config: dict | None = None) -> dict:
    """Compute and store one snapshot; never raises into callers."""
    try:
        snapshot = _collect_snapshot(config)
        _upsert_snapshot(snapshot)
        logger.info(
            "Recorded stats snapshot for %s: %s node(s), %s subscription(s)",
            snapshot["date"],
            snapshot["total_nodes"],
            snapshot["subscription_count"],
        )
        return snapshot
    except Exception:
        logger.error("Failed to record stats snapshot", exc_info=True)
        return {}


def record_stats_snapshot_if_stale(max_age_hours: int = STATS_SNAPSHOT_MAX_AGE_HOURS) -> dict:
    """Record a snapshot only when the latest stored one is older than the limit.

    Returns the stored snapshot, or an empty dict when history is fresh (or
    recording failed — this helper never raises).
    """
    try:
        entries = load_stats_history()
        latest = entries[-1] if entries else None
        if latest:
            recorded_at = _entry_recorded_at(latest)
            # Missing timestamps count as very old so a backfill repairs them.
            if recorded_at > 0 and (time.time() - recorded_at) < max_age_hours * 3600:
                return {}
        return record_stats_snapshot()
    except Exception:
        logger.error("Failed to backfill stats snapshot", exc_info=True)
        return {}
