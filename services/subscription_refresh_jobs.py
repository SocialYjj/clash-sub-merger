"""Scheduled-job implementations: subscription refresh and periodic tasks.

These jobs resolve shared application state (config access, scheduler, refresh
locks, region-history helpers) through the ``server`` module namespace at call
time — the same late-binding seam tests use via ``patch.object(server, ...)``
and the same pattern core.migrations and the API routers already use.
"""

import asyncio
import os
import time

from fastapi import HTTPException

from core.config import AppConfig
from helpers import Constants
from logger_config import get_logger
from services.node_reference_updates import (
    reconcile_subscription_node_references,
    subscription_nodes_from_yaml_content,
)
from services.node_visibility import clear_user_subscription_caches
from services.stats_history import record_stats_snapshot
from services.subscription_fetcher import FetchError, SubscriptionFetcher
from services.subscription_node_count import count_effective_subscription_nodes
from services.subscription_refresh_lock import SubscriptionRefreshInProgress
from services.subscription_state import (
    describe_refresh_error,
    record_refresh_attempt,
    refresh_success_fields,
)
from services.subscription_storage import persist_subscription_content_and_record
from services.vpngate import get_vpngate_settings, run_scheduled_vpngate_refresh

logger = get_logger(__name__)


def _restore_scheduled_jobs():
    """Restore scheduled jobs from config."""
    import server as srv

    try:
        config = srv.load_config()
        scheduler = srv.get_scheduler()
        restored_count = 0
        desired_task_ids = {
            f"sub_refresh_{sub['id']}"
            for sub in config.get("subscriptions", [])
            if sub.get("id") and sub.get("type") != "local" and sub.get("enabled", True) and sub.get("cron_expr")
        }

        for existing_task_id in list(scheduler.jobs):
            if existing_task_id.startswith("sub_refresh_") and existing_task_id not in desired_task_ids:
                scheduler.remove_job(existing_task_id)

        for sub in config.get("subscriptions", []):
            if sub.get("type") == "local" or not sub.get("enabled", True):
                if sub.get("next_update") is not None:
                    srv.update_subscription_fields(sub["id"], {"next_update": None})
                continue

            cron_expr = sub.get("cron_expr")
            if cron_expr:
                try:
                    task_id = f"sub_refresh_{sub['id']}"
                    job_id = scheduler.add_job(task_id, cron_expr, refresh_subscription_job, sub["id"])

                    # Update next_update timestamp
                    job_info = scheduler.get_job_info(task_id)
                    if job_id and job_info and job_info.get("next_run"):
                        next_update = int(job_info["next_run"].timestamp())
                        srv.update_subscription_fields(sub["id"], {"next_update": next_update})
                        restored_count += 1
                        logger.info(
                            f"Restored schedule for subscription '{sub.get('name')}': {cron_expr}, next run: {job_info['next_run']}"
                        )
                    else:
                        srv.update_subscription_fields(sub["id"], {"next_update": None})
                        logger.error("Failed to restore schedule for subscription '%s'", sub.get("name"))
                except Exception as e:
                    logger.error(f"Failed to restore schedule for subscription '{sub.get('name')}': {e}")
                    srv.update_subscription_fields(sub["id"], {"next_update": None})
            elif sub.get("next_update") is not None:
                srv.update_subscription_fields(sub["id"], {"next_update": None})

        if restored_count > 0:
            logger.info(f"Restored {restored_count} scheduled job(s)")
    except Exception as e:
        logger.error(f"Failed to restore scheduled jobs: {e}")


def _schedule_flclash_version_check():
    """Schedule FlClash version check if using flclash mode."""
    import server as srv

    try:
        ua_mode = os.getenv("SUBSCRIPTION_UA_MODE", "flclash").strip().lower()
        if ua_mode != "flclash":
            logger.info(f"FlClash version check disabled (UA mode: {ua_mode})")
            return

        from apscheduler.triggers.cron import CronTrigger

        from helpers_ua import refresh_version_cache

        scheduler = srv.get_scheduler()
        cron_expr = os.getenv("FLCLASH_VERSION_UPDATE_CRON", "0 3 * * *").strip()

        try:
            trigger = CronTrigger.from_crontab(cron_expr)
            scheduler.scheduler.add_job(
                refresh_version_cache, trigger=trigger, id="flclash_version_refresh", replace_existing=True
            )
            logger.info(f"Scheduled FlClash version check with cron: {cron_expr}")
        except Exception as e:
            logger.warning(f"Invalid FLCLASH_VERSION_UPDATE_CRON '{cron_expr}': {e}, using default")
            scheduler.scheduler.add_job(
                refresh_version_cache,
                trigger=CronTrigger(hour=3, minute=0),
                id="flclash_version_refresh",
                replace_existing=True,
            )
            logger.info("Scheduled FlClash version check at 3:00 AM (default)")
    except Exception as e:
        logger.warning(f"Failed to schedule FlClash version check: {e}")


def _schedule_automatic_backup() -> None:
    """Register the configured periodic config backup job."""
    import server as srv

    scheduler = srv.get_scheduler().scheduler
    job_id = "automatic_config_backup"
    try:
        if not AppConfig.AUTO_BACKUP_ENABLED:
            existing_job = scheduler.get_job(job_id)
            if existing_job:
                scheduler.remove_job(job_id)
            logger.info("Automatic config backup disabled")
            return

        from apscheduler.triggers.interval import IntervalTrigger

        from services.backup import create_backup

        scheduler.add_job(
            create_backup,
            trigger=IntervalTrigger(hours=AppConfig.AUTO_BACKUP_INTERVAL_HOURS),
            args=["auto"],
            id=job_id,
            replace_existing=True,
        )
        logger.info("Automatic config backup scheduled every %s hour(s)", AppConfig.AUTO_BACKUP_INTERVAL_HOURS)
    except Exception:
        logger.error("Failed to schedule automatic config backup", exc_info=True)


def _schedule_stats_snapshot() -> None:
    """Register the configured daily dashboard statistics snapshot job."""
    import server as srv

    scheduler = srv.get_scheduler().scheduler
    job_id = "stats_history_snapshot"
    try:
        from apscheduler.triggers.cron import CronTrigger

        cron_expr = os.getenv("STATS_SNAPSHOT_CRON", "0 6 * * *").strip() or "0 6 * * *"
        try:
            trigger = CronTrigger.from_crontab(cron_expr)
        except Exception:
            logger.warning("Invalid STATS_SNAPSHOT_CRON '%s': falling back to 0 6 * * *", cron_expr)
            cron_expr = "0 6 * * *"
            trigger = CronTrigger.from_crontab(cron_expr)
        scheduler.add_job(stats_snapshot_job, trigger=trigger, id=job_id, replace_existing=True)
        logger.info("Daily stats snapshot scheduled with cron: %s", cron_expr)
    except Exception:
        logger.error("Failed to schedule daily stats snapshot", exc_info=True)


def stats_snapshot_job() -> None:
    """Daily dashboard snapshot job; runs in a background scheduler thread."""
    import server as srv

    try:
        record_stats_snapshot(srv.load_config())
    except Exception:
        # record_stats_snapshot already swallows failures; this guard keeps an
        # unexpected seam error from killing the scheduler thread.
        logger.error("Fatal error in stats snapshot job", exc_info=True)


def reschedule_vpngate_refresh() -> None:
    """Synchronize the global VPN Gate refresh job with persisted settings."""
    import server as srv

    scheduler = srv.get_scheduler().scheduler
    job_id = "vpngate_refresh"
    try:
        existing_job = scheduler.get_job(job_id)
        if existing_job:
            scheduler.remove_job(job_id)

        settings = get_vpngate_settings(srv.load_config())
        if not settings.get("enabled"):
            logger.info("VPN Gate automatic refresh disabled")
            return

        from datetime import datetime

        from apscheduler.triggers.interval import IntervalTrigger

        scheduler.add_job(
            run_scheduled_vpngate_refresh,
            trigger=IntervalTrigger(minutes=settings["interval_minutes"]),
            id=job_id,
            replace_existing=True,
            next_run_time=datetime.now(),
        )
        logger.info("VPN Gate automatic refresh scheduled every %s minute(s)", settings["interval_minutes"])
    except Exception:
        logger.error("Failed to schedule VPN Gate refresh", exc_info=True)


def _load_existing_nodes(sub_id: str) -> list:
    """Load existing nodes for history preservation."""
    import server as srv

    try:
        existing_cfg = srv.load_subscription_yaml(sub_id, srv.YAML_SOURCE_DIR, use_cache=False)
        return existing_cfg.get("proxies", []) if isinstance(existing_cfg, dict) else []
    except Exception:
        return []


def _fetch_and_process_subscription(sub: dict) -> tuple:
    """Fetch subscription and apply history/visibility processing."""
    import server as srv

    sub_id = sub["id"]
    existing_nodes = srv._load_existing_nodes(sub_id)

    # Fetch subscription using SubscriptionFetcher (supports proxy fallback, consistent with manual refresh)
    try:
        from helpers_ua import get_subscription_user_agent

        config = srv.load_config()
        proxy_url = config.get("settings", {}).get("subscription_proxy_url")
        user_agent = get_subscription_user_agent()
        fetch_attempts = AppConfig.SUBSCRIPTION_FETCH_RETRIES + 1
        retry_backoff = AppConfig.SUBSCRIPTION_FETCH_RETRY_DELAY_SECONDS * (2**AppConfig.SUBSCRIPTION_FETCH_RETRIES - 1)
        connection_paths = 2 if proxy_url else 1
        refresh_timeout = (
            connection_paths * (fetch_attempts * Constants.TIMEOUT_SUBSCRIPTION_FETCH + retry_backoff) + 10
        )

        async def _do_fetch():
            # Create a dedicated client for this thread's event loop.
            # The global http_client is bound to the main event loop and
            # cannot be used from asyncio.run() in a scheduler thread.
            import httpx as _httpx

            client = _httpx.AsyncClient(
                timeout=_httpx.Timeout(
                    connect=AppConfig.CONNECT_TIMEOUT,
                    read=AppConfig.READ_TIMEOUT,
                    write=AppConfig.WRITE_TIMEOUT,
                    pool=AppConfig.CONNECT_TIMEOUT,
                ),
                follow_redirects=True,
                limits=_httpx.Limits(
                    max_keepalive_connections=AppConfig.HTTP_MAX_KEEPALIVE,
                    max_connections=AppConfig.HTTP_MAX_CONNECTIONS,
                ),
                verify=AppConfig.HTTP_VERIFY_SSL,
                trust_env=False,
            )
            try:
                fetcher = SubscriptionFetcher(client, proxy_url=proxy_url)
                return await fetcher.fetch(sub["url"], user_agent=user_agent)
            finally:
                await client.aclose()

        async def _run_fetch_with_timeout():
            return await asyncio.wait_for(_do_fetch(), timeout=refresh_timeout)

        # Keep coroutine creation inside the event loop.  Besides making the
        # ownership explicit, close the awaitable as a final safeguard when
        # asyncio.run is interrupted or replaced by a test/scheduler adapter.
        fetch_coroutine = _run_fetch_with_timeout()
        try:
            content, sub_info, node_count = asyncio.run(fetch_coroutine)
        finally:
            fetch_coroutine.close()
    except Exception as exc:
        raise FetchError(f"Failed to fetch subscription: {exc}") from None

    # Apply region history
    content, remembered, inherited = srv.apply_region_history_to_yaml_content(
        content,
        existing_nodes=existing_nodes,
        source=f"sub:scheduled-refresh:{sub_id}",
    )

    content, test_metadata_inherited = srv.apply_node_test_metadata_to_yaml_content(
        content,
        existing_nodes=existing_nodes,
        source=f"sub:scheduled-refresh:{sub_id}",
    )

    # Apply node visibility
    content, visibility_inherited = srv.apply_node_visibility_to_yaml_content(
        content,
        existing_nodes=existing_nodes,
    )

    # The fetcher count reflects the upstream payload before history and
    # visibility processing.  Recount the final YAML so scheduled refreshes
    # persist the same effective node count used by manual refreshes and
    # exports (advertisements, malformed nodes, and disabled nodes excluded).
    processed_nodes = subscription_nodes_from_yaml_content(content)
    node_count = count_effective_subscription_nodes(processed_nodes)
    if node_count <= 0:
        raise FetchError("Subscription contains no valid proxy nodes")

    return (
        content,
        sub_info,
        node_count,
        remembered,
        inherited,
        visibility_inherited,
        test_metadata_inherited,
        existing_nodes,
    )


def _build_success_updates(sub_info: dict, node_count: int, subscription: dict, attempted_at: int) -> dict:
    """Build success updates dict for subscription."""
    return {
        "upload": sub_info.get("upload", 0),
        "download": sub_info.get("download", 0),
        "total": sub_info.get("total", 0),
        "expire": sub_info.get("expire", 0),
        "node_count": node_count,
        **refresh_success_fields(
            subscription,
            attempted_at=attempted_at,
            succeeded_at=int(time.time()),
        ),
    }


def refresh_subscription_job(sub_id: str):
    """
    Job function for scheduled subscription refresh.
    This is called by the scheduler and runs in a background thread.
    """
    import server as srv

    logger.info("Scheduled refresh triggered for subscription %s", sub_id)
    attempted_at = int(time.time())
    current_subscription = None
    try:
        with srv.wait_for_scheduled_refresh_slot(sub_id):
            config = srv.load_config()
            sub = next((candidate for candidate in config.get("subscriptions", []) if candidate["id"] == sub_id), None)
            current_subscription = sub

            if not sub:
                logger.warning("Subscription %s no longer exists; removing its scheduled job", sub_id)
                srv.get_scheduler().remove_job(f"sub_refresh_{sub_id}")
                return

            if not sub.get("enabled", True):
                logger.info("Skipping scheduled refresh for disabled subscription %s", sub_id)
                return

            if sub.get("type") == "local":
                logger.warning("Skipping scheduled refresh for local subscription %s", sub_id)
                srv.get_scheduler().remove_job(f"sub_refresh_{sub_id}")
                return

            try:
                record_refresh_attempt(sub, attempted_at)
                (
                    content,
                    sub_info,
                    node_count,
                    remembered,
                    inherited,
                    visibility_inherited,
                    test_metadata_inherited,
                    existing_nodes,
                ) = _fetch_and_process_subscription(sub)
                refreshed_nodes = subscription_nodes_from_yaml_content(content)

                success_updates = _build_success_updates(sub_info, node_count, sub, attempted_at)

                if remembered or inherited or test_metadata_inherited or visibility_inherited:
                    logger.info(
                        "Scheduled refresh %s history: remembered=%s inherited_region=%s inherited_test_metadata=%s inherited_disabled=%s",
                        sub_id,
                        remembered,
                        inherited,
                        test_metadata_inherited,
                        visibility_inherited,
                    )

                def commit_scheduled_refresh(latest_config: dict) -> dict:
                    latest_subscription = next(
                        (
                            candidate
                            for candidate in latest_config.get("subscriptions", [])
                            if candidate.get("id") == sub_id
                        ),
                        None,
                    )
                    if latest_subscription is None:
                        raise HTTPException(status_code=404, detail="Subscription not found") from None
                    subscription_name = str(latest_subscription.get("name") or sub_id)
                    reconcile_subscription_node_references(
                        latest_config,
                        sub_id,
                        old_nodes=existing_nodes,
                        new_nodes=refreshed_nodes,
                        old_subscription_name=subscription_name,
                        new_subscription_name=subscription_name,
                    )
                    latest_subscription.update(success_updates)
                    clear_user_subscription_caches(latest_config)
                    return dict(latest_subscription)

                persist_subscription_content_and_record(
                    sub_id,
                    content,
                    srv.YAML_SOURCE_DIR,
                    lambda: srv.update_config(commit_scheduled_refresh),
                )
                from services.stats_cache import invalidate as invalidate_stats_cache

                invalidate_stats_cache()

                logger.info("Scheduled refresh completed for subscription %s, got %s nodes", sub_id, node_count)
            except Exception as exc:
                error_message = describe_refresh_error(exc)
                logger.error(
                    "Scheduled refresh failed for subscription %s: %s",
                    sub_id,
                    error_message,
                    exc_info=True,
                )
                srv.record_refresh_failure(sub, exc, attempted_at)
    except SubscriptionRefreshInProgress:
        logger.warning("Scheduled refresh skipped because subscription %s is already refreshing", sub_id)
        # A concurrent refresh is not a refresh failure.  Do not overwrite the
        # in-flight job's attempt/success/failure state with a lock-conflict
        # error; the active job owns the authoritative outcome.
    except Exception as exc:
        logger.error(
            "Fatal error in scheduled refresh job for %s: %s",
            sub_id,
            describe_refresh_error(exc),
            exc_info=True,
        )
        if current_subscription:
            try:
                srv.record_refresh_failure(current_subscription, exc, attempted_at)
            except Exception:
                logger.error("Failed to persist scheduled refresh failure for %s", sub_id, exc_info=True)
