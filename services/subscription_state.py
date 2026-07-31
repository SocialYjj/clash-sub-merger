"""Structured subscription refresh state shared by manual and scheduled paths."""

import time
from typing import Optional

from fastapi import HTTPException

from core.database import update_subscription_fields
from logger_config import SensitiveDataFilter, get_logger


logger = get_logger(__name__)


def describe_refresh_error(exc: BaseException) -> str:
    """Return a bounded, credential-safe error suitable for persisted UI state."""
    if isinstance(exc, HTTPException):
        raw_message = exc.detail if isinstance(exc.detail, str) else "Request failed"
    else:
        raw_message = str(exc) or type(exc).__name__
    sanitized = SensitiveDataFilter.sanitize(raw_message).replace("\r", " ").replace("\n", " ").strip()
    return sanitized[:500] or type(exc).__name__


def get_next_update_timestamp(
    subscription_id: str,
    *,
    cron_expr: Optional[str] = None,
    enabled: bool = True,
) -> Optional[int]:
    """Read the registered next run, falling back to the cron expression."""
    if not enabled or not cron_expr:
        return None
    try:
        from scheduler_service import get_scheduler

        scheduler = get_scheduler()
        task_id = f"sub_refresh_{subscription_id}"
        job_info = scheduler.get_job_info(task_id)
        if job_info and job_info.get("next_run"):
            return int(job_info["next_run"].timestamp())

        job = scheduler.scheduler.get_job(f"task_{task_id}") or scheduler.scheduler.get_job(task_id)
        if job and job.next_run_time:
            return int(job.next_run_time.timestamp())

        calculated = scheduler.get_next_run_time(cron_expr)
        return int(calculated.timestamp()) if calculated else None
    except Exception as exc:
        logger.debug("Could not determine next update for %s: %s", subscription_id, type(exc).__name__)
        return None


def refresh_attempt_fields(subscription: dict, attempted_at: Optional[int] = None) -> dict:
    attempted_at = attempted_at or int(time.time())
    return {
        "last_attempt": attempted_at,
        "next_update": get_next_update_timestamp(
            subscription.get("id", ""),
            cron_expr=subscription.get("cron_expr"),
            enabled=subscription.get("enabled", True),
        ),
    }


def refresh_success_fields(
    subscription: dict,
    *,
    attempted_at: Optional[int] = None,
    succeeded_at: Optional[int] = None,
) -> dict:
    succeeded_at = succeeded_at or int(time.time())
    return {
        **refresh_attempt_fields(subscription, attempted_at=attempted_at or succeeded_at),
        "last_success": succeeded_at,
        "last_update": succeeded_at,
        "last_error": None,
        "update_status": "success",
    }


def refresh_failure_fields(subscription: dict, exc: BaseException, attempted_at: Optional[int] = None) -> dict:
    return {
        **refresh_attempt_fields(subscription, attempted_at=attempted_at),
        "last_error": describe_refresh_error(exc),
        "update_status": "error",
    }


def record_refresh_attempt(subscription: dict, attempted_at: Optional[int] = None) -> Optional[dict]:
    return update_subscription_fields(
        subscription.get("id", ""),
        refresh_attempt_fields(subscription, attempted_at),
    )


def record_refresh_failure(
    subscription: dict,
    exc: BaseException,
    attempted_at: Optional[int] = None,
) -> Optional[dict]:
    return update_subscription_fields(
        subscription.get("id", ""),
        refresh_failure_fields(subscription, exc, attempted_at),
    )
