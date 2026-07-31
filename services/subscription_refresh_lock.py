"""Cross-process serialization for every write to one subscription source."""

import os
import re
from contextlib import asynccontextmanager, contextmanager

from fastapi import HTTPException
from filelock import AsyncFileLock, FileLock, Timeout as FileLockTimeout

from core.config import AppConfig


REFRESH_LOCK_DIR = os.path.join(AppConfig.DATA_DIR, "refresh_locks")


class SubscriptionRefreshInProgress(RuntimeError):
    """Raised when the same subscription is already being updated."""


def _refresh_lock_path(subscription_id: str) -> str:
    safe_subscription_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(subscription_id or "unknown"))
    return os.path.join(REFRESH_LOCK_DIR, f"{safe_subscription_id}.lock")


def _try_acquire_refresh_lock(
    subscription_id: str,
    timeout_seconds: float,
) -> FileLock | None:
    os.makedirs(REFRESH_LOCK_DIR, exist_ok=True)
    file_lock = FileLock(_refresh_lock_path(subscription_id), timeout=timeout_seconds)
    try:
        file_lock.acquire()
    except FileLockTimeout:
        file_lock.release(force=True)
        return None
    return file_lock


async def _try_acquire_async_refresh_lock(
    subscription_id: str,
    timeout_seconds: float,
) -> AsyncFileLock | None:
    os.makedirs(REFRESH_LOCK_DIR, exist_ok=True)
    file_lock = AsyncFileLock(
        _refresh_lock_path(subscription_id),
        timeout=timeout_seconds,
    )
    try:
        await file_lock.acquire()
    except FileLockTimeout:
        await file_lock.release(force=True)
        return None
    return file_lock


def _refresh_in_progress(subscription_id: str) -> SubscriptionRefreshInProgress:
    return SubscriptionRefreshInProgress(
        f"Subscription {subscription_id} is already being updated"
    )


def _http_refresh_conflict(exc: SubscriptionRefreshInProgress) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail=str(exc),
        headers={"Retry-After": str(max(1, AppConfig.FILE_LOCK_TIMEOUT))},
    )


@asynccontextmanager
async def reject_concurrent_refresh(subscription_id: str):
    """Acquire immediately for an explicit API refresh, otherwise return 409."""
    file_lock = await _try_acquire_async_refresh_lock(subscription_id, 0)
    if file_lock is None:
        raise _http_refresh_conflict(_refresh_in_progress(subscription_id)) from None

    try:
        yield
    finally:
        await file_lock.release()


@asynccontextmanager
async def wait_for_refresh_slot(subscription_id: str):
    """Wait briefly when subscription generation needs a missing source file."""
    file_lock = await _try_acquire_async_refresh_lock(
        subscription_id,
        AppConfig.FILE_LOCK_TIMEOUT,
    )
    if file_lock is None:
        raise _http_refresh_conflict(_refresh_in_progress(subscription_id)) from None

    try:
        yield
    finally:
        await file_lock.release()


@contextmanager
def wait_for_scheduled_refresh_slot(subscription_id: str):
    """Wait briefly for an explicit refresh before a scheduled refresh is skipped."""
    file_lock = _try_acquire_refresh_lock(subscription_id, AppConfig.FILE_LOCK_TIMEOUT)
    if file_lock is None:
        raise _refresh_in_progress(subscription_id)
    try:
        yield
    finally:
        file_lock.release()


@contextmanager
def subscription_write_slot(subscription_id: str):
    """Serialize synchronous read-modify-write operations with refresh jobs."""
    file_lock = _try_acquire_refresh_lock(subscription_id, AppConfig.FILE_LOCK_TIMEOUT)
    if file_lock is None:
        raise _http_refresh_conflict(_refresh_in_progress(subscription_id)) from None
    try:
        yield
    finally:
        file_lock.release()
