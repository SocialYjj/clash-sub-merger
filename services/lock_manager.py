"""
Lock Manager Service
Manages file locks for subscription refresh operations
"""
import os
import re
import time
import asyncio
from contextlib import asynccontextmanager, contextmanager
from typing import Optional

from filelock import FileLock, Timeout as FileLockTimeout
from fastapi import HTTPException

from logger_config import get_logger
from core.config import AppConfig

logger = get_logger(__name__)


class RefreshAlreadyInProgress(RuntimeError):
    """Raised when the same subscription is already being refreshed."""
    pass


# Lock directory
LOCK_DIR = os.path.join(AppConfig.DATA_DIR, 'refresh_locks')

# Lock max age in seconds - locks older than this are considered stale
LOCK_MAX_AGE = 300  # 5 minutes


def _lock_path(sub_id: str) -> str:
    """Get lock file path for subscription"""
    safe_id = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(sub_id or 'unknown'))
    return os.path.join(LOCK_DIR, f'{safe_id}.lock')


def _remove_stale_lock(lock_path: str) -> bool:
    """Remove a lock file if it's older than LOCK_MAX_AGE."""
    try:
        if not os.path.exists(lock_path):
            return False
        mtime = os.path.getmtime(lock_path)
        age = time.time() - mtime
        if age > LOCK_MAX_AGE:
            os.remove(lock_path)
            logger.info("Removed stale lock file: %s (age: %.0fs)", lock_path, age)
            return True
    except OSError as e:
        logger.debug("Failed to check/remove stale lock %s: %s", lock_path, e)
    return False


def _acquire_lock(sub_id: str, *, wait: bool = False) -> FileLock:
    """
    Acquire file lock for subscription refresh.
    
    Args:
        sub_id: Subscription ID
        wait: If True, wait for lock; if False, raise immediately
        
    Returns:
        FileLock instance
        
    Raises:
        RefreshAlreadyInProgress: If lock is already held and wait=False
    """
    os.makedirs(LOCK_DIR, exist_ok=True)
    lock_path = _lock_path(sub_id)
    
    # Try to remove stale lock before acquiring
    _remove_stale_lock(lock_path)
    
    timeout = AppConfig.FILE_LOCK_TIMEOUT if wait else 0
    lock = FileLock(lock_path, timeout=timeout)
    
    try:
        lock.acquire()
        return lock
    except FileLockTimeout as exc:
        # Double-check: maybe the lock became stale while we were waiting
        if _remove_stale_lock(lock_path):
            try:
                lock.acquire()
                return lock
            except FileLockTimeout:
                pass
        raise RefreshAlreadyInProgress(
            f"Subscription {sub_id} refresh is already in progress"
        ) from exc


@asynccontextmanager
async def async_lock(sub_id: str, *, wait: bool = False):
    """
    Async context manager for subscription refresh lock.
    
    Args:
        sub_id: Subscription ID
        wait: If True, wait for lock
        
    Raises:
        HTTPException: If lock is already held (409 Conflict)
    """
    try:
        lock = await asyncio.to_thread(_acquire_lock, sub_id, wait=wait)
    except RefreshAlreadyInProgress as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    
    try:
        yield
    finally:
        await asyncio.to_thread(lock.release)


@contextmanager
def sync_lock(sub_id: str):
    """
    Synchronous context manager for subscription refresh lock.
    
    Args:
        sub_id: Subscription ID
        
    Raises:
        RefreshAlreadyInProgress: If lock is already held
    """
    lock = _acquire_lock(sub_id, wait=False)
    try:
        yield
    finally:
        lock.release()


def cleanup_stale_locks() -> None:
    """Remove leftover lock files from crashed processes (older than LOCK_MAX_AGE)."""
    try:
        if os.path.exists(LOCK_DIR):
            cleaned = 0
            for f in os.listdir(LOCK_DIR):
                if f.endswith('.lock'):
                    lock_path = os.path.join(LOCK_DIR, f)
                    if _remove_stale_lock(lock_path):
                        cleaned += 1
            if cleaned > 0:
                logger.info("Cleaned up %d stale refresh lock file(s)", cleaned)
    except Exception as e:
        logger.warning("Failed to cleanup stale refresh locks: %s", e)
