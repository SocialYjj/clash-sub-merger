"""Supervise the bundled Go speedtest microservice and the scheduler leader lock.

The mutable service state (process handle, shutting-down flag, leader lock)
intentionally lives in the ``server`` module namespace: app startup/shutdown
and the test suite read and write it there. Functions in this module resolve
that state through a late-bound ``import server as srv`` — the same seam the
API routers use — so module-level re-exports keep working without import
cycles and ``patch.object(server, ...)`` keeps its meaning.
"""

import asyncio
import atexit
import os
import subprocess
import sys
import time

from filelock import FileLock
from filelock import Timeout as FileLockTimeout

from core.config import AppConfig
from helpers import Constants
from logger_config import get_logger

logger = get_logger(__name__)


def _acquire_scheduler_leader() -> bool:
    """Allow only one process/container to own APScheduler jobs."""
    import server as srv

    if srv.SCHEDULER_IS_LEADER:
        return True
    lock_path = os.path.join(AppConfig.DATA_DIR, "scheduler.leader.lock")
    srv.SCHEDULER_LEADER_LOCK = FileLock(lock_path, timeout=0)
    try:
        srv.SCHEDULER_LEADER_LOCK.acquire(timeout=0)
    except FileLockTimeout:
        srv.SCHEDULER_IS_LEADER = False
        logger.warning("Another process owns the scheduler leader lock; scheduled jobs are disabled here")
        return False
    srv.SCHEDULER_IS_LEADER = True
    return True


def _release_scheduler_leader() -> None:
    import server as srv

    if srv.SCHEDULER_LEADER_LOCK is not None and srv.SCHEDULER_IS_LEADER:
        try:
            srv.SCHEDULER_LEADER_LOCK.release()
        except Exception:
            logger.debug("Failed to release scheduler leader lock", exc_info=True)
    srv.SCHEDULER_IS_LEADER = False
    srv.SCHEDULER_LEADER_LOCK = None


def start_go_speedtest_service():
    """Start the Go speedtest service as a subprocess"""
    import server as srv

    if srv.SERVER_SHUTTING_DOWN:
        return False

    # Check if already running
    if srv.GO_SPEEDTEST_PROCESS is not None and srv.GO_SPEEDTEST_PROCESS.poll() is None:
        logger.info("Go speedtest service already running")
        return True

    # Find the speedtest executable
    speedtest_exe = AppConfig.GO_SPEEDTEST_BIN
    if speedtest_exe:
        speedtest_dir = os.path.dirname(speedtest_exe) or AppConfig.BASE_DIR
    else:
        speedtest_dir = os.path.join(AppConfig.BASE_DIR, "speedtest")
        if sys.platform == "win32":
            speedtest_exe = os.path.join(speedtest_dir, "speedtest.exe")
        else:
            speedtest_exe = os.path.join(speedtest_dir, "speedtest")

    if not os.path.exists(speedtest_exe):
        logger.error("Go speedtest executable not found at %s", speedtest_exe)
        return False

    raw_startup_grace = os.environ.get("GO_SPEEDTEST_STARTUP_GRACE", "0.5")
    try:
        startup_grace = float(raw_startup_grace)
        if not (0 <= startup_grace <= 30):
            raise ValueError
    except (TypeError, ValueError):
        startup_grace = 0.5
        logger.warning("Invalid GO_SPEEDTEST_STARTUP_GRACE=%r; using %.1fs", raw_startup_grace, startup_grace)

    try:
        # Start the Go service
        srv.GO_SPEEDTEST_PROCESS = subprocess.Popen(
            [speedtest_exe],
            cwd=speedtest_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        if startup_grace > 0:
            time.sleep(startup_grace)
        exit_code = srv.GO_SPEEDTEST_PROCESS.poll()
        if exit_code is not None:
            logger.error(
                "Go speedtest service exited during startup (code=%s, path=%s). "
                "Check port conflicts or binary compatibility.",
                exit_code,
                speedtest_exe,
            )
            srv.GO_SPEEDTEST_PROCESS = None
            return False
        logger.info("Go speedtest service started (PID: %s)", srv.GO_SPEEDTEST_PROCESS.pid)
        return True
    except FileNotFoundError:
        logger.error("Go speedtest binary not found: %s", speedtest_exe)
        return False
    except Exception as e:
        logger.error("Failed to start Go speedtest service: %s", e, exc_info=True)
        return False


async def _monitor_go_speedtest_service() -> None:
    """Restart the bundled tester if it exits after successful startup."""
    import server as srv

    while True:
        await asyncio.sleep(5)
        if srv.SERVER_SHUTTING_DOWN:
            return
        if not AppConfig.GO_SPEEDTEST_ENABLED:
            continue
        process = srv.GO_SPEEDTEST_PROCESS
        if process is None or process.poll() is None:
            continue
        exit_code = process.poll()
        srv.GO_SPEEDTEST_PROCESS = None
        logger.error("Go speedtest service exited at runtime (code=%s); restarting", exit_code)
        if srv.SERVER_SHUTTING_DOWN:
            return
        if not await asyncio.to_thread(start_go_speedtest_service):
            logger.error("Go speedtest service restart failed; will retry")


def stop_go_speedtest_service():
    """Stop the Go speedtest service"""
    import server as srv

    if srv.GO_SPEEDTEST_PROCESS is not None:
        try:
            srv.GO_SPEEDTEST_PROCESS.terminate()
            srv.GO_SPEEDTEST_PROCESS.wait(timeout=Constants.TIMEOUT_PROCESS_TERMINATE)
            logger.info("Go speedtest service stopped gracefully")
        except subprocess.TimeoutExpired:
            logger.warning("Go speedtest service did not stop gracefully, forcing kill")
            try:
                srv.GO_SPEEDTEST_PROCESS.kill()
                logger.info("Go speedtest service killed")
            except Exception as kill_error:
                logger.error("Failed to kill Go speedtest service: %s", kill_error)
        except Exception as e:
            logger.error("Error stopping Go speedtest service: %s", e, exc_info=True)
        finally:
            srv.GO_SPEEDTEST_PROCESS = None


# Register cleanup on exit
atexit.register(stop_go_speedtest_service)
