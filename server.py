import os
import yaml
import json
import time
import hashlib
import httpx
import subprocess
import sys
import atexit
import base64  # Used for local subscription parsing
import asyncio  # Used for async operations
import uuid  # Used for request IDs
import re
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

# Use C-accelerated safe YAML loader for better performance.
# Remote subscriptions and uploaded templates must never be parsed with
# yaml.Loader/CLoader because those loaders can construct arbitrary Python
# objects from YAML tags.
try:
    from yaml import CSafeLoader as YAMLLoader, CSafeDumper as YAMLDumper
except ImportError:
    from yaml import SafeLoader as YAMLLoader, SafeDumper as YAMLDumper
from typing import Optional, Tuple, Dict, List, Callable, AsyncGenerator
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from filelock import FileLock, Timeout as FileLockTimeout

# Import from refactored modules
from core import (
    http_requests_total, http_request_duration_seconds,
    concurrent_requests,
)
from services.name_transformer import NameTransformer
from services.node_visibility import apply_node_visibility_to_yaml_content, is_node_enabled
from services.proxy_filter import ProxyFilter
from services.country_data import COUNTRY_KEYWORDS, COUNTRY_NAMES, PLACEHOLDER_COUNTRY_MAP
from services.node_parser import parse_node_link
from services.region_history import apply_region_history_to_yaml_content
from geoip_service import GeoIPService
from scheduler_service import get_scheduler, init_scheduler
from logger_config import get_logger
from helpers import (
    Constants,
    load_subscription_yaml, save_subscription_content, save_subscription_yaml,
    generate_timestamp_id,
)

# Import refactored modules
from core.config import AppConfig as CoreAppConfig, env_int
from core.database import load_config, save_config, update_config, find_subscription_by_id, update_subscription_fields
from services.subscription_output import create_subscription_output_router
from services.subscription_fetcher import SubscriptionFetcher

# Import API routers
from api import api_router
from api.health import set_http_client as set_health_http_client
from api.user_allocation import create_user_allocation_router
from api.template_compat import create_template_router, split_template

# Setup logger for this module
logger = get_logger(__name__)

# ==================== Application Configuration ====================

# Keep server.py on the canonical configuration object.  Duplicating AppConfig
# here made environment variables drift between core and server startup paths.
AppConfig = CoreAppConfig

# Setup rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=[AppConfig.RATE_LIMIT_DEFAULT])

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    await startup_event()
    try:
        yield
    finally:
        await shutdown_event()

app = FastAPI(
    title="Clash Config Merger API",
    description="Modern subscription aggregation management panel for Clash/Mihomo",
    version=AppConfig.VERSION,
    docs_url="/docs" if AppConfig.ENABLE_API_DOCS else None,
    redoc_url="/redoc" if AppConfig.ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if AppConfig.ENABLE_API_DOCS else None,
    openapi_tags=[
        {"name": "health", "description": "Health check and metrics"},
        {"name": "auth", "description": "Authentication operations"},
        {"name": "subscriptions", "description": "Subscription management"},
        {"name": "nodes", "description": "Node management"},
        {"name": "users", "description": "User management"},
        {"name": "templates", "description": "Template management"},
        {"name": "speedtest", "description": "Speed test operations"},
        {"name": "stats", "description": "Statistics and analytics"},
        {"name": "Subscription Output", "description": "Generated Clash/Mihomo subscription output"},
    ],
    lifespan=lifespan
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Global exception handler to log all unhandled exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    import traceback
    error_detail = f"Unhandled exception: {str(exc)}\n{traceback.format_exc()}"
    logger.error(error_detail)
    print(f"GLOBAL ERROR: {error_detail}", file=sys.stderr)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next: Callable) -> Response:
    """Add conservative browser security headers for the built-in UI."""
    response = await call_next(request)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    return response


_cors_origins = [origin.strip() for origin in AppConfig.CORS_ORIGINS.split(',') if origin.strip()]
_cors_allow_credentials = True
if AppConfig.CORS_ORIGINS.strip() == '*':
    _cors_origins = ["*"]
    # Browsers reject Access-Control-Allow-Origin: * with credentials=true.
    # This app authenticates API calls with an Authorization header, so wildcard
    # deployments should disable credentialed-cookie CORS instead of emitting an
    # invalid combination.
    _cors_allow_credentials = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip compression middleware for large responses
app.add_middleware(GZipMiddleware, minimum_size=AppConfig.GZIP_MIN_SIZE)


# ==================== Startup/Shutdown Events ====================

def _restore_scheduled_jobs():
    """Restore scheduled jobs from config."""
    try:
        config = load_config()
        scheduler = get_scheduler()
        restored_count = 0
        
        for sub in config.get('subscriptions', []):
            if sub.get('type') == 'local':
                continue
            
            cron_expr = sub.get('cron_expr')
            if cron_expr:
                try:
                    task_id = f"sub_refresh_{sub['id']}"
                    job_id = scheduler.add_job(
                        task_id,
                        cron_expr,
                        refresh_subscription_job,
                        sub['id']
                    )
                    
                    # Update next_update timestamp
                    job_info = scheduler.get_job_info(task_id)
                    if job_id and job_info and job_info.get("next_run"):
                        sub['next_update'] = int(job_info["next_run"].timestamp())
                        restored_count += 1
                        logger.info(f"Restored schedule for subscription '{sub.get('name')}': {cron_expr}, next run: {job_info['next_run']}")
                    else:
                        sub['next_update'] = None
                except Exception as e:
                    logger.error(f"Failed to restore schedule for subscription '{sub.get('name')}': {e}")
                    sub['next_update'] = None
        
        if restored_count > 0:
            save_config(config)
            logger.info(f"Restored {restored_count} scheduled job(s)")
    except Exception as e:
        logger.error(f"Failed to restore scheduled jobs: {e}")


def _schedule_flclash_version_check():
    """Schedule FlClash version check if using flclash mode."""
    try:
        ua_mode = os.getenv('SUBSCRIPTION_UA_MODE', 'flclash').strip().lower()
        if ua_mode != 'flclash':
            logger.info(f"FlClash version check disabled (UA mode: {ua_mode})")
            return
        
        from helpers_ua import refresh_version_cache
        from apscheduler.triggers.cron import CronTrigger
        
        scheduler = get_scheduler()
        cron_expr = os.getenv('FLCLASH_VERSION_UPDATE_CRON', '0 3 * * *').strip()
        
        try:
            trigger = CronTrigger.from_crontab(cron_expr)
            scheduler.scheduler.add_job(
                refresh_version_cache,
                trigger=trigger,
                id="flclash_version_refresh",
                replace_existing=True
            )
            logger.info(f"Scheduled FlClash version check with cron: {cron_expr}")
        except Exception as e:
            logger.warning(f"Invalid FLCLASH_VERSION_UPDATE_CRON '{cron_expr}': {e}, using default")
            scheduler.scheduler.add_job(
                refresh_version_cache,
                trigger=CronTrigger(hour=3, minute=0),
                id="flclash_version_refresh",
                replace_existing=True
            )
            logger.info("Scheduled FlClash version check at 3:00 AM (default)")
    except Exception as e:
        logger.warning(f"Failed to schedule FlClash version check: {e}")


async def startup_event() -> None:
    """Initialize services on startup"""
    global http_client
    logger.info("Starting up application...")
    
    # Initialize HTTP client
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=AppConfig.CONNECT_TIMEOUT,
            read=AppConfig.READ_TIMEOUT,
            write=AppConfig.WRITE_TIMEOUT,
            pool=AppConfig.CONNECT_TIMEOUT
        ),
        follow_redirects=True,
        limits=httpx.Limits(
            max_keepalive_connections=AppConfig.HTTP_MAX_KEEPALIVE,
            max_connections=AppConfig.HTTP_MAX_CONNECTIONS
        ),
        verify=AppConfig.HTTP_VERIFY_SSL,
    )
    set_health_http_client(http_client)
    logger.info("HTTP client initialized")
    
    # Start Go speedtest service
    if AppConfig.GO_SPEEDTEST_ENABLED:
        if await asyncio.to_thread(start_go_speedtest_service):
            logger.info("Go speedtest service started successfully")
        else:
            logger.warning("Failed to start Go speedtest service - proxy fetching will not be available")
    else:
        logger.info("Go speedtest service disabled")
    
    # Initialize scheduler
    init_scheduler()
    logger.info("Scheduler initialized")
    
    # Restore scheduled jobs
    _restore_scheduled_jobs()
    
    # Schedule FlClash version check
    _schedule_flclash_version_check()


async def shutdown_event() -> None:
    """Cleanup on shutdown"""
    logger.info("Shutting down application...")
    stop_go_speedtest_service()
    if http_client:
        await http_client.aclose()
    logger.info("Application shutdown complete")


# Request ID middleware

@app.middleware("http")
async def add_request_id(request: Request, call_next: Callable) -> Response:
    """Add unique request ID to each request"""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

# Request size limit middleware
@app.middleware("http")
async def limit_request_size(request: Request, call_next: Callable) -> Response:
    """Limit request body size"""
    if request.headers.get("content-length"):
        content_length = int(request.headers["content-length"])
        if content_length > Constants.MAX_REQUEST_SIZE:
            raise HTTPException(status_code=413, detail="Request too large")

    return await call_next(request)

# Slow request logging middleware
@app.middleware("http")
async def log_slow_requests(request: Request, call_next: Callable) -> Response:
    """Log slow requests"""
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    # Log slow requests
    if duration > Constants.SLOW_REQUEST_THRESHOLD:
        logger.warning(
            f"Slow request: {request.method} {request.url.path} "
            f"took {duration:.2f}s (request_id: {getattr(request.state, 'request_id', 'unknown')})"
        )

    return response

# Metrics middleware
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Collect HTTP request metrics"""
    start_time = time.time()

    # Get endpoint path (remove query params)
    endpoint = request.url.path
    method = request.method

    # Track concurrent requests
    concurrent_requests.inc()

    try:
        response = await call_next(request)
        status = response.status_code

        # Record metrics
        http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
        duration = time.time() - start_time
        http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

        return response
    except Exception as e:
        # Record error
        http_requests_total.labels(method=method, endpoint=endpoint, status=500).inc()
        duration = time.time() - start_time
        http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)
        raise
    finally:
        concurrent_requests.dec()

# ==================== Register API Routers ====================
# Include modular API routers (migrated endpoints)
app.include_router(api_router)

# Use config values
BASE_DIR = AppConfig.BASE_DIR
DATA_DIR = AppConfig.DATA_DIR
YAML_SOURCE_DIR = os.path.join(DATA_DIR, 'uploads')
OUTPUT_FILE = os.path.join(DATA_DIR, 'myconfig.yaml')
CONFIG_FILE = os.path.join(DATA_DIR, 'config.json')  # Unified config file
MIGRATIONS_LOG = os.path.join(DATA_DIR, 'migrations.log')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(YAML_SOURCE_DIR, exist_ok=True)

# ==================== HTTP Client ====================
# Global async HTTP client - initialized in startup_event()
http_client = None

# ==================== Config Helper Functions ====================

# Fields to exclude from proxy config (metadata fields)
NODE_METADATA_FIELDS = {
    'id', 'link', 'last_latency', 'last_latency_time', 'last_speed',
    'last_peak_speed', 'last_speed_time', 'geoip', 'enabled'
}


def _find_custom_node_by_reference(
    custom_nodes: list,
    node_index: int = None,
    node_name: str = None
) -> Optional[dict]:
    """Find custom node by name or index with transformed name."""
    # Search by name
    if node_name:
        for node in custom_nodes:
            if not is_node_enabled(node):
                continue
            proxy = {k: v for k, v in node.items() if k not in NODE_METADATA_FIELDS}
            proxy = ProxyFilter.sanitize_proxy(proxy)
            transformed = NameTransformer.transform_name(proxy, 'Custom')
            if transformed.get('name') == node_name:
                return transformed
    
    # Search by index
    if node_index is not None and 0 <= node_index < len(custom_nodes):
        node = custom_nodes[node_index]
        if not is_node_enabled(node):
            return None
        proxy = {k: v for k, v in node.items() if k not in NODE_METADATA_FIELDS}
        proxy = ProxyFilter.sanitize_proxy(proxy)
        return NameTransformer.transform_name(proxy, 'Custom')
    
    return None


def _find_subscription_node_by_reference(
    sub_id: str,
    source_name: str,
    node_index: int = None,
    node_name: str = None
) -> Optional[dict]:
    """Find subscription node by name or index with transformed name."""
    try:
        cfg = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=True)
        proxies = cfg.get('proxies', []) if cfg else []
        
        # Search by name
        if node_name:
            for proxy in proxies:
                if not is_node_enabled(proxy):
                    continue
                if not ProxyFilter.is_valid_proxy(proxy):
                    continue
                proxy = ProxyFilter.sanitize_proxy(proxy)
                proxy.pop('enabled', None)
                transformed = NameTransformer.transform_name(proxy, source_name)
                if transformed.get('name') == node_name:
                    return transformed
        
        # Search by index
        if node_index is not None and 0 <= node_index < len(proxies):
            proxy = proxies[node_index]
            if not is_node_enabled(proxy):
                return None
            if not ProxyFilter.is_valid_proxy(proxy):
                return None
            proxy = ProxyFilter.sanitize_proxy(proxy)
            proxy.pop('enabled', None)
            return NameTransformer.transform_name(proxy, source_name)
    except Exception as e:
        logger.warning("Failed to load node %s[%s]: %s", sub_id, node_index, e)
    
    return None


def find_node_by_reference(
    sub_id: str,
    node_index: int = None,
    node_name: str = None
) -> Optional[dict]:
    """Get a proxy node by reference (sub_id + node_name/node_index) with transformed name.

    Returns a proxy dict aligned with ConfigMerger naming, or None if not found/invalid.
    """
    config = load_config()
    
    # Custom nodes
    if sub_id == 'custom':
        return _find_custom_node_by_reference(
            config.get('custom_nodes', []),
            node_index,
            node_name
        )
    
    # Subscription nodes
    sub = find_subscription_by_id(config, sub_id)
    source_name = sub['name'] if sub else sub_id
    return _find_subscription_node_by_reference(sub_id, source_name, node_index, node_name)

def normalize_alloc_name(name: str) -> str:
    """Normalize node name for allocation matching (remove flags and trim)."""
    return NameTransformer.remove_flags(name or '').strip()

def is_name_allocated(name: str, allocated_nodes: list | None) -> bool:
    """Check if a node name is in allocation list (supports legacy partial matches)."""
    if not allocated_nodes:
        return False
    if allocated_nodes == ['*']:
        return True
    if not name:
        return False
    name_clean = normalize_alloc_name(name)
    for alloc in allocated_nodes:
        if not alloc:
            continue
        if alloc == name:
            return True
        if alloc in name:
            return True
        alloc_clean = normalize_alloc_name(alloc)
        if alloc_clean and (alloc_clean == name_clean or alloc_clean in name_clean):
            return True
    return False

# ==================== Request Deduplication ====================

class RefreshAlreadyInProgress(RuntimeError):
    """Raised when the same subscription is already being refreshed."""


REFRESH_LOCK_DIR = os.path.join(DATA_DIR, 'refresh_locks')


def _refresh_lock_path(sub_id: str) -> str:
    safe_id = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(sub_id or 'unknown'))
    return os.path.join(REFRESH_LOCK_DIR, f'{safe_id}.lock')


def _acquire_refresh_file_lock(sub_id: str, *, wait: bool = False) -> FileLock:
    os.makedirs(REFRESH_LOCK_DIR, exist_ok=True)
    timeout = AppConfig.FILE_LOCK_TIMEOUT if wait else 0
    lock = FileLock(_refresh_lock_path(sub_id), timeout=timeout)
    try:
        lock.acquire()
        return lock
    except FileLockTimeout as exc:
        raise RefreshAlreadyInProgress(f"Subscription {sub_id} refresh is already in progress") from exc


@asynccontextmanager
async def subscription_refresh_lock(sub_id: str):
    """Async per-subscription refresh lock used by API routes."""
    try:
        lock = await asyncio.to_thread(_acquire_refresh_file_lock, sub_id, wait=False)
    except RefreshAlreadyInProgress as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        yield
    finally:
        await asyncio.to_thread(lock.release)


@asynccontextmanager
async def subscription_refresh_wait_lock(sub_id: str):
    """Async per-subscription refresh lock that waits briefly for auto-refresh paths."""
    try:
        lock = await asyncio.to_thread(_acquire_refresh_file_lock, sub_id, wait=True)
    except RefreshAlreadyInProgress as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        yield
    finally:
        await asyncio.to_thread(lock.release)


@contextmanager
def subscription_refresh_lock_sync(sub_id: str):
    """Sync per-subscription refresh lock used by scheduler jobs."""
    lock = _acquire_refresh_file_lock(sub_id, wait=False)
    try:
        yield
    finally:
        lock.release()

# ==================== Stats Cache ====================
# Use unified stats cache from services module
from services.stats_cache import invalidate as invalidate_stats_cache

# ==================== Go Speedtest Service Management ====================

GO_SPEEDTEST_PROCESS = None

def start_go_speedtest_service():
    """Start the Go speedtest service as a subprocess"""
    global GO_SPEEDTEST_PROCESS

    # Check if already running
    if GO_SPEEDTEST_PROCESS is not None and GO_SPEEDTEST_PROCESS.poll() is None:
        logger.info("Go speedtest service already running")
        return True

    # Find the speedtest executable
    speedtest_exe = AppConfig.GO_SPEEDTEST_BIN
    if speedtest_exe:
        speedtest_dir = os.path.dirname(speedtest_exe) or BASE_DIR
    else:
        speedtest_dir = os.path.join(BASE_DIR, 'speedtest')
        if sys.platform == 'win32':
            speedtest_exe = os.path.join(speedtest_dir, 'speedtest.exe')
        else:
            speedtest_exe = os.path.join(speedtest_dir, 'speedtest')

    if not os.path.exists(speedtest_exe):
        logger.error("Go speedtest executable not found at %s", speedtest_exe)
        return False

    try:
        # Start the Go service
        GO_SPEEDTEST_PROCESS = subprocess.Popen(
            [speedtest_exe],
            cwd=speedtest_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
        startup_grace = float(os.environ.get('GO_SPEEDTEST_STARTUP_GRACE', '0.5'))
        if startup_grace > 0:
            time.sleep(startup_grace)
        exit_code = GO_SPEEDTEST_PROCESS.poll()
        if exit_code is not None:
            logger.error(
                "Go speedtest service exited during startup (code=%s, path=%s). "
                "Check port conflicts or binary compatibility.",
                exit_code,
                speedtest_exe,
            )
            GO_SPEEDTEST_PROCESS = None
            return False
        logger.info("Go speedtest service started (PID: %s)", GO_SPEEDTEST_PROCESS.pid)
        return True
    except FileNotFoundError:
        logger.error("Go speedtest binary not found: %s", speedtest_exe)
        return False
    except Exception as e:
        logger.error("Failed to start Go speedtest service: %s", e, exc_info=True)
        return False

def stop_go_speedtest_service():
    """Stop the Go speedtest service"""
    global GO_SPEEDTEST_PROCESS

    if GO_SPEEDTEST_PROCESS is not None:
        try:
            GO_SPEEDTEST_PROCESS.terminate()
            GO_SPEEDTEST_PROCESS.wait(timeout=Constants.TIMEOUT_PROCESS_TERMINATE)
            logger.info("Go speedtest service stopped gracefully")
        except subprocess.TimeoutExpired:
            logger.warning("Go speedtest service did not stop gracefully, forcing kill")
            try:
                GO_SPEEDTEST_PROCESS.kill()
                logger.info("Go speedtest service killed")
            except Exception as kill_error:
                logger.error("Failed to kill Go speedtest service: %s", kill_error)
        except Exception as e:
            logger.error("Error stopping Go speedtest service: %s", e, exc_info=True)
        finally:
            GO_SPEEDTEST_PROCESS = None

# Register cleanup on exit
atexit.register(stop_go_speedtest_service)

# ==================== Scheduled Job Functions ====================

def _load_existing_nodes(sub_id: str) -> list:
    """Load existing nodes for history preservation."""
    try:
        existing_cfg = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=False)
        return existing_cfg.get('proxies', []) if isinstance(existing_cfg, dict) else []
    except Exception:
        return []


def _fetch_and_process_subscription(sub: dict) -> tuple:
    """Fetch subscription and apply history/visibility processing."""
    sub_id = sub['id']
    existing_nodes = _load_existing_nodes(sub_id)
    
    # Fetch subscription using SubscriptionFetcher (supports proxy fallback, consistent with manual refresh)
    refresh_timeout = Constants.TIMEOUT_SUBSCRIPTION_FETCH + 10
    
    try:
        from helpers_ua import get_subscription_user_agent
        
        config = load_config()
        proxy_url = config.get('settings', {}).get('subscription_proxy_url')
        user_agent = get_subscription_user_agent()
        
        async def _do_fetch():
            fetcher = SubscriptionFetcher(http_client, proxy_url=proxy_url)
            return await fetcher.fetch(sub['url'], user_agent=user_agent)
        
        content, sub_info, node_count = asyncio.run(
            asyncio.wait_for(_do_fetch(), timeout=refresh_timeout)
        )
    except Exception as e:
        raise Exception(f"Failed to fetch subscription: {e}")
    
    # Apply region history
    content, remembered, inherited = apply_region_history_to_yaml_content(
        content,
        existing_nodes=existing_nodes,
        source=f'sub:scheduled-refresh:{sub_id}',
    )
    
    # Apply node visibility
    content, visibility_inherited = apply_node_visibility_to_yaml_content(
        content,
        existing_nodes=existing_nodes,
    )
    
    return content, sub_info, node_count, remembered, inherited, visibility_inherited


def _build_success_updates(sub_info: dict, node_count: int, sub_id: str) -> dict:
    """Build success updates dict for subscription."""
    updates = {
        'upload': sub_info.get('upload', 0),
        'download': sub_info.get('download', 0),
        'total': sub_info.get('total', 0),
        'expire': sub_info.get('expire', 0),
        'node_count': node_count,
        'last_update': int(time.time()),
        'update_status': 'success'
    }
    
    # Get next scheduled run time
    try:
        task_id = f"sub_refresh_{sub_id}"
        scheduler = get_scheduler()
        job_info = scheduler.get_job_info(task_id)
        if job_info and job_info.get('next_run'):
            updates['next_update'] = int(job_info['next_run'].timestamp())
        else:
            job = scheduler.scheduler.get_job(f"task_{task_id}") or scheduler.scheduler.get_job(task_id)
            updates['next_update'] = int(job.next_run_time.timestamp()) if job and job.next_run_time else None
    except Exception as e:
        logger.debug("Failed to update next scheduled run for %s: %s", sub_id, e)
        updates['next_update'] = None
    
    return updates


def refresh_subscription_job(sub_id: str):
    """
    Job function for scheduled subscription refresh.
    This is called by the scheduler and runs in a background thread.
    """
    try:
        logger.info(f"Scheduled refresh triggered for subscription {sub_id}")
        
        config = load_config()
        sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
        
        if not sub:
            logger.error(f"Subscription {sub_id} not found for scheduled refresh")
            return
        
        if sub.get('type') == 'local':
            logger.warning(f"Skipping scheduled refresh for local subscription {sub_id}")
            return
        
        try:
            content, sub_info, node_count, remembered, inherited, visibility_inherited = \
                _fetch_and_process_subscription(sub)
            
            success_updates = _build_success_updates(sub_info, node_count, sub_id)
            
            if remembered or inherited or visibility_inherited:
                logger.info(
                    "Scheduled refresh %s history: remembered=%s inherited_region=%s inherited_disabled=%s",
                    sub_id, remembered, inherited, visibility_inherited,
                )
            
            save_subscription_content(sub_id, content, YAML_SOURCE_DIR)
            update_subscription_fields(sub_id, success_updates)
            invalidate_stats_cache()
            
            logger.info(f"Scheduled refresh completed for subscription {sub_id}, got {node_count} nodes")
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Scheduled refresh failed for subscription {sub_id}: {error_msg}", exc_info=True)
            update_subscription_fields(sub_id, {'update_status': f'error: {error_msg}'})
    except Exception as e:
        logger.error(f"Fatal error in scheduled refresh job for {sub_id}: {e}", exc_info=True)


# ==================== Config Management ====================

# Config loading/saving is centralized in core.database. Keep server.py as a
# consumer only so startup tasks and extracted routers share the same defaults,
# xhttp compatibility normalization, deep-copy cache behavior, and file locking.

def migrate_old_config():
    """Migrate old config files to unified config"""
    if os.path.exists(CONFIG_FILE):
        return  # Already migrated

    config = {'auth': {}, 'subscriptions': [], 'custom_nodes': [], 'source_order': []}

    # Migrate auth.json
    auth_file = os.path.join(DATA_DIR, 'auth.json')
    if os.path.exists(auth_file):
        with open(auth_file, 'r', encoding='utf-8') as f:
            config['auth'] = json.load(f)

    # Migrate subscriptions.json
    subs_file = os.path.join(DATA_DIR, 'subscriptions.json')
    if os.path.exists(subs_file):
        with open(subs_file, 'r', encoding='utf-8') as f:
            config['subscriptions'] = json.load(f)

    # Migrate custom_nodes.json
    nodes_file = os.path.join(DATA_DIR, 'custom_nodes.json')
    if os.path.exists(nodes_file):
        with open(nodes_file, 'r', encoding='utf-8') as f:
            config['custom_nodes'] = json.load(f)

    # Migrate source_order.json
    order_file = os.path.join(DATA_DIR, 'source_order.json')
    if os.path.exists(order_file):
        with open(order_file, 'r', encoding='utf-8') as f:
            config['source_order'] = json.load(f)

    save_config(config)
    logger.info("Config migration completed")
    log_migration("migrate_old_config: legacy files merged into config.json")

def log_migration(message: str):
    """Write migration message to a separate log file."""
    try:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(MIGRATIONS_LOG, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        logger.warning("Failed to write migrations log: %s", e)

def migrate_legacy_sub_token():
    """Migrate legacy auth.sub_token to admin_tokens if not already migrated"""
    config = load_config()
    auth = config.get('auth', {})
    admin_tokens = config.get('admin_tokens', [])

    # Check if legacy sub_token exists
    legacy_token = auth.get('sub_token')
    if not legacy_token:
        return  # No legacy token to migrate

    # Check if already migrated (token value exists in admin_tokens)
    already_migrated = any(t.get('token') == legacy_token for t in admin_tokens)
    if already_migrated:
        return  # Already migrated

    # Create new admin token from legacy settings
    migrated_token = {
        'id': generate_timestamp_id('adm_'),
        'name': auth.get('sub_name', '默认'),  # Use original config name
        'token': legacy_token,  # Keep the same token value for backward compatibility
        'template_id': 'builtin',
        'sub_filename': auth.get('sub_filename', ''),
        'sub_name': auth.get('sub_name', ''),
        'enabled': True,
        'created_at': int(time.time())
    }

    if 'admin_tokens' not in config:
        config['admin_tokens'] = []
    config['admin_tokens'].insert(0, migrated_token)  # Add at beginning

    # Remove legacy fields after migration
    if 'sub_token' in config['auth']:
        del config['auth']['sub_token']
    if 'sub_filename' in config['auth']:
        del config['auth']['sub_filename']
    if 'sub_name' in config['auth']:
        del config['auth']['sub_name']

    save_config(config)
    logger.info("Legacy sub_token migrated to admin_tokens")
    log_migration("migrate_legacy_sub_token: migrated legacy token")

def migrate_subscription_fields():
    """Migrate subscriptions to add missing cron_expr and next_update fields"""
    config = load_config()
    subs = config.get('subscriptions', [])

    updated = False
    for sub in subs:
        # Add cron_expr field if missing
        if 'cron_expr' not in sub:
            sub['cron_expr'] = None
            updated = True

        # Add next_update field if missing
        if 'next_update' not in sub:
            sub['next_update'] = None
            updated = True

    if updated:
        save_config(config)
        logger.info("Subscription fields migrated: added cron_expr and next_update to %s subscriptions", len(subs))
        log_migration(f"migrate_subscription_fields: updated {len(subs)} subscriptions")

def migrate_proxy_chain_group_ids():
    """Add missing group_id for proxy chain group nodes."""
    config = load_config()
    chains = config.get('proxy_chains', [])
    if not chains:
        return

    updated = False
    added = 0
    for chain in chains:
        chain_id = chain.get('id') or chain.get('name', '')
        rows = chain.get('rows', [])
        for row_idx, row in enumerate(rows):
            nodes = row.get('nodes', [])
            for col_idx, node in enumerate(nodes):
                if isinstance(node, dict) and node.get('type') == 'group':
                    if not node.get('group_id'):
                        seed = f"{chain_id}:{row_idx}:{col_idx}"
                        digest = hashlib.sha1(seed.encode('utf-8')).hexdigest()[:8]
                        node['group_id'] = f"grp_{digest}"
                        updated = True
                        added += 1

    if updated:
        save_config(config)
        logger.info("Proxy chain group_id migration completed")
        log_migration(f"migrate_proxy_chain_group_ids: added {added} group_id")

# Run migration on startup
migrate_old_config()
migrate_legacy_sub_token()
migrate_subscription_fields()
migrate_proxy_chain_group_ids()


def _cleanup_stale_refresh_locks():
    """Remove leftover lock files from crashed processes."""
    try:
        if os.path.exists(REFRESH_LOCK_DIR):
            for f in os.listdir(REFRESH_LOCK_DIR):
                if f.endswith('.lock'):
                    os.remove(os.path.join(REFRESH_LOCK_DIR, f))
            logger.info("Cleaned up stale refresh lock files")
    except Exception as e:
        logger.warning("Failed to cleanup stale refresh locks: %s", e)


_cleanup_stale_refresh_locks()

# Initialize GeoIP config from saved config
def init_geoip_config():
    """Load GeoIP configuration from saved config on startup"""
    from geoip_service import set_online_geoip_config
    config = load_config()
    geoip_config = config.get('geoip_config', {})

    if geoip_config:
        set_online_geoip_config(
            ipinfo_token=geoip_config.get('ipinfo_token'),
            preferred_api=geoip_config.get('preferred_api'),
            custom_apis=geoip_config.get('custom_apis'),
            api_settings=geoip_config.get('api_settings')
        )
        logger.info("GeoIP config loaded: preferred_api=%s, custom_apis=%d",
                   geoip_config.get('preferred_api', 'ip-api.com'),
                   len(geoip_config.get('custom_apis', [])))

init_geoip_config()

# ==================== Country Detection (imported from services) ====================
# COUNTRY_KEYWORDS, COUNTRY_NAMES, PLACEHOLDER_COUNTRY_MAP are now in services/country_data.py

def filter_underscore_fields(data: dict) -> dict:
    """
    Filter out fields starting with underscore from a dictionary.
    Used to remove internal fields like _editable, _icon, _description from template output.

    Args:
        data: Dictionary that may contain underscore-prefixed fields

    Returns:
        New dictionary with underscore fields removed
    """
    return {k: v for k, v in data.items() if not k.startswith('_')}

def process_template_proxy_groups(template_groups: List[dict], all_proxies: List[str],
                                   country_groups: Dict[str, List[str]],
                                   sorted_country_names: List[str]) -> List[dict]:
    """
    Process template proxy-groups by replacing placeholders with actual values.

    Placeholders:
    - {{ALL_PROXIES}}: All proxy node names
    - {{COUNTRY_GROUPS}}: All country group names (e.g., ['🇭🇰 香港', '🇺🇸 美国', ...])
    - {{XX}}: Proxies from specific country (e.g., {{US}} for US proxies, {{HK}} for HK proxies)
    """
    processed_groups = []

    for group in template_groups:
        if not isinstance(group, dict):
            continue

        new_group = dict(group)
        proxies = group.get('proxies', [])

        if not isinstance(proxies, list):
            processed_groups.append(new_group)
            continue

        new_proxies = []
        for item in proxies:
            if not isinstance(item, str):
                new_proxies.append(item)
                continue

            if item == '{{ALL_PROXIES}}':
                # Replace with all proxy names
                new_proxies.extend(all_proxies)
            elif item == '{{COUNTRY_GROUPS}}':
                # Replace with all country group names
                new_proxies.extend(sorted_country_names)
            elif item in PLACEHOLDER_COUNTRY_MAP:
                # Replace with proxies from specific country
                country_code = PLACEHOLDER_COUNTRY_MAP[item]
                # Find the country group name that matches this code
                for country_name in sorted_country_names:
                    # Country name format: "flag + name" - need to check if code matches
                    if country_code in country_name or COUNTRY_NAMES.get(country_code, '') in country_name:
                        if country_name in country_groups:
                            new_proxies.extend(country_groups[country_name])
                        break
            else:
                # Keep as-is (DIRECT, REJECT, group references, etc.)
                new_proxies.append(item)

        new_group['proxies'] = new_proxies
        # Filter out underscore-prefixed fields before adding to output
        filtered_group = filter_underscore_fields(new_group)
        processed_groups.append(filtered_group)

    return processed_groups

def extract_country_from_name(node_name: str, server: str = None) -> Optional[Dict]:
    """
    Extract country info from node name using flag emoji or keywords.
    Priority: 1. Flag emoji  2. Keywords  3. None
    Returns: {'country': str, 'country_code': str, 'flag': str} or None
    """
    if not node_name:
        return None

    # 1. Check for flag emoji first (two regional indicator symbols)
    for i in range(len(node_name) - 1):
        potential_flag = node_name[i:i+2]
        if not (
            len(potential_flag) == 2
            and 0x1F1E6 <= ord(potential_flag[0]) <= 0x1F1FF
            and 0x1F1E6 <= ord(potential_flag[1]) <= 0x1F1FF
        ):
            continue
        code = GeoIPService.flag_to_iso(potential_flag)
        if code and len(code) == 2:
            return {
                'country': COUNTRY_NAMES.get(code, code),
                'country_code': code,
                'flag': GeoIPService.iso_to_flag(code)
            }

    # 2. Check for keywords (case-insensitive)
    # Find the longest matching keyword to prioritize specific names (e.g. 'Antarctica' > 'CA')
    name_lower = node_name.lower()
    best_match_code = None
    max_len = 0

    for code, keywords in COUNTRY_KEYWORDS.items():
        for keyword in keywords:
            if keyword in name_lower:
                if len(keyword) > max_len:
                    max_len = len(keyword)
                    best_match_code = code

    if best_match_code:
        return {
            'country': COUNTRY_NAMES.get(best_match_code, best_match_code),
            'country_code': best_match_code,
            'flag': GeoIPService.iso_to_flag(best_match_code)
        }

    return None

# Data Models moved to core/models.py

# Health Check API moved to api/health.py

# Auth API moved to api/auth.py

# ==================== Proxy Node Settings ====================

def _get_custom_node_by_id(node_id: str, custom_nodes: list) -> Optional[dict]:
    """Get custom node by ID."""
    try:
        idx = int(node_id.rsplit('_', 1)[1])
        if 0 <= idx < len(custom_nodes):
            node = custom_nodes[idx]
            if not is_node_enabled(node):
                return None
            node = dict(node)
            node.pop('enabled', None)
            return node
    except (ValueError, IndexError) as e:
        logger.warning(f"Invalid custom node ID format: {node_id}, error: {e}")
    except Exception as e:
        logger.error(f"Error getting custom node {node_id}: {e}", exc_info=True)
    return None


def _get_subscription_node_by_id(node_id: str, yaml_source_dir: str) -> Optional[dict]:
    """Get subscription node by ID."""
    sub_id = None
    try:
        node_ref, node_idx_text = node_id.rsplit('_', 1)
        if not node_ref or node_ref == 'sub':
            raise ValueError("missing subscription id")
        node_idx = int(node_idx_text)
        
        # Support both sub_<id>_<index> and <id>_<index> formats
        raw_sub_id = node_ref[4:] if node_ref.startswith('sub_') else node_ref
        candidate_sub_ids = []
        for candidate in (raw_sub_id, f"sub_{raw_sub_id}", node_ref):
            if candidate and candidate not in candidate_sub_ids:
                candidate_sub_ids.append(candidate)
        
        for sub_id in candidate_sub_ids:
            sub_file = os.path.join(yaml_source_dir, f"{sub_id}.yaml")
            if not os.path.exists(sub_file):
                continue
            sub_data = load_subscription_yaml(sub_id, yaml_source_dir, use_cache=True)
            proxies = sub_data.get('proxies', [])
            if 0 <= node_idx < len(proxies):
                proxy = proxies[node_idx]
                if not is_node_enabled(proxy):
                    return None
                proxy = dict(proxy)
                proxy.pop('enabled', None)
                return proxy
            logger.warning(f"Node index {node_idx} out of range for subscription {sub_id}")
            break
    except (ValueError, IndexError) as e:
        logger.warning(f"Invalid subscription node ID format: {node_id}, error: {e}")
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse subscription YAML {sub_id}: {e}")
    except Exception as e:
        logger.error(f"Error getting subscription node {node_id}: {e}", exc_info=True)
    return None


# Node Parsing moved to services/node_parser.py

# ==================== Subscription Helper Functions ====================

def parse_subscription_info(headers: dict) -> dict:
    """Parse subscription userinfo from headers"""
    info = {'upload': 0, 'download': 0, 'total': 0, 'expire': 0}
    userinfo = headers.get('subscription-userinfo', '') or headers.get('Subscription-Userinfo', '')
    if userinfo:
        for part in userinfo.split(';'):
            if '=' in part:
                key, val = part.split('=', 1)
                try:
                    info[key.strip().lower()] = int(val.strip())
                except ValueError as e:
                    logger.debug(f"Invalid subscription info value for {key}: {val}, error: {e}")
                except Exception as e:
                    logger.warning(f"Error parsing subscription info: {e}")
    return info


def fetch_subscription(url: str) -> Tuple[str, dict, int]:
    """Fetch subscription content from URL (synchronous wrapper for async call)"""
    _ensure_sync_context("fetch_subscription", "fetch_subscription_async")
    return asyncio.run(fetch_subscription_async(url))


def _ensure_sync_context(sync_name: str, async_name: str) -> None:
    """Prevent synchronous wrappers from being called inside a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError(f"{sync_name}() cannot be called from an async context; use await {async_name}() instead.")


async def fetch_subscription_async(url: str) -> Tuple[str, dict, int]:
    """
    Fetch subscription content from URL.

    Args:
        url: Subscription URL

    Returns:
        Tuple of (content, subscription_info, node_count)
    """
    from helpers_ua import get_subscription_user_agent
    user_agent = get_subscription_user_agent()
    headers = {'User-Agent': user_agent}
    
    try:
        logger.info(f"Fetching subscription from: {url}")
        response = await http_client.get(url, headers=headers, timeout=Constants.TIMEOUT_SUBSCRIPTION_FETCH)
        response.raise_for_status()
        
        sub_info = parse_subscription_info(dict(response.headers))
        content = _process_subscription_content(response)
        node_count = _count_nodes(content)
        
        logger.info(f"Successfully fetched subscription, got {node_count} nodes")
        return content, sub_info, node_count
    except httpx.HTTPStatusError as e:
        raise Exception(f"HTTP {e.response.status_code}: {e}")
    except httpx.TimeoutException as e:
        raise Exception(f"Connection timeout: {e}")
    except Exception as e:
        raise Exception(f"Connection failed: {e}")


def _process_subscription_content(response) -> str:
    """Process subscription content from response object"""
    from services.subscription_parser import parse_subscription_content
    
    try:
        content = response.content.decode('utf-8', errors='ignore').strip()
    except AttributeError:
        try:
            content = response.text.strip()
        except Exception as e:
            logger.error(f"Failed to get response content: {e}")
            content = ""
    except Exception as e:
        logger.error(f"Failed to decode response content: {e}")
        content = ""
    
    if not content:
        return ""
    
    try:
        return parse_subscription_content(content)
    except Exception as e:
        logger.warning(f"Failed to parse subscription content: {e}")
        return content


def _process_subscription_content_str(content: str) -> str:
    """Process subscription content string and return YAML format"""
    from services.subscription_parser import parse_subscription_content
    
    if not content:
        return ""
    
    try:
        return parse_subscription_content(content)
    except Exception as e:
        logger.warning(f"Failed to parse subscription content: {e}")
        return content


def _count_nodes(content: str) -> int:
    """Count number of nodes in YAML content"""
    try:
        cfg = yaml.load(content, Loader=YAMLLoader)
        if cfg and isinstance(cfg, dict) and 'proxies' in cfg:
            count = len(cfg.get('proxies', []))
            logger.debug(f"Counted {count} nodes in content")
            return count
    except yaml.YAMLError as e:
        logger.debug(f"Cannot count nodes - invalid YAML: {e}")
    except Exception as e:
        logger.warning(f"Error counting nodes: {e}")
    return 0


def _pad_base64(value: str) -> str:
    """Add only the Base64 padding that is actually missing."""
    return value + '=' * (-len(value) % 4)


def parse_local_subscription(content: str) -> Tuple[str, List[dict], int]:
    """
    Parse local subscription content.
    Supports: YAML (with proxies), Base64 encoded content, URI list (ss://, vmess://, etc.)

    Returns: (yaml_content, proxies_list, node_count)
    """
    original_content = content.strip()
    decoded_content = original_content

    # Try Base64 decode
    try:
        # Remove possible padding issues
        padded = _pad_base64(original_content)
        decoded = base64.b64decode(padded).decode('utf-8')
        decoded_content = decoded.strip()
        logger.debug("Successfully decoded Base64 content")
    except base64.binascii.Error as e:
        logger.debug(f"Content is not Base64 encoded: {e}")
    except UnicodeDecodeError as e:
        logger.warning(f"Base64 content is not valid UTF-8: {e}")
    except Exception as e:
        logger.warning(f"Failed to decode Base64: {e}")

    proxies = []

    # Check if it's YAML with proxies section
    try:
        cfg = yaml.load(decoded_content, Loader=YAMLLoader)
        if isinstance(cfg, dict) and 'proxies' in cfg:
            proxies = cfg.get('proxies', [])
            yaml_content = decoded_content
            logger.info(f"Parsed {len(proxies)} nodes from YAML content")
            return yaml_content, proxies, len(proxies)
    except yaml.YAMLError as e:
        logger.debug(f"Content is not valid YAML: {e}")
    except Exception as e:
        logger.warning(f"Error parsing YAML content: {e}")

    # Try parsing as URI list (one link per line)
    lines = decoded_content.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Parse various URI formats
        proxy = parse_node_link(line)
        if proxy:
            proxies.append(proxy)

    if proxies:
        # Convert to YAML format
        yaml_content = yaml.dump({'proxies': proxies}, allow_unicode=True, sort_keys=False, Dumper=YAMLDumper)
        return yaml_content, proxies, len(proxies)

    raise ValueError("无法识别订阅内容格式，请检查是否为有效的 YAML、Base64 或节点链接")

def update_custom_nodes_yaml():
    """Update custom nodes yaml file"""
    config = load_config()
    nodes = config.get('custom_nodes', [])
    proxies = []

    # Fields to exclude from proxy config (metadata fields)
    exclude_fields = ['id', 'link', 'last_latency', 'last_latency_time', 'last_speed',
                      'last_peak_speed', 'last_speed_time', 'geoip', 'enabled']

    for node in nodes:
        if not is_node_enabled(node):
            continue
        # Use stored node config instead of re-parsing to avoid performance issues
        # Exclude metadata fields which are not part of proxy config
        proxy = {k: v for k, v in node.items() if k not in exclude_fields}
        proxy = ProxyFilter.sanitize_proxy(proxy)
        if proxy and 'type' in proxy:  # Ensure it's a valid proxy config
            proxies.append(proxy)

    save_subscription_yaml('custom_nodes', {'proxies': proxies}, YAML_SOURCE_DIR)

def get_ordered_sources() -> List[dict]:
    """Get all sources in order"""
    config = load_config()
    subs = config.get('subscriptions', [])
    custom_nodes = config.get('custom_nodes', [])
    order = config.get('source_order', [])

    all_sources = {}
    for s in subs:
        all_sources[s['id']] = {'type': 'subscription', 'data': s}
    if custom_nodes:
        all_sources['custom_nodes'] = {'type': 'custom', 'data': {'id': 'custom_nodes', 'name': 'Custom Nodes', 'nodes': custom_nodes}}

    result = []
    for source_id in order:
        if source_id in all_sources:
            result.append(all_sources.pop(source_id))
    for source in all_sources.values():
        result.append(source)

    return result

# ==================== Helper Functions ====================

def get_all_final_node_names() -> set:
    """Get a set of all current final node names (for validation)"""
    config = load_config()
    names = set()

    # Get subscription nodes
    for sub in config.get('subscriptions', []):
        if sub.get('enabled', True):
            try:
                cfg = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=True)
                for proxy in cfg.get('proxies', []):
                    if not is_node_enabled(proxy):
                        continue
                    transformed = NameTransformer.transform_name(proxy, sub['name'])
                    names.add(transformed.get('name', ''))
            except HTTPException:
                # Subscription file not found, skip
                pass
            except Exception as e:
                logger.error(f"Error getting node names from {sub['id']}: {e}")

    # Get custom nodes
    for node in config.get('custom_nodes', []):
        if not is_node_enabled(node):
            continue
        transformed = NameTransformer.transform_name(node, 'Custom')
        names.add(transformed.get('name', ''))

    return names



# ==================== Modular Route Registration ====================

# Register routers that depend on helper functions defined above.
app.include_router(create_user_allocation_router(
    yaml_source_dir=YAML_SOURCE_DIR,
    load_config=load_config,
    get_all_final_node_names=get_all_final_node_names,
    logger=logger,
))
app.include_router(create_subscription_output_router(
    yaml_source_dir=YAML_SOURCE_DIR,
    output_file=OUTPUT_FILE,
    load_config=load_config,
    update_config=update_config,
    fetch_subscription=fetch_subscription,
    fetch_subscription_async=fetch_subscription_async,
    find_node_by_reference=find_node_by_reference,
    is_name_allocated=is_name_allocated,
    filter_underscore_fields=filter_underscore_fields,
    extract_country_from_name=extract_country_from_name,
    split_template=split_template,
    logger=logger,
    subscription_refresh_lock=subscription_refresh_wait_lock,
))
app.include_router(create_template_router(
    yaml_source_dir=YAML_SOURCE_DIR,
    output_file=OUTPUT_FILE,
    load_config=load_config,
    update_config=update_config,
    logger=logger,
))


# ==================== Static Files ====================

frontend_dist = os.environ.get('FRONTEND_DIST_DIR') or os.path.join(BASE_DIR, 'submerger', 'dist')
if not os.path.isabs(frontend_dist):
    frontend_dist = os.path.join(BASE_DIR, frontend_dist)
frontend_dist_path = Path(frontend_dist).resolve()


def _is_path_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _resolve_frontend_static_file(full_path: str) -> Optional[Path]:
    """Resolve a SPA/static file request without allowing path traversal."""
    normalized = (full_path or '').replace('\\', '/').lstrip('/')
    target = (frontend_dist_path / normalized).resolve()
    if not _is_path_within(target, frontend_dist_path):
        return None
    if target.is_file():
        return target
    return None


if os.path.exists(frontend_dist):
    # 1. Mount assets with cache headers for performance
    assets_path = os.path.join(frontend_dist, 'assets')
    if os.path.exists(assets_path):
        app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

    # 2. Serve root requests
    @app.get("/", include_in_schema=False)
    async def serve_index():
        response = FileResponse(str(frontend_dist_path / "index.html"))
        # No cache for HTML to ensure fresh content
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    # 3. Catch-all for SPA routes (e.g. /settings, /nodes)
    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        # API 404s should return JSON, not HTML
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")

        # Try to serve static file if it exists (e.g. favicon.ico)
        file_path = _resolve_frontend_static_file(full_path)
        if file_path:
            response = FileResponse(str(file_path))
            # Cache static assets (js, css, images) for 1 year (immutable with hash)
            if full_path.endswith(('.js', '.css', '.woff', '.woff2', '.ttf', '.eot')):
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            elif full_path.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp')):
                response.headers["Cache-Control"] = "public, max-age=86400"  # 1 day for images
            elif full_path.endswith('.json'):
                response.headers["Cache-Control"] = "public, max-age=3600"  # 1 hour for JSON
            return response

        # Fallback to index.html for React Router
        response = FileResponse(str(frontend_dist_path / "index.html"))
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

if __name__ == "__main__":
    import uvicorn
    from dotenv import load_dotenv

    # Load .env file
    load_dotenv()

    # Get configuration from environment variables
    port = env_int('PORT', 8666, minimum=1, maximum=65535)
    host = os.getenv('HOST', '0.0.0.0')

    logger.info(f"Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
