import asyncio  # Used for async operations
import os
import subprocess  # Patched via server.subprocess in tests; kept as a module seam
import time
import uuid  # Used for request IDs
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, Callable, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Import API routers
from api import api_router
from api.health import set_http_client as set_health_http_client
from api.template_compat import create_template_router, split_template
from api.user_allocation import create_user_allocation_router

# Import from refactored modules
from core import (
    concurrent_requests,
    http_request_duration_seconds,
    http_requests_total,
)

# Import refactored modules
from core.config import AppConfig as CoreAppConfig
from core.config import env_int

# The load/save helpers below stay imported even where this module no longer
# calls them: extracted services and the scheduler jobs resolve them through
# the ``server`` namespace at call time (the app-wide patch seam), so the
# names must keep existing here.
from core.database import find_subscription_by_id, load_config, save_config, update_config, update_subscription_fields
from core.http_middleware import RequestSizeLimitMiddleware
from core.initialization import initialize_administrator
from core.migrations import (
    init_geoip_config,
    log_migration,
    migrate_legacy_sub_token,
    migrate_node_pool_ids,
    migrate_old_config,
    migrate_proxy_chain_group_ids,
    migrate_stable_node_references,
    migrate_subscription_fields,
    migrate_subscription_node_counts,
    reload_runtime_configuration,
)
from core.rate_limit import limiter
from helpers import Constants, load_subscription_yaml
from logger_config import get_logger
from scheduler_service import get_scheduler, init_scheduler
from services.country_data import extract_country_from_name
from services.node_manager import find_node_by_reference, is_name_allocated
from services.node_metadata import filter_underscore_fields
from services.node_visibility import apply_node_visibility_to_yaml_content
from services.region_history import (
    apply_node_test_metadata_to_yaml_content,
    apply_region_history_to_yaml_content,
)
from services.source_ordering import get_all_final_node_names, get_ordered_sources, update_custom_nodes_yaml
from services.speedtest_supervisor import (
    _acquire_scheduler_leader,
    _monitor_go_speedtest_service,
    _release_scheduler_leader,
    start_go_speedtest_service,
    stop_go_speedtest_service,
)
from services.stats_cache import invalidate as invalidate_stats_cache
from services.stats_history import record_stats_snapshot_if_stale
from services.subscription_output import create_subscription_output_router
from services.subscription_processing import (
    _pad_base64,
    _process_subscription_content_str,
    fetch_subscription,
    fetch_subscription_async,
    parse_local_subscription,
)
from services.subscription_refresh_jobs import (
    _build_success_updates,
    _fetch_and_process_subscription,
    _load_existing_nodes,
    _restore_scheduled_jobs,
    _schedule_automatic_backup,
    _schedule_flclash_version_check,
    _schedule_stats_snapshot,
    refresh_subscription_job,
    reschedule_vpngate_refresh,
)
from services.subscription_refresh_lock import (
    SubscriptionRefreshInProgress,
    wait_for_refresh_slot,
    wait_for_scheduled_refresh_slot,
)
from services.subscription_state import record_refresh_failure
from services.subscription_storage import recover_pending_subscription_transactions

# Setup logger for this module
logger = get_logger(__name__)

# ==================== Application Configuration ====================

# Keep server.py on the canonical configuration object.  Duplicating AppConfig
# here made environment variables drift between core and server startup paths.
AppConfig = CoreAppConfig


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
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


# Global exception handler to log all unhandled exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled request exception", exc_info=(type(exc), exc, exc.__traceback__))
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


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
        "form-action 'self'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    return response


_cors_origins = [origin.strip() for origin in AppConfig.CORS_ORIGINS.split(",") if origin.strip()]
_cors_allow_credentials = True
if AppConfig.CORS_ORIGINS.strip() == "*":
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
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=AppConfig.MAX_REQUEST_SIZE)


# ==================== Startup/Shutdown Events ====================


async def startup_event() -> None:
    """Initialize services on startup"""
    global http_client, GO_SPEEDTEST_MONITOR_TASK, SERVER_SHUTTING_DOWN
    SERVER_SHUTTING_DOWN = False
    logger.info("Starting up application...")

    # Migrations and first-start initialization run inside lifespan rather than
    # at module import, so an invalid configuration prevents readiness cleanly.
    recover_pending_subscription_transactions(AppConfig.YAML_SOURCE_DIR)
    migrate_old_config()
    migrate_legacy_sub_token()
    migrate_subscription_fields()
    migrate_subscription_node_counts()
    migrate_proxy_chain_group_ids()
    migrate_node_pool_ids()
    migrate_stable_node_references()
    initialize_administrator()
    init_geoip_config()

    # Seed the dashboard trend history when the stored snapshot is stale so a
    # fresh deployment gets a first data point without waiting for the cron.
    # Crash-safe and idempotent: failures are logged, never raised.
    record_stats_snapshot_if_stale()

    # Initialize HTTP client
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=AppConfig.CONNECT_TIMEOUT,
            read=AppConfig.READ_TIMEOUT,
            write=AppConfig.WRITE_TIMEOUT,
            pool=AppConfig.CONNECT_TIMEOUT,
        ),
        follow_redirects=True,
        limits=httpx.Limits(
            max_keepalive_connections=AppConfig.HTTP_MAX_KEEPALIVE, max_connections=AppConfig.HTTP_MAX_CONNECTIONS
        ),
        verify=AppConfig.HTTP_VERIFY_SSL,
        trust_env=False,
    )
    set_health_http_client(http_client)
    logger.info("HTTP client initialized")

    # Start Go speedtest service
    if AppConfig.GO_SPEEDTEST_ENABLED:
        if await asyncio.to_thread(start_go_speedtest_service):
            logger.info("Go speedtest service started successfully")
            GO_SPEEDTEST_MONITOR_TASK = asyncio.create_task(_monitor_go_speedtest_service())
        else:
            logger.warning("Failed to start Go speedtest service - proxy fetching will not be available")
    else:
        logger.info("Go speedtest service disabled")

    # APScheduler is process-local. A shared leader lock prevents multiple
    # replicas from registering refresh, version-check and backup jobs.
    if _acquire_scheduler_leader():
        init_scheduler()
        logger.info("Scheduler initialized")
        _restore_scheduled_jobs()
        _schedule_flclash_version_check()
        _schedule_automatic_backup()
        _schedule_stats_snapshot()
        reschedule_vpngate_refresh()


async def shutdown_event() -> None:
    """Cleanup on shutdown"""
    logger.info("Shutting down application...")
    global GO_SPEEDTEST_MONITOR_TASK, SERVER_SHUTTING_DOWN
    SERVER_SHUTTING_DOWN = True
    if GO_SPEEDTEST_MONITOR_TASK is not None:
        GO_SPEEDTEST_MONITOR_TASK.cancel()
        await asyncio.gather(GO_SPEEDTEST_MONITOR_TASK, return_exceptions=True)
        GO_SPEEDTEST_MONITOR_TASK = None
    if SCHEDULER_IS_LEADER:
        get_scheduler().stop()
    stop_go_speedtest_service()
    _release_scheduler_leader()
    if http_client:
        await http_client.aclose()
    # Close the subscription fetcher's dedicated HTTP client
    try:
        from api.subscriptions import close_fetcher

        await close_fetcher()
    except Exception:
        pass
    # Close the shared speedtest HTTP client
    try:
        from api.speedtest import _speedtest_client

        if _speedtest_client is not None:
            await _speedtest_client.aclose()
    except Exception:
        pass
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

    method = request.method

    # Track concurrent requests
    concurrent_requests.inc()

    try:
        response = await call_next(request)
        status = response.status_code
        route = request.scope.get("route")
        endpoint = getattr(route, "path", None) or "<unmatched>"

        # Record metrics
        http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
        duration = time.time() - start_time
        http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

        return response
    except Exception:
        # Record error
        route = request.scope.get("route")
        endpoint = getattr(route, "path", None) or "<unmatched>"
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
YAML_SOURCE_DIR = os.path.join(DATA_DIR, "uploads")
OUTPUT_FILE = os.path.join(DATA_DIR, "myconfig.yaml")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")  # Unified config file
MIGRATIONS_LOG = os.path.join(DATA_DIR, "migrations.log")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(YAML_SOURCE_DIR, exist_ok=True)

# ==================== HTTP Client ====================
# Global async HTTP client - initialized in startup_event()
http_client = None

# ==================== Go Speedtest Service & Scheduler Leader State ====================
# Mutable service state lives in this namespace: startup/shutdown assign it and
# services/speedtest_supervisor.py resolves it through the server seam.
GO_SPEEDTEST_PROCESS = None
GO_SPEEDTEST_MONITOR_TASK = None
SCHEDULER_LEADER_LOCK = None
SCHEDULER_IS_LEADER = False
SERVER_SHUTTING_DOWN = False


# ==================== Modular Route Registration ====================

# Register routers that depend on helper functions re-exported above.
app.include_router(
    create_user_allocation_router(
        yaml_source_dir=YAML_SOURCE_DIR,
        load_config=load_config,
        get_all_final_node_names=get_all_final_node_names,
        logger=logger,
    )
)
app.include_router(
    create_subscription_output_router(
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
        subscription_refresh_lock=wait_for_refresh_slot,
    )
)
app.include_router(
    create_template_router(
        yaml_source_dir=YAML_SOURCE_DIR,
        output_file=OUTPUT_FILE,
        load_config=load_config,
        update_config=update_config,
        logger=logger,
    )
)


# ==================== Static Files ====================

frontend_dist = os.environ.get("FRONTEND_DIST_DIR") or os.path.join(BASE_DIR, "submerger", "dist")
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
    normalized = (full_path or "").replace("\\", "/").lstrip("/")
    target = (frontend_dist_path / normalized).resolve()
    if not _is_path_within(target, frontend_dist_path):
        return None
    if target.is_file():
        return target
    return None


if os.path.exists(frontend_dist):
    # 1. Mount assets with cache headers for performance
    assets_path = os.path.join(frontend_dist, "assets")
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
            if full_path.endswith((".js", ".css", ".woff", ".woff2", ".ttf", ".eot")):
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            elif full_path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp")):
                response.headers["Cache-Control"] = "public, max-age=86400"  # 1 day for images
            elif full_path.endswith(".json"):
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
    port = env_int("PORT", 8666, minimum=1, maximum=65535)
    host = os.getenv("HOST", "0.0.0.0")

    logger.info(f"Starting server on {host}:{port}")
    # Subscription clients authenticate in the URL. Uvicorn's default access
    # log records the full query string, so it must stay disabled here.
    uvicorn.run(app, host=host, port=port, access_log=False)
