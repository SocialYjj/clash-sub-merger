import os
import yaml
import json
import time
import re
import hashlib
import httpx
import subprocess
import sys
import atexit
import base64  # Used for node parsing
import asyncio  # Used for async operations
import uuid  # Used for request IDs
import ipaddress  # IPv6 formatting for URI links
import signal  # Used for signal handling
from contextlib import asynccontextmanager

# Use C-accelerated YAML loader for better performance
try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
except ImportError:
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote, quote
from typing import Optional, Tuple, Dict, List, Callable
from collections import OrderedDict
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Header, BackgroundTasks, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl, Field, validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from filelock import FileLock, Timeout
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

# Import from refactored modules
from core import (
    http_requests_total, http_request_duration_seconds,
    subscription_refresh_total, subscription_refresh_duration_seconds,
    subscription_node_count, nodes_total, speedtest_total,
    speedtest_latency_milliseconds, config_operations_total,
    concurrent_requests,
)
from services.config_merger import ConfigMerger, ProxyGroupGenerator
from services.name_transformer import NameTransformer
from services.country_grouper import CountryGrouper
from services.proxy_filter import ProxyFilter
from services.country_data import COUNTRY_KEYWORDS, COUNTRY_NAMES, PLACEHOLDER_COUNTRY_MAP, detect_country
from services.node_parser import parse_node_link
from services.region_history import apply_region_history_to_yaml_content
from geoip_service import GeoIPService, lookup_ip_online
from scheduler_service import get_scheduler, init_scheduler, CRON_PRESETS, get_cron_description
from speedtest_service import (
    get_speedtest_service, SpeedTestConfig, SpeedTestResult,
    get_latency_color, get_speed_color, format_speed, format_latency
)
from logger_config import get_logger, LOG_LEVEL, get_log_format
from helpers import (
    Constants, YAMLCache, yaml_cache,
    load_subscription_yaml, save_subscription_yaml, save_subscription_content,
    get_subscription_node, save_custom_nodes_yaml, generate_timestamp_id,
    find_item_by_id, load_yaml_file_cached,
    Validators, handle_api_errors,
    cache_hits_total as helper_cache_hits,
    cache_misses_total as helper_cache_misses,
    file_operations_total as helper_file_ops,
    file_operation_duration_seconds as helper_file_duration
)

# Import refactored modules
from core.config import AppConfig as CoreAppConfig
from core.dependencies import verify_session
from services.backup import (
    create_backup, list_backups, restore_backup, delete_backup,
    export_config, import_config
)
from services.key_rotation import check_key_rotation_needed

# Import node parser service
from services.node_parser import (
    decode_base64, parse_node_link, parse_vmess_link, parse_vless_link,
    parse_ss_link, parse_ssr_link, parse_trojan_link, parse_hysteria_link,
    parse_hysteria2_link, parse_tuic_link, parse_socks_link, parse_http_link
)

# Import data models
from core.models import (
    SetPassword, Login, AddSubscription, AddLocalSubscription,
    UpdateSubscription, UpdateLocalSubscription, ReorderSubscriptions,
    TemplateContent, FinalContent, CustomNode, UpdateNodeName, UpdateNodeFull,
    UpdateSubNode, UpdateSubNodeFull, CreateUser, UpdateUser,
    UserNodeAllocation, UpdateUserGroupConfig, PortMappingCreate,
    PortMappingUpdate, ProxyChainNode, ProxyChainRow, CreateProxyChain, UpdateProxyChain
)

# Import API routers
from api import api_router
from api.health import set_http_client

# Setup logger for this module
logger = get_logger(__name__)

# ==================== Application Configuration ====================

class AppConfig:
    """Centralized application configuration"""
    
    # Directories
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.environ.get('DATA_DIR', os.path.join(BASE_DIR, 'data'))
    
    # Go Speedtest Service
    GO_SPEEDTEST_URL = os.environ.get('GO_SPEEDTEST_URL', 'http://localhost:9876')
    GO_SPEEDTEST_PORT = int(os.environ.get('GO_SPEEDTEST_PORT', '9876'))
    GO_SPEEDTEST_ENABLED = os.environ.get('GO_SPEEDTEST_ENABLED', 'true').strip().lower() in ('1', 'true', 'yes', 'on')
    GO_SPEEDTEST_BIN = os.environ.get('GO_SPEEDTEST_BIN', '').strip()
    
    # Timeouts (seconds) - fine-grained control
    DEFAULT_TIMEOUT = int(os.environ.get('DEFAULT_TIMEOUT', '30'))
    SPEEDTEST_TIMEOUT = int(os.environ.get('SPEEDTEST_TIMEOUT', '10'))
    HEALTH_CHECK_TIMEOUT = int(os.environ.get('HEALTH_CHECK_TIMEOUT', '2'))
    CONNECT_TIMEOUT = int(os.environ.get('CONNECT_TIMEOUT', '10'))  # Connection establishment
    READ_TIMEOUT = int(os.environ.get('READ_TIMEOUT', '30'))  # Reading response
    WRITE_TIMEOUT = int(os.environ.get('WRITE_TIMEOUT', '10'))  # Writing request
    
    # Retry settings
    MAX_RETRIES = int(os.environ.get('MAX_RETRIES', '3'))
    RETRY_DELAY = int(os.environ.get('RETRY_DELAY', '1'))
    
    # Cache settings
    STATS_CACHE_DURATION = int(os.environ.get('STATS_CACHE_DURATION', '60'))
    CONFIG_CACHE_DURATION = int(os.environ.get('CONFIG_CACHE_DURATION', '5'))
    
    # File lock timeout
    FILE_LOCK_TIMEOUT = int(os.environ.get('FILE_LOCK_TIMEOUT', '10'))
    
    # Rate limiting
    RATE_LIMIT_LOGIN = os.environ.get('RATE_LIMIT_LOGIN', '10/minute')
    RATE_LIMIT_REFRESH_SINGLE = os.environ.get('RATE_LIMIT_REFRESH_SINGLE', '10/minute')
    RATE_LIMIT_REFRESH_ALL = os.environ.get('RATE_LIMIT_REFRESH_ALL', '5/minute')
    RATE_LIMIT_SPEEDTEST = os.environ.get('RATE_LIMIT_SPEEDTEST', '5/minute')
    RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '200/minute')
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*')  # Comma-separated or *
    
    # GZip compression threshold (bytes)
    GZIP_MIN_SIZE = int(os.environ.get('GZIP_MIN_SIZE', '500'))
    
    # HTTP connection pool settings
    HTTP_MAX_KEEPALIVE = int(os.environ.get('HTTP_MAX_KEEPALIVE', '20'))
    HTTP_MAX_CONNECTIONS = int(os.environ.get('HTTP_MAX_CONNECTIONS', '50'))
    
    # Version
    VERSION = CoreAppConfig.VERSION

# Setup rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=[AppConfig.RATE_LIMIT_DEFAULT])

@asynccontextmanager
async def lifespan(app: FastAPI):
    await startup_event()
    try:
        yield
    finally:
        await shutdown_event()

app = FastAPI(
    title="Clash Config Merger API",
    description="Modern subscription aggregation management panel for Clash/Mihomo",
    version=AppConfig.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "health", "description": "Health check and metrics"},
        {"name": "auth", "description": "Authentication operations"},
        {"name": "subscriptions", "description": "Subscription management"},
        {"name": "nodes", "description": "Node management"},
        {"name": "users", "description": "User management"},
        {"name": "templates", "description": "Template management"},
        {"name": "speedtest", "description": "Speed test operations"},
        {"name": "stats", "description": "Statistics and analytics"},
    ],
    lifespan=lifespan
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Global exception handler to log all unhandled exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    import traceback
    error_detail = f"Unhandled exception: {str(exc)}\n{traceback.format_exc()}"
    logger.error(error_detail)
    print(f"GLOBAL ERROR: {error_detail}", file=sys.stderr)
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)}
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=AppConfig.CORS_ORIGINS.split(',') if AppConfig.CORS_ORIGINS != '*' else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip compression middleware for large responses
app.add_middleware(GZipMiddleware, minimum_size=AppConfig.GZIP_MIN_SIZE)


# ==================== Startup/Shutdown Events ====================

async def startup_event():
    """Initialize services on startup"""
    logger.info("Starting up application...")
    
    # Start Go speedtest service
    if AppConfig.GO_SPEEDTEST_ENABLED:
        if start_go_speedtest_service():
            logger.info("Go speedtest service started successfully")
        else:
            logger.warning("Failed to start Go speedtest service - proxy fetching will not be available")
    else:
        logger.info("Go speedtest service disabled")
    
    # Initialize scheduler
    init_scheduler()
    logger.info("Scheduler initialized")
    
    # Restore scheduled jobs from config
    try:
        from core.database import load_config
        
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
            from core.database import save_config
            save_config(config)
            logger.info(f"Restored {restored_count} scheduled job(s)")
    except Exception as e:
        logger.error(f"Failed to restore scheduled jobs: {e}")
    
    # Schedule FlClash version check (only if using flclash mode)
    try:
        ua_mode = os.getenv('SUBSCRIPTION_UA_MODE', 'flclash').strip().lower()
        if ua_mode == 'flclash':
            from helpers_ua import refresh_version_cache
            from apscheduler.triggers.cron import CronTrigger
            
            # Get cron expression from env, default to daily at 3 AM
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
                # Fallback to default
                scheduler.scheduler.add_job(
                    refresh_version_cache,
                    trigger=CronTrigger(hour=3, minute=0),
                    id="flclash_version_refresh",
                    replace_existing=True
                )
                logger.info("Scheduled FlClash version check at 3:00 AM (default)")
        else:
            logger.info(f"FlClash version check disabled (UA mode: {ua_mode})")
    except Exception as e:
        logger.warning(f"Failed to schedule FlClash version check: {e}")


async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down application...")
    stop_go_speedtest_service()
    if http_client:
        await http_client.aclose()
    logger.info("Application shutdown complete")
# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Request ID middleware

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add unique request ID to each request"""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

# Request size limit middleware
@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Limit request body size"""
    if request.headers.get("content-length"):
        content_length = int(request.headers["content-length"])
        if content_length > Constants.MAX_REQUEST_SIZE:
            raise HTTPException(status_code=413, detail="Request too large")
    
    return await call_next(request)

# Slow request logging middleware
@app.middleware("http")
async def log_slow_requests(request: Request, call_next):
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
# Create global async HTTP client for better performance
# Connection pool optimized for concurrent subscription refreshes
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
    verify=False  # Disable SSL verification to handle certificates with hostname mismatch
)

# ==================== Config Helper Functions ====================

def find_subscription_by_id(config: dict, sub_id: str) -> Optional[dict]:
    """Fast subscription lookup by ID (O(n) but with early return)"""
    for s in config.get('subscriptions', []):
        if s['id'] == sub_id:
            return s
    return None

def find_custom_node_by_id(config: dict, node_id: str) -> Optional[dict]:
    """Fast custom node lookup by ID"""
    for node in config.get('custom_nodes', []):
        if node['id'] == node_id:
            return node
    return None

def find_user_by_id(config: dict, user_id: str) -> Optional[dict]:
    """Fast user lookup by ID"""
    for user in config.get('users', []):
        if user['id'] == user_id:
            return user
    return None

def find_template_by_id(config: dict, template_id: str) -> Optional[dict]:
    """Fast template lookup by ID"""
    for template in config.get('templates', []):
        if template['id'] == template_id:
            return template
    return None

def find_admin_token_by_id(config: dict, token_id: str) -> Optional[dict]:
    """Fast admin token lookup by ID"""
    for token in config.get('admin_tokens', []):
        if token['id'] == token_id:
            return token
    return None

def find_proxy_chain_by_id(config: dict, chain_id: str) -> Optional[dict]:
    """Fast proxy chain lookup by ID"""
    for chain in config.get('proxy_chains', []):
        if chain['id'] == chain_id:
            return chain
    return None

def find_node_by_reference(sub_id: str, node_index: int | None = None, node_name: str | None = None) -> Optional[dict]:
    """Get a proxy node by reference (sub_id + node_name/node_index) with transformed name.

    Returns a proxy dict aligned with ConfigMerger naming, or None if not found/invalid.
    """
    config = load_config()

    # Custom nodes
    if sub_id == 'custom':
        custom_nodes = config.get('custom_nodes', [])
        if node_name:
            for node in custom_nodes:
                exclude_fields = {
                    'id', 'link', 'last_latency', 'last_latency_time', 'last_speed',
                    'last_peak_speed', 'last_speed_time', 'geoip'
                }
                proxy = {k: v for k, v in node.items() if k not in exclude_fields}
                proxy = ProxyFilter.sanitize_proxy(proxy)
                transformed = NameTransformer.transform_name(proxy, 'Custom')
                if transformed.get('name') == node_name:
                    return transformed
        if node_index is not None and 0 <= node_index < len(custom_nodes):
            node = custom_nodes[node_index]
            # Strip metadata fields not part of Clash proxy config
            exclude_fields = {
                'id', 'link', 'last_latency', 'last_latency_time', 'last_speed',
                'last_peak_speed', 'last_speed_time', 'geoip'
            }
            proxy = {k: v for k, v in node.items() if k not in exclude_fields}
            proxy = ProxyFilter.sanitize_proxy(proxy)
            return NameTransformer.transform_name(proxy, 'Custom')
        return None

    # Subscription nodes
    sub = find_subscription_by_id(config, sub_id)
    source_name = sub['name'] if sub else sub_id
    try:
        cfg = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=True)
        proxies = cfg.get('proxies', []) if cfg else []
        if node_name:
            for proxy in proxies:
                if not ProxyFilter.is_valid_proxy(proxy):
                    continue
                proxy = ProxyFilter.sanitize_proxy(proxy)
                transformed = NameTransformer.transform_name(proxy, source_name)
                if transformed.get('name') == node_name:
                    return transformed
        if node_index is not None and 0 <= node_index < len(proxies):
            proxy = proxies[node_index]
            if not ProxyFilter.is_valid_proxy(proxy):
                return None
            proxy = ProxyFilter.sanitize_proxy(proxy)
            return NameTransformer.transform_name(proxy, source_name)
    except Exception as e:
        logger.warning("Failed to load node %s[%s]: %s", sub_id, node_index, e)
    return None

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
# Track ongoing subscription refresh operations to prevent duplicates
from typing import Set

_ongoing_refresh_locks: Dict[str, asyncio.Lock] = {}
_ongoing_refresh_lock = asyncio.Lock()  # Lock for accessing the locks dict

async def get_refresh_lock(sub_id: str) -> asyncio.Lock:
    """Get or create a lock for a subscription refresh operation"""
    async with _ongoing_refresh_lock:
        if sub_id not in _ongoing_refresh_locks:
            _ongoing_refresh_locks[sub_id] = asyncio.Lock()
        return _ongoing_refresh_locks[sub_id]

# ==================== Stats Cache ====================
# Cache stats data to improve dashboard performance
STATS_CACHE = {
    'overview': None,
    'countries': None,
    'last_update': 0,
    'cache_duration': AppConfig.STATS_CACHE_DURATION
}

def invalidate_stats_cache():
    """Invalidate stats cache when data changes"""
    STATS_CACHE['overview'] = None
    STATS_CACHE['countries'] = None
    STATS_CACHE['last_update'] = 0

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
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
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

# Also handle signals for proper cleanup (only in main thread)
def signal_handler(signum, frame):
    """Handle termination signals to ensure Go service is stopped"""
    logger.info("Received signal %s, stopping Go speedtest service...", signum)
    stop_go_speedtest_service()
    sys.exit(0)

# Register signal handlers (Windows only supports SIGINT and SIGTERM)
# Only register if running in main thread
try:
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
except ValueError:
    # Not in main thread, skip signal registration
    pass


# ==================== Scheduled Job Functions ====================

def refresh_subscription_job(sub_id: str):
    """
    Job function for scheduled subscription refresh.
    This is called by the scheduler and runs in a background thread.
    """
    try:
        from core.database import load_config, update_subscription_fields
        import asyncio
        
        logger.info(f"Scheduled refresh triggered for subscription {sub_id}")
        
        config = load_config()
        sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
        
        if not sub:
            logger.error(f"Subscription {sub_id} not found for scheduled refresh")
            return
        
        if sub.get('type') == 'local':
            logger.warning(f"Skipping scheduled refresh for local subscription {sub_id}")
            return
        
        # Run the async refresh in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            proxy_node = get_configured_proxy_node()
            force_proxy = sub.get('force_proxy', False)
            try:
                existing_cfg = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=False)
                existing_nodes = existing_cfg.get('proxies', []) if isinstance(existing_cfg, dict) else []
            except Exception:
                existing_nodes = []
            
            content, sub_info, node_count = loop.run_until_complete(
                fetch_subscription_async(sub['url'], proxy_node=proxy_node, force_proxy=force_proxy)
            )
            content, remembered, inherited = apply_region_history_to_yaml_content(
                content,
                existing_nodes=existing_nodes,
                source=f'sub:scheduled-refresh:{sub_id}',
            )

            success_updates = {
                'upload': sub_info.get('upload', 0),
                'download': sub_info.get('download', 0),
                'total': sub_info.get('total', 0),
                'expire': sub_info.get('expire', 0),
                'node_count': node_count,
                'last_update': int(time.time()),
                'update_status': 'success'
            }

            try:
                task_id = f"sub_refresh_{sub_id}"
                scheduler = get_scheduler()
                job_info = scheduler.get_job_info(task_id)
                if job_info and job_info.get('next_run'):
                    success_updates['next_update'] = int(job_info['next_run'].timestamp())
                else:
                    job = scheduler.scheduler.get_job(f"task_{task_id}") or scheduler.scheduler.get_job(task_id)
                    success_updates['next_update'] = int(job.next_run_time.timestamp()) if job and job.next_run_time else None
            except Exception as e:
                logger.debug("Failed to update next scheduled run for %s: %s", sub_id, e)
                success_updates['next_update'] = None

            if remembered or inherited:
                logger.info(
                    "Scheduled refresh %s region history: remembered=%s inherited=%s",
                    sub_id,
                    remembered,
                    inherited,
                )
            
            save_subscription_content(sub_id, content, YAML_SOURCE_DIR)
            update_subscription_fields(sub_id, success_updates)
            invalidate_stats_cache()
            
            logger.info(f"Scheduled refresh completed for subscription {sub_id}, got {node_count} nodes")
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Scheduled refresh failed for subscription {sub_id}: {error_msg}", exc_info=True)
            update_subscription_fields(sub_id, {'update_status': f'error: {error_msg}'})
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Fatal error in scheduled refresh job for {sub_id}: {e}", exc_info=True)


# ==================== Config Management ====================

# Config cache for performance (avoid repeated file I/O)
_config_cache = None
_config_mtime = None

def load_config() -> dict:
    """Load unified config with caching"""
    global _config_cache, _config_mtime
    
    default = {
        'auth': {},
        'subscriptions': [],
        'custom_nodes': [],
        'source_order': [],
        'users': [],  # User management
        'templates': [],  # Multi-template management
        'admin_tokens': []  # Admin multi-token management
    }
    
    if not os.path.exists(CONFIG_FILE):
        logger.debug("Config file not found: %s, using default config", CONFIG_FILE)
        return default
    
    try:
        # Check if file has been modified
        current_mtime = os.path.getmtime(CONFIG_FILE)
        
        # Return cached config if file hasn't changed
        if _config_cache is not None and _config_mtime == current_mtime:
            return _config_cache.copy()  # Return copy to prevent external modifications
        
        # Load from file
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Ensure all required keys exist
        for key in default:
            if key not in config:
                config[key] = default[key]
        
        # Update cache
        _config_cache = config
        _config_mtime = current_mtime
        
        logger.debug("Config loaded successfully from %s", CONFIG_FILE)
        return config.copy()
    except json.JSONDecodeError as e:
        logger.error("Config file is corrupted (invalid JSON): %s, error: %s", CONFIG_FILE, e)
        # Backup corrupted file
        backup_file = f"{CONFIG_FILE}.corrupted.{int(time.time())}"
        try:
            import shutil
            shutil.copy(CONFIG_FILE, backup_file)
            logger.info("Corrupted config backed up to: %s", backup_file)
        except Exception as backup_error:
            logger.error("Failed to backup corrupted config: %s", backup_error)
        return default
    except Exception as e:
        logger.error("Unexpected error loading config: %s", e, exc_info=True)
        return default

def save_config(config: dict):
    """Save unified config with file locking to prevent concurrent write conflicts"""
    global _config_cache, _config_mtime
    
    lock_file = f"{CONFIG_FILE}.lock"
    lock = FileLock(lock_file, timeout=AppConfig.FILE_LOCK_TIMEOUT)
    
    try:
        with lock:
            # Write to temporary file first
            temp_file = f"{CONFIG_FILE}.tmp"
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            
            # Backup existing config
            if os.path.exists(CONFIG_FILE):
                backup_file = f"{CONFIG_FILE}.backup"
                import shutil
                shutil.copy(CONFIG_FILE, backup_file)
            
            # Atomic replace
            os.replace(temp_file, CONFIG_FILE)
            
            # Invalidate cache
            _config_cache = None
            _config_mtime = None
            
            # Record success metric
            config_operations_total.labels(operation='write', status='success').inc()
            
            logger.debug("Config saved successfully to %s", CONFIG_FILE)
    except Timeout:
        config_operations_total.labels(operation='write', status='timeout').inc()
        logger.error("Timeout waiting for config file lock")
        raise HTTPException(status_code=503, detail="Configuration is being updated by another request, please try again")
    except Exception as e:
        config_operations_total.labels(operation='write', status='failed').inc()
        logger.error("Failed to save config: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to save configuration: {str(e)}")

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
        'id': generate_timestamp_id('tpl_'),
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
    logger.info("Legacy sub_token migrated to admin_tokens: %s...", legacy_token[:8])
    log_migration(f"migrate_legacy_sub_token: migrated legacy token {legacy_token[:8]}...")

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
    
    # 1. Check for flag emoji first (decode from name)
    for char in node_name:
        # Check if it's a regional indicator symbol (flag emoji)
        if len(char) == 2 or ord(char) >= 0x1F1E6:
            # Try to convert flag back to country code
            code = GeoIPService.flag_to_iso(char)
            if code and len(code) == 2:
                return {
                    'country': COUNTRY_NAMES.get(code, code),
                    'country_code': code,
                    'flag': GeoIPService.iso_to_flag(code)
                }
    
    # Also check for two-char flag sequences
    for i in range(len(node_name) - 1):
        potential_flag = node_name[i:i+2]
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
def get_proxy_node_by_id(node_id: str) -> dict:
    """Get proxy node config by ID"""
    if not node_id:
        return None
    
    config = load_config()
    
    # Check custom nodes
    if node_id.startswith('custom_'):
        try:
            idx = int(node_id.split('_')[1])
            custom_nodes = config.get('custom_nodes', [])
            if 0 <= idx < len(custom_nodes):
                return custom_nodes[idx]
        except (ValueError, IndexError) as e:
            logger.warning(f"Invalid custom node ID format: {node_id}, error: {e}")
        except Exception as e:
            logger.error(f"Error getting custom node {node_id}: {e}", exc_info=True)
    
    # Check subscription nodes
    if node_id.startswith('sub_'):
        try:
            parts = node_id.split('_')
            sub_id = f"sub_{parts[1]}"
            node_idx = int(parts[2])
            
            sub_file = os.path.join(YAML_SOURCE_DIR, f"{sub_id}.yaml")
            if os.path.exists(sub_file):
                # Use cached load for better performance
                sub_data = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=True)
                proxies = sub_data.get('proxies', [])
                if 0 <= node_idx < len(proxies):
                    return proxies[node_idx]
                else:
                    logger.warning(f"Node index {node_idx} out of range for subscription {sub_id}")
        except (ValueError, IndexError) as e:
            logger.warning(f"Invalid subscription node ID format: {node_id}, error: {e}")
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse subscription YAML {sub_id}: {e}")
        except Exception as e:
            logger.error(f"Error getting subscription node {node_id}: {e}", exc_info=True)
    
    return None

def get_proxy_node_by_name(node_name: str) -> dict:
    """Get proxy node config by transformed display name."""
    if not node_name:
        return None
    config = load_config()

    # Custom nodes
    for node in config.get('custom_nodes', []):
        exclude_fields = {
            'id', 'link', 'last_latency', 'last_latency_time', 'last_speed',
            'last_peak_speed', 'last_speed_time', 'geoip'
        }
        proxy = {k: v for k, v in node.items() if k not in exclude_fields}
        proxy = ProxyFilter.sanitize_proxy(proxy)
        transformed = NameTransformer.transform_name(proxy, 'Custom')
        if transformed.get('name') == node_name:
            return transformed

    # Subscription nodes
    for sub in config.get('subscriptions', []):
        if not sub.get('enabled', True):
            continue
        try:
            cfg = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=True)
            proxies = cfg.get('proxies', []) if cfg else []
            for proxy in proxies:
                if not ProxyFilter.is_valid_proxy(proxy):
                    continue
                proxy = ProxyFilter.sanitize_proxy(proxy)
                transformed = NameTransformer.transform_name(proxy, sub['name'])
                if transformed.get('name') == node_name:
                    return transformed
        except Exception as e:
            logger.warning("Failed to load node by name from %s: %s", sub.get('id'), e)
    return None


def get_configured_proxy_node() -> dict:
    """Get the configured proxy node from settings"""
    config = load_config()
    settings = config.get('settings', {})
    proxy_node_id = settings.get('proxy_node_id')
    if proxy_node_id:
        node = get_proxy_node_by_id(proxy_node_id)
        if node:
            return node
    proxy_node_name = settings.get('proxy_node_name')
    if proxy_node_name:
        return get_proxy_node_by_name(proxy_node_name)
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

def fetch_subscription(url: str, proxy_node: dict = None, force_proxy: bool = False) -> Tuple[str, dict, int]:
    """
    Fetch subscription content from URL (synchronous wrapper for async call)
    """
    import asyncio
    return asyncio.run(fetch_subscription_async(url, proxy_node, force_proxy))


async def fetch_subscription_async(url: str, proxy_node: dict = None, force_proxy: bool = False) -> Tuple[str, dict, int]:
    """
    Fetch subscription content from URL
    
    Args:
        url: Subscription URL
        proxy_node: Optional proxy node config to use for fetching
        force_proxy: If True, always use proxy; if False, try direct first then fallback to proxy
    
    Returns:
        Tuple of (content, subscription_info, node_count)
    """
    # Use FlClash User-Agent to get all nodes including anytls
    # Format: FlClash/v{version} clash-verge Platform/{os}
    # Priority: 1. SUBSCRIPTION_USER_AGENT env var, 2. Auto-fetch latest version
    from helpers_ua import get_subscription_user_agent
    user_agent = get_subscription_user_agent()
    headers = {
        'User-Agent': user_agent,
    }
    
    # Try direct connection first (unless force_proxy is True)
    if not force_proxy:
        try:
            logger.info(f"Fetching subscription directly from: {url}")
            response = await http_client.get(url, headers=headers, timeout=Constants.TIMEOUT_SUBSCRIPTION_FETCH)
            response.raise_for_status()
            
            sub_info = parse_subscription_info(dict(response.headers))
            content = _process_subscription_content(response)
            node_count = _count_nodes(content)
            logger.info(f"Successfully fetched subscription, got {node_count} nodes")
            return content, sub_info, node_count
        except httpx.HTTPStatusError as e:
            # If 403, 418, 429 or other HTTP error and proxy is available, try with proxy
            logger.warning(f"Direct connection failed with HTTP {e.response.status_code}: {e}")
            if proxy_node and e.response.status_code in [403, 418, 429]:
                logger.info(f"Trying with proxy due to HTTP {e.response.status_code}...")
            else:
                raise Exception(f"HTTP {e.response.status_code}: {e}")
        except httpx.TimeoutException as e:
            logger.warning(f"Direct connection timeout: {e}")
            if proxy_node:
                logger.info("Trying with proxy due to timeout...")
            else:
                raise Exception(f"Connection timeout: {e}")
        except Exception as e:
            # If other error and proxy is available, try with proxy
            logger.warning(f"Direct connection failed: {type(e).__name__}: {e}")
            if proxy_node:
                logger.info("Trying with proxy...")
            else:
                raise Exception(f"Connection failed: {e}")
    
    # Use proxy if available
    if proxy_node:
        try:
            logger.info(f"Fetching subscription via proxy node: {proxy_node.get('name', 'Unknown')}")
            return await _fetch_via_proxy_async(url, proxy_node)
        except Exception as e:
            logger.error(f"Proxy fetch failed: {e}", exc_info=True)
            raise Exception(f"Proxy fetch failed: {e}")
    
    # No proxy available and direct failed
    raise Exception("Direct connection failed and no proxy configured")


def _fetch_via_proxy(url: str, proxy_node: dict) -> Tuple[str, dict, int]:
    """Fetch subscription via speedtest service proxy (synchronous wrapper)"""
    import asyncio
    return asyncio.run(_fetch_via_proxy_async(url, proxy_node))


async def _fetch_via_proxy_async(url: str, proxy_node: dict) -> Tuple[str, dict, int]:
    """Fetch subscription via speedtest service proxy"""
    try:
        payload = {
            "node": proxy_node,
            "url": url,
            "timeout": 30
        }
        
        resp = await http_client.post(f"{AppConfig.GO_SPEEDTEST_URL}/api/fetch-url", json=payload, timeout=Constants.TIMEOUT_SPEEDTEST_PROXY)
        result = resp.json()
        
        if not result.get("success"):
            raise Exception(result.get("error", "Unknown error"))
        
        content = result.get("content", "")
        headers = result.get("headers", {})
        
        # Parse subscription info from headers
        sub_info = {}
        if "subscription-userinfo" in headers:
            sub_info = parse_subscription_info({"subscription-userinfo": headers["subscription-userinfo"]})
        
        # Process content
        processed_content = _process_subscription_content_str(content)
        node_count = _count_nodes(processed_content)
        
        return processed_content, sub_info, node_count
        
    except Exception as e:
        raise Exception(f"Proxy service error: {e}")


def _process_subscription_content(response) -> str:
    """Process subscription content from response object"""
    try:
        content = response.content.decode('utf-8', errors='ignore').strip()
    except AttributeError:
        # Response object doesn't have content attribute, try text
        try:
            content = response.text.strip()
        except Exception as e:
            logger.error(f"Failed to get response content: {e}")
            content = ""
    except Exception as e:
        logger.error(f"Failed to decode response content: {e}")
        content = ""
    
    return _process_subscription_content_str(content)


def _process_subscription_content_str(content: str) -> str:
    """Process subscription content string and return YAML format"""
    
    # Try to parse as YAML first
    try:
        cfg = yaml.load(content, Loader=YAMLLoader)
        if cfg and isinstance(cfg, dict) and 'proxies' in cfg:
            logger.debug("Subscription content is valid YAML format")
            return content
    except yaml.YAMLError as e:
        logger.debug(f"Content is not YAML format: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error parsing YAML: {e}")
    
    # If not YAML, try Base64 decode
    try:
        # Try to decode as Base64
        padded = content + '=' * (4 - len(content) % 4)
        # Ensure content is ASCII before decoding
        padded_bytes = padded.encode('ascii')
        decoded = base64.b64decode(padded_bytes).decode('utf-8', errors='ignore').strip()
        
        # Check if decoded content is YAML
        try:
            cfg = yaml.load(decoded, Loader=YAMLLoader)
            if cfg and isinstance(cfg, dict) and 'proxies' in cfg:
                logger.debug("Decoded Base64 content is valid YAML")
                return decoded
        except yaml.YAMLError as e:
            logger.debug(f"Decoded content is not YAML: {e}")
        except Exception as e:
            logger.warning(f"Error parsing decoded YAML: {e}")
        
        # If not YAML, parse as URI list (ss://, vmess://, vless://, etc.)
        proxies = []
        lines = decoded.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse node link
            proxy = parse_node_link(line)
            if proxy:
                proxies.append(proxy)
        
        if proxies:
            # Convert to YAML format
            # Use Python Dumper to ensure allow_unicode works correctly
            from yaml import Dumper as PyDumper
            yaml_content = yaml.dump({'proxies': proxies}, allow_unicode=True, sort_keys=False, Dumper=PyDumper)
            logger.debug(f"Parsed {len(proxies)} nodes from Base64 URI list")
            return yaml_content
    except base64.binascii.Error as e:
        logger.debug(f"Content is not valid Base64: {e}")
    except UnicodeEncodeError as e:
        logger.debug(f"Content contains non-ASCII characters, not Base64: {e}")
    except UnicodeDecodeError as e:
        logger.warning(f"Base64 decoded content is not valid UTF-8: {e}")
    except Exception as e:
        logger.warning(f"Failed to process Base64 content: {e}")
    
    # Try parsing as plain URI list (not Base64 encoded)
    proxies = []
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        proxy = parse_node_link(line)
        if proxy:
            proxies.append(proxy)
    
    if proxies:
        # Use Python Dumper to ensure allow_unicode works correctly
        from yaml import Dumper as PyDumper
        yaml_content = yaml.dump({'proxies': proxies}, allow_unicode=True, sort_keys=False, Dumper=PyDumper)
        return yaml_content
    
    # If all parsing failed, return original content
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
        padded = original_content + '=' * (4 - len(original_content) % 4)
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
                      'last_peak_speed', 'last_speed_time', 'geoip']
    
    for node in nodes:
        # Use stored node config instead of re-parsing to avoid performance issues
        # Exclude metadata fields which are not part of proxy config
        proxy = {k: v for k, v in node.items() if k not in exclude_fields}
        proxy = ProxyFilter.sanitize_proxy(proxy)
        if proxy and 'type' in proxy:  # Ensure it's a valid proxy config
            proxies.append(proxy)
    
    filepath = os.path.join(YAML_SOURCE_DIR, 'custom_nodes.yaml')
    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.dump({'proxies': proxies}, f, allow_unicode=True, sort_keys=False, Dumper=YAMLDumper)

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
                    transformed = NameTransformer.transform_name(proxy, sub['name'])
                    names.add(transformed.get('name', ''))
            except HTTPException:
                # Subscription file not found, skip
                pass
            except Exception as e:
                logger.error(f"Error getting node names from {sub['id']}: {e}")
    
    # Get custom nodes
    for node in config.get('custom_nodes', []):
        transformed = NameTransformer.transform_name(node, 'Custom')
        names.add(transformed.get('name', ''))
    
    return names


@app.get("/api/available-nodes")
async def get_available_nodes_for_users(_: bool = Depends(verify_session)):
    """Get all available nodes grouped by source for user allocation"""
    config = load_config()
    sources = {}
    
    # Info node keywords to filter out
    info_keywords = [
        '剩余流量', '套餐到期', '距离下次重置', '建议', '官网', '未到期',
        '剩余', '到期', '重置', '流量', '过期', '订阅', '网址', '公告',
        '群组', 'Telegram', 'TG', '客服', '续费', '购买', '套餐',
        '使用说明', '教程', '更新', '通知', '邀请', '返利'
    ]
    
    def is_info_node(name: str) -> bool:
        if not name:
            return True
        return any(kw in name for kw in info_keywords)
    
    # Get custom nodes first
    custom_nodes = config.get('custom_nodes', [])
    if custom_nodes:
        node_names = []
        for node in custom_nodes:
            original_name = node.get('name', '')
            if is_info_node(original_name):
                continue
            transformed = NameTransformer.transform_name(node, 'Custom')
            node_names.append(transformed.get('name', original_name))
        if node_names:
            sources['custom_nodes'] = {
                'name': '自建节点',
                'nodes': node_names
            }
    
    # Get subscription nodes
    for sub in config.get('subscriptions', []):
        if not sub.get('enabled', True):
            continue
        
        try:
            cfg = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=True)
            proxies = cfg.get('proxies', []) if cfg else []
            
            node_names = []
            for proxy in proxies:
                original_name = proxy.get('name', '')
                if is_info_node(original_name):
                    continue
                transformed = NameTransformer.transform_name(proxy, sub['name'])
                node_names.append(transformed.get('name', original_name))
            
            if node_names:
                sources[sub['id']] = {
                    'name': sub['name'],
                    'nodes': node_names
                }
        except Exception as e:
            logger.warning(f"Failed to load subscription {sub['id']}: {e}")

    # Get chain nodes and chain pools
    proxy_chains = config.get('proxy_chains', [])
    if proxy_chains:
        chain_nodes = []
        chain_pools = []

        existing_names = get_all_final_node_names()
        existing_group_names = set()

        def unique_chain_name(base: str) -> str:
            if base not in existing_names:
                existing_names.add(base)
                return base
            idx = 2
            while f"{base} ({idx})" in existing_names:
                idx += 1
            name = f"{base} ({idx})"
            existing_names.add(name)
            return name

        def _group_id_suffix(group_id: str | None) -> str:
            if not group_id:
                return ''
            clean = re.sub(r'[^A-Za-z0-9]', '', group_id)
            return clean[-4:] if clean else ''

        def unique_group_name(base: str, group_id: str | None = None) -> str:
            if base not in existing_group_names:
                existing_group_names.add(base)
                return base
            suffix = _group_id_suffix(group_id)
            if suffix:
                candidate = f"{base} ({suffix})"
                if candidate not in existing_group_names:
                    existing_group_names.add(candidate)
                    return candidate
            idx = 2
            while f"{base} ({idx})" in existing_group_names:
                idx += 1
            name = f"{base} ({idx})"
            existing_group_names.add(name)
            return name

        def coerce_group_strategy(spec: dict) -> dict:
            strategy = (spec.get('group_strategy') or 'load-balance').strip()
            strategy = strategy if strategy in ['url-test', 'fallback', 'load-balance'] else 'load-balance'
            group_cfg = {'type': strategy}
            if strategy in ['url-test', 'fallback']:
                group_cfg['url'] = spec.get('group_url') or 'http://www.gstatic.com/generate_204'
                group_cfg['interval'] = int(spec.get('group_interval') or 300)
            if strategy == 'url-test':
                group_cfg['tolerance'] = int(spec.get('group_tolerance') or 50)
            if strategy == 'load-balance':
                lb_strategy = (spec.get('lb_strategy') or 'round-robin').strip()
                if lb_strategy not in ['round-robin', 'consistent-hashing', 'sticky-sessions']:
                    lb_strategy = 'round-robin'
                group_cfg['strategy'] = lb_strategy
            return group_cfg


        for chain in proxy_chains:
            if not chain.get('enabled', True):
                continue

            rows = chain.get('rows', [])
            for row_idx, row in enumerate(rows):
                nodes = row.get('nodes', [])
                if len(nodes) < 2:
                    continue

                chain_name = chain.get('name', '')
                if len(rows) > 1:
                    chain_name = f"{chain_name} #{row_idx + 1}"

                # Collect transit groups and terminal group
                terminal_group = None
                transit_groups = []
                for idx, node_ref in enumerate(nodes):
                    if isinstance(node_ref, dict) and node_ref.get('type') == 'group':
                        if idx == len(nodes) - 1:
                            terminal_group = node_ref
                        else:
                            transit_groups.append(node_ref)

                # Record transit pools
                for t_idx, spec in enumerate(transit_groups):
                    base_name = spec.get('group_name') or f"{chain_name} 中转池{t_idx + 1}"
                    group_name = unique_group_name(f"🔀 {base_name}", spec.get('group_id'))
                    if group_name not in chain_pools:
                        chain_pools.append(group_name)

                # Record terminal pool
                if terminal_group:
                    group_base_name = terminal_group.get('group_name') or f"{chain_name} 落地池"
                    group_name = unique_group_name(f"🔀 {group_base_name}", terminal_group.get('group_id'))
                    if group_name not in chain_pools:
                        chain_pools.append(group_name)
                else:
                    # Normal chain (no terminal pool)
                    chain_name_full = f"🔗 {chain_name}"
                    chain_nodes.append(unique_chain_name(chain_name_full))

        if chain_nodes:
            sources['chain_nodes'] = {
                'name': '链式代理单节点',
                'nodes': chain_nodes
            }
        if chain_pools:
            sources['chain_pools'] = {
                'name': '链式代理池',
                'nodes': chain_pools
            }
    
    return {"sources": sources}


def proxy_to_link(proxy: dict) -> str:
    """Convert Clash proxy config to node link"""
    proxy_type = proxy.get('type', '')
    name = proxy.get('name', '')
    server = proxy.get('server', '')
    port = proxy.get('port', '')

    def format_server_for_uri(host: str) -> str:
        if not host:
            return host
        if host.startswith('[') and host.endswith(']'):
            return host
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 6:
                return f'[{host}]'
        except ValueError:
            pass
        return host

    server_uri = format_server_for_uri(server)
    
    try:
        if proxy_type == 'vmess':
            # vmess://base64(json)
            vmess_obj = {
                'v': '2',
                'ps': name,
                'add': server,
                'port': str(port),
                'id': proxy.get('uuid', ''),
                'aid': str(proxy.get('alterId', 0)),
                'scy': proxy.get('cipher', 'auto'),
                'net': proxy.get('network', 'tcp'),
                'type': 'none',
            }
            if proxy.get('tls'):
                vmess_obj['tls'] = 'tls'
                if proxy.get('servername'):
                    vmess_obj['sni'] = proxy.get('servername')
            if proxy.get('network') == 'ws':
                ws_opts = proxy.get('ws-opts', {})
                vmess_obj['path'] = ws_opts.get('path', '/')
                if ws_opts.get('headers', {}).get('Host'):
                    vmess_obj['host'] = ws_opts['headers']['Host']
            elif proxy.get('network') == 'grpc':
                grpc_opts = proxy.get('grpc-opts', {})
                vmess_obj['path'] = grpc_opts.get('grpc-service-name', '')
            return 'vmess://' + base64.b64encode(json.dumps(vmess_obj).encode()).decode()
        
        elif proxy_type == 'vless':
            # vless://uuid@server:port?params#name
            params = []
            network = proxy.get('network')
            if network:
                if network == 'h2':
                    params.append("type=http")
                else:
                    params.append(f"type={network}")
            if proxy.get('encryption') is not None:
                params.append(f"encryption={quote(str(proxy.get('encryption')))}")
            if proxy.get('tls'):
                if proxy.get('reality-opts'):
                    params.append('security=reality')
                    if proxy['reality-opts'].get('public-key'):
                        params.append(f"pbk={proxy['reality-opts']['public-key']}")
                    if proxy['reality-opts'].get('short-id'):
                        params.append(f"sid={proxy['reality-opts']['short-id']}")
                    if proxy['reality-opts'].get('spider-x'):
                        params.append(f"spx={quote(str(proxy['reality-opts']['spider-x']))}")
                else:
                    params.append('security=tls')
            if proxy.get('servername'):
                params.append(f"sni={quote(str(proxy['servername']))}")
            if proxy.get('client-fingerprint'):
                params.append(f"fp={quote(str(proxy['client-fingerprint']))}")
            if proxy.get('alpn'):
                alpn_val = proxy.get('alpn')
                if isinstance(alpn_val, list):
                    alpn_val = ','.join(alpn_val)
                params.append(f"alpn={quote(str(alpn_val))}")
            if proxy.get('skip-cert-verify'):
                params.append("allowInsecure=1")
                params.append("insecure=1")
            if proxy.get('flow'):
                params.append(f"flow={quote(str(proxy['flow']))}")
            if proxy.get('ech'):
                params.append(f"ech={quote(str(proxy['ech']))}")
            if proxy.get('pqv'):
                params.append(f"pqv={quote(str(proxy['pqv']))}")
            if proxy.get('cert-sha'):
                params.append(f"pcs={quote(str(proxy['cert-sha']))}")
            if proxy.get('finalmask'):
                params.append(f"fm={quote(str(proxy['finalmask']))}")
            if network in ['ws', 'httpupgrade']:
                ws_opts = proxy.get('ws-opts', {})
                if ws_opts.get('path'):
                    params.append(f"path={quote(ws_opts['path'])}")
                if ws_opts.get('headers', {}).get('Host'):
                    params.append(f"host={ws_opts['headers']['Host']}")
            elif network == 'grpc':
                grpc_opts = proxy.get('grpc-opts', {})
                if grpc_opts.get('grpc-service-name'):
                    params.append(f"serviceName={grpc_opts['grpc-service-name']}")
                if grpc_opts.get('mode'):
                    params.append(f"mode={grpc_opts['mode']}")
                if grpc_opts.get('authority'):
                    params.append(f"authority={grpc_opts['authority']}")
            elif network in ['h2', 'http']:
                h2_opts = proxy.get('h2-opts', {})
                if h2_opts.get('path'):
                    params.append(f"path={quote(h2_opts['path'])}")
                host_val = h2_opts.get('host')
                if isinstance(host_val, list) and host_val:
                    host_val = host_val[0]
                if host_val:
                    params.append(f"host={host_val}")
            elif network == 'xhttp':
                xhttp_opts = proxy.get('xhttp-opts', {})
                if not isinstance(xhttp_opts, dict):
                    xhttp_opts = {}
                xhttp_mode = xhttp_opts.get('mode') or proxy.get('xhttp-mode')
                xhttp_host = xhttp_opts.get('host') or proxy.get('host')
                xhttp_path = xhttp_opts.get('path') or proxy.get('path')
                if xhttp_mode:
                    params.append(f"mode={quote(str(xhttp_mode))}")
                if xhttp_host:
                    params.append(f"host={quote(str(xhttp_host))}")
                if xhttp_path:
                    params.append(f"path={quote(str(xhttp_path))}")
            query = '&'.join(params) if params else ''
            return f"vless://{proxy.get('uuid', '')}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"
        
        elif proxy_type == 'ss':
            # ss://base64(method:password)@server:port#name
            method = proxy.get('cipher', '')
            password = proxy.get('password', '')
            userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
            return f"ss://{userinfo}@{server_uri}:{port}#{quote(name)}"
        
        elif proxy_type == 'ssr':
            # ssr://base64(server:port:protocol:method:obfs:base64(password)/?params)
            password_b64 = base64.b64encode(proxy.get('password', '').encode()).decode()
            main = f"{server}:{port}:{proxy.get('protocol', 'origin')}:{proxy.get('cipher', '')}:{proxy.get('obfs', 'plain')}:{password_b64}"
            params = []
            if name:
                params.append(f"remarks={base64.b64encode(name.encode()).decode()}")
            if proxy.get('obfs-param'):
                params.append(f"obfsparam={base64.b64encode(proxy['obfs-param'].encode()).decode()}")
            if proxy.get('protocol-param'):
                params.append(f"protoparam={base64.b64encode(proxy['protocol-param'].encode()).decode()}")
            full = main + ('/?' + '&'.join(params) if params else '')
            return 'ssr://' + base64.b64encode(full.encode()).decode()
        
        elif proxy_type == 'trojan':
            # trojan://password@server:port?params#name
            params = []
            if proxy.get('sni'):
                params.append(f"sni={proxy['sni']}")
            if proxy.get('network') == 'ws':
                params.append('type=ws')
                ws_opts = proxy.get('ws-opts', {})
                if ws_opts.get('path'):
                    params.append(f"path={quote(ws_opts['path'])}")
            elif proxy.get('network') == 'grpc':
                params.append('type=grpc')
            query = '&'.join(params) if params else ''
            return f"trojan://{quote(proxy.get('password', ''))}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"
        
        elif proxy_type == 'hysteria2':
            # hysteria2://password@server:port?params#name
            params = []
            if proxy.get('sni'):
                params.append(f"sni={proxy['sni']}")
            if proxy.get('obfs'):
                params.append(f"obfs={proxy['obfs']}")
                if proxy.get('obfs-password'):
                    params.append(f"obfs-password={proxy['obfs-password']}")
            query = '&'.join(params) if params else ''
            return f"hysteria2://{quote(proxy.get('password', ''))}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"
        
        elif proxy_type == 'tuic':
            # tuic://uuid:password@server:port?params#name
            params = []
            if proxy.get('sni'):
                params.append(f"sni={proxy['sni']}")
            if proxy.get('congestion-controller'):
                params.append(f"congestion_control={proxy['congestion-controller']}")
            query = '&'.join(params) if params else ''
            return f"tuic://{proxy.get('uuid', '')}:{proxy.get('password', '')}@{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"
        
        elif proxy_type == 'hysteria':
            # hysteria://server:port?params#name
            params = []
            if proxy.get('auth-str'):
                params.append(f"auth={proxy['auth-str']}")
            if proxy.get('sni'):
                params.append(f"peer={proxy['sni']}")
            if proxy.get('up'):
                params.append(f"upmbps={proxy['up']}")
            if proxy.get('down'):
                params.append(f"downmbps={proxy['down']}")
            query = '&'.join(params) if params else ''
            return f"hysteria://{server_uri}:{port}{'?' + query if query else ''}#{quote(name)}"
        
        elif proxy_type == 'socks5':
            # socks5://user:pass@server:port#name
            auth = ''
            if proxy.get('username'):
                auth = f"{quote(proxy['username'])}:{quote(proxy.get('password', ''))}@"
            prefix = 'socks5+tls://' if proxy.get('tls') else 'socks5://'
            return f"{prefix}{auth}{server_uri}:{port}#{quote(name)}"
        
        elif proxy_type == 'http':
            # http://user:pass@server:port#name
            auth = ''
            if proxy.get('username'):
                auth = f"{quote(proxy['username'])}:{quote(proxy.get('password', ''))}@"
            prefix = 'https://' if proxy.get('tls') else 'http://'
            return f"{prefix}{auth}{server_uri}:{port}#{quote(name)}"
        
        else:
            # Unsupported type, return empty
            return ''
    except Exception:
        return ''

@app.get("/sub")
async def get_merged_subscription(
    token: Optional[str] = None, 
    format: Optional[str] = None,
    user_agent: Optional[str] = Header(None, alias="User-Agent")
):
    config = load_config()
    auth = config.get('auth', {})
    
    # Check if token is admin token or user token
    is_admin = False
    user_info = None
    user_allocations = None
    template_id = 'builtin'  # Default template
    admin_token_info = None  # Store matched admin token for its settings
    
    # 1. Check legacy admin token (backward compatibility)
    if auth.get('sub_token') and token == auth['sub_token']:
        is_admin = True
        # Legacy admin uses current saved template (if any)
        if 'template' in config:
            template_id = 'legacy'  # Special marker for legacy template
    else:
        # 2. Check new admin tokens
        for admin_token in config.get('admin_tokens', []):
            if admin_token.get('token') == token:
                if not admin_token.get('enabled', True):
                    raise HTTPException(status_code=403, detail="Token is disabled")
                is_admin = True
                template_id = admin_token.get('template_id', 'builtin')
                admin_token_info = admin_token  # Save for later use
                break
        
        # 3. Check user tokens
        if not is_admin:
            for user in config.get('users', []):
                if user.get('token') == token:
                    # Check if user is enabled
                    if not user.get('enabled', True):
                        raise HTTPException(status_code=403, detail="User account is disabled")
                    # Check if user is expired
                    expire_time = user.get('expire_time', 0)
                    if expire_time > 0 and expire_time < time.time():
                        raise HTTPException(status_code=403, detail="Subscription expired")
                    user_info = user
                    user_allocations = user.get('allocations', {})
                    template_id = user.get('template_id', 'builtin')
                    break
        
        if not is_admin and not user_info:
            raise HTTPException(status_code=401, detail="Invalid subscription token")
    
    # Check cache for user subscriptions (admin subscriptions are not cached as they may change frequently)
    if user_info and not format:  # Only cache YAML format
        cache = user_info.get('sub_cache', {})
        cache_time = cache.get('timestamp', 0)
        cache_content = cache.get('content', '')
        cache_headers = cache.get('headers', {})
        
        # Cache is valid for 5 minutes (300 seconds)
        if cache_content and (time.time() - cache_time) < 300:
            logger.debug(f"Using cached subscription for user {user_info['name']}")
            return PlainTextResponse(
                cache_content,
                media_type='text/yaml',
                headers=cache_headers
            )
    
    subs = config.get('subscriptions', [])
    enabled_subs = [s for s in subs if s['enabled']]
    custom_nodes = config.get('custom_nodes', [])
    
    # Filter subscriptions based on user allocations
    has_chain_allocations = False
    if user_allocations is not None:
        # User mode: only show allocated subscriptions
        all_sub_ids = {s['id'] for s in subs}
        allocated_sub_ids = {sid for sid in user_allocations.keys() if sid in all_sub_ids}
        enabled_subs = [s for s in enabled_subs if s['id'] in allocated_sub_ids]
        
        # Filter custom nodes if allocated
        if 'custom_nodes' in user_allocations:
            allocated_custom = user_allocations['custom_nodes']
            if allocated_custom != ['*']:
                filtered = []
                for node in custom_nodes:
                    transformed = NameTransformer.transform_name(node, 'Custom')
                    node_name = transformed.get('name', node.get('name', ''))
                    if is_name_allocated(node_name, allocated_custom):
                        filtered.append(node)
                custom_nodes = filtered
        else:
            custom_nodes = []  # No custom nodes allocated

        # Chain allocations allow chain-only subscriptions even without sub/custom allocations
        has_chain_allocations = bool(user_allocations.get('chain_nodes') or user_allocations.get('chain_pools'))
    
    if not enabled_subs and not custom_nodes and not has_chain_allocations:
        raise HTTPException(status_code=404, detail="No enabled subscriptions or custom nodes")
    
    # Check and auto-refresh missing subscription files
    # This prevents slow first-time access by ensuring files exist
    missing_subs = []
    for sub in enabled_subs:
        filepath = os.path.join(YAML_SOURCE_DIR, f"{sub['id']}.yaml")
        if not os.path.exists(filepath):
            missing_subs.append(sub)
    
    # If there are missing subscription files, fetch them now
    if missing_subs:
        logger.info(f"Auto-refreshing {len(missing_subs)} missing subscription(s)...")
        proxy_node = get_configured_proxy_node()
        for sub in missing_subs:
            try:
                force_proxy = sub.get('force_proxy', False)
                try:
                    existing_cfg = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=False)
                    existing_nodes = existing_cfg.get('proxies', []) if isinstance(existing_cfg, dict) else []
                except Exception:
                    existing_nodes = []
                content, sub_info, node_count = fetch_subscription(sub['url'], proxy_node=proxy_node, force_proxy=force_proxy)
                content, remembered, inherited = apply_region_history_to_yaml_content(
                    content,
                    existing_nodes=existing_nodes,
                    source=f"sub:auto-refresh-missing:{sub['id']}",
                )
                sub.update({
                    'upload': sub_info.get('upload', 0),
                    'download': sub_info.get('download', 0),
                    'total': sub_info.get('total', 0),
                    'expire': sub_info.get('expire', 0),
                    'node_count': node_count,
                    'last_update': int(time.time()),
                    'update_status': 'success'
                })
                if remembered or inherited:
                    logger.info(
                        "Missing subscription %s region history: remembered=%s inherited=%s",
                        sub['id'],
                        remembered,
                        inherited,
                    )
                save_subscription_content(sub['id'], content, YAML_SOURCE_DIR)
                logger.info(f"  ✓ Refreshed: {sub['name']}")
            except Exception as e:
                logger.error(f"  ✗ Failed to refresh {sub['name']}: {e}")
                sub['update_status'] = f'error: {str(e)}'
        # Save updated subscription info
        save_config(config)
    
    # Smart format detection: auto-select based on User-Agent
    # Clash clients → YAML, others → Base64
    if format is None and user_agent:
        ua_lower = user_agent.lower()
        # Clash client keywords
        clash_keywords = ['clash', 'stash', 'shadowrocket', 'quantumult', 'surge', 'loon']
        # If Clash client, use YAML; otherwise use Base64
        is_clash = any(kw in ua_lower for kw in clash_keywords)
        if not is_clash:
            # V2RayN, V2RayNG, Nekoray etc use Base64
            format = 'base64'
    
    # Get template based on template_id
    template_proxy_groups = None  # Will store template's proxy-groups if available
    
    if template_id == 'legacy':
        # Use legacy saved template
        tpl = config.get('template', {})
        header = tpl.get('header', ConfigMerger.DEFAULT_HEADER)
        suffix = tpl.get('suffix', ConfigMerger.DEFAULT_SUFFIX)
    elif template_id == 'builtin':
        # Check for user customization of builtin template
        override = config.get('builtin_template_override')
        if override:
            header = override.get('header', ConfigMerger.DEFAULT_HEADER)
            suffix = override.get('suffix', ConfigMerger.DEFAULT_SUFFIX)
            template_proxy_groups = override.get('proxy_groups', [])
        else:
            header = ConfigMerger.DEFAULT_HEADER
            suffix = ConfigMerger.DEFAULT_SUFFIX
    else:
        # Find template by ID
        template = next((t for t in config.get('templates', []) if t['id'] == template_id), None)
        if template:
            # Check if template needs migration (only if both header and suffix are missing)
            needs_migration = ('header' not in template or 'suffix' not in template) and 'content' in template
            
            if needs_migration:
                # Auto-migrate old format templates
                try:
                    parsed = yaml.load(template['content'], Loader=YAMLLoader)
                    if isinstance(parsed, dict):
                        # Split the content
                        header, suffix = split_template(template['content'])
                        template['header'] = header
                        template['suffix'] = suffix
                        if 'proxy_groups' not in template:
                            template['proxy_groups'] = parsed.get('proxy-groups', [])
                        # Remove old content field
                        del template['content']
                        # Save migrated template (only once)
                        save_config(config)
                        logger.info(f"Template {template_id} migrated successfully")
                except Exception as e:
                    logger.error(f"Template migration failed: {e}")
                    # If migration fails, use fallback
                    header = ConfigMerger.DEFAULT_HEADER
                    suffix = ConfigMerger.DEFAULT_SUFFIX
                    template_proxy_groups = None
            
            # Use template data (either already migrated or just migrated)
            if not needs_migration or ('header' in template and 'suffix' in template):
                header = template.get('header', ConfigMerger.DEFAULT_HEADER)
                suffix = template.get('suffix', ConfigMerger.DEFAULT_SUFFIX)
                template_proxy_groups = template.get('proxy_groups')
        else:
            # Fallback to built-in
            header = ConfigMerger.DEFAULT_HEADER
            suffix = ConfigMerger.DEFAULT_SUFFIX
    
    # Build file_aliases based on filtered subscriptions (not all sources)
    file_aliases = OrderedDict()
    
    # Get order from source_order config
    config_order = config.get('source_order', [])
    
    # Add custom nodes first if allocated
    if custom_nodes:
        if 'custom_nodes' in config_order:
            # Will be added in order below
            pass
        else:
            file_aliases['custom_nodes.yaml'] = 'Custom'
    
    # Add sources in order
    for source_id in config_order:
        if source_id == 'custom_nodes' and custom_nodes:
            file_aliases['custom_nodes.yaml'] = 'Custom'
        else:
            # Check if this subscription is in enabled_subs (already filtered for user)
            for sub in enabled_subs:
                if sub['id'] == source_id:
                    file_aliases[f"{sub['id']}.yaml"] = sub['name']
                    break
    
    # Add any remaining enabled_subs not in order
    for sub in enabled_subs:
        filename = f"{sub['id']}.yaml"
        if filename not in file_aliases:
            file_aliases[filename] = sub['name']
    
    merger = ConfigMerger(
        yaml_dir=YAML_SOURCE_DIR, output_file=OUTPUT_FILE,
        custom_header=header, custom_suffix=suffix, file_aliases=file_aliases
    )
    
    try:
        cfg = merger.merge_and_generate()
        proxies = cfg.get('proxies', [])
        proxy_groups = cfg.get('proxy-groups', [])
        
        # Filter proxies based on user allocations (specific nodes)
        if user_allocations is not None:
            allowed_proxy_names = set()

            # Subscription nodes
            for sub in enabled_subs:
                alloc_list = user_allocations.get(sub['id'])
                if not alloc_list:
                    continue
                try:
                    sub_cfg = load_subscription_yaml(sub['id'], YAML_SOURCE_DIR, use_cache=True)
                    sub_proxies = sub_cfg.get('proxies', []) if sub_cfg else []
                    for proxy in sub_proxies:
                        transformed = NameTransformer.transform_name(proxy, sub['name'])
                        proxy_name = transformed.get('name', proxy.get('name', ''))
                        if is_name_allocated(proxy_name, alloc_list):
                            allowed_proxy_names.add(proxy_name)
                except Exception as e:
                    logger.warning("Failed to build allocation list for %s: %s", sub['id'], e)

            # Custom nodes
            alloc_custom = user_allocations.get('custom_nodes')
            if alloc_custom and custom_nodes:
                for node in custom_nodes:
                    transformed = NameTransformer.transform_name(node, 'Custom')
                    node_name = transformed.get('name', node.get('name', ''))
                    if is_name_allocated(node_name, alloc_custom):
                        allowed_proxy_names.add(node_name)

            proxies = [p for p in proxies if p.get('name', '') in allowed_proxy_names]

            # Regenerate proxy groups based on filtered proxies
            from services.country_grouper import CountryGrouper
            from services.config_merger import ProxyGroupGenerator
            country_groups = CountryGrouper.group_by_country(proxies)
            proxy_groups = ProxyGroupGenerator.generate_groups(proxies, country_groups)

        # If using custom template with proxy-groups, process user config
        if template_proxy_groups and isinstance(template_proxy_groups, list) and len(template_proxy_groups) > 0:
            # Get all proxy names
            all_proxy_names = [p['name'] for p in proxies]
            
            # Identify primary selection groups (groups that contain actual proxy nodes)
            # These are typically "manual select" or "auto select" type groups
            primary_groups = []
            for g in template_proxy_groups:
                g_name = g.get('name', '')
                g_type = g.get('type', '')
                # Primary groups are usually select or url-test types that will contain actual nodes
                # Common patterns: "Node Selection", "Auto Select", "Manual Select", etc.
                if g_type in ['select', 'url-test', 'fallback', 'load-balance']:
                    # Check if this looks like a primary selection group (not a policy group)
                    # Policy groups typically have names like "Ad Block", "Domestic Service", etc.
                    is_policy = any(keyword in g_name for keyword in ['广告', '拦截', '国内', '服务', '私有', '网络', '漏网', 'Ad', 'Block', 'Domestic', 'Private', 'Catch'])
                    if not is_policy:
                        primary_groups.append(g_name)
            
            # Process each group
            custom_groups = []
            for group in template_proxy_groups:
                new_group = dict(group)
                group_name = new_group.get('name', '')
                group_type = new_group.get('type', '')
                
                # Remove underscore fields
                new_group = filter_underscore_fields(new_group)
                
                # Build fixed options based on group type
                # Base options that are always safe
                base_options = ["DIRECT", "REJECT"]
                
                # For policy groups (like ad-block, domestic, etc.), add primary selection groups
                # For primary selection groups, don't add other groups to avoid loops
                is_policy = any(keyword in group_name for keyword in ['广告', '拦截', '国内', '服务', '私有', '网络', '漏网', 'Ad', 'Block', 'Domestic', 'Private', 'Catch'])
                
                if is_policy:
                    # Policy groups can reference primary selection groups
                    fixed_options = base_options + primary_groups
                else:
                    # Primary selection groups only get DIRECT/REJECT
                    fixed_options = base_options
                
                # Apply user's group_config if exists
                if user_info and user_info.get('group_config'):
                    group_config = user_info['group_config']
                    
                    # If user configured this group, use user's selection
                    if group_name in group_config and group_config[group_name]:
                        # Extract group references from original template (for other groups, not DIRECT/REJECT)
                        original_proxies = group.get('proxies', [])
                        group_refs = []
                        
                        for item in original_proxies:
                            # Only keep group references (not DIRECT/REJECT, those come from user config)
                            if item not in ['DIRECT', 'REJECT'] and item in [g.get('name') for g in template_proxy_groups]:
                                group_refs.append(item)
                        
                        # Filter user's selected nodes
                        user_selected_nodes = group_config[group_name]
                        valid_nodes = []
                        
                        # Log node selection for debugging
                        logger.debug(f"Group '{group_name}': user selected {len(user_selected_nodes)} nodes")
                        logger.debug(f"Available proxy names: {len(all_proxy_names)} nodes")
                        if len(all_proxy_names) > 0:
                            logger.debug(f"Sample proxy names: {all_proxy_names[:3]}")
                        if len(user_selected_nodes) > 0:
                            logger.debug(f"Sample user selected: {user_selected_nodes[:5]}")
                        
                        for node in user_selected_nodes:
                            # Keep DIRECT and REJECT
                            if node in ['DIRECT', 'REJECT']:
                                valid_nodes.append(node)
                            # Keep actual proxy nodes that exist
                            elif node in all_proxy_names:
                                valid_nodes.append(node)
                            else:
                                # Node not found in available proxies
                                logger.debug(f"Node '{node}' not found in all_proxy_names")
                        
                        logger.debug(f"Valid nodes after filtering: {len(valid_nodes)} nodes")
                        
                        # Combine: group refs + user selected nodes (including DIRECT/REJECT)
                        if valid_nodes:
                            new_group['proxies'] = group_refs + valid_nodes
                        else:
                            # If no valid nodes, use group refs + all available nodes
                            new_group['proxies'] = group_refs + ["DIRECT", "REJECT"] + all_proxy_names
                    else:
                        # No user config for this group - keep original template structure
                        # but replace actual proxy nodes with user's available nodes
                        original_proxies = group.get('proxies', [])
                        new_proxies = []
                        
                        # Keep group references and special keywords (DIRECT, REJECT)
                        for item in original_proxies:
                            if item in ['DIRECT', 'REJECT'] or item in [g.get('name') for g in template_proxy_groups]:
                                # Keep DIRECT, REJECT, and group references
                                new_proxies.append(item)
                        
                        # Add user's available proxy nodes
                        new_proxies.extend(all_proxy_names)
                        
                        # Remove duplicates while preserving order
                        seen = set()
                        new_group['proxies'] = [x for x in new_proxies if not (x in seen or seen.add(x))]
                else:
                    # No user config at all - keep original template structure
                    # but replace actual proxy nodes with user's available nodes
                    original_proxies = group.get('proxies', [])
                    new_proxies = []
                    
                    # Keep group references and special keywords (DIRECT, REJECT)
                    for item in original_proxies:
                        if item in ['DIRECT', 'REJECT'] or item in [g.get('name') for g in template_proxy_groups]:
                            # Keep DIRECT, REJECT, and group references
                            new_proxies.append(item)
                    
                    # Add user's available proxy nodes
                    new_proxies.extend(all_proxy_names)
                    
                    # Remove duplicates while preserving order
                    seen = set()
                    new_group['proxies'] = [x for x in new_proxies if not (x in seen or seen.add(x))]
                
                custom_groups.append(new_group)
            
            proxy_groups = custom_groups
        # Get custom config name
        # Priority: user's sub_name > admin_token's sub_name > global sub_name
        if user_info:
            # User subscription - use user's sub_name if set
            if user_info.get('sub_name'):
                sub_name = f"{user_info['sub_name']} - {user_info['name']}"
            else:
                # Fallback to global sub_name
                sub_name = f"{auth.get('sub_name', 'Aggregated')} - {user_info['name']}"
        else:
            # Admin token subscription - use admin token's sub_name or global sub_name
            if admin_token_info and admin_token_info.get('sub_name'):
                sub_name = admin_token_info['sub_name']
            else:
                sub_name = auth.get('sub_name', 'Aggregated')
        
        # Generate traffic info nodes for each subscription
        def format_bytes(b):
            if not b or b == 0:
                return '0B'
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if b < 1024:
                    return f'{b:.1f}{unit}' if b != int(b) else f'{int(b)}{unit}'
                b /= 1024
            return f'{b:.1f}PB'
        
        def format_expire(ts):
            if not ts or ts == 0:
                return '永久'
            from datetime import datetime
            return datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
        
        traffic_info_nodes = []
        traffic_info_names = []
        
        # Calculate aggregated total first
        agg_used = sum((s.get('upload', 0) or 0) + (s.get('download', 0) or 0) for s in enabled_subs)
        agg_total = sum(s.get('total', 0) or 0 for s in enabled_subs)
        
        # Add aggregated total node first (only traffic, no time)
        if agg_total > 0:
            agg_name = f"📊 总计 | {format_bytes(agg_used)}/{format_bytes(agg_total)}"
            traffic_info_names.append(agg_name)
            traffic_info_nodes.append({
                'name': agg_name,
                'type': 'http',
                'server': '1.0.0.1',
                'port': 65535
            })
        
        # Add individual subscription traffic info
        for sub in enabled_subs:
            used = (sub.get('upload', 0) or 0) + (sub.get('download', 0) or 0)
            total = sub.get('total', 0) or 0
            expire = sub.get('expire', 0) or 0
            
            # Create info node name: "sub_name | used/total | expire_date"
            if total > 0:
                info_name = f"📊 {sub['name']} | {format_bytes(used)}/{format_bytes(total)} | {format_expire(expire)}"
            else:
                info_name = f"📊 {sub['name']} | {format_expire(expire)}"
            
            traffic_info_names.append(info_name)
            # Create a dummy HTTP node (looks valid but won't work, just for display)
            traffic_info_nodes.append({
                'name': info_name,
                'type': 'http',
                'server': '1.0.0.1',
                'port': 65535
            })
        
        # Prepend traffic info nodes to proxies
        proxies = traffic_info_nodes + proxies
        
        # Process proxy chains - add chain proxies with dialer-proxy
        proxy_chains = config.get('proxy_chains', [])
        chain_proxies = []
        chain_proxy_names = []

        existing_names = {p.get('name') for p in proxies if isinstance(p, dict) and p.get('name')}

        pool_group_names = []
        chain_allocations_enabled = user_allocations is not None and bool(
            user_allocations.get('chain_nodes') or user_allocations.get('chain_pools')
        )

        def short_node_name(name: str) -> str:
            if not name:
                return ''
            clean = NameTransformer.remove_flags(name)
            if ' ' in clean:
                clean = clean.split(' ', 1)[1]
            return clean.strip()

        def unique_chain_name(base: str) -> str:
            if base not in existing_names:
                existing_names.add(base)
                return base
            idx = 2
            while f"{base} ({idx})" in existing_names:
                idx += 1
            name = f"{base} ({idx})"
            existing_names.add(name)
            return name

        existing_group_names = {g.get('name') for g in proxy_groups if isinstance(g, dict) and g.get('name')}

        def _group_id_suffix(group_id: str | None) -> str:
            if not group_id:
                return ''
            clean = re.sub(r'[^A-Za-z0-9]', '', group_id)
            return clean[-4:] if clean else ''

        def unique_group_name(base: str, group_id: str | None = None) -> str:
            if base not in existing_group_names:
                existing_group_names.add(base)
                return base
            suffix = _group_id_suffix(group_id)
            if suffix:
                candidate = f"{base} ({suffix})"
                if candidate not in existing_group_names:
                    existing_group_names.add(candidate)
                    return candidate
            idx = 2
            while f"{base} ({idx})" in existing_group_names:
                idx += 1
            name = f"{base} ({idx})"
            existing_group_names.add(name)
            return name

        def coerce_group_strategy(spec: dict) -> dict:
            strategy = (spec.get('group_strategy') or 'load-balance').strip()
            strategy = strategy if strategy in ['url-test', 'fallback', 'load-balance'] else 'load-balance'
            group_cfg = {'type': strategy}
            if strategy in ['url-test', 'fallback']:
                group_cfg['url'] = spec.get('group_url') or 'http://www.gstatic.com/generate_204'
                group_cfg['interval'] = int(spec.get('group_interval') or 300)
            if strategy == 'url-test':
                group_cfg['tolerance'] = int(spec.get('group_tolerance') or 50)
            if strategy == 'load-balance':
                lb_strategy = (spec.get('lb_strategy') or 'round-robin').strip()
                if lb_strategy not in ['round-robin', 'consistent-hashing', 'sticky-sessions']:
                    lb_strategy = 'round-robin'
                group_cfg['strategy'] = lb_strategy
            return group_cfg

        def insert_pool_group(group_cfg: dict) -> None:
            group_name = group_cfg.get('name')
            if not group_name:
                return
            proxy_groups[:] = [g for g in proxy_groups if g.get('name') != group_name]

            insert_idx = next((i for i, g in enumerate(proxy_groups) if g.get('name') == '🔯 故障转移'), -1)
            if insert_idx == -1:
                country_names = set(ProxyGroupGenerator.COUNTRY_ORDER)
                insert_idx = next((i for i, g in enumerate(proxy_groups) if g.get('name') in country_names), len(proxy_groups))
            else:
                insert_idx += 1
                while insert_idx < len(proxy_groups) and proxy_groups[insert_idx].get('name') in pool_group_names:
                    insert_idx += 1
            proxy_groups.insert(insert_idx, group_cfg)

        def build_chain_entry(
            chain_display_name: str,
            chain_nodes: list,
            add_to_manual: bool = True,
            include_country_info: bool = True,
            allow_name: Callable[[str], bool] | None = None
        ) -> str | None:
            """Build chain proxies for given nodes and return the final chain proxy name."""
            if len(chain_nodes) < 2:
                return None
            def hop_name(hop: dict) -> str:
                if not hop:
                    return ''
                if hop.get('type') == 'group':
                    return hop.get('name', '')
                return hop.get('name', '')

            last_node = chain_nodes[-1]
            if last_node.get('type') == 'group':
                return None
            chain_proxy = dict(last_node)

            last_node_name = last_node.get('name', '')
            last_node_server = last_node.get('server', '')
            chain_country_info = extract_country_from_name(last_node_name, last_node_server)

            final_chain_name = unique_chain_name(chain_display_name)
            if allow_name and not allow_name(final_chain_name):
                return None

            chain_proxy['name'] = final_chain_name
            if include_country_info and chain_country_info:
                chain_proxy['_country_info'] = chain_country_info

            if len(chain_nodes) == 2:
                prev_name = hop_name(chain_nodes[0])
                if not prev_name:
                    return None
                chain_proxy['dialer-proxy'] = prev_name
            else:
                prev_proxy_name = hop_name(chain_nodes[0])
                if not prev_proxy_name:
                    return None
                intermediates = []
                for i in range(1, len(chain_nodes) - 1):
                    hop = chain_nodes[i]
                    hop_display = hop_name(hop)
                    if hop.get('type') == 'group':
                        if not hop_display:
                            return None
                        prev_proxy_name = hop_display
                        continue
                    intermediate = dict(hop)
                    intermediate_name = unique_chain_name(f"{chain_display_name} (via {i})")
                    intermediate['name'] = intermediate_name
                    intermediate['dialer-proxy'] = prev_proxy_name
                    intermediates.append(intermediate)
                    if add_to_manual:
                        chain_proxy_names.append(intermediate_name)
                    prev_proxy_name = intermediate_name
                chain_proxy['dialer-proxy'] = prev_proxy_name
                for intermediate in intermediates:
                    chain_proxies.append(intermediate)

            chain_proxies.append(chain_proxy)
            if add_to_manual:
                chain_proxy_names.append(chain_proxy['name'])
            return chain_proxy['name']

        def is_allocated_ref(node_ref: dict, node_proxy: dict | None) -> bool:
            if user_allocations is None:
                return True
            if not node_ref:
                return False
            sub_id = node_ref.get('sub_id')
            if not sub_id:
                return False
            alloc_key = 'custom_nodes' if sub_id == 'custom' else sub_id
            allocated_nodes = user_allocations.get(alloc_key)
            if not allocated_nodes:
                return False
            if allocated_nodes == ['*']:
                return True

            name = ''
            if node_proxy and node_proxy.get('name'):
                name = node_proxy.get('name', '')
            if not name:
                name = node_ref.get('node_name', '')

            if not name:
                return False
            return is_name_allocated(name, allocated_nodes)

        def is_allocated_chain_name(name: str, alloc_key: str) -> bool:
            if user_allocations is None:
                return True
            if not name:
                return False
            allocated = user_allocations.get(alloc_key)
            if not allocated:
                return False
            if allocated == ['*']:
                return True
            name_clean = normalize_alloc_name(name)
            base_name = re.sub(r" \\([A-Za-z0-9]{4}\\)$", "", name)
            base_clean = normalize_alloc_name(base_name)
            for alloc in allocated:
                if not alloc:
                    continue
                if alloc == name or alloc in name:
                    return True
                alloc_clean = normalize_alloc_name(alloc)
                if alloc_clean and (
                    alloc_clean == name_clean
                    or alloc_clean in name_clean
                    or alloc_clean == base_clean
                    or (base_clean and alloc_clean in base_clean)
                ):
                    return True
            return False

        
        for chain in proxy_chains:
            if not chain.get('enabled', True):
                continue
            
            for row_idx, row in enumerate(chain.get('rows', [])):
                nodes = row.get('nodes', [])
                if len(nodes) < 2:
                    continue
                
                # Build the chain by setting dialer-proxy on each node
                # For chain [A, B, C]: B.dialer-proxy = A, C.dialer-proxy = B
                # We create a new proxy entry based on the last node with dialer-proxy set
                
                # Parse chain hops (nodes + transit groups), terminal group is handled separately
                chain_hops = []
                group_spec = None
                for idx, node_ref in enumerate(nodes):
                    if isinstance(node_ref, dict) and node_ref.get('type') == 'group':
                        if idx == len(nodes) - 1:
                            group_spec = node_ref
                            break
                        chain_hops.append({'type': 'group', 'spec': node_ref})
                        continue
                    chain_hops.append({'type': 'node', 'ref': node_ref})

                if not chain_hops:
                    continue

                # Set chain display name (with row suffix when multiple rows)
                chain_name = chain['name']
                if len(chain.get('rows', [])) > 1:
                    chain_name = f"{chain_name} #{row_idx + 1}"

                def build_transit_group(base_name: str, spec: dict) -> str | None:
                    group_base_name = spec.get('group_name') or base_name
                    group_name = unique_group_name(f"🔀 {group_base_name}", spec.get('group_id'))
                    if user_allocations is not None and not is_allocated_chain_name(group_name, 'chain_pools'):
                        return None
                    group_nodes = spec.get('group_nodes', []) or []
                    member_proxies = []
                    for member_ref in group_nodes:
                        node_proxy = find_node_by_reference(
                            member_ref.get('sub_id'),
                            member_ref.get('node_index'),
                            member_ref.get('node_name')
                        )
                        if node_proxy and (chain_allocations_enabled or is_allocated_ref(member_ref, node_proxy)):
                            member_proxies.append(dict(node_proxy))
                    if not member_proxies:
                        return None
                    member_names = [p.get('name', '') for p in member_proxies if p.get('name')]
                    if not member_names:
                        return None
                    group_cfg = {'name': group_name, 'proxies': member_names}
                    group_cfg.update(coerce_group_strategy(spec))
                    insert_pool_group(group_cfg)
                    chain_proxy_names.append(group_name)
                    if group_name not in pool_group_names:
                        pool_group_names.append(group_name)
                    return group_name

                # Resolve hops into chain nodes (proxies + group placeholders)
                chain_nodes = []
                base_allowed = True
                require_base_allocation = not (user_allocations is not None and chain_allocations_enabled)
                transit_idx = 0
                for hop in chain_hops:
                    if hop['type'] == 'node':
                        node_ref = hop['ref']
                        node_proxy = find_node_by_reference(
                            node_ref.get('sub_id'),
                            node_ref.get('node_index'),
                            node_ref.get('node_name')
                        )
                        if not node_proxy or (require_base_allocation and not is_allocated_ref(node_ref, node_proxy)):
                            base_allowed = False
                            break
                        chain_nodes.append(dict(node_proxy))
                    else:
                        transit_idx += 1
                        base_name = hop['spec'].get('group_name') or f"{chain_name} 中转池{transit_idx}"
                        group_name = build_transit_group(base_name, hop['spec'])
                        if not group_name:
                            base_allowed = False
                            break
                        chain_nodes.append({'type': 'group', 'name': group_name})

                if not base_allowed or not chain_nodes:
                    continue
                if not group_spec and len(chain_nodes) < 2:
                    continue

                if group_spec:
                    # Build group name first to check allocation
                    group_base_name = group_spec.get('group_name') or f"{chain_name} 落地池"
                    group_name = unique_group_name(f"🔀 {group_base_name}", group_spec.get('group_id'))
                    if user_allocations is not None and not is_allocated_chain_name(group_name, 'chain_pools'):
                        continue

                    group_nodes = group_spec.get('group_nodes', []) or []
                    member_proxies = []
                    for member_ref in group_nodes:
                        node_proxy = find_node_by_reference(
                            member_ref.get('sub_id'),
                            member_ref.get('node_index'),
                            member_ref.get('node_name')
                        )
                        if node_proxy and (chain_allocations_enabled or is_allocated_ref(member_ref, node_proxy)):
                            member_proxies.append(dict(node_proxy))

                    if not member_proxies:
                        continue

                    chain_member_names = []
                    base_start_name = short_node_name(chain_nodes[0].get('name', '')) if chain_nodes else ''
                    for member_proxy in member_proxies:
                        chain_nodes_with_member = chain_nodes + [member_proxy]
                        end_name = short_node_name(member_proxy.get('name', ''))
                        path_name = f"{base_start_name} → {end_name}" if base_start_name and end_name else chain_name
                        chain_name_full = f"🔗 {chain_name}: {path_name}"
                        chain_proxy_name = build_chain_entry(chain_name_full, chain_nodes_with_member, add_to_manual=False, include_country_info=False)
                        if chain_proxy_name:
                            chain_member_names.append(chain_proxy_name)

                    if not chain_member_names:
                        continue

                    # Build group for chain members
                    strategy = (group_spec.get('group_strategy') or 'load-balance').strip()
                    strategy = strategy if strategy in ['url-test', 'fallback', 'load-balance'] else 'load-balance'

                    group_cfg = {
                        'name': group_name,
                        'type': strategy,
                        'proxies': chain_member_names
                    }
                    if strategy in ['url-test', 'fallback']:
                        group_cfg['url'] = group_spec.get('group_url') or 'http://www.gstatic.com/generate_204'
                        group_cfg['interval'] = int(group_spec.get('group_interval') or 300)
                    if strategy == 'url-test':
                        group_cfg['tolerance'] = int(group_spec.get('group_tolerance') or 50)
                    if strategy == 'load-balance':
                        lb_strategy = (group_spec.get('lb_strategy') or 'round-robin').strip()
                        if lb_strategy not in ['round-robin', 'consistent-hashing', 'sticky-sessions']:
                            lb_strategy = 'round-robin'
                        group_cfg['strategy'] = lb_strategy

                    insert_pool_group(group_cfg)
                    chain_proxy_names.append(group_name)
                    if group_name not in pool_group_names:
                        pool_group_names.append(group_name)
                else:
                    # Normal chain (no group)
                    if len(chain_nodes) < 2:
                        continue
                    chain_name_full = f"🔗 {chain_name}"
                    if user_allocations is not None and not is_allocated_chain_name(chain_name_full, 'chain_nodes'):
                        continue
                    build_chain_entry(chain_name_full, chain_nodes, add_to_manual=True)
        
        # Add pool groups to GLOBAL after fallback
        if pool_group_names:
            for group in proxy_groups:
                if group.get('name') == 'GLOBAL':
                    proxies_list = list(group.get('proxies', []))
                    if '🔯 故障转移' in proxies_list:
                        insert_idx = proxies_list.index('🔯 故障转移') + 1
                    else:
                        insert_idx = len(proxies_list)
                    for name in pool_group_names:
                        if name not in proxies_list:
                            proxies_list.insert(insert_idx, name)
                            insert_idx += 1
                    group['proxies'] = proxies_list
                    break

        # Add chain proxies to the proxies list
        # Position: after custom nodes, before subscription nodes
        # Order: traffic_info -> custom_nodes -> chain_proxies -> subscription_nodes
        if chain_proxies:
            # Find the position after custom nodes
            # Custom nodes have "Custom" in their name (from file_aliases)
            custom_node_end_idx = 0
            for i, proxy in enumerate(proxies):
                proxy_name = proxy.get('name', '')
                # Traffic info nodes start with 📊, skip them
                if proxy_name.startswith('📊'):
                    custom_node_end_idx = i + 1
                    continue
                # Custom nodes have "Custom" as provider name
                if 'Custom' in proxy_name:
                    custom_node_end_idx = i + 1
                else:
                    # First non-custom, non-traffic node found
                    break
            
            # Insert chain proxies after custom nodes
            proxies = proxies[:custom_node_end_idx] + chain_proxies + proxies[custom_node_end_idx:]
            
            # Add chain proxies to corresponding country groups (only when country info is present)

            for chain_proxy in chain_proxies:
                chain_proxy_name = chain_proxy.get('name', '')
                # Use stored country info from exit node
                country_info = chain_proxy.get('_country_info')
                if country_info:
                    country_group_name = f"{country_info['flag']} {country_info['country']}"
                    # Find and update the country group
                    for group in proxy_groups:
                        if group.get('name') == country_group_name:
                            if chain_proxy_name not in group.get('proxies', []):
                                group['proxies'].insert(0, chain_proxy_name)  # Add at beginning
                            break
                    # Clean up temporary field before output
                    del chain_proxy['_country_info']

        
        # Add traffic info nodes and chain proxies to manual select group
        if traffic_info_names or chain_proxy_names:
            for group in proxy_groups:
                if group.get('name') == '🚀 手动选择':
                    current_proxies = group.get('proxies', [])

                    # Insert chain proxies after REJECT (or DIRECT if REJECT not present)
                    updated = list(current_proxies)
                    if 'REJECT' in updated:
                        insert_idx = updated.index('REJECT') + 1
                    elif 'DIRECT' in updated:
                        insert_idx = updated.index('DIRECT') + 1
                    else:
                        insert_idx = 0

                    for name in chain_proxy_names:
                        if name not in updated:
                            updated.insert(insert_idx, name)
                            insert_idx += 1

                    # Prepend traffic info nodes, avoid duplicates
                    final_proxies = traffic_info_names + [p for p in updated if p not in traffic_info_names]
                    group['proxies'] = final_proxies
                    break
        
        # Calculate total traffic info from all subscriptions
        total_upload = sum(s.get('upload', 0) or 0 for s in enabled_subs)
        total_download = sum(s.get('download', 0) or 0 for s in enabled_subs)
        total_traffic = sum(s.get('total', 0) or 0 for s in enabled_subs)
        # Use the earliest expire time (ignore 0 which means permanent/unknown)
        expire_times = [s.get('expire', 0) or 0 for s in enabled_subs if (s.get('expire', 0) or 0) > 0]
        total_expire = min(expire_times) if expire_times else 0
        
        # Base64 format output
        if format == 'base64':
            links = []
            for proxy in proxies:
                link = proxy_to_link(proxy)
                if link:
                    links.append(link)
            content = base64.b64encode('\n'.join(links).encode()).decode()
            
            # Get custom config name
            from urllib.parse import quote
            encoded_name = quote(sub_name)
            
            return PlainTextResponse(
                content,
                media_type='text/plain; charset=utf-8',
                headers={
                    "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}",
                    "profile-title": encoded_name,
                    "profile-update-interval": "24",
                    "subscription-userinfo": f"upload={total_upload}; download={total_download}; total={total_traffic}; expire={total_expire}",
                }
            )
        
        # SOCKS format output - minimal config with listeners
        if format == 'socks' or format == 'socks-manual':
            # Get custom config name
            from urllib.parse import quote
            encoded_name = quote(sub_name)
            safe_name = ''.join(c for c in sub_name if c.isalnum() or c in ' _-' or '\u4e00' <= c <= '\u9fff')
            if not safe_name:
                safe_name = 'socks-config'
            
            # Filter out traffic info nodes (those starting with 📊)
            socks_proxies = [p for p in proxies if not p.get('name', '').startswith('📊')]
            
            # Parse header to extract DNS configuration
            dns_config = None
            try:
                header_yaml = yaml.load(header, Loader=YAMLLoader)
                if isinstance(header_yaml, dict) and 'dns' in header_yaml:
                    dns_config = header_yaml['dns']
            except Exception as e:
                logger.warning(f"Failed to parse DNS from header: {e}")
            
            # Build minimal YAML with only 4 sections
            output_parts = []
            
            # 1. allow-lan
            output_parts.append('allow-lan: true')
            
            # 2. DNS configuration (from template or fallback)
            if dns_config:
                output_parts.append('\ndns:')
                output_parts.append(yaml.dump({'dns': dns_config}, allow_unicode=True, default_flow_style=False).replace('dns:\n', '').rstrip())
            else:
                # Fallback DNS config
                fallback_dns = """
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 114.114.114.114
  nameserver:
    - https://doh.pub/dns-query"""
                output_parts.append(fallback_dns)
            
            # 3. Listeners
            output_parts.append('\nlisteners:')
            
            if format == 'socks-manual':
                # Manual mode: only use configured port mappings
                port_mappings = config.get('port_mappings', {})
                if port_mappings:
                    # Get current proxy names for validation (excluding traffic info nodes)
                    proxy_names = {p.get('name', '') for p in socks_proxies}
                    proxy_names.update({g.get('name', '') for g in proxy_groups if isinstance(g, dict)})
                    
                    # Build listeners for valid mappings only
                    listener_idx = 0
                    for node_name, port in sorted(port_mappings.items(), key=lambda x: x[1]):
                        if node_name in proxy_names:
                            listener = {
                                'name': f'mixed{listener_idx}',
                                'type': 'mixed',
                                'port': port,
                                'proxy': node_name
                            }
                            output_parts.append(f'  - {json.dumps(listener, ensure_ascii=False, separators=(",",":"))}')
                            listener_idx += 1
            else:
                # Auto mode: generate listeners for all nodes starting from port 42000
                start_port = 42000
                for idx, proxy in enumerate(socks_proxies):
                    listener = {
                        'name': f'mixed{idx}',
                        'type': 'mixed',
                        'port': start_port + idx,
                        'proxy': proxy.get('name', '')
                    }
                    output_parts.append(f'  - {json.dumps(listener, ensure_ascii=False, separators=(",",":"))}')
            
            # 4. Proxies (excluding traffic info nodes)
            output_parts.append('\nproxies:')
            for proxy in socks_proxies:
                output_parts.append(f'  - {json.dumps(proxy, ensure_ascii=False, separators=(",",":"))}')
            
            yaml_content = "\n".join(output_parts)
            response_headers = {
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(safe_name)}-socks.yaml",
                "profile-title": encoded_name,
                "profile-update-interval": "24",
                "subscription-userinfo": f"upload={total_upload}; download={total_download}; total={total_traffic}; expire={total_expire}",
            }
            
            return PlainTextResponse(
                yaml_content,
                media_type='text/yaml',
                headers=response_headers
            )
        
        # Clash YAML format output (default)
        output_parts = [f'name: {sub_name}\n' + header.rstrip()]
        
        # Generate listeners based on port mappings
        port_mappings = config.get('port_mappings', {})
        if port_mappings:
            # Get current proxy names for validation
            proxy_names = {p.get('name', '') for p in proxies}
            proxy_names.update({g.get('name', '') for g in proxy_groups if isinstance(g, dict)})
            
            # Build listeners for valid mappings only
            listeners = []
            for node_name, port in sorted(port_mappings.items(), key=lambda x: x[1]):
                if node_name in proxy_names:
                    listener = {
                        'name': f'mixed-{port}',
                        'type': 'mixed',
                        'port': port,
                        'proxy': node_name
                    }
                    listeners.append(listener)
            
            if listeners:
                output_parts.append('\nlisteners:')
                for listener in listeners:
                    output_parts.append(f'  - {json.dumps(listener, ensure_ascii=False, separators=(",",":"))}')
        
        output_parts.append('\nproxies:')
        for proxy in proxies:
            output_parts.append(f'  - {json.dumps(proxy, ensure_ascii=False, separators=(",",":"))}')
        output_parts.append('\nproxy-groups:')
        for group in proxy_groups:
            output_parts.append(f'  - {json.dumps(group, ensure_ascii=False, separators=(",",":"))}')
        
        if suffix:
            output_parts.append('\n' + suffix)
        
        # Get custom filename and config name
        # Priority: user's sub_filename > admin_token's sub_filename > global sub_filename
        if user_info and user_info.get('sub_filename'):
            filename = user_info['sub_filename']
        elif admin_token_info and admin_token_info.get('sub_filename'):
            filename = admin_token_info['sub_filename']
        else:
            filename = auth.get('sub_filename', 'config.yaml')
        
        # Use URL encoding for names
        from urllib.parse import quote
        encoded_name = quote(sub_name)
        # Filename also uses config name (remove unsafe chars, keep Chinese)
        safe_name = ''.join(c for c in sub_name if c.isalnum() or c in ' _-' or '\u4e00' <= c <= '\u9fff')
        if not safe_name:
            safe_name = filename.replace('.yaml', '').replace('.yml', '')
        
        yaml_content = "\n".join(output_parts)
        response_headers = {
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(safe_name)}.yaml",
            "profile-title": encoded_name,
            "profile-update-interval": "24",
            "subscription-userinfo": f"upload={total_upload}; download={total_download}; total={total_traffic}; expire={total_expire}",
        }
        
        # Cache the generated YAML for user subscriptions
        if user_info:
            # Update cache in user object
            user_info['sub_cache'] = {
                'content': yaml_content,
                'headers': response_headers,
                'timestamp': time.time()
            }
            # Save config with updated cache
            save_config(config)
            logger.debug(f"Cached subscription for user {user_info['name']}")
        
        return PlainTextResponse(
            yaml_content, 
            media_type='text/yaml',
            headers=response_headers
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = f"Failed to generate subscription: {str(e)}\n{traceback.format_exc()}"
        logger.error(error_detail)
        print(f"ERROR in /sub endpoint: {error_detail}", file=sys.stderr)
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Template API (Legacy - single template) ====================

def split_template(full_content: str) -> Tuple[str, str]:
    """
    Split template into header (config before proxies) and suffix (rules after proxy-groups).
    Removes proxies: and proxy-groups: sections completely.
    """
    lines = full_content.splitlines(keepends=True)
    header_lines, suffix_lines = [], []
    state = 0  # 0=header, 1=skip(proxies/groups), 2=suffix
    
    for line in lines:
        stripped = line.strip()
        
        if state == 0:
            # In header section
            if stripped.startswith('proxies:') or stripped.startswith('proxy-groups:'):
                # Start skipping proxies/proxy-groups sections
                state = 1
                continue
            header_lines.append(line)
            
        elif state == 1:
            # Skipping proxies/proxy-groups sections
            # Check if we've reached the suffix (rules, etc.)
            if any(stripped.startswith(k) for k in ['rules:', 'rule-providers:', 'script:', 'url-rewrite:']):
                state = 2
                suffix_lines.append(line)
            # Otherwise, skip this line (it's part of proxies/proxy-groups)
            
        elif state == 2:
            # In suffix section
            suffix_lines.append(line)
    
    return "".join(header_lines).strip(), "".join(suffix_lines).strip()

@app.get("/api/template")
def get_saved_template(_: bool = Depends(verify_session)):
    """Get saved template or default if none saved"""
    config = load_config()
    if 'template' in config:
        template = config['template']
        header = template.get('header', ConfigMerger.DEFAULT_HEADER)
        suffix = template.get('suffix', ConfigMerger.DEFAULT_SUFFIX)
    else:
        header = ConfigMerger.DEFAULT_HEADER
        suffix = ConfigMerger.DEFAULT_SUFFIX
    return {"content": header.strip() + "\n\nproxies: []\n\nproxy-groups: []\n\n" + suffix.strip()}

@app.get("/api/template/default")
def get_default_template(_: bool = Depends(verify_session)):
    header = ConfigMerger.DEFAULT_HEADER
    suffix = ConfigMerger.DEFAULT_SUFFIX
    return {"content": header.strip() + "\n\nproxies: []\n\nproxy-groups: []\n\n" + suffix.strip()}

@app.post("/api/template/parse")
async def parse_template_file(file: UploadFile = File(...), current_template: str = Form(default=""), _: bool = Depends(verify_session)):
    """Parse uploaded template file with size validation"""
    try:
        # Read file content with size limit
        content_bytes = await file.read()
        
        # Validate file size
        if len(content_bytes) > Constants.MAX_REQUEST_SIZE:
            raise HTTPException(
                status_code=413, 
                detail=f"File too large. Maximum size: {Constants.MAX_REQUEST_SIZE / 1024 / 1024:.1f}MB"
            )
        
        content = content_bytes.decode('utf-8')
        
        try:
            uploaded_config = yaml.load(content, Loader=YAMLLoader)
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)[:100]}")
        
        if not isinstance(uploaded_config, dict):
            raise HTTPException(status_code=400, detail="Invalid file format")
        
        if current_template:
            try:
                base_config = yaml.load(current_template, Loader=YAMLLoader)
            except yaml.YAMLError as e:
                logger.warning(f"Failed to parse current template: {e}")
                base_config = {}
            except Exception as e:
                logger.error(f"Error loading current template: {e}")
                base_config = {}
        else:
            header = ConfigMerger.DEFAULT_HEADER
            suffix = ConfigMerger.DEFAULT_SUFFIX
            try:
                base_config = yaml.load(header + "\nproxies: []\nproxy-groups: []\n" + suffix, Loader=YAMLLoader)
            except yaml.YAMLError as e:
                logger.error(f"Failed to parse default template: {e}")
                base_config = {}
            except Exception as e:
                logger.error(f"Error loading default template: {e}")
                base_config = {}
        
        if not isinstance(base_config, dict):
            base_config = {}
        
        merged = {}
        for key in base_config:
            if key == 'proxies':
                merged[key] = []
            elif key == 'proxy-groups':
                # Preserve from uploaded config if exists
                continue
            elif key in uploaded_config:
                merged[key] = uploaded_config[key]
            else:
                merged[key] = base_config[key]
        
        for key in uploaded_config:
            if key not in merged:
                if key == 'proxies':
                    merged[key] = []
                elif key == 'proxy-groups':
                    # Process proxy-groups: keep structure, clean proxy nodes
                    pass
                else:
                    merged[key] = uploaded_config[key]
        
        merged['proxies'] = []
        
        # Process proxy-groups: keep structure, clean proxy node names
        uploaded_groups = uploaded_config.get('proxy-groups', [])
        if uploaded_groups and isinstance(uploaded_groups, list):
            # Get all group names defined in the config
            group_names = set()
            for group in uploaded_groups:
                if isinstance(group, dict) and group.get('name'):
                    group_names.add(group['name'])
            
            # Special entries to preserve
            preserved_entries = {'DIRECT', 'REJECT', 'GLOBAL', 'PASS'}
            preserved_entries.update(group_names)
            
            cleaned_groups = []
            for group in uploaded_groups:
                if not isinstance(group, dict):
                    continue
                cleaned_group = dict(group)
                proxies = group.get('proxies', [])
                if isinstance(proxies, list):
                    # Keep only DIRECT, REJECT, and other group references
                    cleaned_proxies = [p for p in proxies if p in preserved_entries]
                    cleaned_group['proxies'] = cleaned_proxies
                cleaned_groups.append(cleaned_group)
            
            merged['proxy-groups'] = cleaned_groups
        else:
            merged['proxy-groups'] = []
        
        new_content = yaml.dump(merged, allow_unicode=True, sort_keys=False, default_flow_style=False, width=float("inf"), Dumper=YAMLDumper)
        section_keys = ['dns:', 'sniffer:', 'tun:', 'proxies:', 'proxy-groups:', 'rules:', 'rule-providers:', 'script:', 'url-rewrite:']
        lines = new_content.split('\n')
        result_lines = []
        for line in lines:
            stripped = line.strip()
            if any(stripped.startswith(key) for key in section_keys):
                if not line.startswith(' ') and not line.startswith('\t'):
                    if result_lines and result_lines[-1].strip() != '':
                        result_lines.append('')
            result_lines.append(line)
        return {"content": '\n'.join(result_lines).strip()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class TemplateSaveRequest(BaseModel):
    content: str

@app.post("/api/template/save")
def save_template(data: TemplateSaveRequest, _: bool = Depends(verify_session)):
    """Save template content to config"""
    try:
        content = data.content.strip()
        # Parse to validate YAML
        try:
            parsed = yaml.load(content, Loader=YAMLLoader)
            if not isinstance(parsed, dict):
                raise HTTPException(status_code=400, detail="Invalid template format")
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)[:100]}")
        
        # Split into header and suffix
        header, suffix = split_template(content)
        
        # Update ConfigMerger templates
        ConfigMerger.DEFAULT_HEADER = header
        ConfigMerger.DEFAULT_SUFFIX = suffix
        
        # Save to config.json
        config = load_config()
        config['template'] = {
            'header': header,
            'suffix': suffix
        }
        save_config(config)
        
        return {"success": True, "message": "Template saved"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/preview")
def generate_preview(template: TemplateContent, _: bool = Depends(verify_session)):
    header, suffix = split_template(template.content)
    
    config = load_config()
    subs = config.get('subscriptions', [])
    custom_nodes = config.get('custom_nodes', [])
    
    file_aliases = OrderedDict(template.file_aliases or {})
    
    if custom_nodes and 'custom_nodes.yaml' not in file_aliases:
        new_aliases = OrderedDict()
        new_aliases['custom_nodes.yaml'] = 'Custom'
        new_aliases.update(file_aliases)
        file_aliases = new_aliases
    
    for s in subs:
        if s['enabled']:
            filename = f"{s['id']}.yaml"
            if filename not in file_aliases:
                file_aliases[filename] = s['name']
    
    merger = ConfigMerger(
        yaml_dir=YAML_SOURCE_DIR, output_file=OUTPUT_FILE,
        custom_header=header, custom_suffix=suffix, file_aliases=file_aliases
    )
    
    try:
        cfg = merger.merge_and_generate()
        proxies = cfg.get('proxies', [])
        proxy_groups = cfg.get('proxy-groups', [])
        
        output_parts = [header.rstrip(), '\nproxies:']
        for proxy in proxies:
            output_parts.append(f'  - {json.dumps(proxy, ensure_ascii=False, separators=(",",":"))}')
        output_parts.append('\nproxy-groups:')
        for group in proxy_groups:
            output_parts.append(f'  - {json.dumps(group, ensure_ascii=False, separators=(",",":"))}')
        
        if suffix:
            output_parts.append('\n' + suffix)
        return {"content": "\n".join(output_parts)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/save_content")
def save_final_content(data: FinalContent, _: bool = Depends(verify_session)):
    target = data.save_path if data.save_path else OUTPUT_FILE
    try:
        with open(target, 'w', encoding='utf-8') as f:
            f.write(data.content)
        return {"status": "success", "output_file": target}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/download_result")
def download_result(_: bool = Depends(verify_session)):
    if os.path.exists(OUTPUT_FILE):
        return FileResponse(OUTPUT_FILE, media_type='application/yaml', filename='myconfig.yaml')
    raise HTTPException(status_code=404, detail="Config not generated yet")

# ==================== Static Files ====================

frontend_dist = os.environ.get('FRONTEND_DIST_DIR') or os.path.join(BASE_DIR, 'submerger', 'dist')
if not os.path.isabs(frontend_dist):
    frontend_dist = os.path.join(BASE_DIR, frontend_dist)
if os.path.exists(frontend_dist):
    # 1. Mount assets with cache headers for performance
    assets_path = os.path.join(frontend_dist, 'assets')
    if os.path.exists(assets_path):
        app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

    # 2. Serve root requests
    @app.get("/")
    async def serve_index():
        response = FileResponse(os.path.join(frontend_dist, "index.html"))
        # No cache for HTML to ensure fresh content
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    # 3. Catch-all for SPA routes (e.g. /settings, /nodes)
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # API 404s should return JSON, not HTML
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")
            
        # Try to serve static file if it exists (e.g. favicon.ico)
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            response = FileResponse(file_path)
            # Cache static assets (js, css, images) for 1 year (immutable with hash)
            if full_path.endswith(('.js', '.css', '.woff', '.woff2', '.ttf', '.eot')):
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            elif full_path.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp')):
                response.headers["Cache-Control"] = "public, max-age=86400"  # 1 day for images
            elif full_path.endswith('.json'):
                response.headers["Cache-Control"] = "public, max-age=3600"  # 1 hour for JSON
            return response
            
        # Fallback to index.html for React Router
        response = FileResponse(os.path.join(frontend_dist, "index.html"))
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

if __name__ == "__main__":
    import uvicorn
    from dotenv import load_dotenv
    
    # Load .env file
    load_dotenv()
    
    # Get configuration from environment variables
    port = int(os.getenv('PORT', '8666'))
    host = os.getenv('HOST', '0.0.0.0')
    
    logger.info(f"Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
