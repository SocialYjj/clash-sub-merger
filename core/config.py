"""
Application configuration module
Centralized configuration management with environment variable support
"""
import os
import warnings
from dotenv import load_dotenv

# Load .env file first
load_dotenv()

# Base directories - handle both direct run and module import
_current_file = os.path.abspath(__file__)
_core_dir = os.path.dirname(_current_file)
BASE_DIR = os.path.dirname(_core_dir)  # Go up from core/ to project root

DATA_DIR = os.environ.get('DATA_DIR', os.path.join(BASE_DIR, 'data'))
YAML_SOURCE_DIR = os.path.join(DATA_DIR, 'uploads')
CONFIG_FILE = os.path.join(DATA_DIR, 'config.json')
DATABASE_FILE = os.path.join(DATA_DIR, 'app.db')
STORAGE_BACKEND = os.environ.get('STORAGE_BACKEND', 'sqlite').strip().lower()
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')
LOG_DIR = os.path.join(DATA_DIR, 'logs')
REFRESH_LOCK_DIR = os.path.join(DATA_DIR, 'refresh_locks')

# Ensure directories exist. Docker repairs bind-mount ownership in its entrypoint;
# direct deployments should fail immediately with a useful path and cause.
try:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(YAML_SOURCE_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(REFRESH_LOCK_DIR, exist_ok=True)
except OSError as exc:
    raise RuntimeError(f"Cannot initialize DATA_DIR '{DATA_DIR}': {exc}") from exc


def env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment variable without treating typos as false."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {'1', 'true', 'yes', 'on'}:
        return True
    if normalized in {'0', 'false', 'no', 'off'}:
        return False
    warnings.warn(
        f"Invalid boolean environment variable {name}={raw!r}; using {default!r}",
        RuntimeWarning,
        stacklevel=2,
    )
    return default


def env_int(name: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    """Read an integer environment variable without crashing on invalid input."""
    raw = os.environ.get(name)
    if raw is None:
        value = default
    else:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            warnings.warn(
                f"Invalid integer environment variable {name}={raw!r}; using {default!r}",
                RuntimeWarning,
                stacklevel=2,
            )
            value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


class AppConfig:
    """Centralized application configuration"""
    
    # Directories
    BASE_DIR = BASE_DIR
    DATA_DIR = DATA_DIR
    YAML_SOURCE_DIR = YAML_SOURCE_DIR
    CONFIG_FILE = CONFIG_FILE
    DATABASE_FILE = DATABASE_FILE
    STORAGE_BACKEND = STORAGE_BACKEND
    BACKUP_DIR = BACKUP_DIR
    LOG_DIR = LOG_DIR
    REFRESH_LOCK_DIR = REFRESH_LOCK_DIR
    
    # Go Speedtest Service
    GO_SPEEDTEST_URL = os.environ.get('GO_SPEEDTEST_URL', 'http://localhost:9876')
    GO_SPEEDTEST_PORT = env_int('GO_SPEEDTEST_PORT', 9876, minimum=1, maximum=65535)
    GO_SPEEDTEST_ENABLED = env_bool('GO_SPEEDTEST_ENABLED', True)
    GO_SPEEDTEST_BIN = os.environ.get('GO_SPEEDTEST_BIN', '').strip()
    
    # Timeouts (seconds) - fine-grained control
    DEFAULT_TIMEOUT = env_int('DEFAULT_TIMEOUT', 30, minimum=1)
    SPEEDTEST_TIMEOUT = env_int('SPEEDTEST_TIMEOUT', 10, minimum=1)
    HEALTH_CHECK_TIMEOUT = env_int('HEALTH_CHECK_TIMEOUT', 2, minimum=1)
    CONNECT_TIMEOUT = env_int('CONNECT_TIMEOUT', 10, minimum=1)
    READ_TIMEOUT = env_int('READ_TIMEOUT', 30, minimum=1)
    WRITE_TIMEOUT = env_int('WRITE_TIMEOUT', 10, minimum=1)
    
    # Subscription refresh concurrency
    SUBSCRIPTION_REFRESH_CONCURRENCY = env_int(
        'SUBSCRIPTION_REFRESH_CONCURRENCY',
        4,
        minimum=1,
        maximum=20,
    )
    SCHEDULED_REFRESH_WORKERS = env_int('SCHEDULED_REFRESH_WORKERS', 4, minimum=1, maximum=20)
    SCHEDULED_REFRESH_MISFIRE_GRACE_SECONDS = env_int(
        'SCHEDULED_REFRESH_MISFIRE_GRACE_SECONDS',
        300,
        minimum=1,
    )
    SCHEDULED_REFRESH_JITTER_SECONDS = env_int(
        'SCHEDULED_REFRESH_JITTER_SECONDS',
        120,
        minimum=0,
        maximum=900,
    )
    SUBSCRIPTION_FETCH_RETRIES = env_int(
        'SUBSCRIPTION_FETCH_RETRIES',
        1,
        minimum=0,
        maximum=5,
    )
    SUBSCRIPTION_FETCH_RETRY_DELAY_SECONDS = env_int(
        'SUBSCRIPTION_FETCH_RETRY_DELAY_SECONDS',
        1,
        minimum=0,
        maximum=30,
    )
    
    # Cache settings
    STATS_CACHE_DURATION = env_int('STATS_CACHE_DURATION', 60, minimum=0)
    CONFIG_CACHE_DURATION = env_int('CONFIG_CACHE_DURATION', 5, minimum=0)
    YAML_CACHE_DURATION = env_int('YAML_CACHE_DURATION', 60, minimum=0)

    # Input/output limits
    MAX_REQUEST_SIZE = env_int('MAX_REQUEST_SIZE', 10 * 1024 * 1024, minimum=1024)
    SUBSCRIPTION_MAX_BYTES = env_int(
        'SUBSCRIPTION_MAX_BYTES',
        10 * 1024 * 1024,
        minimum=1024,
    )
    
    # File lock timeout
    FILE_LOCK_TIMEOUT = env_int('FILE_LOCK_TIMEOUT', 10, minimum=0)
    
    # Rate limiting
    RATE_LIMIT_LOGIN = os.environ.get('RATE_LIMIT_LOGIN', '10/minute')
    RATE_LIMIT_REFRESH_SINGLE = os.environ.get('RATE_LIMIT_REFRESH_SINGLE', '10/minute')
    RATE_LIMIT_REFRESH_ALL = os.environ.get('RATE_LIMIT_REFRESH_ALL', '5/minute')
    RATE_LIMIT_SPEEDTEST = os.environ.get('RATE_LIMIT_SPEEDTEST', '5/minute')
    RATE_LIMIT_NODE_TEST = os.environ.get('RATE_LIMIT_NODE_TEST', '600/minute')
    RATE_LIMIT_NODE_SAVE = os.environ.get('RATE_LIMIT_NODE_SAVE', '30/minute')
    RATE_LIMIT_GEOIP = os.environ.get('RATE_LIMIT_GEOIP', '30/minute')
    RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '200/minute')
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*')
    
    # API docs are disabled by default for production hardening. Set
    # ENABLE_API_DOCS=true to expose /docs, /redoc and /openapi.json.
    ENABLE_API_DOCS = env_bool('ENABLE_API_DOCS', False)

    # Optional HMAC signing key for newly issued admin session tokens.
    # Existing unsigned sessions remain compatible when upgrading.
    SESSION_SECRET = os.environ.get('SESSION_SECRET', '').strip()
    INITIAL_ADMIN_PASSWORD = os.environ.get('INITIAL_ADMIN_PASSWORD', '').strip()
    SESSION_TTL_SECONDS = env_int('SESSION_TTL_SECONDS', 86400, minimum=300)
    MAX_ACTIVE_SESSIONS = env_int('MAX_ACTIVE_SESSIONS', 20, minimum=1, maximum=200)
    METRICS_TOKEN = os.environ.get('METRICS_TOKEN', '').strip()
    
    # GZip compression threshold (bytes)
    GZIP_MIN_SIZE = env_int('GZIP_MIN_SIZE', 500, minimum=0)
    
    # HTTP connection pool settings
    HTTP_MAX_KEEPALIVE = env_int('HTTP_MAX_KEEPALIVE', 20, minimum=0)
    HTTP_MAX_CONNECTIONS = env_int('HTTP_MAX_CONNECTIONS', 50, minimum=1)
    HTTP_VERIFY_SSL = env_bool('HTTP_VERIFY_SSL', True)

    # Cloudflare Radar is a backend-only optional integration.  The token is
    # intentionally never exposed through the frontend or persisted config.
    CLOUDFLARE_RADAR_TIMEOUT = env_int('CLOUDFLARE_RADAR_TIMEOUT', 5, minimum=1, maximum=60)
    
    # Backup settings
    AUTO_BACKUP_ENABLED = env_bool('AUTO_BACKUP_ENABLED', True)
    AUTO_BACKUP_INTERVAL_HOURS = env_int('AUTO_BACKUP_INTERVAL_HOURS', 24, minimum=1)
    AUTO_BACKUP_KEEP_COUNT = env_int('AUTO_BACKUP_KEEP_COUNT', 7, minimum=1)
    
    # Key rotation settings
    KEY_ROTATION_DAYS = env_int('KEY_ROTATION_DAYS', 90, minimum=1)
    KEY_ROTATION_CHECK_ENABLED = env_bool('KEY_ROTATION_CHECK_ENABLED', True)
    
    # Version - read from VERSION file
    @staticmethod
    def _read_version():
        """Read version from VERSION file"""
        try:
            version_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'VERSION')
            with open(version_file, 'r') as f:
                return f.read().strip()
        except Exception:
            return "3.1.1"  # Fallback version
    
    VERSION = _read_version.__func__()


def get_config_file() -> str:
    """Get config file path"""
    return CONFIG_FILE


def get_database_file() -> str:
    """Get the SQLite database path."""
    return DATABASE_FILE


def get_data_dir() -> str:
    """Get data directory path"""
    return DATA_DIR


def get_yaml_source_dir() -> str:
    """Get YAML source directory path"""
    return YAML_SOURCE_DIR


def get_backup_dir() -> str:
    """Get backup directory path"""
    return BACKUP_DIR
