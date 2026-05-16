"""
Application configuration module
Centralized configuration management with environment variable support
"""
import os
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
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')

# Ensure directories exist - wrapped in try/except for Docker volume mount scenarios
try:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(YAML_SOURCE_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
except PermissionError:
    # Directories will be created by Docker volume mount or already exist
    pass


def env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment variable with safe fallback."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


def env_int(name: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    """Read an integer environment variable without crashing on invalid input."""
    raw = os.environ.get(name)
    if raw is None:
        value = default
    else:
        try:
            value = int(raw)
        except (TypeError, ValueError):
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
    
    # Retry settings
    MAX_RETRIES = env_int('MAX_RETRIES', 3, minimum=0)
    RETRY_DELAY = env_int('RETRY_DELAY', 1, minimum=0)
    
    # Cache settings
    STATS_CACHE_DURATION = env_int('STATS_CACHE_DURATION', 60, minimum=0)
    CONFIG_CACHE_DURATION = env_int('CONFIG_CACHE_DURATION', 5, minimum=0)
    
    # File lock timeout
    FILE_LOCK_TIMEOUT = env_int('FILE_LOCK_TIMEOUT', 10, minimum=0)
    
    # Rate limiting
    RATE_LIMIT_LOGIN = os.environ.get('RATE_LIMIT_LOGIN', '10/minute')
    RATE_LIMIT_REFRESH_SINGLE = os.environ.get('RATE_LIMIT_REFRESH_SINGLE', '10/minute')
    RATE_LIMIT_REFRESH_ALL = os.environ.get('RATE_LIMIT_REFRESH_ALL', '5/minute')
    RATE_LIMIT_SPEEDTEST = os.environ.get('RATE_LIMIT_SPEEDTEST', '5/minute')
    RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '200/minute')
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*')
    
    # API docs are disabled by default for production hardening. Set
    # ENABLE_API_DOCS=true to expose /docs, /redoc and /openapi.json.
    ENABLE_API_DOCS = env_bool('ENABLE_API_DOCS', False)

    # Optional HMAC signing key for newly issued admin session tokens.
    # Existing unsigned sessions remain compatible when upgrading.
    SESSION_SECRET = os.environ.get('SESSION_SECRET', '').strip()
    
    # GZip compression threshold (bytes)
    GZIP_MIN_SIZE = env_int('GZIP_MIN_SIZE', 500, minimum=0)
    
    # HTTP connection pool settings
    HTTP_MAX_KEEPALIVE = env_int('HTTP_MAX_KEEPALIVE', 20, minimum=0)
    HTTP_MAX_CONNECTIONS = env_int('HTTP_MAX_CONNECTIONS', 50, minimum=1)
    HTTP_VERIFY_SSL = env_bool('HTTP_VERIFY_SSL', True)
    
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


def get_data_dir() -> str:
    """Get data directory path"""
    return DATA_DIR


def get_yaml_source_dir() -> str:
    """Get YAML source directory path"""
    return YAML_SOURCE_DIR


def get_backup_dir() -> str:
    """Get backup directory path"""
    return BACKUP_DIR
