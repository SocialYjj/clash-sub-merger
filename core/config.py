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


class AppConfig:
    """Centralized application configuration"""
    
    # Directories
    BASE_DIR = BASE_DIR
    DATA_DIR = DATA_DIR
    
    # Go Speedtest Service
    GO_SPEEDTEST_URL = os.environ.get('GO_SPEEDTEST_URL', 'http://localhost:9876')
    GO_SPEEDTEST_PORT = int(os.environ.get('GO_SPEEDTEST_PORT', '9876'))
    GO_SPEEDTEST_ENABLED = os.environ.get('GO_SPEEDTEST_ENABLED', 'true').strip().lower() in ('1', 'true', 'yes', 'on')
    GO_SPEEDTEST_BIN = os.environ.get('GO_SPEEDTEST_BIN', '').strip()
    
    # Timeouts (seconds) - fine-grained control
    DEFAULT_TIMEOUT = int(os.environ.get('DEFAULT_TIMEOUT', '30'))
    SPEEDTEST_TIMEOUT = int(os.environ.get('SPEEDTEST_TIMEOUT', '10'))
    HEALTH_CHECK_TIMEOUT = int(os.environ.get('HEALTH_CHECK_TIMEOUT', '2'))
    CONNECT_TIMEOUT = int(os.environ.get('CONNECT_TIMEOUT', '10'))
    READ_TIMEOUT = int(os.environ.get('READ_TIMEOUT', '30'))
    WRITE_TIMEOUT = int(os.environ.get('WRITE_TIMEOUT', '10'))
    
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
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*')
    
    # GZip compression threshold (bytes)
    GZIP_MIN_SIZE = int(os.environ.get('GZIP_MIN_SIZE', '500'))
    
    # HTTP connection pool settings
    HTTP_MAX_KEEPALIVE = int(os.environ.get('HTTP_MAX_KEEPALIVE', '20'))
    HTTP_MAX_CONNECTIONS = int(os.environ.get('HTTP_MAX_CONNECTIONS', '50'))
    
    # Backup settings
    AUTO_BACKUP_ENABLED = os.environ.get('AUTO_BACKUP_ENABLED', 'true').lower() == 'true'
    AUTO_BACKUP_INTERVAL_HOURS = int(os.environ.get('AUTO_BACKUP_INTERVAL_HOURS', '24'))
    AUTO_BACKUP_KEEP_COUNT = int(os.environ.get('AUTO_BACKUP_KEEP_COUNT', '7'))
    
    # Key rotation settings
    KEY_ROTATION_DAYS = int(os.environ.get('KEY_ROTATION_DAYS', '90'))
    KEY_ROTATION_CHECK_ENABLED = os.environ.get('KEY_ROTATION_CHECK_ENABLED', 'true').lower() == 'true'
    
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
