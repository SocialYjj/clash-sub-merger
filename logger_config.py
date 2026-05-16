"""
Logging configuration for the application
Supports both plain text and JSON structured logging formats
"""
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Get log level from environment variable
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
# Enable JSON logging with LOG_FORMAT=json
LOG_FORMAT_TYPE = os.environ.get('LOG_FORMAT', 'text').lower()
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(os.path.dirname(__file__), 'data'))

# Ensure logs directory exists
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
try:
    Path(LOGS_DIR).mkdir(parents=True, exist_ok=True)
except (PermissionError, OSError):
    # Directory will be created by Docker volume mount or already exists
    pass

# Log file path
LOG_FILE = os.path.join(LOGS_DIR, 'app.log')

# Log format
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging
    Outputs logs in JSON format for easy parsing by log aggregation tools
    """
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': self._sanitize_message(record.getMessage()),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if any
        if hasattr(record, 'extra_data'):
            log_data['extra'] = record.extra_data
        
        return json.dumps(log_data, ensure_ascii=False)
    
    def _sanitize_message(self, message: str) -> str:
        """Sanitize sensitive information from log messages"""
        return SensitiveDataFilter.sanitize(message)


class SensitiveDataFilter(logging.Filter):
    """
    Filter to sanitize sensitive data from log messages
    Masks tokens, passwords, API keys, etc.
    """
    
    # Patterns for sensitive data
    PATTERNS = [
        # API tokens and keys (generic)
        (re.compile(r'(token["\s:=]+)["\']?([a-zA-Z0-9_-]{16,})["\']?', re.IGNORECASE), r'\1***REDACTED***'),
        (re.compile(r'(api[_-]?key["\s:=]+)["\']?([a-zA-Z0-9_-]{16,})["\']?', re.IGNORECASE), r'\1***REDACTED***'),
        (re.compile(r'(secret["\s:=]+)["\']?([a-zA-Z0-9_-]{8,})["\']?', re.IGNORECASE), r'\1***REDACTED***'),
        # Passwords
        (re.compile(r'(password["\s:=]+)["\']?([^"\s,}]+)["\']?', re.IGNORECASE), r'\1***REDACTED***'),
        (re.compile(r'(passwd["\s:=]+)["\']?([^"\s,}]+)["\']?', re.IGNORECASE), r'\1***REDACTED***'),
        # Authorization headers
        (re.compile(r'(Authorization["\s:=]+)["\']?(Bearer\s+)?([a-zA-Z0-9_.-]+)["\']?', re.IGNORECASE), r'\1***REDACTED***'),
        # URLs with credentials
        (re.compile(r'(https?://)[^:]+:[^@]+@', re.IGNORECASE), r'\1***:***@'),
    ]
    
    @classmethod
    def sanitize(cls, message: str) -> str:
        """Apply all sanitization patterns to a message"""
        for pattern, replacement in cls.PATTERNS:
            message = pattern.sub(replacement, message)
        return message
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and sanitize the log record"""
        if record.msg:
            record.msg = self.sanitize(str(record.msg))
        if record.args:
            record.args = tuple(
                self.sanitize(str(arg)) if isinstance(arg, str) else arg
                for arg in record.args
            )
        return True

# Store all loggers for dynamic level adjustment
_all_loggers = {}


def _get_formatter() -> logging.Formatter:
    """
    Get the appropriate formatter based on LOG_FORMAT_TYPE
    
    Returns:
        JSONFormatter for 'json', standard Formatter for 'text'
    """
    if LOG_FORMAT_TYPE == 'json':
        return JSONFormatter()
    return logging.Formatter(LOG_FORMAT, DATE_FORMAT)


def setup_logger(name: str = None) -> logging.Logger:
    """
    Setup and return a logger instance
    
    Args:
        name: Logger name (usually __name__ of the module)
    
    Returns:
        Configured logger instance
    
    Environment Variables:
        LOG_LEVEL: Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        LOG_FORMAT: Set output format ('text' or 'json')
    """
    logger = logging.getLogger(name or 'submerger')
    
    # Store logger reference for dynamic adjustment
    _all_loggers[name or 'submerger'] = logger
    
    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger
    
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    
    # Add sensitive data filter
    logger.addFilter(SensitiveDataFilter())
    
    # Get formatter based on configuration
    formatter = _get_formatter()
    
    # Console handler (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (rotating) - only add if we have write permission
    try:
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except (PermissionError, OSError) as e:
        # Log to console only if file logging fails
        logger.warning(f"Could not create file handler: {e}. Logging to console only.")
    
    return logger


# Create default logger
logger = setup_logger()


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module
    
    Args:
        name: Module name (usually __name__)
    
    Returns:
        Logger instance
    """
    if name not in _all_loggers:
        # Setup logger with handlers if not already configured
        return setup_logger(name)
    return _all_loggers[name]


def set_log_level(level: str):
    """
    Dynamically adjust log level for all loggers at runtime
    
    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    level_upper = level.upper()
    if level_upper not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        raise ValueError(f"Invalid log level: {level}. Must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    
    log_level = getattr(logging, level_upper)
    
    # Update all existing loggers
    for logger_name, logger_instance in _all_loggers.items():
        logger_instance.setLevel(log_level)
        logger.info("Log level changed to %s for logger: %s", level_upper, logger_name)
    
    # Update root logger
    logging.getLogger().setLevel(log_level)
    
    logger.info("Global log level changed to: %s", level_upper)


def get_current_log_level() -> str:
    """
    Get current log level
    
    Returns:
        Current log level as string
    """
    return logging.getLevelName(logger.level)


def list_all_loggers() -> dict:
    """
    List all registered loggers and their levels
    
    Returns:
        Dictionary of logger names and their levels
    """
    return {
        name: logging.getLevelName(logger_instance.level)
        for name, logger_instance in _all_loggers.items()
    }


def get_log_format() -> str:
    """
    Get current log format type
    
    Returns:
        Current log format ('text' or 'json')
    """
    return LOG_FORMAT_TYPE

