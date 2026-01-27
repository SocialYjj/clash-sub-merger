"""
Logging configuration for the application
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Get log level from environment variable
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(os.path.dirname(__file__), 'data'))

# Ensure logs directory exists
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
Path(LOGS_DIR).mkdir(parents=True, exist_ok=True)

# Log file path
LOG_FILE = os.path.join(LOGS_DIR, 'app.log')

# Log format
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Store all loggers for dynamic level adjustment
_all_loggers = {}


def setup_logger(name: str = None) -> logging.Logger:
    """
    Setup and return a logger instance
    
    Args:
        name: Logger name (usually __name__ of the module)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name or 'submerger')
    
    # Store logger reference for dynamic adjustment
    _all_loggers[name or 'submerger'] = logger
    
    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger
    
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    
    # Console handler (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    
    # File handler (rotating)
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    file_handler.setFormatter(file_formatter)
    
    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
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
        _all_loggers[name] = logging.getLogger(name)
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

