"""
Stats Cache Service
Caches statistics data for dashboard performance
"""
import time
from typing import Optional, Dict, Any

from logger_config import get_logger
from core.config import AppConfig

logger = get_logger(__name__)


class StatsCache:
    """Thread-safe stats cache with TTL"""
    
    def __init__(self, duration: int = None):
        """
        Initialize cache.
        
        Args:
            duration: Cache TTL in seconds
        """
        self._duration = duration or AppConfig.STATS_CACHE_DURATION
        self._data: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get cached value.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if expired/missing
        """
        if key not in self._data:
            return None
        
        # Check TTL
        if time.time() - self._timestamps.get(key, 0) > self._duration:
            self.invalidate(key)
            return None
        
        return self._data[key]
    
    def set(self, key: str, value: Any) -> None:
        """
        Set cache value.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        self._data[key] = value
        self._timestamps[key] = time.time()
    
    def invalidate(self, key: str = None) -> None:
        """
        Invalidate cache.
        
        Args:
            key: Specific key to invalidate, or None to clear all
        """
        if key:
            self._data.pop(key, None)
            self._timestamps.pop(key, None)
        else:
            self._data.clear()
            self._timestamps.clear()
    
    def is_valid(self, key: str) -> bool:
        """Check if cache key is valid (exists and not expired)"""
        if key not in self._data:
            return False
        return time.time() - self._timestamps.get(key, 0) <= self._duration


# Global cache instance
_cache = StatsCache()


def get_overview() -> Optional[Dict[str, Any]]:
    """Get cached overview stats"""
    return _cache.get('overview')


def set_overview(data: Dict[str, Any]) -> None:
    """Cache overview stats"""
    _cache.set('overview', data)


def get_countries() -> Optional[Dict[str, Any]]:
    """Get cached countries stats"""
    return _cache.get('countries')


def set_countries(data: Dict[str, Any]) -> None:
    """Cache countries stats"""
    _cache.set('countries', data)


def invalidate() -> None:
    """Invalidate all cached stats"""
    _cache.invalidate()
    logger.debug("Stats cache invalidated")


def invalidate_on_change() -> None:
    """Invalidate cache when data changes (alias for invalidate)"""
    invalidate()
