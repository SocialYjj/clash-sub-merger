"""
Prometheus metrics module
Centralized metrics definitions to avoid duplicate registration
"""
from prometheus_client import Counter, Histogram, Gauge

# HTTP request metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

# Cache metrics
cache_hits_total = Counter(
    'cache_hits_total',
    'Total cache hits',
    ['cache_type']
)

cache_misses_total = Counter(
    'cache_misses_total',
    'Total cache misses',
    ['cache_type']
)

# File operation metrics
file_operations_total = Counter(
    'file_operations_total',
    'Total file operations',
    ['operation', 'status']
)

file_operation_duration_seconds = Histogram(
    'file_operation_duration_seconds',
    'File operation duration in seconds',
    ['operation']
)

# Concurrent requests
concurrent_requests = Gauge(
    'concurrent_requests',
    'Current concurrent requests'
)
