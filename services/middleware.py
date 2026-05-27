"""
Middleware Service
Provides FastAPI middleware for security, metrics, and logging
"""
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from logger_config import get_logger
from helpers import Constants
from core import (
    http_requests_total,
    http_request_duration_seconds,
    concurrent_requests,
)

logger = get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Content Security Policy
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
        
        # Other security headers
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()"
        )
        
        return response


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Add unique request ID to each request"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Limit request body size"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > Constants.MAX_REQUEST_SIZE:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request too large"}
            )
        
        return await call_next(request)


class SlowRequestLogMiddleware(BaseHTTPMiddleware):
    """Log slow requests"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        
        if duration > Constants.SLOW_REQUEST_THRESHOLD:
            request_id = getattr(request.state, 'request_id', 'unknown')
            logger.warning(
                f"Slow request: {request.method} {request.url.path} "
                f"took {duration:.2f}s (request_id: {request_id})"
            )
        
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    """Collect HTTP request metrics"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        endpoint = request.url.path
        method = request.method
        
        # Track concurrent requests
        concurrent_requests.inc()
        
        try:
            response = await call_next(request)
            status = response.status_code
            
            # Record metrics
            http_requests_total.labels(
                method=method,
                endpoint=endpoint,
                status=status
            ).inc()
            
            duration = time.time() - start_time
            http_request_duration_seconds.labels(
                method=method,
                endpoint=endpoint
            ).observe(duration)
            
            return response
            
        except Exception as e:
            # Record error
            http_requests_total.labels(
                method=method,
                endpoint=endpoint,
                status=500
            ).inc()
            
            duration = time.time() - start_time
            http_request_duration_seconds.labels(
                method=method,
                endpoint=endpoint
            ).observe(duration)
            
            raise
        finally:
            concurrent_requests.dec()


class GlobalExceptionMiddleware(BaseHTTPMiddleware):
    """Global exception handler"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            return await call_next(request)
        except Exception as exc:
            import traceback
            error_detail = f"Unhandled exception: {str(exc)}\n{traceback.format_exc()}"
            logger.error(error_detail)
            
            return JSONResponse(
                status_code=500,
                content={"detail": str(exc)}
            )


def setup_middleware(app) -> None:
    """
    Setup all middleware for the FastAPI app.
    
    Args:
        app: FastAPI application instance
    """
    # Order matters - middleware is executed in reverse order of addition
    
    # Global exception handler (outermost)
    app.add_middleware(GlobalExceptionMiddleware)
    
    # Metrics collection
    app.add_middleware(MetricsMiddleware)
    
    # Slow request logging
    app.add_middleware(SlowRequestLogMiddleware)
    
    # Request size limit
    app.add_middleware(RequestSizeLimitMiddleware)
    
    # Request ID
    app.add_middleware(RequestIdMiddleware)
    
    # Security headers (innermost)
    app.add_middleware(SecurityHeadersMiddleware)
    
    logger.info("All middleware configured")
