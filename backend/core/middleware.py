"""
Security and performance middleware for FastAPI application.
"""
import logging
from typing import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Request size limit (10 MB default)
MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10 MB in bytes


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.

    Implements OWASP security best practices for HTTP headers.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add security headers to response."""
        response = await call_next(request)

        # Prevent clickjacking attacks
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Enable XSS protection (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Strict Transport Security (HSTS) - 1 year
        # Only enable in production with HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Content Security Policy
        # Restrict resource loading to same origin
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        # Referrer policy - don't leak referrer
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy (formerly Feature-Policy)
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=()"
        )

        # Server identification - hide server details
        response.headers["Server"] = "AdversarialShield"

        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Limit request body size to prevent memory exhaustion attacks.

    Prevents DoS attacks through large file uploads or payloads.
    """

    def __init__(self, app, max_size: int = MAX_REQUEST_SIZE):
        """
        Initialize middleware.

        Args:
            app: FastAPI application
            max_size: Maximum request size in bytes (default: 10 MB)
        """
        super().__init__(app)
        self.max_size = max_size

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Check request size before processing."""
        # Get content length from headers
        content_length = request.headers.get("content-length")

        if content_length:
            try:
                content_length = int(content_length)

                if content_length > self.max_size:
                    logger.warning(
                        f"Request too large: {content_length} bytes (max: {self.max_size})"
                    )
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={
                            "detail": f"Request body too large. Maximum size: {self.max_size / (1024*1024):.1f} MB"
                        },
                    )
            except ValueError:
                # Invalid content-length header
                pass

        response = await call_next(request)
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log all requests for audit and debugging.

    Logs method, path, status code, and response time.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log request details."""
        import time

        # Start timing
        start_time = time.time()

        # Get client IP
        client_ip = request.client.host if request.client else "unknown"

        # Forward for proxy support
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()

        # Process request
        response = await call_next(request)

        # Calculate processing time
        process_time = (time.time() - start_time) * 1000  # Convert to ms

        # Add processing time header
        response.headers["X-Process-Time"] = f"{process_time:.2f}ms"

        # Log request
        logger.info(
            f"{request.method} {request.url.path} "
            f"- Status: {response.status_code} "
            f"- Time: {process_time:.2f}ms "
            f"- IP: {client_ip}"
        )

        return response


class CORSSecurityMiddleware(BaseHTTPMiddleware):
    """
    Enhanced CORS middleware with security checks.

    Validates origin against allowlist in production.
    """

    def __init__(self, app, allowed_origins: list = None):
        """
        Initialize CORS middleware.

        Args:
            app: FastAPI application
            allowed_origins: List of allowed origins (default: localhost only)
        """
        super().__init__(app)
        self.allowed_origins = allowed_origins or [
            "http://localhost:3000",
            "http://localhost:8000",
        ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add CORS headers with security checks."""
        origin = request.headers.get("origin")

        # Process request
        response = await call_next(request)

        # Check if origin is allowed
        if origin in self.allowed_origins or "*" in self.allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-API-Key"
            response.headers["Access-Control-Max-Age"] = "3600"
        else:
            # Origin not allowed, don't add CORS headers
            if origin:
                logger.warning(f"CORS request from unauthorized origin: {origin}")

        return response


class RateLimitExceededMiddleware(BaseHTTPMiddleware):
    """
    Add rate limit information to responses.

    Works with rate_limit.py token bucket implementation.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add rate limit headers."""
        response = await call_next(request)

        # Rate limit headers (if rate limiting is active)
        # These should be set by rate_limit.py middleware
        # This middleware just ensures they're present
        if "X-RateLimit-Limit" not in response.headers:
            response.headers["X-RateLimit-Limit"] = "100"

        if "X-RateLimit-Remaining" not in response.headers:
            response.headers["X-RateLimit-Remaining"] = "99"

        if "X-RateLimit-Reset" not in response.headers:
            import time

            response.headers["X-RateLimit-Reset"] = str(int(time.time()) + 60)

        return response
