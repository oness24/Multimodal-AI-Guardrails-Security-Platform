"""
Rate limiting middleware and utilities.

Implements token bucket algorithm for API rate limiting.
"""
import logging
import time
from collections import defaultdict
from typing import Callable, Optional

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware

from backend.core.config import settings

logger = logging.getLogger(__name__)


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.

        Args:
            capacity: Maximum number of tokens
            refill_rate: Tokens per second refill rate
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()

    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens were consumed, False otherwise
        """
        # Refill tokens based on time passed
        now = time.time()
        time_passed = now - self.last_refill
        refill_amount = time_passed * self.refill_rate

        self.tokens = min(self.capacity, self.tokens + refill_amount)
        self.last_refill = now

        # Try to consume
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True

        return False

    def get_retry_after(self) -> float:
        """
        Get seconds until next token available.

        Returns:
            Seconds to wait
        """
        if self.tokens >= 1:
            return 0.0

        tokens_needed = 1 - self.tokens
        return tokens_needed / self.refill_rate


class RateLimiter:
    """
    Global rate limiter.

    Tracks rate limits per identifier (IP, user, API key).
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        burst_size: Optional[int] = None,
    ):
        """
        Initialize rate limiter.

        Args:
            requests_per_minute: Requests allowed per minute
            burst_size: Maximum burst size (defaults to requests_per_minute)
        """
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size or requests_per_minute
        self.refill_rate = requests_per_minute / 60.0  # per second
        self.buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(self.burst_size, self.refill_rate)
        )

    def check_limit(self, identifier: str, tokens: int = 1) -> tuple[bool, Optional[float]]:
        """
        Check if request is allowed.

        Args:
            identifier: Unique identifier (IP, user ID, etc.)
            tokens: Number of tokens to consume

        Returns:
            Tuple of (allowed, retry_after_seconds)
        """
        bucket = self.buckets[identifier]

        if bucket.consume(tokens):
            return True, None

        retry_after = bucket.get_retry_after()
        return False, retry_after

    def reset(self, identifier: str):
        """Reset rate limit for identifier."""
        if identifier in self.buckets:
            del self.buckets[identifier]


# Global rate limiter
rate_limiter = RateLimiter(
    requests_per_minute=settings.rate_limit_per_minute,
    burst_size=settings.rate_limit_per_minute * 2,  # Allow 2x burst
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for rate limiting.

    Limits requests based on IP address or authenticated user.
    """

    def __init__(self, app, rate_limiter: RateLimiter):
        """
        Initialize middleware.

        Args:
            app: FastAPI app
            rate_limiter: Rate limiter instance
        """
        super().__init__(app)
        self.rate_limiter = rate_limiter

    async def dispatch(self, request: Request, call_next: Callable):
        """
        Process request with rate limiting.

        Args:
            request: HTTP request
            call_next: Next middleware

        Returns:
            HTTP response
        """
        # Skip rate limiting for health check
        if request.url.path in ["/health", "/", "/docs", "/openapi.json"]:
            return await call_next(request)

        # Get identifier (IP or user)
        identifier = self._get_identifier(request)

        # Check rate limit
        allowed, retry_after = self.rate_limiter.check_limit(identifier)

        if not allowed:
            logger.warning(f"Rate limit exceeded for {identifier}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(int(retry_after or 60))},
            )

        # Add rate limit headers
        response = await call_next(request)

        # Could add X-RateLimit-* headers here
        response.headers["X-RateLimit-Limit"] = str(self.rate_limiter.requests_per_minute)

        return response

    def _get_identifier(self, request: Request) -> str:
        """
        Get unique identifier for rate limiting.

        Args:
            request: HTTP request

        Returns:
            Identifier string
        """
        # Try to get user from auth (if implemented)
        # For now, use IP address

        # Get real IP (considering proxies)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
        else:
            ip = request.client.host if request.client else "unknown"

        return f"ip:{ip}"


def rate_limit(requests_per_minute: int = 60):
    """
    Decorator for route-specific rate limiting.

    Args:
        requests_per_minute: Requests allowed per minute

    Returns:
        Decorator function

    Example:
        @router.post("/expensive-operation")
        @rate_limit(requests_per_minute=10)
        async def expensive_operation():
            pass
    """
    limiter = RateLimiter(requests_per_minute=requests_per_minute)

    def decorator(func: Callable):
        async def wrapper(request: Request, *args, **kwargs):
            identifier = f"ip:{request.client.host if request.client else 'unknown'}"

            allowed, retry_after = limiter.check_limit(identifier)

            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Max {requests_per_minute} requests per minute.",
                    headers={"Retry-After": str(int(retry_after or 60))},
                )

            return await func(request, *args, **kwargs)

        return wrapper

    return decorator
