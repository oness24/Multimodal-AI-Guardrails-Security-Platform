"""
Caching utilities for performance optimization.

Implements Redis-based caching with fallback to in-memory cache.
"""
import hashlib
import json
import logging
from functools import wraps
from typing import Any, Callable, Optional

import redis
from backend.core.config import settings

logger = logging.getLogger(__name__)


class CacheBackend:
    """Abstract cache backend."""

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        raise NotImplementedError

    async def set(self, key: str, value: Any, ttl: int = 3600):
        """Set value in cache with TTL in seconds."""
        raise NotImplementedError

    async def delete(self, key: str):
        """Delete key from cache."""
        raise NotImplementedError

    async def clear(self):
        """Clear all cache."""
        raise NotImplementedError


class RedisCache(CacheBackend):
    """Redis cache backend."""

    def __init__(self):
        """Initialize Redis connection."""
        try:
            self.redis = redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            # Test connection
            self.redis.ping()
            self.available = True
            logger.info("Redis cache initialized successfully")
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"Redis connection failed: {e}. Falling back to in-memory cache.")
            self.available = False

    async def get(self, key: str) -> Optional[Any]:
        """Get value from Redis."""
        if not self.available:
            return None

        try:
            value = self.redis.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error(f"Error getting from Redis: {e}")
            return None

    async def set(self, key: str, value: Any, ttl: int = 3600):
        """Set value in Redis with TTL."""
        if not self.available:
            return

        try:
            serialized = json.dumps(value)
            self.redis.setex(key, ttl, serialized)
        except Exception as e:
            logger.error(f"Error setting in Redis: {e}")

    async def delete(self, key: str):
        """Delete key from Redis."""
        if not self.available:
            return

        try:
            self.redis.delete(key)
        except Exception as e:
            logger.error(f"Error deleting from Redis: {e}")

    async def clear(self):
        """Clear all keys from Redis."""
        if not self.available:
            return

        try:
            self.redis.flushdb()
            logger.info("Redis cache cleared")
        except Exception as e:
            logger.error(f"Error clearing Redis: {e}")


class InMemoryCache(CacheBackend):
    """In-memory cache backend (fallback)."""

    def __init__(self):
        """Initialize in-memory cache."""
        self._cache: dict = {}
        logger.info("In-memory cache initialized")

    async def get(self, key: str) -> Optional[Any]:
        """Get value from memory."""
        return self._cache.get(key)

    async def set(self, key: str, value: Any, ttl: int = 3600):
        """Set value in memory (TTL not implemented for simplicity)."""
        self._cache[key] = value

    async def delete(self, key: str):
        """Delete key from memory."""
        self._cache.pop(key, None)

    async def clear(self):
        """Clear all cache."""
        self._cache.clear()
        logger.info("In-memory cache cleared")


class Cache:
    """
    Unified cache interface with automatic fallback.

    Tries Redis first, falls back to in-memory cache.
    """

    def __init__(self):
        """Initialize cache with Redis and in-memory fallback."""
        self.redis_cache = RedisCache()
        self.memory_cache = InMemoryCache()

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None
        """
        # Try Redis first
        value = await self.redis_cache.get(key)
        if value is not None:
            return value

        # Fall back to memory
        return await self.memory_cache.get(key)

    async def set(self, key: str, value: Any, ttl: int = 3600):
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds
        """
        # Set in both Redis and memory
        await self.redis_cache.set(key, value, ttl)
        await self.memory_cache.set(key, value, ttl)

    async def delete(self, key: str):
        """
        Delete key from cache.

        Args:
            key: Cache key
        """
        await self.redis_cache.delete(key)
        await self.memory_cache.delete(key)

    async def clear(self):
        """Clear all cache."""
        await self.redis_cache.clear()
        await self.memory_cache.clear()


# Global cache instance
cache = Cache()


def cache_key(*args, **kwargs) -> str:
    """
    Generate cache key from arguments.

    Args:
        *args: Positional arguments
        **kwargs: Keyword arguments

    Returns:
        Cache key string
    """
    # Create stable string from args
    key_parts = [str(arg) for arg in args]

    # Add sorted kwargs
    for k, v in sorted(kwargs.items()):
        key_parts.append(f"{k}={v}")

    # Hash to fixed length
    key_str = "|".join(key_parts)
    return hashlib.sha256(key_str.encode()).hexdigest()


def cached(ttl: int = 3600, key_prefix: str = ""):
    """
    Decorator to cache function results.

    Args:
        ttl: Time-to-live in seconds (default: 1 hour)
        key_prefix: Prefix for cache key

    Returns:
        Decorated function

    Example:
        @cached(ttl=300, key_prefix="scan")
        async def scan_code(code: str):
            # Expensive operation
            return result
    """

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            func_name = f"{func.__module__}.{func.__name__}"
            key = f"{key_prefix}:{func_name}:{cache_key(*args, **kwargs)}"

            # Try to get from cache
            cached_value = await cache.get(key)
            if cached_value is not None:
                logger.debug(f"Cache hit: {key}")
                return cached_value

            # Execute function
            logger.debug(f"Cache miss: {key}")
            result = await func(*args, **kwargs)

            # Store in cache
            await cache.set(key, result, ttl)

            return result

        return wrapper

    return decorator


def invalidate_cache(key_pattern: str):
    """
    Invalidate cache entries matching pattern.

    Args:
        key_pattern: Pattern to match keys

    Note: This is a simple implementation. For production,
    consider using Redis SCAN for pattern matching.
    """

    async def _invalidate():
        # For now, just clear all
        # In production, implement pattern matching
        await cache.clear()

    return _invalidate


# Example usage:
# @cached(ttl=300, key_prefix="vulnerability_scan")
# async def scan_code(code: str) -> dict:
#     # Expensive scanning operation
#     return {"vulnerabilities": []}
