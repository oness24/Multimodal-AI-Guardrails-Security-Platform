"""
Performance cache for guardrails detection.
"""
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Cache entry with TTL support."""

    key: str
    value: Any
    timestamp: float
    ttl: int  # Time to live in seconds
    hits: int = 0

    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        return (time.time() - self.timestamp) > self.ttl

    def record_hit(self) -> None:
        """Record a cache hit."""
        self.hits += 1


class PerformanceCache:
    """
    Performance cache for guardrails detection results.

    Caches detection results to avoid redundant processing.
    Uses LRU eviction and TTL expiration.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize performance cache.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.max_size = self.config.get("max_size", 1000)
        self.default_ttl = self.config.get("default_ttl", 300)  # 5 minutes
        self.enabled = self.config.get("enabled", True)

        self.cache: Dict[str, CacheEntry] = {}
        self.access_order = []  # For LRU

        # Statistics
        self.total_requests = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.evictions = 0

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        if not self.enabled:
            return None

        self.total_requests += 1

        if key not in self.cache:
            self.cache_misses += 1
            return None

        entry = self.cache[key]

        # Check if expired
        if entry.is_expired():
            self._remove(key)
            self.cache_misses += 1
            return None

        # Record hit and update access order
        entry.record_hit()
        self._update_access(key)
        self.cache_hits += 1

        logger.debug(f"Cache hit: {key[:20]}...")
        return entry.value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (uses default if not specified)
        """
        if not self.enabled:
            return

        # Check if we need to evict
        if key not in self.cache and len(self.cache) >= self.max_size:
            self._evict_lru()

        # Create or update entry
        entry = CacheEntry(
            key=key,
            value=value,
            timestamp=time.time(),
            ttl=ttl or self.default_ttl,
            hits=0,
        )

        self.cache[key] = entry
        self._update_access(key)

        logger.debug(f"Cache set: {key[:20]}...")

    def cache_detection_result(
        self,
        text: str,
        detector_type: str,
        result: Any,
        ttl: Optional[int] = None,
    ) -> None:
        """
        Cache detection result.

        Args:
            text: Input text
            detector_type: Type of detector
            result: Detection result
            ttl: Time to live
        """
        key = self._generate_detection_key(text, detector_type)
        self.set(key, result, ttl)

    def get_detection_result(
        self, text: str, detector_type: str
    ) -> Optional[Any]:
        """
        Get cached detection result.

        Args:
            text: Input text
            detector_type: Type of detector

        Returns:
            Cached result or None
        """
        key = self._generate_detection_key(text, detector_type)
        return self.get(key)

    def _generate_detection_key(self, text: str, detector_type: str) -> str:
        """
        Generate cache key for detection.

        Args:
            text: Input text
            detector_type: Detector type

        Returns:
            Cache key
        """
        # Use hash of text to avoid storing large keys
        text_hash = hashlib.sha256(text.encode()).hexdigest()
        return f"{detector_type}:{text_hash}"

    def _update_access(self, key: str) -> None:
        """Update access order for LRU."""
        if key in self.access_order:
            self.access_order.remove(key)
        self.access_order.append(key)

    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self.access_order:
            return

        lru_key = self.access_order[0]
        self._remove(lru_key)
        self.evictions += 1
        logger.debug(f"Cache evicted: {lru_key[:20]}...")

    def _remove(self, key: str) -> None:
        """Remove entry from cache."""
        if key in self.cache:
            del self.cache[key]
        if key in self.access_order:
            self.access_order.remove(key)

    def clear(self) -> None:
        """Clear all cache entries."""
        self.cache = {}
        self.access_order = []
        logger.info("Cache cleared")

    def cleanup_expired(self) -> int:
        """
        Remove all expired entries.

        Returns:
            Number of entries removed
        """
        expired_keys = [
            key for key, entry in self.cache.items() if entry.is_expired()
        ]

        for key in expired_keys:
            self._remove(key)

        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")

        return len(expired_keys)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Statistics dictionary
        """
        hit_rate = (
            self.cache_hits / self.total_requests if self.total_requests > 0 else 0
        )

        return {
            "enabled": self.enabled,
            "total_requests": self.total_requests,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate": round(hit_rate, 3),
            "current_size": len(self.cache),
            "max_size": self.max_size,
            "evictions": self.evictions,
            "fill_rate": round(len(self.cache) / self.max_size, 3),
        }

    def get_entry_stats(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get statistics for specific cache entry.

        Args:
            key: Cache key

        Returns:
            Entry statistics or None
        """
        if key not in self.cache:
            return None

        entry = self.cache[key]
        age = time.time() - entry.timestamp

        return {
            "hits": entry.hits,
            "age_seconds": round(age, 2),
            "ttl": entry.ttl,
            "expires_in": round(entry.ttl - age, 2),
            "is_expired": entry.is_expired(),
        }

    def resize(self, new_size: int) -> None:
        """
        Resize cache.

        Args:
            new_size: New maximum size
        """
        self.max_size = new_size

        # Evict if necessary
        while len(self.cache) > self.max_size:
            self._evict_lru()

        logger.info(f"Cache resized to {new_size}")

    def set_ttl(self, new_ttl: int) -> None:
        """
        Set default TTL.

        Args:
            new_ttl: New default TTL in seconds
        """
        self.default_ttl = new_ttl
        logger.info(f"Cache TTL set to {new_ttl} seconds")

    def enable(self) -> None:
        """Enable caching."""
        self.enabled = True
        logger.info("Cache enabled")

    def disable(self) -> None:
        """Disable caching."""
        self.enabled = False
        logger.info("Cache disabled")

    def reset_statistics(self) -> None:
        """Reset cache statistics."""
        self.total_requests = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.evictions = 0
        logger.info("Cache statistics reset")


# Global cache instance (singleton pattern)
_global_cache: Optional[PerformanceCache] = None


def get_global_cache() -> PerformanceCache:
    """Get or create global cache instance."""
    global _global_cache
    if _global_cache is None:
        _global_cache = PerformanceCache()
    return _global_cache


def configure_global_cache(config: Dict[str, Any]) -> None:
    """Configure global cache with custom settings."""
    global _global_cache
    _global_cache = PerformanceCache(config)
    logger.info("Global cache configured")
