"""In-memory TTL cache for threat intelligence results.

Prevents redundant API calls for the same IOC within a configurable
time window. Does NOT cache failure results indefinitely — providers
being unavailable, rate-limited, or timing out are cached with a much
shorter TTL so they can be retried sooner.

Cache key format:
    threatintel:{ioc_type}:{normalized_ioc_value}:{provider_name}

When a cached result is returned, the ``cached`` field is set to True
and ``queried_at`` reflects the original query time.
"""

from __future__ import annotations

import logging
import time
from copy import deepcopy
from typing import Any

LOGGER = logging.getLogger(__name__)

# Default TTL values (seconds)
DEFAULT_SUCCESS_TTL: int = 3600       # 1 hour for successful results
DEFAULT_NOT_FOUND_TTL: int = 1800     # 30 min for confirmed "not found"
DEFAULT_FAILURE_TTL: int = 120        # 2 min for errors/timeouts/rate limits
DEFAULT_DISABLED_TTL: int = 86400     # 24 hours for disabled/not_configured

# Statuses considered "non-cacheable failures" with short TTL
_SHORT_TTL_STATUSES = {"timeout", "rate_limited", "request_error", "unavailable"}
_LONG_DISABLED_STATUSES = {"disabled", "not_configured", "not_applicable"}


class ThreatIntelCache:
    """Thread-unsafe in-process TTL cache for threat intelligence results.

    For production deployments with multiple workers, replace with a
    Redis-backed implementation using the same interface.
    """

    def __init__(
        self,
        success_ttl: int = DEFAULT_SUCCESS_TTL,
        not_found_ttl: int = DEFAULT_NOT_FOUND_TTL,
        failure_ttl: int = DEFAULT_FAILURE_TTL,
        disabled_ttl: int = DEFAULT_DISABLED_TTL,
        max_entries: int = 10_000,
    ) -> None:
        self._store: dict[str, tuple[float, dict[str, Any]]] = {}
        self._success_ttl = success_ttl
        self._not_found_ttl = not_found_ttl
        self._failure_ttl = failure_ttl
        self._disabled_ttl = disabled_ttl
        self._max_entries = max_entries

    def _make_key(self, ioc_type: str, ioc_value: str, provider: str) -> str:
        """Build a deterministic cache key."""
        return f"threatintel:{ioc_type.lower()}:{ioc_value.lower()}:{provider.lower()}"

    def _ttl_for_status(self, status: str) -> int:
        if status in _SHORT_TTL_STATUSES:
            return self._failure_ttl
        if status in _LONG_DISABLED_STATUSES:
            return self._disabled_ttl
        if status == "not_found":
            return self._not_found_ttl
        if status == "success":
            return self._success_ttl
        return self._failure_ttl

    def get(self, ioc_type: str, ioc_value: str, provider: str) -> dict[str, Any] | None:
        """Return a cached result if present and not expired, else None."""
        key = self._make_key(ioc_type, ioc_value, provider)
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, result = entry
        if time.monotonic() > expires_at:
            del self._store[key]
            return None
        cached = deepcopy(result)
        cached["cached"] = True
        return cached

    def set(self, ioc_type: str, ioc_value: str, provider: str, result: dict[str, Any]) -> None:
        """Store a result in the cache with appropriate TTL."""
        if len(self._store) >= self._max_entries:
            self._evict_expired()
        key = self._make_key(ioc_type, ioc_value, provider)
        status = str(result.get("status", ""))
        ttl = self._ttl_for_status(status)
        expires_at = time.monotonic() + ttl
        self._store[key] = (expires_at, deepcopy(result))
        LOGGER.debug("Cached %s/%s/%s (TTL=%ds)", ioc_type, ioc_value, provider, ttl)

    def _evict_expired(self) -> None:
        """Remove all expired entries."""
        now = time.monotonic()
        expired = [k for k, (exp, _) in self._store.items() if now > exp]
        for key in expired:
            del self._store[key]

    def invalidate(self, ioc_type: str, ioc_value: str, provider: str) -> bool:
        """Manually invalidate a specific cache entry. Returns True if removed."""
        key = self._make_key(ioc_type, ioc_value, provider)
        if key in self._store:
            del self._store[key]
            return True
        return False

    def clear(self) -> None:
        """Clear the entire cache."""
        self._store.clear()

    @property
    def size(self) -> int:
        """Number of entries in the cache (including expired)."""
        return len(self._store)

    def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        self._evict_expired()
        return {
            "total_entries": len(self._store),
            "max_entries": self._max_entries,
        }


# Module-level shared cache instance used by all providers
_shared_cache = ThreatIntelCache()


def get_shared_cache() -> ThreatIntelCache:
    """Return the module-level shared cache instance."""
    return _shared_cache
