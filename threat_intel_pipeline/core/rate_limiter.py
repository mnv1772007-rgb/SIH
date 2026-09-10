"""
Rate limiter with exponential backoff for API calls.
"""

import time
import threading
from typing import Dict, Optional
from collections import deque
from dataclasses import dataclass, field
from contextlib import contextmanager

from .config import get_config


@dataclass
class RateLimitState:
    requests: deque = field(default_factory=deque)
    last_request: float = 0.0
    consecutive_errors: int = 0
    backoff_until: float = 0.0


class TokenBucketRateLimiter:
    def __init__(self, rpm: int = 60, burst: int = None):
        self.rpm = rpm
        self.burst = burst or max(1, rpm // 10)
        self.tokens = float(self.burst)
        self.last_refill = time.time()
        self._lock = threading.Lock()

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * (self.rpm / 60.0))
        self.last_refill = now

    def acquire(self, tokens: int = 1, timeout: float = 30.0) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            with self._lock:
                self._refill()
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
            time.sleep(0.1)
        return False


class SlidingWindowRateLimiter:
    def __init__(self, rpm: int = 60):
        self.rpm = rpm
        self.window_seconds = 60.0
        self.requests = deque()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            with self._lock:
                now = time.time()
                while self.requests and self.requests[0] <= now - self.window_seconds:
                    self.requests.popleft()

                if len(self.requests) < self.rpm:
                    self.requests.append(now)
                    return True

                wait_time = self.requests[0] + self.window_seconds - now
            if wait_time > 0:
                time.sleep(min(wait_time, 0.5))
        return False


class AdaptiveRateLimiter:
    def __init__(self, source: str, base_rpm: int = 60):
        self.source = source
        self.base_rpm = base_rpm
        self.current_rpm = base_rpm
        self.state = RateLimitState()
        self._lock = threading.Lock()
        self.min_rpm = max(1, base_rpm // 10)
        self.max_rpm = base_rpm * 2

    def _calculate_backoff(self) -> float:
        return min(300, (2 ** self.state.consecutive_errors) * 1.5)

    def acquire(self, timeout: float = 60.0) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            with self._lock:
                now = time.time()

                if now < self.state.backoff_until:
                    wait = self.state.backoff_until - now
                    if wait > timeout:
                        return False
                    time.sleep(min(wait, 1.0))
                    continue

                while self.state.requests and self.state.requests[0] <= now - 60:
                    self.state.requests.popleft()

                if len(self.state.requests) < self.current_rpm:
                    self.state.requests.append(now)
                    self.state.last_request = now
                    return True

                if self.state.requests:
                    wait_time = self.state.requests[0] + 60 - now
                else:
                    wait_time = 60 / self.current_rpm

            time.sleep(min(wait_time, 1.0))

        return False

    def record_success(self):
        with self._lock:
            self.state.consecutive_errors = 0
            if self.current_rpm < self.base_rpm:
                self.current_rpm = min(self.base_rpm, self.current_rpm + 1)

    def record_error(self, is_rate_limit: bool = False):
        with self._lock:
            self.state.consecutive_errors += 1
            if is_rate_limit:
                self.current_rpm = max(self.min_rpm, self.current_rpm // 2)
                self.state.backoff_until = time.time() + self._calculate_backoff()
            elif self.state.consecutive_errors >= 3:
                self.current_rpm = max(self.min_rpm, self.current_rpm - 1)


class RateLimiterRegistry:
    def __init__(self):
        self._limiters: Dict[str, AdaptiveRateLimiter] = {}
        self._lock = threading.Lock()
        self.config = get_config()

    def get_limiter(self, source: str) -> AdaptiveRateLimiter:
        with self._lock:
            if source not in self._limiters:
                rpm_map = {
                    "virustotal": self.config.rate_limit.virustotal_rpm,
                    "abuseipdb": self.config.rate_limit.abuseipdb_rpm,
                    "urlhaus": self.config.rate_limit.urlhaus_rpm,
                    "phishtank": self.config.rate_limit.phishtank_rpm,
                    "alienvault_otx": self.config.rate_limit.alienvault_rpm,
                    "misp": self.config.rate_limit.misp_rpm,
                    "greynoise": self.config.rate_limit.greynoise_rpm,
                    "ipinfo": self.config.rate_limit.ipinfo_rpm,
                    "dns": 100,
                    "rdap": 60,
                    "whois": 30,
                }
                rpm = rpm_map.get(source, self.config.rate_limit.default_rpm)
                self._limiters[source] = AdaptiveRateLimiter(source, rpm)
            return self._limiters[source]

    def acquire(self, source: str, timeout: float = 60.0) -> bool:
        return self.get_limiter(source).acquire(timeout)

    def record_success(self, source: str):
        self.get_limiter(source).record_success()

    def record_error(self, source: str, is_rate_limit: bool = False):
        self.get_limiter(source).record_error(is_rate_limit)

    def get_stats(self) -> Dict[str, Dict]:
        with self._lock:
            return {
                source: {
                    "current_rpm": limiter.current_rpm,
                    "base_rpm": limiter.base_rpm,
                    "consecutive_errors": limiter.state.consecutive_errors,
                    "pending_requests": len(limiter.state.requests),
                    "backoff_until": limiter.state.backoff_until
                }
                for source, limiter in self._limiters.items()
            }


_global_registry: Optional[RateLimiterRegistry] = None


def get_rate_limiter() -> RateLimiterRegistry:
    global _global_registry
    if _global_registry is None:
        _global_registry = RateLimiterRegistry()
    return _global_registry


@contextmanager
def rate_limited(source: str, timeout: float = 60.0):
    limiter = get_rate_limiter()
    acquired = limiter.acquire(source, timeout)
    if not acquired:
        raise TimeoutError(f"Rate limit timeout for {source}")
    try:
        yield
        limiter.record_success(source)
    except Exception as e:
        is_rate_limit = "429" in str(e) or "rate limit" in str(e).lower()
        limiter.record_error(source, is_rate_limit)
        raise