"""Shared HTTP request utilities for threat intelligence provider adapters.

Provides:
- A centralized requests.Session with timeouts and retry headers
- Configuration flag checking utilities
- Safe JSON parsing that never raises on malformed provider responses
- Rate limit detection helpers
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

LOGGER = logging.getLogger(__name__)

# Default HTTP timeouts (connect, read) in seconds
DEFAULT_CONNECT_TIMEOUT = 5
DEFAULT_READ_TIMEOUT = 12


def is_threat_intel_enabled() -> bool:
    """Return True if threat intelligence lookups are globally enabled."""
    return os.getenv("THREAT_INTELLIGENCE_ENABLED", "true").lower() == "true"


def get_api_key(env_var: str) -> str | None:
    """Return an API key from the environment, or None if absent/empty."""
    value = os.getenv(env_var, "").strip()
    return value if value else None


def make_session(
    retries: int = 2,
    backoff_factor: float = 0.5,
    status_forcelist: tuple[int, ...] = (500, 502, 503, 504),
) -> requests.Session:
    """Create a requests.Session with retry logic and timeout defaults."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def safe_get_json(response: requests.Response) -> dict[str, Any] | None:
    """Safely parse a JSON response; return None if malformed."""
    try:
        data = response.json()
        if not isinstance(data, (dict, list)):
            LOGGER.debug("Provider returned unexpected JSON type: %s", type(data).__name__)
            return None
        return data  # type: ignore[return-value]
    except (ValueError, requests.JSONDecodeError):
        LOGGER.debug("Provider response is not valid JSON (status=%d)", response.status_code)
        return None


def classify_http_error(response: requests.Response | int) -> str:
    """Map an HTTP error status code to a canonical provider status string."""
    code = response.status_code if hasattr(response, "status_code") else int(response)
    if code in (401, 403):
        return "unauthorized"
    if code == 404:
        return "not_found"
    if code == 429:
        return "rate_limited"
    if code >= 500:
        return "unavailable"
    return "request_error"

