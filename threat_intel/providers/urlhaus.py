"""URLhaus (abuse.ch) provider adapter for Module 3.

Supports URL lookups against the URLhaus malware URL database.

API documentation: https://urlhaus-api.abuse.ch/

Rate limits:
- No public rate limit documented; use responsibly
- Auth key provides higher limits and better support

Licensing / attribution:
- URLhaus data is under CC0 / public domain for lookup results.
- Attribution to abuse.ch is appreciated.

Environment variables:
    URLHAUS_AUTH_KEY  - URLhaus auth key (optional; improves rate limits)
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from ..schema import (
    make_disabled_result,
    make_not_configured_result,
    make_provider_result,
    make_unavailable_result,
)
from .base import (
    DEFAULT_READ_TIMEOUT,
    classify_http_error,
    get_api_key,
    is_threat_intel_enabled,
    make_session,
    safe_get_json,
)

LOGGER = logging.getLogger(__name__)
PROVIDER_NAME = "URLhaus"
BASE_URL = "https://urlhaus-api.abuse.ch/v1"

_session = make_session(retries=1)


def lookup_url(url: str) -> dict[str, Any]:
    """Look up a URL against the URLhaus malware URL database.

    NOTE: The URL itself is sent to URLhaus to perform the lookup.
    This is a passive lookup (no browser, no download).
    Set URLHAUS_AUTH_KEY for higher rate limits.
    """
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "url", url)
    key = get_api_key("URLHAUS_AUTH_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "url", url)
    headers: dict[str, str] = {"Auth-Key": key}
    try:
        response = _session.post(
            f"{BASE_URL}/url/",
            data={"url": url},
            headers=headers,
            timeout=DEFAULT_READ_TIMEOUT,
        )
        if response.status_code == 429:
            return make_unavailable_result(PROVIDER_NAME, "url", url, status="rate_limited")
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "url", url, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "url", url, status="malformed_response")
        query_status = str(data.get("query_status", "")).lower()
        if query_status in {"no_results", "is_offline"}:
            return make_provider_result(
                provider=PROVIDER_NAME, ioc_type="url", ioc_value=url,
                status="not_found", malicious=False, suspicious=False,
                extra={"query_status": query_status},
            )
        url_status = str(data.get("url_status", "")).lower()
        threat = data.get("threat") or None
        is_malicious = query_status in {"ok"} and url_status in {"online", "unknown"}
        is_suspicious = query_status in {"ok"} and url_status == "offline"
        tags = data.get("tags") or []
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="url",
            ioc_value=url,
            status="success",
            malicious=is_malicious,
            suspicious=is_suspicious,
            tags=tags if isinstance(tags, list) else [tags],
            report_url=data.get("urlhaus_reference"),
            extra={
                "query_status": query_status,
                "url_status": url_status,
                "threat": threat,
                "urlhaus_reference": data.get("urlhaus_reference"),
            },
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "url", url, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("URLhaus URL lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "url", url, status="request_error",
                                       error="Request failed")


def lookup_domain(domain: str) -> dict[str, Any]:
    """Look up a domain host against the URLhaus database."""
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "domain", domain)
    key = get_api_key("URLHAUS_AUTH_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "domain", domain)
    headers: dict[str, str] = {"Auth-Key": key}
    try:
        response = _session.post(
            f"{BASE_URL}/host/",
            data={"host": domain},
            headers=headers,
            timeout=DEFAULT_READ_TIMEOUT,
        )
        if response.status_code == 429:
            return make_unavailable_result(PROVIDER_NAME, "domain", domain, status="rate_limited")
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "domain", domain, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "domain", domain,
                                           status="malformed_response")
        query_status = str(data.get("query_status", "")).lower()
        if query_status == "no_results":
            return make_provider_result(
                provider=PROVIDER_NAME, ioc_type="domain", ioc_value=domain,
                status="not_found", malicious=False, suspicious=False,
            )
        urls = data.get("urls") or []
        active_count = sum(1 for u in urls if str(u.get("url_status", "")).lower() == "online")
        is_malicious = active_count > 0
        is_suspicious = (not is_malicious) and len(urls) > 0
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="domain",
            ioc_value=domain,
            status="success",
            malicious=is_malicious,
            suspicious=is_suspicious,
            extra={"total_urls": len(urls), "active_urls": active_count},
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "domain", domain, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("URLhaus domain lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "domain", domain, status="request_error",
                                       error="Request failed")
