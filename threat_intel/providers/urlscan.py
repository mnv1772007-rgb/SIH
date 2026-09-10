"""URLScan.io provider adapter for Module 3: Threat Intelligence & Data.

Supports passive historical searches only:
- Domain historical scans
- URL historical scans

CRITICAL: Never creates or submits new scans (passive search only) to prevent
leaking private or sensitive URLs to third parties.

API documentation: https://urlscan.io/docs/api/

Rate limits (free tier):
- Search API: 60 requests per minute
- Public scans search only

Environment variables:
    URLSCAN_API_KEY  - URLScan.io API key
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import requests

from ..schema import (
    make_disabled_result,
    make_not_configured_result,
    make_provider_result,
    make_unavailable_result,
)
from .base import (
    classify_http_error,
    get_api_key,
    is_threat_intel_enabled,
    make_session,
    safe_get_json,
)

LOGGER = logging.getLogger(__name__)
PROVIDER_NAME = "URLScan"
BASE_URL = "https://urlscan.io/api/v1/search"

_session = make_session(retries=1)


def _headers() -> dict[str, str]:
    key = get_api_key("URLSCAN_API_KEY")
    if not key:
        return {}
    return {"API-Key": key, "Accept": "application/json"}


def lookup_domain(domain: str) -> dict[str, Any]:
    """Search URLScan historical records for a domain."""
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "domain", domain)

    key = get_api_key("URLSCAN_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "domain", domain)

    query = f"page.domain:{domain}"
    try:
        response = _session.get(
            BASE_URL,
            headers=_headers(),
            params={"q": query, "size": 10},
            timeout=12,
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "domain", domain, "timeout", "Request timed out")
    except requests.RequestException as exc:
        return make_unavailable_result(PROVIDER_NAME, "domain", domain, "request_error", str(exc))

    if response.status_code != 200:
        status = classify_http_error(response)
        return make_unavailable_result(PROVIDER_NAME, "domain", domain, status, f"HTTP {response.status_code}")

    data = safe_get_json(response)
    if not data:
        return make_unavailable_result(
            PROVIDER_NAME, "domain", domain, "malformed_response", "Empty or invalid JSON response"
        )

    total = int(data.get("total", 0) or 0)
    results = data.get("results") or []

    if total == 0 or not results:
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="domain",
            ioc_value=domain,
            status="not_found",
            malicious=False,
            suspicious=False,
            confidence=0.0,
            tags=["no_historical_scans"],
            extra={"total": 0, "results": []},
        )

    # Inspect verdicts in the recent scans
    malicious_votes = 0
    suspicious_votes = 0
    categories: set[str] = set()
    first_seen: str | None = None
    last_seen: str | None = None

    for entry in results:
        verdicts = entry.get("verdicts", {})
        overall = verdicts.get("overall", {})
        if overall.get("malicious"):
            malicious_votes += 1
        elif overall.get("score", 0) > 50:
            suspicious_votes += 1

        for cat in overall.get("categories", []):
            categories.add(str(cat))

        task = entry.get("task", {})
        scan_time = task.get("time")
        if scan_time:
            if not last_seen or scan_time > last_seen:
                last_seen = scan_time
            if not first_seen or scan_time < first_seen:
                first_seen = scan_time

    is_malicious = malicious_votes > 0
    is_suspicious = not is_malicious and (suspicious_votes > 0)
    confidence = min(1.0, (malicious_votes * 0.4) + (0.5 if is_malicious else 0.2)) if is_malicious else 0.3

    tags = [f"historical_scans:{total}"]
    if is_malicious:
        tags.append("flagged_malicious_scan")

    report_url = results[0].get("result") if results else None

    return make_provider_result(
        provider=PROVIDER_NAME,
        ioc_type="domain",
        ioc_value=domain,
        status="success",
        malicious=is_malicious,
        suspicious=is_suspicious,
        confidence=confidence,
        categories=list(categories),
        tags=tags,
        first_seen=first_seen,
        last_seen=last_seen,
        report_url=report_url,
        extra={"total": total, "results_sample": results[:3]},
    )


def lookup_url(url: str) -> dict[str, Any]:
    """Search URLScan historical records for a URL."""
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "url", url)

    key = get_api_key("URLSCAN_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "url", url)

    query = f'page.url:"{url}"'
    try:
        response = _session.get(
            BASE_URL,
            headers=_headers(),
            params={"q": query, "size": 10},
            timeout=12,
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "url", url, "timeout", "Request timed out")
    except requests.RequestException as exc:
        return make_unavailable_result(PROVIDER_NAME, "url", url, "request_error", str(exc))

    if response.status_code != 200:
        status = classify_http_error(response)
        return make_unavailable_result(PROVIDER_NAME, "url", url, status, f"HTTP {response.status_code}")

    data = safe_get_json(response)
    if not data:
        return make_unavailable_result(
            PROVIDER_NAME, "url", url, "malformed_response", "Empty or invalid JSON response"
        )

    total = int(data.get("total", 0) or 0)
    results = data.get("results") or []

    if total == 0 or not results:
        # Fallback to domain search if URL had no exact matches
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0] if parsed.netloc else None
        if domain:
            dom_res = lookup_domain(domain)
            dom_res["ioc"]["type"] = "url"
            dom_res["ioc"]["value"] = url
            return dom_res

        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="url",
            ioc_value=url,
            status="not_found",
            malicious=False,
            suspicious=False,
            confidence=0.0,
            tags=["no_historical_scans"],
            extra={"total": 0, "results": []},
        )

    malicious_votes = sum(
        1 for entry in results if entry.get("verdicts", {}).get("overall", {}).get("malicious")
    )
    is_malicious = malicious_votes > 0
    confidence = min(1.0, 0.5 + (malicious_votes * 0.25)) if is_malicious else 0.3

    report_url = results[0].get("result") if results else None

    return make_provider_result(
        provider=PROVIDER_NAME,
        ioc_type="url",
        ioc_value=url,
        status="success",
        malicious=is_malicious,
        suspicious=False,
        confidence=confidence,
        tags=[f"historical_scans:{total}"],
        report_url=report_url,
        extra={"total": total, "results_sample": results[:3]},
    )
