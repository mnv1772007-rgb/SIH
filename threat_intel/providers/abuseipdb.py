"""AbuseIPDB API v2 provider adapter for Module 3.

Supports IP address reputation lookups only.

API documentation: https://docs.abuseipdb.com/

Rate limits (free tier):
- 1,000 checks per day
- 15 reports per 15 minutes (reporting; not used here)

Licensing / attribution:
- AbuseIPDB data attribution required when displaying results.
- Data may not be bulk-redistributed.

Environment variables:
    ABUSEIPDB_API_KEY  - AbuseIPDB API key
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
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
PROVIDER_NAME = "AbuseIPDB"
BASE_URL = "https://api.abuseipdb.com/api/v2"
MAX_AGE_DAYS = 90

_session = make_session(retries=1)


def lookup_ip(ip: str) -> dict[str, Any]:
    """Look up an IP address on AbuseIPDB.

    The confidence score ranges 0–100. We classify as:
    - malicious: score >= 50 (per AbuseIPDB's own recommendation)
    - suspicious: score >= 25 and < 50
    - no threat detected: score < 25

    IMPORTANT: This is an evidence signal, not a definitive verdict.
    A high abuse score may reflect shared hosting, VPN exits, or
    legitimate infrastructure with one past abuse report.
    """
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "ip", ip)
    key = get_api_key("ABUSEIPDB_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "ip", ip)
    try:
        response = _session.get(
            f"{BASE_URL}/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS},
            timeout=DEFAULT_READ_TIMEOUT,
        )
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "ip", ip, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "ip", ip, status="malformed_response")
        d = data.get("data", {})
        score: int = int(d.get("abuseConfidenceScore") or 0)
        is_malicious = score >= 50
        is_suspicious = (not is_malicious) and score >= 25
        confidence = round(score / 100.0, 3)
        usage_type = d.get("usageType") or None
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="ip",
            ioc_value=ip,
            status="success",
            malicious=is_malicious,
            suspicious=is_suspicious,
            confidence=confidence,
            reputation=-score,  # negative = bad (convention: lower is worse)
            country_code=d.get("countryCode"),
            isp=d.get("isp"),
            organization=d.get("domain"),
            tags=[usage_type] if usage_type else [],
            extra={
                "abuse_confidence_score": score,
                "total_reports": d.get("totalReports", 0),
                "distinct_users": d.get("numDistinctUsers", 0),
                "last_reported_at": d.get("lastReportedAt"),
                "is_tor": d.get("isTor", False),
                "is_whitelisted": d.get("isWhitelisted", False),
                "usage_type": usage_type,
            },
            queried_at=datetime.now(timezone.utc).isoformat(),
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "ip", ip, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("AbuseIPDB lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "ip", ip, status="request_error",
                                       error="Request failed")
