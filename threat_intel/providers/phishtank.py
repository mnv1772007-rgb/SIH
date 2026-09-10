"""PhishTank provider adapter for Module 3.

IMPORTANT: PhishTank requires operators to explicitly opt in because
querying PhishTank sends the URL to their servers. This may expose
the indicator being analyzed to a third party.

Set both PHISHTANK_ENABLED=true AND THREAT_INTELLIGENCE_ENABLED=true
to enable this provider.

API documentation: https://www.phishtank.com/api_info.php

Rate limits (free tier):
- ~10 requests/minute without app_key
- Higher limits with a registered app_key

Licensing / attribution:
- PhishTank data is under CC BY-SA 3.0.
- Results must be attributed to PhishTank if displayed.

Environment variables:
    PHISHTANK_ENABLED   - Must be 'true' to enable (privacy protection)
    PHISHTANK_API_KEY   - Optional app key for higher rate limits
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests

from ..schema import (
    make_disabled_result,
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
PROVIDER_NAME = "PhishTank"
CHECK_URL = "https://checkurl.phishtank.com/checkurl/"

_session = make_session(retries=0)  # No retry - each call sends the URL


def _is_phishtank_enabled() -> bool:
    return os.getenv("PHISHTANK_ENABLED", "false").lower() == "true"


def lookup_url(url: str) -> dict[str, Any]:
    """Check a URL against PhishTank's database.

    This operation sends the URL to PhishTank. Only enable when the
    operator has explicitly set PHISHTANK_ENABLED=true to acknowledge
    this privacy consideration.
    """
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "url", url)
    if not _is_phishtank_enabled():
        return make_disabled_result(
            PROVIDER_NAME, "url", url,
            reason="Set PHISHTANK_ENABLED=true to permit URL sharing with PhishTank.",
        )
    payload: dict[str, str] = {"url": url, "format": "json"}
    key = get_api_key("PHISHTANK_API_KEY")
    if key:
        payload["app_key"] = key
    try:
        response = _session.post(CHECK_URL, data=payload, timeout=DEFAULT_READ_TIMEOUT)
        if response.status_code == 429:
            return make_unavailable_result(PROVIDER_NAME, "url", url, status="rate_limited")
        if response.status_code in {401, 403}:
            return make_unavailable_result(PROVIDER_NAME, "url", url, status="unauthorized")
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "url", url, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "url", url, status="malformed_response")
        results = data.get("results", {}) if isinstance(data.get("results"), dict) else {}
        in_database = bool(results.get("in_database"))
        verified = bool(results.get("verified"))
        valid = bool(results.get("valid"))
        is_malicious = in_database and verified and valid
        is_suspicious = in_database and not is_malicious
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="url",
            ioc_value=url,
            status="success",
            malicious=is_malicious,
            suspicious=is_suspicious,
            report_url=results.get("phish_detail_page"),
            extra={
                "in_database": in_database,
                "verified": verified,
                "valid": valid,
            },
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "url", url, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("PhishTank lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "url", url, status="request_error",
                                       error="Request failed")
