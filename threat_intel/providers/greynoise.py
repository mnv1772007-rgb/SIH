"""GreyNoise Community/Enterprise API provider adapter for Module 3.

Supports IP address lookups only.
API documentation: https://docs.greynoise.io/reference/get_v3_community_ip

Licensing / rate limits:
- Free Community API tier available with API key
- Enterprise API supported via identical response parsing

Environment variables:
    GREYNOISE_API_KEY  - GreyNoise API key
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
    classify_http_error,
    get_api_key,
    is_threat_intel_enabled,
    make_session,
    safe_get_json,
)

LOGGER = logging.getLogger(__name__)
PROVIDER_NAME = "GreyNoise"
BASE_URL = "https://api.greynoise.io/v3/community"

_session = make_session(retries=1)


def _headers() -> dict[str, str]:
    key = get_api_key("GREYNOISE_API_KEY")
    if not key:
        return {}
    return {"key": key, "Accept": "application/json"}


def lookup_ip(ip: str) -> dict[str, Any]:
    """Look up an IP address against the GreyNoise Community API.

    Passive query; returns noise/riot classification.
    """
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "ip", ip)

    key = get_api_key("GREYNOISE_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "ip", ip)

    url = f"{BASE_URL}/{ip}"
    try:
        response = _session.get(url, headers=_headers(), timeout=10)
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "ip", ip, "timeout", "Request timed out")
    except requests.RequestException as exc:
        return make_unavailable_result(PROVIDER_NAME, "ip", ip, "request_error", str(exc))

    if response.status_code == 404:
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="ip",
            ioc_value=ip,
            status="not_found",
            malicious=False,
            suspicious=False,
            confidence=0.0,
            tags=["not_observed_noise"],
        )

    if response.status_code != 200:
        status = classify_http_error(response)
        return make_unavailable_result(PROVIDER_NAME, "ip", ip, status, f"HTTP {response.status_code}")

    data = safe_get_json(response)
    if not data:
        return make_unavailable_result(
            PROVIDER_NAME, "ip", ip, "malformed_response", "Empty or invalid JSON response"
        )

    # GreyNoise community fields:
    # classification: "malicious" | "benign" | "unknown"
    # noise: bool
    # riot: bool (Rule It Out - trusted business service)
    # name: str (e.g. "Googlebot", "Censys")
    # link: str (viz.greynoise.io link)
    # last_seen: str
    classification = str(data.get("classification", "")).lower()
    noise = bool(data.get("noise", False))
    riot = bool(data.get("riot", False))
    actor_name = data.get("name")
    last_seen = data.get("last_seen")
    link = data.get("link")

    malicious = classification == "malicious"
    suspicious = False
    if classification == "unknown" and noise:
        suspicious = True

    confidence = 0.85 if malicious else (0.90 if riot or classification == "benign" else 0.40)
    tags = []
    if noise:
        tags.append("internet_scanner")
    if riot:
        tags.append("common_business_service")
    if actor_name:
        tags.append(f"actor:{actor_name}")
    if classification:
        tags.append(f"classification:{classification}")

    return make_provider_result(
        provider=PROVIDER_NAME,
        ioc_type="ip",
        ioc_value=ip,
        status="success",
        malicious=malicious,
        suspicious=suspicious,
        confidence=confidence,
        tags=tags,
        last_seen=last_seen,
        report_url=link,
        extra=data,
    )
