"""AlienVault OTX (Open Threat Exchange) provider adapter for Module 3.

Supports passive lookups:
- IP address indicators
- Domain indicators
- URL indicators
- File hash indicators

API documentation: https://otx.alienvault.com/api

Rate limits:
- Free tier: 10,000 requests/hour
- Results are public intelligence from community pulses

Licensing / attribution:
- OTX data is community-contributed. Individual pulse licensing varies.
- Attribution to AlienVault OTX is required for displayed results.
- Data shared under OTX TOS; commercial use requires agreement review.

Environment variables:
    OTX_API_KEY  - AlienVault OTX API key
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
PROVIDER_NAME = "AlienVault OTX"
BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

_session = make_session(retries=1)


def _headers() -> dict[str, str]:
    key = get_api_key("OTX_API_KEY")
    if not key:
        return {}
    return {"X-OTX-API-KEY": key}


def _extract_pulse_info(general_data: dict[str, Any]) -> dict[str, Any]:
    """Extract pulse count and tags from OTX general section."""
    pulse_info = general_data.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    count = int(pulse_info.get("count", 0) or len(pulses))
    all_tags: list[str] = []
    all_names: list[str] = []
    for pulse in pulses:
        all_tags.extend(pulse.get("tags", []))
        name = pulse.get("name")
        if name:
            all_names.append(name)
    return {
        "pulse_count": count,
        "tags": list(set(all_tags)),
        "pulse_names": all_names[:5],  # limit to 5 for space
    }


def lookup_ip(ip: str) -> dict[str, Any]:
    """Look up an IP address on AlienVault OTX."""
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "ip", ip)
    key = get_api_key("OTX_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "ip", ip)
    try:
        response = _session.get(
            f"{BASE_URL}/IPv4/{ip}/general",
            headers=_headers(),
            timeout=DEFAULT_READ_TIMEOUT,
        )
        if response.status_code == 404:
            return make_provider_result(
                provider=PROVIDER_NAME, ioc_type="ip", ioc_value=ip,
                status="not_found", malicious=False,
            )
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "ip", ip, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "ip", ip, status="malformed_response")
        pulse_info = _extract_pulse_info(data)
        count = pulse_info["pulse_count"]
        is_malicious = count >= 3
        is_suspicious = count > 0 and not is_malicious
        confidence = min(0.9, count * 0.1) if count > 0 else 0.0
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="ip",
            ioc_value=ip,
            status="success",
            malicious=is_malicious,
            suspicious=is_suspicious,
            confidence=round(confidence, 3),
            country_code=data.get("country_code"),
            country=data.get("country_name"),
            asn=str(data.get("asn", "")) or None,
            tags=pulse_info["tags"],
            extra={
                "pulse_count": count,
                "pulse_names": pulse_info["pulse_names"],
                "reputation": data.get("reputation", 0),
            },
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "ip", ip, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("OTX IP lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "ip", ip, status="request_error",
                                       error="Request failed")


def lookup_domain(domain: str) -> dict[str, Any]:
    """Look up a domain on AlienVault OTX."""
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "domain", domain)
    key = get_api_key("OTX_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "domain", domain)
    try:
        response = _session.get(
            f"{BASE_URL}/domain/{domain}/general",
            headers=_headers(),
            timeout=DEFAULT_READ_TIMEOUT,
        )
        if response.status_code == 404:
            return make_provider_result(
                provider=PROVIDER_NAME, ioc_type="domain", ioc_value=domain,
                status="not_found", malicious=False,
            )
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "domain", domain, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "domain", domain,
                                           status="malformed_response")
        pulse_info = _extract_pulse_info(data)
        count = pulse_info["pulse_count"]
        is_malicious = count >= 3
        is_suspicious = count > 0 and not is_malicious
        confidence = min(0.9, count * 0.1) if count > 0 else 0.0
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="domain",
            ioc_value=domain,
            status="success",
            malicious=is_malicious,
            suspicious=is_suspicious,
            confidence=round(confidence, 3),
            tags=pulse_info["tags"],
            extra={
                "pulse_count": count,
                "pulse_names": pulse_info["pulse_names"],
            },
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "domain", domain, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("OTX domain lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "domain", domain, status="request_error",
                                       error="Request failed")


def lookup_url(url: str) -> dict[str, Any]:
    """Look up a URL on AlienVault OTX."""
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "url", url)
    key = get_api_key("OTX_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "url", url)
    try:
        response = _session.get(
            f"{BASE_URL}/url/{url}/general",
            headers=_headers(),
            timeout=DEFAULT_READ_TIMEOUT,
        )
        if response.status_code == 404:
            return make_provider_result(
                provider=PROVIDER_NAME, ioc_type="url", ioc_value=url,
                status="not_found", malicious=False,
            )
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "url", url, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "url", url, status="malformed_response")
        pulse_info = _extract_pulse_info(data)
        count = pulse_info["pulse_count"]
        is_malicious = count >= 3
        is_suspicious = count > 0 and not is_malicious
        confidence = min(0.9, count * 0.1) if count > 0 else 0.0
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="url",
            ioc_value=url,
            status="success",
            malicious=is_malicious,
            suspicious=is_suspicious,
            confidence=round(confidence, 3),
            tags=pulse_info["tags"],
            extra={"pulse_count": count, "pulse_names": pulse_info["pulse_names"]},
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "url", url, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("OTX URL lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "url", url, status="request_error",
                                       error="Request failed")


def lookup_hash(hash_value: str) -> dict[str, Any]:
    """Look up a file hash on AlienVault OTX."""
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "hash", hash_value)
    key = get_api_key("OTX_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "hash", hash_value)
    try:
        response = _session.get(
            f"{BASE_URL}/file/{hash_value}/general",
            headers=_headers(),
            timeout=DEFAULT_READ_TIMEOUT,
        )
        if response.status_code == 404:
            return make_provider_result(
                provider=PROVIDER_NAME, ioc_type="hash", ioc_value=hash_value,
                status="not_found", malicious=False,
            )
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "hash", hash_value, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "hash", hash_value,
                                           status="malformed_response")
        pulse_info = _extract_pulse_info(data)
        count = pulse_info["pulse_count"]
        is_malicious = count >= 1  # Any pulse with a file hash is significant
        confidence = min(0.9, count * 0.15) if count > 0 else 0.0
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="hash",
            ioc_value=hash_value,
            status="success",
            malicious=is_malicious,
            suspicious=False,
            confidence=round(confidence, 3),
            tags=pulse_info["tags"],
            extra={"pulse_count": count, "pulse_names": pulse_info["pulse_names"]},
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "hash", hash_value, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("OTX hash lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "hash", hash_value, status="request_error",
                                       error="Request failed")
