"""VirusTotal API v3 provider adapter for Module 3.

Supports passive lookups only:
- IP address reputation
- Domain reputation
- URL reputation (existing reports; URLs are NEVER submitted)
- File hash reputation

API documentation: https://developers.virustotal.com/reference/overview

Rate limits (public/free tier):
- 4 lookups per minute
- 500 lookups per day
- Timestamps and quota tracked by VirusTotal

Licensing / attribution:
- VirusTotal TOS requires attribution for any results presented to users.
- Data may not be redistributed or re-shared without permission.
- URLs are NEVER submitted to VirusTotal (only hash-based lookups of
  existing reports) to avoid leaking potentially sensitive URLs.

Environment variables:
    VIRUSTOTAL_API_KEY  - VirusTotal API key (v3)
"""

from __future__ import annotations

import base64
import logging
import os
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
PROVIDER_NAME = "VirusTotal"
BASE_URL = "https://www.virustotal.com/api/v3"

_session = make_session(retries=1)


def _headers() -> dict[str, str]:
    key = get_api_key("VIRUSTOTAL_API_KEY")
    if not key:
        return {}
    return {"x-apikey": key, "Accept": "application/json"}


def _parse_analysis_stats(attrs: dict[str, Any]) -> tuple[bool, bool, float | None]:
    """Extract malicious/suspicious classification from last_analysis_stats."""
    stats = attrs.get("last_analysis_stats") or {}

    def _int(name: str) -> int:
        try:
            return max(0, int(stats.get(name) or 0))
        except (TypeError, ValueError):
            return 0

    malicious = _int("malicious")
    suspicious = _int("suspicious")
    undetected = _int("undetected")
    total = malicious + suspicious + undetected + _int("harmless") + _int("timeout")
    confidence: float | None = None
    if total > 0:
        confidence = round(malicious / total, 3)
    is_malicious = malicious > 0
    is_suspicious = malicious == 0 and suspicious > 0
    return is_malicious, is_suspicious, confidence


def _safe_timestamp(value: Any) -> str | None:
    """Convert a Unix timestamp to ISO format, or return None."""
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def lookup_ip(ip: str) -> dict[str, Any]:
    """Look up an IP address on VirusTotal."""
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "ip", ip)
    key = get_api_key("VIRUSTOTAL_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "ip", ip)
    try:
        response = _session.get(
            f"{BASE_URL}/ip_addresses/{ip}",
            headers=_headers(),
            timeout=DEFAULT_READ_TIMEOUT,
        )
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "ip", ip, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "ip", ip, status="malformed_response")
        attrs = data.get("data", {}).get("attributes", {})
        is_malicious, is_suspicious, confidence = _parse_analysis_stats(attrs)
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="ip",
            ioc_value=ip,
            status="success",
            malicious=is_malicious,
            suspicious=is_suspicious,
            confidence=confidence,
            reputation=attrs.get("reputation"),
            country=attrs.get("country"),
            asn=str(attrs.get("asn", "")) or None,
            asn_name=attrs.get("as_owner"),
            network=attrs.get("network"),
            categories=list(attrs.get("categories", {}).values()),
            tags=attrs.get("tags", []),
            last_seen=_safe_timestamp(attrs.get("last_analysis_date")),
            extra={"last_analysis_stats": attrs.get("last_analysis_stats", {})},
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "ip", ip, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("VirusTotal IP lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "ip", ip, status="request_error",
                                       error="Request failed")


def lookup_domain(domain: str) -> dict[str, Any]:
    """Look up a domain on VirusTotal."""
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "domain", domain)
    key = get_api_key("VIRUSTOTAL_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "domain", domain)
    try:
        response = _session.get(
            f"{BASE_URL}/domains/{domain}",
            headers=_headers(),
            timeout=DEFAULT_READ_TIMEOUT,
        )
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "domain", domain, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "domain", domain,
                                           status="malformed_response")
        attrs = data.get("data", {}).get("attributes", {})
        is_malicious, is_suspicious, confidence = _parse_analysis_stats(attrs)
        registrar = attrs.get("registrar")
        creation_date = _safe_timestamp(attrs.get("creation_date"))
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="domain",
            ioc_value=domain,
            status="success",
            malicious=is_malicious,
            suspicious=is_suspicious,
            confidence=confidence,
            reputation=attrs.get("reputation"),
            categories=list(attrs.get("categories", {}).values()),
            tags=attrs.get("tags", []),
            first_seen=creation_date,
            last_seen=_safe_timestamp(attrs.get("last_analysis_date")),
            extra={"registrar": registrar, "last_analysis_stats": attrs.get("last_analysis_stats")},
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "domain", domain, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("VirusTotal domain lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "domain", domain, status="request_error",
                                       error="Request failed")


def lookup_url(url: str) -> dict[str, Any]:
    """Look up an existing VirusTotal URL report. URLs are NEVER submitted."""
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "url", url)
    key = get_api_key("VIRUSTOTAL_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "url", url)
    try:
        identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        response = _session.get(
            f"{BASE_URL}/urls/{identifier}",
            headers=_headers(),
            timeout=DEFAULT_READ_TIMEOUT,
        )
        if response.status_code == 404:
            return make_provider_result(
                provider=PROVIDER_NAME, ioc_type="url", ioc_value=url,
                status="not_found", malicious=False, suspicious=False,
            )
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "url", url, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "url", url,
                                           status="malformed_response")
        attrs = data.get("data", {}).get("attributes", {})
        is_malicious, is_suspicious, confidence = _parse_analysis_stats(attrs)
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="url",
            ioc_value=url,
            status="success",
            malicious=is_malicious,
            suspicious=is_suspicious,
            confidence=confidence,
            reputation=attrs.get("reputation"),
            categories=list(attrs.get("categories", {}).values()),
            tags=attrs.get("tags", []),
            last_seen=_safe_timestamp(attrs.get("last_analysis_date")),
            extra={
                "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                "times_submitted": attrs.get("times_submitted"),
            },
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "url", url, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("VirusTotal URL lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "url", url, status="request_error",
                                       error="Request failed")


def lookup_hash(hash_value: str) -> dict[str, Any]:
    """Look up a file hash on VirusTotal."""
    if not is_threat_intel_enabled():
        return make_disabled_result(PROVIDER_NAME, "hash", hash_value)
    key = get_api_key("VIRUSTOTAL_API_KEY")
    if not key:
        return make_not_configured_result(PROVIDER_NAME, "hash", hash_value)
    try:
        response = _session.get(
            f"{BASE_URL}/files/{hash_value}",
            headers=_headers(),
            timeout=DEFAULT_READ_TIMEOUT,
        )
        if response.status_code == 404:
            return make_provider_result(
                provider=PROVIDER_NAME, ioc_type="hash", ioc_value=hash_value,
                status="not_found", malicious=False, suspicious=False,
            )
        if response.status_code != 200:
            return make_unavailable_result(
                PROVIDER_NAME, "hash", hash_value, status=classify_http_error(response)
            )
        data = safe_get_json(response)
        if not isinstance(data, dict):
            return make_unavailable_result(PROVIDER_NAME, "hash", hash_value,
                                           status="malformed_response")
        attrs = data.get("data", {}).get("attributes", {})
        is_malicious, is_suspicious, confidence = _parse_analysis_stats(attrs)
        return make_provider_result(
            provider=PROVIDER_NAME,
            ioc_type="hash",
            ioc_value=hash_value,
            status="success",
            malicious=is_malicious,
            suspicious=is_suspicious,
            confidence=confidence,
            tags=attrs.get("tags", []),
            first_seen=_safe_timestamp(attrs.get("first_submission_date")),
            last_seen=_safe_timestamp(attrs.get("last_analysis_date")),
            extra={
                "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                "meaningful_name": attrs.get("meaningful_name"),
                "type_description": attrs.get("type_description"),
                "size": attrs.get("size"),
            },
        )
    except requests.Timeout:
        return make_unavailable_result(PROVIDER_NAME, "hash", hash_value, status="timeout")
    except requests.RequestException as exc:
        LOGGER.debug("VirusTotal hash lookup failed: %s", exc)
        return make_unavailable_result(PROVIDER_NAME, "hash", hash_value, status="request_error",
                                       error="Request failed")
