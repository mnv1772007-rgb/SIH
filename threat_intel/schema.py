"""Provider result schema for Module 3: Threat Intelligence & Data.

Defines the canonical normalized structure that every provider adapter
must return. This ensures the aggregator and the rest of the pipeline
see a consistent schema regardless of which provider is queried.

Provenance fields ensure forensic chain-of-custody:
- Which provider produced this result?
- When was it queried?
- What IOC was queried?
- What was the provider response/status?
- Was the result cached?
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

ProviderStatus = Literal[
    "success",
    "not_found",
    "not_configured",
    "disabled",
    "rate_limited",
    "timeout",
    "unauthorized",
    "unavailable",
    "request_error",
    "malformed_response",
    "not_applicable",
    "invalid_ioc",
]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_provider_result(
    *,
    provider: str,
    ioc_type: str,
    ioc_value: str,
    status: ProviderStatus,
    queried_at: str | None = None,
    cached: bool = False,
    # Threat classification
    malicious: bool | None = None,
    suspicious: bool | None = None,
    confidence: float | None = None,
    reputation: int | None = None,
    # Classification labels
    categories: list[str] | None = None,
    tags: list[str] | None = None,
    # Timeline
    first_seen: str | None = None,
    last_seen: str | None = None,
    # Geolocation (IP-specific)
    country: str | None = None,
    country_code: str | None = None,
    region: str | None = None,
    city: str | None = None,
    latitude: float | None = None,
    longitude: float | None = None,
    timezone: str | None = None,
    # Network information
    asn: str | None = None,
    asn_name: str | None = None,
    isp: str | None = None,
    organization: str | None = None,
    network: str | None = None,
    # Reference
    raw_reference: str | None = None,
    report_url: str | None = None,
    # Error information
    error: str | None = None,
    # Provider-specific extras (stored for forensic reference, not surfaced to frontend)
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a normalized provider result with mandatory provenance fields.

    The return value is the canonical structure used throughout the pipeline.
    Every provider adapter must return results in this format.

    IMPORTANT: ``malicious=False`` is only set when the provider explicitly
    reported a clean result. A provider being unavailable/unconfigured/timed-out
    does NOT imply ``malicious=False``.
    """
    return {
        # Provenance (mandatory for forensic chain-of-custody)
        "provider": provider,
        "ioc": {
            "type": ioc_type,
            "value": ioc_value,
        },
        "queried_at": queried_at or _utcnow(),
        "status": status,
        "cached": cached,
        # Threat assessment (None = not determined by this provider)
        "malicious": malicious,
        "suspicious": suspicious,
        "confidence": confidence,
        "reputation": reputation,
        # Labels
        "categories": categories or [],
        "tags": tags or [],
        # Timeline
        "first_seen": first_seen,
        "last_seen": last_seen,
        # Geolocation (IP-specific; None for non-IP IOCs)
        "country": country,
        "country_code": country_code,
        "region": region,
        "city": city,
        "latitude": latitude,
        "longitude": longitude,
        "timezone_info": timezone,
        # Network (IP-specific)
        "asn": asn,
        "asn_name": asn_name,
        "isp": isp,
        "organization": organization,
        "network": network,
        # References
        "raw_reference": raw_reference,
        "report_url": report_url,
        # Error
        "error": error,
        # Forensic extras (not forwarded to frontend summary)
        "_extra": extra or {},
    }


def make_unavailable_result(
    provider: str,
    ioc_type: str,
    ioc_value: str,
    status: ProviderStatus = "unavailable",
    error: str | None = None,
    cached: bool = False,
) -> dict[str, Any]:
    """Shortcut for creating a result when a provider is unavailable.

    CRITICAL: This result intentionally leaves ``malicious`` as None
    because unavailability != clean.
    """
    return make_provider_result(
        provider=provider,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        status=status,
        cached=cached,
        malicious=None,  # explicitly unknown
        error=error,
    )


def make_not_configured_result(
    provider: str,
    ioc_type: str,
    ioc_value: str,
) -> dict[str, Any]:
    """Shortcut for results where the provider API key is not configured."""
    return make_provider_result(
        provider=provider,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        status="not_configured",
        malicious=None,
    )


def make_disabled_result(
    provider: str,
    ioc_type: str,
    ioc_value: str,
    reason: str | None = None,
) -> dict[str, Any]:
    """Shortcut for results where the provider is disabled in configuration."""
    return make_provider_result(
        provider=provider,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        status="disabled",
        malicious=None,
        error=reason,
    )
