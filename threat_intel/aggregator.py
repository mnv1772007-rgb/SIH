"""Threat intelligence aggregator for Module 3.

Combines results from multiple provider adapters into a single, cohesive,
defensible threat intelligence assessment while preserving forensic provenance.

Key principles:
1. Fail-Soft Consensus: An unavailable or unconfigured provider does NOT count
   as a clean vote. Absence of evidence is not evidence of absence.
2. Forensic Provenance: Every provider's response, status, timestamp, and error
   is preserved in the final output.
3. Multi-source Corroboration: Multiple independent detections increase the
   confidence score.
4. Attribution Safety: Geolocation is reported as infrastructure location, not
   attacker physical location.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def aggregate_results(
    ioc_type: str,
    ioc_value: str,
    provider_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Aggregate individual provider lookup results for a single IOC.

    Args:
        ioc_type: "ip", "domain", "url", or "hash"
        ioc_value: The canonical IOC string
        provider_results: List of normalized provider result dicts

    Returns:
        A consolidated assessment dictionary including verdict, confidence,
        corroborating sources, timeline, categories, tags, and full provenance.
    """
    total_providers = len(provider_results)
    successful_results = [r for r in provider_results if r.get("status") in {"success", "not_found"}]
    malicious_results = [r for r in provider_results if r.get("malicious") is True]
    suspicious_results = [
        r for r in provider_results
        if r.get("suspicious") is True and not r.get("malicious")
    ]

    # Corroborating sources
    malicious_sources = [r.get("provider", "unknown") for r in malicious_results]
    suspicious_sources = [r.get("provider", "unknown") for r in suspicious_results]

    # Consolidated verdict determination
    if malicious_results:
        verdict = "malicious"
        # Base confidence from max confidence of detecting providers + boost for corroboration
        max_conf = max((r.get("confidence") or 0.7 for r in malicious_results), default=0.7)
        corroboration_boost = min(0.25, (len(malicious_results) - 1) * 0.15)
        confidence = round(min(1.0, max_conf + corroboration_boost), 2)
    elif suspicious_results:
        verdict = "suspicious"
        max_conf = max((r.get("confidence") or 0.5 for r in suspicious_results), default=0.5)
        confidence = round(min(0.85, max_conf), 2)
    elif successful_results:
        # At least one provider responded successfully and none found threats
        verdict = "clean"
        confidence = 0.6 if len(successful_results) >= 2 else 0.4
    else:
        # No provider responded with usable intelligence (all unconfigured/unavailable/error)
        verdict = "unknown"
        confidence = 0.0

    # Aggregate categories and tags
    categories_set: set[str] = set()
    tags_set: set[str] = set()
    first_seen: str | None = None
    last_seen: str | None = None

    # Geolocation / network info (primarily for IP)
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: str | None = None
    asn_name: str | None = None
    isp: str | None = None

    for res in provider_results:
        # Categories & tags
        for cat in res.get("categories") or []:
            if cat:
                categories_set.add(str(cat).lower())
        for tag in res.get("tags") or []:
            if tag:
                tags_set.add(str(tag).lower())

        # Timeline
        fs = res.get("first_seen")
        if fs:
            if not first_seen or fs < first_seen:
                first_seen = fs
        ls = res.get("last_seen")
        if ls:
            if not last_seen or ls > last_seen:
                last_seen = ls

        # Geolocation fields (first non-empty)
        if not country and res.get("country"):
            country = res.get("country")
        if not country_code and res.get("country_code"):
            country_code = res.get("country_code")
        if not region and res.get("region"):
            region = res.get("region")
        if not city and res.get("city"):
            city = res.get("city")
        if latitude is None and res.get("latitude") is not None:
            latitude = res.get("latitude")
        if longitude is None and res.get("longitude") is not None:
            longitude = res.get("longitude")
        if not asn and res.get("asn"):
            asn = res.get("asn")
        if not asn_name and res.get("asn_name"):
            asn_name = res.get("asn_name")
        if not isp and res.get("isp"):
            isp = res.get("isp")

    # Forensic summary notes
    notes: list[str] = []
    if verdict == "malicious":
        notes.append(f"Confirmed malicious by {len(malicious_sources)} source(s): {', '.join(malicious_sources)}.")
    elif verdict == "suspicious":
        notes.append(f"Suspicious activity observed by {len(suspicious_sources)} source(s): {', '.join(suspicious_sources)}.")
    elif verdict == "clean":
        notes.append(f"No threat indicators observed across {len(successful_results)} active source(s). Note: Absence of detections is not absolute proof of safety.")
    else:
        notes.append("Threat intelligence was unavailable or unconfigured; no determination could be made.")

    return {
        "ioc": {
            "type": ioc_type,
            "value": ioc_value,
        },
        "verdict": verdict,
        "confidence": confidence,
        "is_threat": verdict in {"malicious", "suspicious"},
        "malicious_sources": malicious_sources,
        "suspicious_sources": suspicious_sources,
        "categories": sorted(categories_set),
        "tags": sorted(tags_set),
        "timeline": {
            "first_seen": first_seen,
            "last_seen": last_seen,
        },
        "network": {
            "country": country,
            "country_code": country_code,
            "region": region,
            "city": city,
            "latitude": latitude,
            "longitude": longitude,
            "asn": asn,
            "asn_name": asn_name,
            "isp": isp,
            "disclaimer": "Approximate infrastructure geolocation, not a person's physical location." if country else None,
        } if ioc_type == "ip" else None,
        "notes": notes,
        "providers_queried": total_providers,
        "providers_responded": len(successful_results),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        # Forensic provenance: full list of provider responses
        "provenance": provider_results,
    }
