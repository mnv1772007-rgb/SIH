"""Static domain-indicator analysis."""

from __future__ import annotations

import ipaddress
import re


def analyze_domain(domain: str) -> dict[str, object]:
    domain = (domain or "").strip().rstrip(".").lower()
    try:
        is_ip_address = bool(ipaddress.ip_address(domain))
    except ValueError:
        is_ip_address = False
    labels = [label for label in domain.split(".") if label]
    return {
        "domain": domain,
        "length": len(domain),
        "subdomain_count": max(0, len(labels) - 2),
        "has_punycode": "xn--" in domain,
        "has_suspicious_characters": bool(re.search(r"[^a-z0-9.\-]", domain)),
        "has_ip_address": is_ip_address,
    }
