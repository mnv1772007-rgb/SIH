"""Provider adapters package for Module 3: Threat Intelligence & Data.

Provides a unified interface to external threat intelligence sources:
    - virustotal (IP, domain, URL, hash)
    - abuseipdb (IP)
    - urlhaus (URL, domain)
    - phishtank (URL)
    - otx (IP, domain, URL, hash)
    - greynoise (IP)
    - urlscan (domain, URL)

All providers return normalized dictionaries conformant to ``threat_intel.schema``.
"""

from __future__ import annotations

from typing import Any, Callable

from . import abuseipdb, greynoise, otx, phishtank, urlhaus, urlscan, virustotal

# Registry mapping IOC types to provider lookup functions:
# ioc_type -> list of (provider_name, lookup_func)
PROVIDER_LOOKUPS: dict[str, list[tuple[str, Callable[[str], dict[str, Any]]]]] = {
    "ip": [
        ("VirusTotal", virustotal.lookup_ip),
        ("AbuseIPDB", abuseipdb.lookup_ip),
        ("OTX", otx.lookup_ip),
        ("GreyNoise", greynoise.lookup_ip),
    ],
    "domain": [
        ("VirusTotal", virustotal.lookup_domain),
        ("URLhaus", urlhaus.lookup_domain),
        ("OTX", otx.lookup_domain),
        ("URLScan", urlscan.lookup_domain),
    ],
    "url": [
        ("VirusTotal", virustotal.lookup_url),
        ("URLhaus", urlhaus.lookup_url),
        ("PhishTank", phishtank.lookup_url),
        ("OTX", otx.lookup_url),
        ("URLScan", urlscan.lookup_url),
    ],
    "hash": [
        ("VirusTotal", virustotal.lookup_hash),
        ("OTX", otx.lookup_hash),
    ],
}

__all__ = [
    "virustotal",
    "abuseipdb",
    "urlhaus",
    "phishtank",
    "otx",
    "greynoise",
    "urlscan",
    "PROVIDER_LOOKUPS",
]
