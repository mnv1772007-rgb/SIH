"""Bounded DNS enrichment, enabled only by the central service configuration."""

from __future__ import annotations

import dns.resolver


def query_dns(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout, resolver.lifetime = 3, 5
    records: dict[str, list[str]] = {}
    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            records[record_type] = [answer.to_text() for answer in resolver.resolve(domain, record_type)]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            records[record_type] = []
        except Exception as error:
            records[record_type] = [f"error: {error}"]
    return {"domain": domain, "status": "success", "records": records}
