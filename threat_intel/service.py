"""Threat Intelligence Service (Module 3 Orchestrator).

Provides the unified high-level interface for enriching indicators of compromise
(IOCs) extracted from emails or submitted via API.

Features:
- Thread-safe concurrent lookups across multiple providers
- Integrated caching to minimize API rate limit usage
- Automatic IOC normalization and validation
- Fail-soft execution (one failing provider never crashes the lookup)
- Complete forensic provenance tracking
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import Any

from .aggregator import aggregate_results
from .cache import ThreatIntelCache, get_shared_cache
from .normalizer import IOCNormalizer, NormalizedIOC, normalize_ioc
from .providers import PROVIDER_LOOKUPS
from .schema import make_provider_result

LOGGER = logging.getLogger(__name__)


class ThreatIntelService:
    """High-level threat intelligence enrichment service."""

    def __init__(
        self,
        cache: ThreatIntelCache | None = None,
        max_workers: int = 8,
    ) -> None:
        self.cache = cache or get_shared_cache()
        self.normalizer = IOCNormalizer()
        self.max_workers = max_workers

    def _query_single_provider(
        self,
        provider_name: str,
        lookup_func: Any,
        ioc_type: str,
        ioc_value: str,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """Query one provider with caching and safety wraps."""
        if not force_refresh:
            cached = self.cache.get(ioc_type, ioc_value, provider_name)
            if cached:
                return cached

        try:
            res = lookup_func(ioc_value)
        except Exception as exc:
            LOGGER.warning("Unhandled error querying %s for %s: %s", provider_name, ioc_value, exc)
            res = make_provider_result(
                provider=provider_name,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                status="unavailable",
                error=str(exc),
            )

        # Store in cache
        self.cache.set(ioc_type, ioc_value, provider_name, res)
        return res

    def lookup_ioc(
        self,
        value: str,
        ioc_type: str | None = None,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """Perform normalized, multi-provider enrichment on a single IOC value.

        Args:
            value: The raw indicator string (IP, URL, domain, hash, etc.)
            ioc_type: Optional explicit type; if None, auto-detected.
            force_refresh: If True, bypasses cache and queries providers directly.

        Returns:
            Consolidated threat intelligence report conforming to aggregator schema.
        """
        normalized: NormalizedIOC = normalize_ioc(value, ioc_type=ioc_type)
        if not normalized.is_valid:
            return {
                "ioc": {"type": normalized.type, "value": value},
                "verdict": "unknown",
                "confidence": 0.0,
                "is_threat": False,
                "error": f"Invalid IOC format: {normalized.error}",
                "provenance": [],
            }

        target_type = normalized.type
        canonical_val = normalized.value or value

        # Retrieve registered providers for this IOC type
        providers = PROVIDER_LOOKUPS.get(target_type, [])
        if not providers:
            return {
                "ioc": {"type": target_type, "value": canonical_val},
                "verdict": "unknown",
                "confidence": 0.0,
                "is_threat": False,
                "note": f"No threat intelligence providers registered for IOC type '{target_type}'.",
                "provenance": [],
            }

        # Query registered providers concurrently
        provider_results: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, len(providers))) as executor:
            future_to_provider = {
                executor.submit(
                    self._query_single_provider,
                    name,
                    func,
                    target_type,
                    canonical_val,
                    force_refresh,
                ): name
                for name, func in providers
            }
            for future in concurrent.futures.as_completed(future_to_provider):
                try:
                    res = future.result()
                    provider_results.append(res)
                except Exception as exc:
                    prov_name = future_to_provider[future]
                    provider_results.append(
                        make_provider_result(
                            provider=prov_name,
                            ioc_type=target_type,
                            ioc_value=canonical_val,
                            status="unavailable",
                            error=str(exc),
                        )
                    )

        return aggregate_results(target_type, canonical_val, provider_results)

    def lookup_batch(
        self,
        iocs: list[dict[str, str]],
        force_refresh: bool = False,
    ) -> list[dict[str, Any]]:
        """Perform enrichment on a list of IOC items concurrently.

        Each item in ``iocs`` should be a dict with at least ``value`` and optional ``type``.
        """
        results: list[dict[str, Any]] = []
        if not iocs:
            return results

        # Process each IOC concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_item = {
                executor.submit(
                    self.lookup_ioc,
                    item.get("value", ""),
                    item.get("type"),
                    force_refresh,
                ): item
                for item in iocs
                if item.get("value")
            }
            for future in concurrent.futures.as_completed(future_to_item):
                results.append(future.result())

        return results

    def enrich_email_indicators(
        self,
        extracted_iocs: dict[str, list[str]],
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """Enrich all indicators extracted from an email message.

        Args:
            extracted_iocs: Dictionary like:
                {
                    "ips": ["192.0.2.1", "198.51.100.2"],
                    "urls": ["https://example.com/login", "http://test.com"],
                    "domains": ["example.com", "suspicious-bank.xyz"],
                    "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
                }

        Returns:
            Dictionary mapping indicator types to list of enriched results, plus
            an overall threat count summary.
        """
        enriched_ips = [
            self.lookup_ioc(ip, ioc_type="ip", force_refresh=force_refresh)
            for ip in extracted_iocs.get("ips", [])
        ]
        enriched_urls = [
            self.lookup_ioc(url, ioc_type="url", force_refresh=force_refresh)
            for url in extracted_iocs.get("urls", [])
        ]
        enriched_domains = [
            self.lookup_ioc(dom, ioc_type="domain", force_refresh=force_refresh)
            for dom in extracted_iocs.get("domains", [])
        ]
        enriched_hashes = [
            self.lookup_ioc(h, ioc_type="hash", force_refresh=force_refresh)
            for h in extracted_iocs.get("hashes", [])
        ]

        all_results = enriched_ips + enriched_urls + enriched_domains + enriched_hashes
        threat_count = sum(1 for r in all_results if r.get("is_threat"))
        malicious_count = sum(1 for r in all_results if r.get("verdict") == "malicious")
        suspicious_count = sum(1 for r in all_results if r.get("verdict") == "suspicious")

        return {
            "summary": {
                "total_indicators": len(all_results),
                "threat_count": threat_count,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "clean_count": sum(1 for r in all_results if r.get("verdict") == "clean"),
                "unknown_count": sum(1 for r in all_results if r.get("verdict") == "unknown"),
            },
            "ips": enriched_ips,
            "urls": enriched_urls,
            "domains": enriched_domains,
            "hashes": enriched_hashes,
        }


# Global singleton instance
_service = ThreatIntelService()


def get_threat_intel_service() -> ThreatIntelService:
    """Return the global ThreatIntelService singleton."""
    return _service
