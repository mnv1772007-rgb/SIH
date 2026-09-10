"""Threat Intelligence & Data module (Module 3).

Provides a unified, fail-soft threat-intelligence enrichment layer that
accepts IOCs extracted from emails and enriches them using multiple
external and local intelligence sources.

Design principles:
- Every provider failure is isolated; one unavailable provider must not
  break the overall email-analysis pipeline.
- Provider responses are normalized into a consistent internal schema.
- Source provenance is always retained for forensic chain-of-custody.
- Geolocation results are never presented as the attacker's physical location.
- No IOC content is executed or browsed; all lookups are passive.
"""

from __future__ import annotations

from .aggregator import aggregate_results
from .cache import ThreatIntelCache, get_shared_cache
from .normalizer import IOCNormalizer, NormalizedIOC, normalize_ioc
from .service import ThreatIntelService, get_threat_intel_service

__all__ = [
    "IOCNormalizer",
    "NormalizedIOC",
    "normalize_ioc",
    "aggregate_results",
    "ThreatIntelCache",
    "get_shared_cache",
    "ThreatIntelService",
    "get_threat_intel_service",
]
