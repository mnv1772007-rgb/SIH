"""
Standardized data models for threat intelligence pipeline.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import json


class IOCType(Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HASH = "hash"


class SourceName(Enum):
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    URLHAUS = "urlhaus"
    PHISHTANK = "phishtank"
    ALIENVAULT_OTX = "alienvault_otx"
    MISP = "misp"
    GREYNOISE = "greynoise"
    DNS = "dns"
    RDAP = "rdap"
    WHOIS = "whois"
    GEOIP = "geoip"


@dataclass
class SourceResult:
    source: SourceName
    indicator: str
    ioc_type: IOCType
    raw_data: Dict[str, Any]
    threat_score: float = 0.0
    malicious_votes: int = 0
    total_votes: int = 0
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkContext:
    asn: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_dynamic_dns: bool = False
    is_hosting: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    is_vpn: bool = False
    network_range: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class DNSRecords:
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)
    mx: List[Dict[str, str]] = field(default_factory=list)
    txt: List[str] = field(default_factory=list)
    ns: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    soa: Optional[Dict[str, str]] = None
    spf: Optional[str] = None
    dmarc: Optional[str] = None
    dkim: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DomainIntel:
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    dnssec: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class UnifiedThreatIntel:
    indicator: str
    ioc_type: IOCType
    threat_score: float = 0.0
    confidence: str = "low"
    malicious_votes: int = 0
    total_votes: int = 0
    sources_flagged: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    network_context: Optional[NetworkContext] = None
    dns_records: Optional[DNSRecords] = None
    domain_intel: Optional[DomainIntel] = None
    source_results: List[SourceResult] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['ioc_type'] = self.ioc_type.value
        result['confidence'] = self.confidence
        if self.network_context:
            result['network_context'] = self.network_context.to_dict()
        if self.dns_records:
            result['dns_records'] = self.dns_records.to_dict()
        if self.domain_intel:
            result['domain_intel'] = self.domain_intel.to_dict()
        result['source_results'] = [sr.to_dict() for sr in self.source_results]
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def calculate_confidence(score: float, sources_count: int) -> str:
    if score >= 0.8 and sources_count >= 3:
        return "high"
    elif score >= 0.5 and sources_count >= 2:
        return "medium"
    elif score > 0:
        return "low"
    return "none"


def normalize_threat_score(scores: List[float], weights: List[float] = None) -> float:
    if not scores:
        return 0.0
    if weights is None:
        weights = [1.0] * len(scores)
    weighted_sum = sum(s * w for s, w in zip(scores, weights))
    total_weight = sum(weights)
    return min(1.0, weighted_sum / total_weight if total_weight > 0 else 0.0)