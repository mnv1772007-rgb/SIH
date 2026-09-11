"""
Forensic Report Schema — Shared JSON contract for all 6 roles.
SIH 26106 — IronPulse | Role 1: Email Forensics & Protocol

All modules (AI/ML, Threat Intel, Graph, Backend, Dashboard) consume this schema.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SpfResult(str, Enum):
    PASS       = "pass"
    FAIL       = "fail"
    SOFTFAIL   = "softfail"
    NEUTRAL    = "neutral"
    NONE       = "none"
    TEMPERROR  = "temperror"
    PERMERROR  = "permerror"


class DkimResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"


class DmarcResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"


class DmarcPolicy(str, Enum):
    NONE        = "none"
    QUARANTINE  = "quarantine"
    REJECT      = "reject"


class ArcResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"


class OriginConfidence(str, Enum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"


class IpType(str, Enum):
    PUBLIC   = "public"
    PRIVATE  = "private"
    LOOPBACK = "loopback"
    RESERVED = "reserved"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# ---------------------------------------------------------------------------
# Header Analysis
# ---------------------------------------------------------------------------

class HeaderAnalysis(BaseModel):
    """Parsed email header fields."""
    from_address: Optional[str]        = Field(None, description="RFC 5322 From address")
    from_display_name: Optional[str]   = Field(None, description="Display name in From header")
    to: list[str]                      = Field(default_factory=list, description="To recipients")
    cc: list[str]                      = Field(default_factory=list, description="CC recipients")
    bcc: list[str]                     = Field(default_factory=list, description="BCC recipients")
    reply_to: Optional[str]            = Field(None, description="Reply-To address")
    return_path: Optional[str]         = Field(None, description="Return-Path (bounce address)")
    subject: Optional[str]             = Field(None)
    date: Optional[str]                = Field(None, description="Date header (ISO 8601 UTC)")
    message_id: Optional[str]          = Field(None, description="Message-ID header")
    in_reply_to: Optional[str]         = Field(None)
    references: list[str]              = Field(default_factory=list)
    x_originating_ip: Optional[str]    = Field(None, description="X-Originating-IP header")
    x_mailer: Optional[str]            = Field(None, description="X-Mailer / User-Agent header")
    x_spam_status: Optional[str]       = Field(None)
    x_spam_score: Optional[float]      = Field(None)
    x_priority: Optional[str]           = Field(None)
    recorded_auth: dict[str, Any]       = Field(default_factory=dict, description="Parsed Authentication-Results headers")
    mime_version: Optional[str]        = Field(None)
    content_type: Optional[str]        = Field(None)
    custom_headers: dict[str, str]     = Field(default_factory=dict, description="Any other X-* headers")

    # Anomaly flags set during extraction
    from_reply_to_mismatch: bool       = Field(False, description="From ≠ Reply-To domain")
    from_return_path_mismatch: bool    = Field(False, description="From ≠ Return-Path domain")
    display_name_spoofing_suspected: bool = Field(False)


# ---------------------------------------------------------------------------
# Authentication Results
# ---------------------------------------------------------------------------

class SpfResult_(BaseModel):
    result: SpfResult          = Field(SpfResult.NONE)
    domain: Optional[str]      = None
    ip_checked: Optional[str]  = None
    record: Optional[str]      = Field(None, description="Raw SPF TXT record")
    explanation: Optional[str] = None
    source: str                = Field("live_dns", description="live_dns | recorded_mta_header")


class DkimResult_(BaseModel):
    result: DkimResult           = Field(DkimResult.NONE)
    domain: Optional[str]        = None
    selector: Optional[str]      = None
    algorithm: Optional[str]     = None
    key_bits: Optional[int]      = None
    header_hash: Optional[str]   = None
    body_hash: Optional[str]     = None
    error: Optional[str]         = None
    source: str                  = Field("live_dns", description="live_dns | recorded_mta_header")


class DmarcResult_(BaseModel):
    result: DmarcResult            = Field(DmarcResult.NONE)
    domain: Optional[str]          = None
    policy: Optional[DmarcPolicy]  = None
    subdomain_policy: Optional[DmarcPolicy] = None
    pct: Optional[int]             = Field(None, description="Percentage of mail subject to policy")
    rua: list[str]                 = Field(default_factory=list, description="Aggregate report URIs")
    ruf: list[str]                 = Field(default_factory=list, description="Forensic report URIs")
    spf_alignment: Optional[str]   = None
    dkim_alignment: Optional[str]  = None
    record: Optional[str]          = None
    error: Optional[str]           = None
    source: str                    = Field("live_dns", description="live_dns | recorded_mta_header")


class ArcResult_(BaseModel):
    result: ArcResult         = Field(ArcResult.NONE)
    chain_length: int         = 0
    chain_valid: bool         = False
    cv_field: Optional[str]   = Field(None, description="Final ARC-Seal cv= value")
    error: Optional[str]      = None


class AuthResults(BaseModel):
    """SPF + DKIM + DMARC + ARC authentication results."""
    spf:   SpfResult_   = Field(default_factory=SpfResult_)
    dkim:  DkimResult_  = Field(default_factory=DkimResult_)
    dmarc: DmarcResult_ = Field(default_factory=DmarcResult_)
    arc:   ArcResult_   = Field(default_factory=ArcResult_)

    @property
    def all_pass(self) -> bool:
        return (
            self.spf.result   == SpfResult.PASS and
            self.dkim.result  == DkimResult.PASS and
            self.dmarc.result == DmarcResult.PASS
        )


# ---------------------------------------------------------------------------
# SMTP Relay Path
# ---------------------------------------------------------------------------

class SmtpHop(BaseModel):
    """One hop in the SMTP relay chain (from a Received: header)."""
    hop: int                          = Field(..., description="1 = closest to sender")
    from_host: Optional[str]          = None
    from_ip: Optional[str]            = None
    by_host: Optional[str]            = None
    with_protocol: Optional[str]      = Field(None, description="e.g. ESMTP, ESMTPS, HTTP")
    id: Optional[str]                 = Field(None, description="Queue ID on receiving MTA")
    for_address: Optional[str]        = None
    timestamp: Optional[str]          = Field(None, description="ISO 8601 UTC")
    delay_seconds: Optional[float]    = Field(None, description="Time delta from previous hop")
    raw_header: Optional[str]         = None
    flags: list[str]                  = Field(default_factory=list,
                                              description="anomaly flags: time_skew, private_ip, etc.")


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------

class ExtractedUrl(BaseModel):
    url: str
    defanged: str                  = Field(..., description="hxxps://... form")
    domain: Optional[str]          = None
    scheme: Optional[str]          = None
    source: str                    = Field(..., description="body|header|attachment")
    suspicious: bool               = False
    redirect_chain: list[str]      = Field(default_factory=list)


class ExtractedIp(BaseModel):
    ip: str
    ip_type: IpType                = Field(IpType.PUBLIC)
    source: str                    = Field(..., description="header|body|smtp_path")
    is_tor_exit: bool              = False
    reverse_dns: Optional[str]     = None


class ExtractedDomain(BaseModel):
    domain: str
    registered_domain: Optional[str]  = None
    tld: Optional[str]                = None
    subdomain: Optional[str]          = None
    source: str                       = Field(..., description="header|body|url")
    homoglyph_suspected: bool         = False
    typosquat_suspected: bool         = False
    age_days: Optional[int]           = Field(None, description="Domain registration age")


class AttachmentInfo(BaseModel):
    filename: Optional[str]     = None
    content_type: str           = ""
    size_bytes: int             = 0
    md5: str                    = ""
    sha1: str                   = ""
    sha256: str                 = ""
    is_executable: bool         = False
    is_archive: bool            = False
    is_office_doc: bool         = False
    contains_macros: Optional[bool] = None


class IocBundle(BaseModel):
    """All Indicators of Compromise extracted from the email."""
    urls: list[ExtractedUrl]           = Field(default_factory=list)
    ips: list[ExtractedIp]             = Field(default_factory=list)
    domains: list[ExtractedDomain]     = Field(default_factory=list)
    attachments: list[AttachmentInfo]  = Field(default_factory=list)
    body_text_sha256: Optional[str]    = None
    body_html_sha256: Optional[str]    = None


# ---------------------------------------------------------------------------
# Origin Inference
# ---------------------------------------------------------------------------

class OriginInference(BaseModel):
    """
    Probable sending infrastructure based on SMTP relay chain analysis.

    ⚠️  DISCLAIMER: This identifies the probable sending mail server (MTA)
    infrastructure. It does NOT prove the attacker's physical location
    or identity. IP geolocation data is probabilistic.
    """
    probable_sending_ip: Optional[str]      = None
    probable_sending_host: Optional[str]    = None
    rdns: Optional[str]                     = None
    asn: Optional[str]                      = None
    asn_org: Optional[str]                  = None
    country_code: Optional[str]             = None
    country_name: Optional[str]             = None
    isp: Optional[str]                      = None
    city: Optional[str]                     = None
    region: Optional[str]                   = None
    latitude: Optional[float]               = None
    longitude: Optional[float]              = None
    abuse_score: Optional[int]              = None
    threat_intel: dict[str, Any]            = Field(default_factory=dict)
    is_cloud_provider: bool                 = False
    is_vpn_suspected: bool                  = False
    is_tor: bool                            = False
    confidence: OriginConfidence            = OriginConfidence.LOW
    method: str                             = Field(
        "first_external_smtp_hop",
        description="How origin was inferred"
    )
    note: str = (
        "Probable sending MTA infrastructure — NOT the attacker's physical "
        "identity. IP geolocation is probabilistic."
    )


# ---------------------------------------------------------------------------
# Risk Signal
# ---------------------------------------------------------------------------

class RiskSignal(BaseModel):
    """A single risk indicator produced by Role 1."""
    signal_id: str
    level: RiskLevel
    category: str                   = Field(..., description="auth|header|smtp|ioc|origin")
    description: str
    evidence: dict[str, Any]        = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Top-level ForensicReport
# ---------------------------------------------------------------------------

class ForensicReport(BaseModel):
    """
    Top-level forensic report produced by Role 1.
    Consumed by Roles 2–6 as the common integration contract.
    """
    report_id: str                  = Field(default_factory=lambda: str(uuid4()))
    analyzed_at: str                = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    source_file: Optional[str]      = None
    raw_email_sha256: Optional[str] = None
    raw_email_size_bytes: int       = 0

    # Sub-reports
    headers: HeaderAnalysis         = Field(default_factory=HeaderAnalysis)
    auth: AuthResults               = Field(default_factory=AuthResults)
    smtp_path: list[SmtpHop]        = Field(default_factory=list)
    iocs: IocBundle                 = Field(default_factory=IocBundle)
    origin: OriginInference         = Field(default_factory=OriginInference)
    risk_signals: list[RiskSignal]  = Field(default_factory=list)

    # Threat Intelligence, ML & AI enrichment
    threat_intelligence: dict[str, Any] = Field(default_factory=dict)
    ai_assessment: dict[str, Any]       = Field(default_factory=dict)
    ml_assessment: dict[str, Any]       = Field(default_factory=dict, description="Baseline ML classifier predictions")

    # Pipeline metadata
    pipeline_version: str           = "1.0.0"
    processing_errors: list[str]    = Field(default_factory=list)

    def to_json(self, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_json(cls, data: str | bytes) -> "ForensicReport":
        return cls.model_validate_json(data)
