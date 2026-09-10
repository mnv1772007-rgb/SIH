"""
Common Integration Contract — SIH Problem Statement 26106
Role 4: Graph & Campaign Correlation Module
"""

from typing import Optional, List, Dict, Any, Union
from datetime import datetime, timezone
import ipaddress
import re
import hashlib
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator, model_validator


def normalize_domain(domain: Optional[str]) -> Optional[str]:
    if not domain:
        return None
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    return d if d else None


def normalize_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    clean_ip = ip.strip()
    try:
        addr = ipaddress.ip_address(clean_ip)
        return str(addr)
    except ValueError:
        raise ValueError(f"Invalid IP address format: '{ip}'")


def normalize_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    u = url.strip()
    # Case-insensitive scheme check
    if not re.match(r"^https?://", u, re.IGNORECASE):
        u = "http://" + u
    try:
        parsed = urlparse(u)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return u


def compute_url_hash(normalized_url: str) -> str:
    return hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()


def normalize_hash(h: Optional[str]) -> Optional[str]:
    if not h:
        return None
    clean_h = h.strip().lower()
    if not re.fullmatch(r"[a-f0-9]+", clean_h):
        raise ValueError(f"Invalid cryptographic hash value: '{h}'")
    return clean_h


def normalize_timestamp(ts: Optional[Union[str, datetime]]) -> Optional[str]:
    if not ts:
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        return ts.isoformat()
    try:
        clean_ts = str(ts).strip()
        clean_ts = clean_ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat()
    except Exception:
        return str(ts)


class EmailData(BaseModel):
    email_id: str = Field(..., description="Unique email analysis or forensic UUID")
    message_id: Optional[str] = Field(None, description="RFC 5322 Message-ID header value")
    subject: Optional[str] = Field(None, description="Subject line of the email")
    sender: Optional[str] = Field(None, description="Full sender email address")
    sender_domain: Optional[str] = Field(None, description="Sender domain extracted/normalized")
    recipient: Optional[str] = Field(None, description="Primary recipient email address")
    recipients: List[str] = Field(default_factory=list, description="All recipient addresses")
    timestamp: Optional[str] = Field(None, description="UTC ISO-8601 timestamp")

    @field_validator("sender_domain", mode="before")
    @classmethod
    def validate_sender_domain(cls, v, values):
        if v:
            return normalize_domain(v)
        return None

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_timestamp(cls, v):
        return normalize_timestamp(v)

    @model_validator(mode="after")
    def populate_defaults(self):
        if not self.sender_domain and self.sender and "@" in self.sender:
            self.sender_domain = normalize_domain(self.sender.split("@")[-1])
        if self.recipient and self.recipient not in self.recipients:
            self.recipients.append(self.recipient)
        return self


class AuthenticationData(BaseModel):
    spf: Optional[str] = Field("unknown", description="SPF validation status (pass/fail/neutral/unknown)")
    dkim: Optional[str] = Field("unknown", description="DKIM validation status")
    dmarc: Optional[str] = Field("unknown", description="DMARC validation status")

    @field_validator("spf", "dkim", "dmarc", mode="before")
    @classmethod
    def validate_status(cls, v):
        if not v:
            return "unknown"
        return str(v).strip().lower()


class IOCDomain(BaseModel):
    value: str
    source: Optional[str] = "extracted"

    @field_validator("value", mode="before")
    @classmethod
    def validate_val(cls, v):
        res = normalize_domain(v)
        if not res:
            raise ValueError(f"Invalid domain value: '{v}'")
        return res


class IOCIP(BaseModel):
    value: str
    source: Optional[str] = "extracted"
    asn: Optional[str] = None
    country: Optional[str] = None

    @field_validator("value", mode="before")
    @classmethod
    def validate_val(cls, v):
        return normalize_ip(v)


class IOCUrl(BaseModel):
    value: str
    domain: Optional[str] = None
    url_hash: Optional[str] = None

    @field_validator("value", mode="before")
    @classmethod
    def validate_val(cls, v):
        norm = normalize_url(v)
        if not norm:
            raise ValueError(f"Invalid URL value: '{v}'")
        return norm

    @model_validator(mode="after")
    def set_domain_and_hash(self):
        if not self.domain and self.value:
            try:
                parsed = urlparse(self.value)
                self.domain = normalize_domain(parsed.netloc)
            except Exception:
                pass
        if not self.url_hash and self.value:
            self.url_hash = compute_url_hash(self.value)
        return self


class IOCHash(BaseModel):
    value: str
    type: Optional[str] = "sha256"
    filename: Optional[str] = None

    @field_validator("value", mode="before")
    @classmethod
    def validate_val(cls, v):
        return normalize_hash(v)

    @field_validator("type", mode="before")
    @classmethod
    def validate_type(cls, v, values):
        if v:
            return str(v).strip().lower()
        return "sha256"

    @model_validator(mode="after")
    def infer_hash_type(self):
        val_len = len(self.value)
        if self.type == "unknown" or not self.type:
            if val_len == 32:
                self.type = "md5"
            elif val_len == 40:
                self.type = "sha1"
            elif val_len == 64:
                self.type = "sha256"
            elif val_len == 128:
                self.type = "sha512"
        return self


class IOCSet(BaseModel):
    domains: List[IOCDomain] = Field(default_factory=list)
    ips: List[IOCIP] = Field(default_factory=list)
    urls: List[IOCUrl] = Field(default_factory=list)
    hashes: List[IOCHash] = Field(default_factory=list)
    ip_domain_mapping: Dict[str, str] = Field(default_factory=dict)

    @field_validator("domains", mode="before")
    @classmethod
    def parse_domains(cls, v):
        if not v:
            return []
        res = []
        for item in v:
            if isinstance(item, str):
                norm = normalize_domain(item)
                if norm:
                    res.append(IOCDomain(value=norm, source="list"))
            elif isinstance(item, dict):
                res.append(IOCDomain(**item))
            elif isinstance(item, IOCDomain):
                res.append(item)
        return res

    @field_validator("ips", mode="before")
    @classmethod
    def parse_ips(cls, v):
        if not v:
            return []
        res = []
        for item in v:
            if isinstance(item, str):
                try:
                    norm = normalize_ip(item)
                    if norm:
                        res.append(IOCIP(value=norm, source="list"))
                except ValueError:
                    continue
            elif isinstance(item, dict):
                res.append(IOCIP(**item))
            elif isinstance(item, IOCIP):
                res.append(item)
        return res

    @field_validator("urls", mode="before")
    @classmethod
    def parse_urls(cls, v):
        if not v:
            return []
        res = []
        for item in v:
            if isinstance(item, str):
                norm = normalize_url(item)
                if norm:
                    res.append(IOCUrl(value=norm))
            elif isinstance(item, dict):
                res.append(IOCUrl(**item))
            elif isinstance(item, IOCUrl):
                res.append(item)
        return res

    @field_validator("hashes", mode="before")
    @classmethod
    def parse_hashes(cls, v):
        if not v:
            return []
        res = []
        for item in v:
            if isinstance(item, str):
                try:
                    norm = normalize_hash(item)
                    if norm:
                        res.append(IOCHash(value=norm))
                except ValueError:
                    continue
            elif isinstance(item, dict):
                res.append(IOCHash(**item))
            elif isinstance(item, IOCHash):
                res.append(item)
        return res


class ThreatIntelData(BaseModel):
    domains: Dict[str, Any] = Field(default_factory=dict)
    ips: Dict[str, Any] = Field(default_factory=dict)
    urls: Dict[str, Any] = Field(default_factory=dict)
    hashes: Dict[str, Any] = Field(default_factory=dict)


class DetectionData(BaseModel):
    classification: Optional[str] = Field("suspicious", description="phishing, malware, benign, suspicious")
    risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall risk score between 0.0 and 1.0")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Model confidence between 0.0 and 1.0")

    @field_validator("risk_score", "confidence", mode="before")
    @classmethod
    def clamp_score(cls, v):
        if v is None:
            return 0.0
        val = float(v)
        return max(0.0, min(1.0, val))


class EmailAnalysisIngestPayload(BaseModel):
    schema_version: str = Field("1.0", description="Contract schema version")
    analysis_id: str = Field(..., description="Unique analysis pipeline identifier")
    email: EmailData
    authentication: Optional[AuthenticationData] = Field(default_factory=AuthenticationData)
    iocs: IOCSet = Field(default_factory=IOCSet)
    threat_intel: Optional[ThreatIntelData] = Field(default_factory=ThreatIntelData)
    detection: Optional[DetectionData] = Field(default_factory=DetectionData)

    @model_validator(mode="before")
    @classmethod
    def support_legacy_and_flat_payloads(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        # Check if incoming data is already in standard format
        if "email" in data and isinstance(data["email"], dict):
            # Ensure analysis_id exists
            if not data.get("analysis_id"):
                data["analysis_id"] = data["email"].get("email_id") or data["email"].get("message_id") or "analysis-" + hashlib.md5(str(datetime.now()).encode()).hexdigest()[:12]
            if not data["email"].get("email_id"):
                data["email"]["email_id"] = data["email"].get("message_id") or data["analysis_id"]

            # Migrate top-level risk_score or detection if not structured
            if "detection" not in data or not data["detection"]:
                if "risk_score" in data:
                    r = float(data["risk_score"])
                    data["detection"] = {
                        "classification": "phishing" if r > 0.6 else "suspicious",
                        "risk_score": r,
                        "confidence": 0.85 if r > 0.6 else 0.5,
                    }
            return data

        # Backward compatibility for completely flat payloads
        email_info = data.get("email", {})
        if not isinstance(email_info, dict):
            email_info = {}

        msg_id = email_info.get("message_id") or data.get("message_id") or "msg-" + hashlib.md5(str(datetime.now()).encode()).hexdigest()[:10]
        analysis_id = data.get("analysis_id") or email_info.get("email_id") or msg_id

        email_data = {
            "email_id": email_info.get("email_id") or analysis_id,
            "message_id": msg_id,
            "subject": email_info.get("subject") or data.get("subject", ""),
            "sender": email_info.get("sender") or data.get("sender", ""),
            "sender_domain": email_info.get("sender_domain"),
            "recipient": email_info.get("recipient") or (data.get("recipients", [None])[0] if data.get("recipients") else None),
            "recipients": email_info.get("recipients") or data.get("recipients", []),
            "timestamp": email_info.get("timestamp") or data.get("timestamp"),
        }

        iocs_raw = data.get("iocs", {})
        headers_raw = data.get("headers", {})

        auth_data = {
            "spf": headers_raw.get("Authentication-Results", "unknown") if isinstance(headers_raw, dict) else "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
        }
        if "authentication" in data and isinstance(data["authentication"], dict):
            auth_data.update(data["authentication"])

        risk = data.get("risk_score") or data.get("detection", {}).get("risk_score", 0.0)
        detection_data = {
            "classification": "phishing" if float(risk) > 0.6 else "suspicious",
            "risk_score": float(risk),
            "confidence": 0.85 if float(risk) > 0.6 else 0.5,
        }

        return {
            "schema_version": data.get("schema_version", "1.0"),
            "analysis_id": analysis_id,
            "email": email_data,
            "authentication": auth_data,
            "iocs": iocs_raw,
            "threat_intel": data.get("threat_intel", {}),
            "detection": detection_data,
        }
