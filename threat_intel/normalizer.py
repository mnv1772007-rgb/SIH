"""IOC normalization layer for Module 3: Threat Intelligence & Data.

Provides canonical representations for all IOC types:
- IP addresses (IPv4/IPv6)
- Domains
- URLs
- File hashes (MD5, SHA-1, SHA-256)
- Email addresses

Normalization is safe and non-destructive; it produces a canonical form
without altering the original IOC's semantic meaning.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any, Literal
from urllib.parse import urlparse, urlsplit, urlunsplit

# ---------------------------------------------------------------------------
# IOC type definitions
# ---------------------------------------------------------------------------

IOCType = Literal["ip", "domain", "url", "hash", "email", "unknown"]

HASH_PATTERNS: dict[str, re.Pattern[str]] = {
    "md5": re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE),
    "sha1": re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE),
    "sha256": re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE),
}

# RFC5322-compatible local+domain pattern (conservative subset)
EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

# Conservative domain label pattern
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


# ---------------------------------------------------------------------------
# Individual normalizers
# ---------------------------------------------------------------------------


def normalize_ip(value: str) -> dict[str, Any]:
    """Normalize an IP address to its canonical string representation.

    Returns a dict with:
      - ``canonical``: normalized string or None if invalid
      - ``version``: 4 or 6 or None
      - ``error``: error message if invalid
    """
    value = (value or "").strip()
    if not value:
        return {"canonical": None, "version": None, "error": "Empty value"}
    try:
        addr = ipaddress.ip_address(value)
        return {
            "canonical": str(addr),
            "version": addr.version,
            "is_private": addr.is_private,
            "is_global": addr.is_global,
            "is_loopback": addr.is_loopback,
            "is_reserved": addr.is_reserved,
            "is_link_local": addr.is_link_local,
            "error": None,
        }
    except ValueError as exc:
        return {"canonical": None, "version": None, "error": str(exc)}


def normalize_domain(value: str) -> dict[str, Any]:
    """Normalize a domain to lowercase stripped form.

    Does NOT perform DNS resolution. Validates label structure.
    Returns a dict with:
      - ``canonical``: normalized domain or None if invalid
      - ``error``: error description if invalid
    """
    value = (value or "").strip().rstrip(".").lower()
    if not value:
        return {"canonical": None, "error": "Empty value"}
    if len(value) > 253:
        return {"canonical": None, "error": "Domain exceeds 253 characters"}
    # Check if it's actually an IP address (IP-based URLs)
    try:
        ipaddress.ip_address(value)
        return {"canonical": None, "error": "Value is an IP address, not a domain"}
    except ValueError:
        pass
    labels = value.split(".")
    if len(labels) < 2:
        return {"canonical": None, "error": "Domain must have at least two labels"}
    for label in labels:
        if not label:
            return {"canonical": None, "error": "Empty label in domain"}
        # Allow punycode (xn--...) labels
        check_label = label
        if label.startswith("xn--"):
            check_label = label  # punycode is valid if it matches the pattern
        if not DOMAIN_LABEL_PATTERN.match(check_label):
            # Allow underscore in some internal domains (common in practice)
            if not re.match(r"^[a-zA-Z0-9_\-]+$", check_label):
                return {"canonical": None, "error": f"Invalid label: {label!r}"}
    return {"canonical": value, "error": None}


def normalize_url(value: str) -> dict[str, Any]:
    """Normalize a URL without fetching it.

    Normalizes scheme and hostname to lowercase; preserves path/query.
    Returns a dict with:
      - ``canonical``: normalized URL or None if invalid
      - ``scheme``, ``hostname``, ``port``, ``path``, ``query``: components
      - ``error``: error description if invalid
    """
    value = (value or "").strip()
    if not value:
        return {"canonical": None, "scheme": None, "hostname": None, "port": None,
                "path": None, "query": None, "error": "Empty value"}
    try:
        parsed = urlsplit(value)
        scheme = (parsed.scheme or "").lower()
        hostname = (parsed.hostname or "").lower()
        if not scheme:
            return {"canonical": None, "scheme": None, "hostname": None, "port": None,
                    "path": None, "query": None, "error": "Missing URL scheme"}
        if scheme in {"http", "https"} and not hostname:
            return {"canonical": None, "scheme": scheme, "hostname": None, "port": None,
                    "path": None, "query": None, "error": "Missing hostname for http/https URL"}
        # Rebuild netloc with normalized hostname
        netloc = f"[{hostname}]" if ":" in hostname else hostname
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc = f"{netloc}:{port}"
        canonical = urlunsplit((scheme, netloc, parsed.path or "", parsed.query or "", ""))
        return {
            "canonical": canonical,
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": parsed.path or "",
            "query": parsed.query or "",
            "error": None,
        }
    except (ValueError, Exception) as exc:
        return {"canonical": None, "scheme": None, "hostname": None, "port": None,
                "path": None, "query": None, "error": str(exc)}


def normalize_hash(value: str) -> dict[str, Any]:
    """Normalize a file hash to lowercase hexadecimal.

    Validates length and character set for MD5, SHA-1, SHA-256.
    Returns a dict with:
      - ``canonical``: normalized hash or None if invalid
      - ``algorithm``: 'md5', 'sha1', 'sha256', or None
      - ``error``: error description if invalid
    """
    value = (value or "").strip().lower()
    if not value:
        return {"canonical": None, "algorithm": None, "error": "Empty value"}
    if not re.match(r"^[0-9a-f]+$", value):
        return {"canonical": None, "algorithm": None,
                "error": "Hash contains non-hexadecimal characters"}
    for algo, pattern in HASH_PATTERNS.items():
        if pattern.match(value):
            return {"canonical": value, "algorithm": algo, "error": None}
    return {"canonical": None, "algorithm": None,
            "error": f"Hash length {len(value)} does not match MD5 (32), SHA-1 (40), or SHA-256 (64)"}


def normalize_email(value: str) -> dict[str, Any]:
    """Normalize an email address.

    The local part is case-sensitive in theory (RFC5321) but case-insensitive
    in practice for most providers. We normalize only the domain portion.
    Returns a dict with:
      - ``canonical``: normalized email (local@normalized_domain) or None
      - ``local``: local-part (unchanged)
      - ``domain``: normalized domain
      - ``error``: error description if invalid
    """
    value = (value or "").strip()
    if not value:
        return {"canonical": None, "local": None, "domain": None, "error": "Empty value"}
    if "@" not in value:
        return {"canonical": None, "local": None, "domain": None,
                "error": "Missing @ in email address"}
    parts = value.rsplit("@", 1)
    local, domain_part = parts[0], parts[1].lower()
    if not local:
        return {"canonical": None, "local": None, "domain": None, "error": "Empty local part"}
    if not EMAIL_PATTERN.match(value.lower()):
        # Try basic validation without strict pattern
        if not domain_part or "." not in domain_part:
            return {"canonical": None, "local": local, "domain": domain_part,
                    "error": "Invalid email domain"}
    canonical = f"{local.lower()}@{domain_part}"
    return {"canonical": canonical, "local": local, "domain": domain_part, "error": None}


def detect_ioc_type(value: str) -> IOCType:
    """Detect the IOC type from a raw value string."""
    value = (value or "").strip()
    if not value:
        return "unknown"
    # IP address check
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    # URL check (has scheme)
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", value):
        return "url"
    # Email check
    if "@" in value and EMAIL_PATTERN.match(value.lower()):
        return "email"
    # Hash check
    for pattern in HASH_PATTERNS.values():
        if pattern.match(value):
            return "hash"
    # Domain check (last resort)
    result = normalize_domain(value)
    if result["canonical"]:
        return "domain"
    return "unknown"


# ---------------------------------------------------------------------------
# Unified IOC structure
# ---------------------------------------------------------------------------


class NormalizedIOC:
    """Canonical representation of an Indicator of Compromise."""

    def __init__(
        self,
        ioc_type: IOCType,
        raw_value: str,
        canonical: str | None,
        source: str = "extracted",
        metadata: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        self.type: IOCType = ioc_type
        self.raw_value: str = raw_value
        self.value: str | None = canonical
        self.normalized_value: str | None = canonical
        self.source: str = source
        self.metadata: dict[str, Any] = metadata or {}
        self.error: str | None = error
        self.valid: bool = canonical is not None and error is None

    @property
    def is_valid(self) -> bool:
        return self.valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "raw_value": self.raw_value,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "source": self.source,
            "valid": self.valid,
            "metadata": self.metadata,
            "error": self.error,
        }

    def __repr__(self) -> str:
        return f"NormalizedIOC(type={self.type!r}, value={self.value!r}, valid={self.valid})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NormalizedIOC):
            return NotImplemented
        return self.type == other.type and self.value == other.value

    def __hash__(self) -> int:
        return hash((self.type, self.value))


def normalize_ioc(
    value: str,
    ioc_type: IOCType | None = None,
    source: str = "extracted",
) -> NormalizedIOC:
    """Normalize a single IOC value into canonical form.

    Args:
        value: Raw IOC value.
        ioc_type: Explicit type hint. Auto-detected if None.
        source: Provenance label (e.g., 'email_body', 'email_header').

    Returns:
        NormalizedIOC with canonical form, type, and validation status.
    """
    raw = (value or "").strip()
    detected_type = ioc_type or detect_ioc_type(raw)

    if detected_type == "ip":
        result = normalize_ip(raw)
        return NormalizedIOC(
            ioc_type="ip",
            raw_value=raw,
            canonical=result.get("canonical"),
            source=source,
            metadata={k: v for k, v in result.items() if k not in ("canonical", "error")},
            error=result.get("error"),
        )
    elif detected_type == "domain":
        result = normalize_domain(raw)
        return NormalizedIOC(
            ioc_type="domain",
            raw_value=raw,
            canonical=result.get("canonical"),
            source=source,
            metadata={},
            error=result.get("error"),
        )
    elif detected_type == "url":
        result = normalize_url(raw)
        metadata = {k: v for k, v in result.items() if k not in ("canonical", "error")}
        return NormalizedIOC(
            ioc_type="url",
            raw_value=raw,
            canonical=result.get("canonical"),
            source=source,
            metadata=metadata,
            error=result.get("error"),
        )
    elif detected_type == "hash":
        result = normalize_hash(raw)
        return NormalizedIOC(
            ioc_type="hash",
            raw_value=raw,
            canonical=result.get("canonical"),
            source=source,
            metadata={"algorithm": result.get("algorithm")},
            error=result.get("error"),
        )
    elif detected_type == "email":
        result = normalize_email(raw)
        metadata = {k: v for k, v in result.items() if k not in ("canonical", "error")}
        return NormalizedIOC(
            ioc_type="email",
            raw_value=raw,
            canonical=result.get("canonical"),
            source=source,
            metadata=metadata,
            error=result.get("error"),
        )
    else:
        return NormalizedIOC(
            ioc_type="unknown",
            raw_value=raw,
            canonical=None,
            source=source,
            error="Could not determine IOC type",
        )


class IOCNormalizer:
    """Batch IOC normalizer with deduplication.

    Usage::

        normalizer = IOCNormalizer()
        iocs = normalizer.normalize_batch([
            {"type": "ip", "value": "8.8.8.8"},
            {"type": "domain", "value": "EXAMPLE.COM"},
        ])
    """

    def normalize_batch(
        self,
        iocs: list[dict[str, Any]],
        source: str = "batch",
    ) -> list[NormalizedIOC]:
        """Normalize and deduplicate a list of IOC dicts.

        Each dict should have at minimum a ``value`` key and optionally a
        ``type`` key. Duplicates (same type + canonical value) are removed.
        """
        seen: set[tuple[str, str | None]] = set()
        results: list[NormalizedIOC] = []
        for item in iocs:
            raw = str(item.get("value", "")).strip()
            if not raw:
                continue
            ioc_type = item.get("type")
            normalized = normalize_ioc(raw, ioc_type=ioc_type, source=source)
            key = (normalized.type, normalized.value)
            if key in seen:
                continue
            seen.add(key)
            results.append(normalized)
        return results

    def normalize_single(self, value: str, ioc_type: IOCType | None = None,
                         source: str = "single") -> NormalizedIOC:
        """Normalize a single IOC value."""
        return normalize_ioc(value, ioc_type=ioc_type, source=source)
