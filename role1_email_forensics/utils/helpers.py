"""Shared utilities — regex patterns, header decoders, IP classifiers."""

from __future__ import annotations

import ipaddress
import re
from email.header import decode_header as _decode_header

import chardet


# ---------------------------------------------------------------------------
# Header decoding
# ---------------------------------------------------------------------------

def decode_mime_words(encoded: str | None) -> str:
    """Decode RFC 2047 encoded header words (=?UTF-8?B?...?= etc.)."""
    if not encoded:
        return ""
    parts: list[str] = []
    for raw_bytes, charset in _decode_header(encoded):
        if isinstance(raw_bytes, str):
            parts.append(raw_bytes)
        else:
            if charset:
                try:
                    parts.append(raw_bytes.decode(charset, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    parts.append(raw_bytes.decode("utf-8", errors="replace"))
            else:
                # Try chardet
                detected = chardet.detect(raw_bytes)
                enc = detected.get("encoding") or "utf-8"
                parts.append(raw_bytes.decode(enc, errors="replace"))
    return "".join(parts)


# ---------------------------------------------------------------------------
# Email address helpers
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

DISPLAY_RE = re.compile(r'^"?([^"<]+?)"?\s*<([^>]+)>', re.IGNORECASE)


def extract_email_address(value: str | None) -> tuple[str | None, str | None]:
    """Return (display_name, email) from a header value like 'Alice <alice@example.com>'."""
    if not value:
        return None, None
    value = decode_mime_words(value).strip()
    m = DISPLAY_RE.match(value)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    emails = EMAIL_RE.findall(value)
    if emails:
        return None, emails[0]
    return None, None


def get_domain(email_or_host: str | None) -> str | None:
    """Extract domain from an email address or hostname."""
    if not email_or_host:
        return None
    if "@" in email_or_host:
        return email_or_host.split("@", 1)[1].strip().lower().rstrip(">")
    return email_or_host.strip().lower()


# ---------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------

def classify_ip(ip_str: str) -> str:
    """Return 'public' | 'private' | 'loopback' | 'reserved'."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private"
        if addr.is_reserved or addr.is_link_local or addr.is_multicast:
            return "reserved"
        return "public"
    except ValueError:
        return "reserved"


def is_public_ip(ip_str: str) -> bool:
    return classify_ip(ip_str) == "public"


# ---------------------------------------------------------------------------
# URL defanging
# ---------------------------------------------------------------------------

def defang_url(url: str) -> str:
    """Convert URL to defanged form for safe reporting (hxxps://evil[.]com)."""
    url = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Replace dots in domain part
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        netloc = parsed.netloc.replace(".", "[.]")
        defanged = url.replace(parsed.netloc, netloc, 1)
        return defanged
    except Exception:
        return url.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


# ---------------------------------------------------------------------------
# IP extraction regex
# ---------------------------------------------------------------------------

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

IPV6_RE = re.compile(
    r"(?<![:\w])"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|(?:2[0-4]|1?\d)?\d)(?:\.(?:25[0-5]|(?:2[0-4]|1?\d)?\d)){3}"
    r"(?<![:\w])"
)

# Parens-wrapped IPs seen in Received headers: (1.2.3.4)
RECEIVED_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")


def extract_ips_from_text(text: str) -> list[str]:
    """Extract all IPv4 addresses from a block of text."""
    found = set()
    # Bracket-wrapped first (Received headers)
    found.update(RECEIVED_IP_RE.findall(text))
    # Generic
    found.update(IPV4_RE.findall(text))
    return list(found)


# ---------------------------------------------------------------------------
# URL extraction regex
# ---------------------------------------------------------------------------

URL_RE = re.compile(
    r"https?://"
    r"(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+"
    r")",
    re.IGNORECASE,
)


def extract_urls_from_text(text: str) -> list[str]:
    return list(dict.fromkeys(URL_RE.findall(text)))  # preserve order, deduplicate


# ---------------------------------------------------------------------------
# Homoglyph / lookalike detection
# ---------------------------------------------------------------------------

# Common IDN homoglyph confusables (Latin lookalikes)
_HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ԁ": "d", "ո": "n",
    "ᴵ": "I", "ⅼ": "l", "０": "0", "１": "1",
}


def has_homoglyph(domain: str) -> bool:
    """Detect suspected IDN homoglyph characters in a domain."""
    for ch in domain:
        if ch in _HOMOGLYPH_MAP:
            return True
    return False


# Simple typosquatting: check if registered domain SLD is 1–2 edits from known brands
_KNOWN_BRANDS = [
    "google", "microsoft", "amazon", "paypal", "apple", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "github",
]

_LEGITIMATE_BRAND_DOMAINS = {
    "google.com", "microsoft.com", "amazon.com", "paypal.com", "apple.com",
    "facebook.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
    "dropbox.com", "github.com", "live.com", "office.com", "outlook.com",
}


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def is_typosquat(domain: str, registered_domain: str | None = None) -> bool:
    """
    Heuristic: registered domain SLD is 1–2 Levenshtein edits from a known brand.
    Never flags legitimate brand domains (e.g. apps.microsoft.com -> registered: microsoft.com).
    """
    if not domain:
        return False

    domain_lower = domain.lower().strip()

    # If domain itself or registered domain is a known legitimate brand domain, NOT typosquat
    if domain_lower in _LEGITIMATE_BRAND_DOMAINS:
        return False
    if registered_domain and registered_domain.lower() in _LEGITIMATE_BRAND_DOMAINS:
        return False

    # Extract the SLD (e.g. 'paypa1' from 'paypa1.com' or 'apps.microsoft.com')
    target = registered_domain or domain_lower
    parts = target.split(".")
    if len(parts) >= 2:
        # e.g. 'microsoft' from 'microsoft.com' or 'paypa1' from 'paypa1.com'
        sld = parts[-2]
    else:
        sld = parts[0]

    for brand in _KNOWN_BRANDS:
        # If SLD is identical to the brand, it's the actual brand name, not a typosquat
        if sld == brand:
            return False

        dist = _levenshtein(sld, brand)
        # For short brand names (<= 4 chars like apple), require strictly 1 edit
        max_dist = 1 if len(brand) <= 5 else 2
        if 0 < dist <= max_dist:
            # Also require at least 65% length similarity
            if abs(len(sld) - len(brand)) <= 2:
                return True

    return False


# ---------------------------------------------------------------------------
# Risk signal ID generator
# ---------------------------------------------------------------------------

_sig_counter: dict[str, int] = {}


def make_signal_id(category: str) -> str:
    n = _sig_counter.get(category, 0) + 1
    _sig_counter[category] = n
    return f"{category.upper()}-{n:03d}"
