"""
Defensive Fallback Utilities — Role 4
Used strictly as defensive helpers when upstream parser metadata is incomplete.
Primary parsing and extraction belongs to Roles 1 & 2.
"""

import re
import hashlib
import ipaddress
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse


def extract_domain_from_url(url: str) -> Optional[str]:
    """Safely extracts normalized netloc domain from a URL string."""
    if not url:
        return None
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0].lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain if domain else None
    except Exception:
        return None


def extract_domain_from_email(email_address: str) -> Optional[str]:
    """Extracts lowercase domain from an RFC 5322 email address."""
    if not email_address or "@" not in email_address:
        return None
    try:
        parts = email_address.strip().split("@")
        return parts[-1].strip().lower().rstrip(">")
    except Exception:
        return None


def is_valid_ip(ip_str: str) -> bool:
    """Checks if a string is a valid IPv4 or IPv6 address."""
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def calculate_sha256(content: str) -> str:
    """Calculates lowercase SHA-256 hash of a string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def fallback_extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Defensive fallback IOC extractor for unstructured text.
    Only called if upstream modules did not supply pre-extracted IOCs.
    """
    if not text:
        return {"domains": [], "ips": [], "urls": [], "hashes": []}

    urls = set(re.findall(r"https?://[^\s\"'>]+", text))
    clean_urls = {u.rstrip(".,;:!?)]}") for u in urls}

    raw_ips = re.findall(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        text,
    )
    valid_ips = {ip for ip in raw_ips if is_valid_ip(ip)}

    sha256s = set(re.findall(r"\b[a-fA-F0-9]{64}\b", text))
    md5s = set(re.findall(r"\b[a-fA-F0-9]{32}\b", text))
    all_hashes = {h.lower() for h in sha256s | md5s}

    domains = set()
    for u in clean_urls:
        d = extract_domain_from_url(u)
        if d:
            domains.add(d)

    return {
        "domains": list(domains),
        "ips": list(valid_ips),
        "urls": list(clean_urls),
        "hashes": list(all_hashes),
    }