"""Static URL feature extraction used by the forensic pipeline.

The module records observations. It deliberately does not turn generic URL
shape (length, query strings, tracking parameters, or marketing vocabulary)
into a malicious verdict. Verdicting belongs to the evidence-tiered service
layer, where static observations can be combined with threat intelligence.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlparse


# These are observations only. They are kept separate from structural URL
# signals so words such as "security" or "update" cannot become proof of a
# threat merely because they appear in a marketing or notification URL.
GENERIC_TERMS = {
    "account", "authentication", "message", "network", "notification",
    "security", "secure", "update", "verify", "verification",
}
CREDENTIAL_TERMS = {"credential", "login", "passcode", "password", "signin"}
# Retained from the former lexical detector as low-specificity context. These
# words are not evidence of maliciousness without independent URL signals.
CONTEXTUAL_TERMS = {"bank", "confirm", "invoice", "payment", "wallet"}
TRACKING_PARAMETER_NAMES = {
    "_hsenc", "_hsmi", "campaign", "cid", "email", "fbclid", "gclid",
    "mc_cid", "mc_eid", "midtoken", "msclkid", "ref", "source", "trk",
    "tracking", "utm_campaign", "utm_content", "utm_medium", "utm_source",
    "utm_term",
}
SENSITIVE_QUERY_PARAMETER_NAMES = {
    "card", "cardnumber", "credential", "cvv", "passcode", "password",
    "pin", "securitycode", "ssn",
}
SHORTENER_DOMAINS = {
    "bit.ly", "cutt.ly", "goo.gl", "is.gd", "rb.gy", "rebrand.ly", "t.co", "tinyurl.com",
}
UNSAFE_SCHEMES = {"javascript", "data", "file", "vbscript"}


def _numeric_ip(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Interpret conventional and deliberately obfuscated numeric hosts."""
    if not hostname:
        return None
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        pass
    try:
        if hostname.isdecimal():
            return ipaddress.ip_address(int(hostname, 10))
        if hostname.lower().startswith("0x"):
            return ipaddress.ip_address(int(hostname, 16))
    except ValueError:
        return None
    return None


def analyze_url(url: str) -> dict[str, object]:
    """Return explainable, non-network URL observations for *url*."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        parse_error = False
    except ValueError:
        parsed = urlparse("")
        hostname = ""
        parse_error = True

    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    try:
        port = parsed.port
        invalid_port = False
    except ValueError:
        port = None
        invalid_port = True

    try:
        query_pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        query_pairs = []
        parse_error = True
    query_names = [name.lower() for name, _ in query_pairs]
    tracking_parameters = [name for name in query_names if name in TRACKING_PARAMETER_NAMES or name.startswith("utm_")]
    sensitive_parameters = [name for name in query_names if name in SENSITIVE_QUERY_PARAMETER_NAMES]

    path_and_query = f"{path}?{query}".lower()
    generic_terms = sorted(term for term in GENERIC_TERMS if term in path_and_query)
    credential_terms = sorted(term for term in CREDENTIAL_TERMS if term in path_and_query)
    contextual_terms = sorted(term for term in CONTEXTUAL_TERMS if term in path_and_query)
    numeric_ip = _numeric_ip(hostname)
    is_ip_address = numeric_ip is not None

    # Query values are intentionally not duplicated in the feature record: the
    # raw URL already preserves evidence, while parameter names explain the
    # shape without needlessly surfacing recipient or tracking tokens again.
    query_parameters = [
        {"name": name, "value_present": bool(value)}
        for name, value in query_pairs
    ]

    return {
        "url": url,
        "scheme": scheme,
        "domain": hostname.lower(),
        "hostname": hostname.lower(),
        "path": path,
        "query": query,
        "query_parameters": query_parameters,
        "query_parameter_names": query_names,
        "query_parameter_count": len(query_pairs),
        "port": port,
        "https": scheme == "https",
        "url_length": len(url),
        "domain_length": len(hostname),
        "path_length": len(path),
        "is_long_url": len(url) >= 200,
        "has_ip_address": bool(is_ip_address and numeric_ip and numeric_ip.version == 4),
        "has_ipv6_address": bool(is_ip_address and numeric_ip and numeric_ip.version == 6),
        "ip_address": str(numeric_ip) if numeric_ip else None,
        "ip_is_private": bool(numeric_ip and numeric_ip.is_private),
        "ip_is_loopback": bool(numeric_ip and numeric_ip.is_loopback),
        "ip_is_reserved": bool(numeric_ip and numeric_ip.is_reserved),
        "has_at_symbol": "@" in url,
        "has_punycode": "xn--" in hostname.lower(),
        "has_suspicious_words": bool(generic_terms or credential_terms or contextual_terms),
        "suspicious_words": sorted(set(generic_terms + credential_terms + contextual_terms)),
        "generic_terms": generic_terms,
        "credential_terms": credential_terms,
        "contextual_terms": contextual_terms,
        "has_credential_terms": bool(credential_terms),
        "subdomain_count": max(0, len(hostname.split(".")) - 2) if hostname else 0,
        "has_encoded_characters": bool(re.search(r"%[0-9a-fA-F]{2}", url)),
        "has_suspicious_port": port is not None and port not in {80, 443},
        "has_credentials": bool(parsed.username or parsed.password),
        "has_decimal_ip": hostname.isdecimal(),
        "has_hexadecimal_ip": hostname.lower().startswith("0x"),
        "has_homoglyph_characters": any(ord(character) > 127 for character in hostname),
        "is_shortened_url": hostname.lower() in SHORTENER_DOMAINS,
        "has_tracking_parameters": bool(tracking_parameters),
        "tracking_parameters": tracking_parameters,
        "has_sensitive_query_parameters": bool(sensitive_parameters),
        "sensitive_query_parameters": sensitive_parameters,
        "has_open_redirect_pattern": bool(re.search(
            r"(?:[?&](?:url|uri|redirect|redirect_url|next|return|target)=https?%3A|"
            r"[?&](?:url|uri|redirect|next|return|target)=https?://)",
            url.lower(),
        )),
        "has_unsafe_scheme": scheme in UNSAFE_SCHEMES,
        "invalid_port": invalid_port,
        "parse_error": parse_error,
    }
