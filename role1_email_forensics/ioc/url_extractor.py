"""
URL Extractor — harvests URLs from email body (text + HTML) and headers.
SIH 26106 — IronPulse | Role 1
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urlparse

import tldextract

from ..schema.forensic_report import ExtractedUrl
from ..utils.helpers import extract_urls_from_text, defang_url


# Suspicious TLDs and patterns
_SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work",
    "click", "link", "info", "online", "site", "pw",
}

_SUSPICIOUS_KEYWORDS = re.compile(
    r"login|verify|secure|account|update|confirm|banking|paypal|"
    r"signin|password|credential|suspend|unlock|alert|invoice|wire",
    re.IGNORECASE,
)


class UrlExtractor:
    def extract(
        self,
        text_body: Optional[str],
        html_body: Optional[str],
        headers_raw: dict[str, str] | None = None,
    ) -> list[ExtractedUrl]:
        """Extract, deduplicate, and classify URLs from all email parts."""
        seen: dict[str, ExtractedUrl] = {}

        # Text body
        if text_body:
            for url in extract_urls_from_text(text_body):
                if url not in seen:
                    seen[url] = _build_url(url, "body")

        # HTML body (href + src attributes)
        if html_body:
            for url in _extract_from_html(html_body):
                if url not in seen:
                    seen[url] = _build_url(url, "body")

        # Headers (Received, etc.)
        if headers_raw:
            for value in headers_raw.values():
                for url in extract_urls_from_text(value):
                    if url not in seen:
                        seen[url] = _build_url(url, "header")

        return list(seen.values())


# ---------------------------------------------------------------------------

import html as html_pkg


class _HrefParser(HTMLParser):
    """Extract href= and src= attribute values from HTML."""
    def __init__(self):
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag, attrs):
        for attr, val in attrs:
            if attr in ("href", "src", "action") and val:
                val_clean = html_pkg.unescape(val.strip())
                # Handle defanged hxxp(s)
                val_clean = re.sub(r"^hxxp", "http", val_clean, flags=re.IGNORECASE)
                val_clean = val_clean.replace("[.]", ".")
                if val_clean.startswith("http://") or val_clean.startswith("https://"):
                    self.urls.append(val_clean)


def _extract_from_html(html: str) -> list[str]:
    parser = _HrefParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    # Also regex-scan raw HTML (catches obfuscated markup)
    extra_raw = extract_urls_from_text(html)
    extra_clean = []
    for u in extra_raw:
        u_clean = html_pkg.unescape(u.strip())
        u_clean = re.sub(r"^hxxp", "http", u_clean, flags=re.IGNORECASE).replace("[.]", ".")
        extra_clean.append(u_clean)

    # Deduplicate while suppressing truncated URL fragments (e.g. prefix of an existing href)
    all_urls = list(dict.fromkeys(parser.urls + extra_clean))
    final_urls: list[str] = []
    for u in all_urls:
        # Check if u is a strict prefix/truncated fragment of another longer URL in all_urls
        is_fragment = any(other != u and other.startswith(u) and len(other) > len(u) for other in all_urls)
        if not is_fragment and u not in final_urls:
            final_urls.append(u)

    return final_urls


def _build_url(url: str, source: str) -> ExtractedUrl:
    # Normalize defanged prefixes if passed
    norm_url = re.sub(r"^hxxp", "http", url.strip(), flags=re.IGNORECASE).replace("[.]", ".")
    parsed = urlparse(norm_url)
    extracted = tldextract.extract(norm_url)
    reg = getattr(extracted, "top_domain_under_public_suffix", None) or extracted.registered_domain
    domain = (reg or parsed.netloc or "").lower()

    suspicious = _is_suspicious(norm_url, domain, extracted)

    return ExtractedUrl(
        url=norm_url,
        defanged=defang_url(norm_url),
        domain=domain,
        scheme=parsed.scheme,
        source=source,
        suspicious=suspicious,
    )


_TRUSTED_URL_DOMAINS = {
    "linkedin.com", "google.com", "microsoft.com", "apple.com", "github.com",
    "amazon.com", "twitter.com", "x.com", "youtube.com", "facebook.com",
    "instagram.com", "office.com", "live.com", "outlook.com",
}


def _is_suspicious(url: str, domain: str, extracted: tldextract.tldextract.ExtractResult) -> bool:
    reg = (getattr(extracted, "top_domain_under_public_suffix", None) or extracted.registered_domain or "").lower()
    is_trusted = reg in _TRUSTED_URL_DOMAINS

    # 1. Lookalike / typosquat domain
    from ..utils.helpers import is_typosquat, has_homoglyph
    if is_typosquat(domain, registered_domain=reg) or has_homoglyph(domain):
        return True

    # 2. Numeric IP instead of hostname is always suspicious
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        return True

    # 3. Suspicious TLD
    if extracted.suffix in _SUSPICIOUS_TLDS:
        return True

    # 4. Phishing / credential harvesting keywords in path or query
    if _SUSPICIOUS_KEYWORDS.search(url):
        if not is_trusted:
            return True

    # 5. Excessively long URL (>200 chars) on UNTRUSTED domains
    if len(url) > 200 and not is_trusted:
        return True

    return False
