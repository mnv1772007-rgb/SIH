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

class _HrefParser(HTMLParser):
    """Extract href= and src= attribute values from HTML."""
    def __init__(self):
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag, attrs):
        for attr, val in attrs:
            if attr in ("href", "src", "action") and val:
                if val.startswith("http://") or val.startswith("https://"):
                    self.urls.append(val)


def _extract_from_html(html: str) -> list[str]:
    parser = _HrefParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    # Also regex-scan raw HTML (catches obfuscated markup)
    extra = extract_urls_from_text(html)
    return list(dict.fromkeys(parser.urls + extra))


def _build_url(url: str, source: str) -> ExtractedUrl:
    parsed  = urlparse(url)
    extracted = tldextract.extract(url)
    reg = getattr(extracted, "top_domain_under_public_suffix", None) or extracted.registered_domain
    domain = reg or parsed.netloc

    suspicious = _is_suspicious(url, extracted)

    return ExtractedUrl(
        url=url,
        defanged=defang_url(url),
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


def _is_suspicious(url: str, extracted: tldextract.tldextract.ExtractResult) -> bool:
    reg = getattr(extracted, "top_domain_under_public_suffix", None) or extracted.registered_domain or ""
    is_trusted = reg.lower() in _TRUSTED_URL_DOMAINS

    # Numeric IP instead of hostname is always suspicious
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        return True

    # Suspicious TLD
    if extracted.suffix in _SUSPICIOUS_TLDS:
        return True

    # Phishing / credential harvesting keywords in path or query
    # (only check path/query if on trusted domain, e.g. open redirects)
    if _SUSPICIOUS_KEYWORDS.search(url):
        if not is_trusted:
            return True

    # Excessively long URL (>200 chars) on UNTRUSTED domains
    if len(url) > 200 and not is_trusted:
        return True

    return False
