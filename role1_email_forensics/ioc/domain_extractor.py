"""
Domain Extractor — extracts domains from email headers and body, detects
homoglyph/IDN and typosquatting lookalikes.
SIH 26106 — IronPulse | Role 1
"""

from __future__ import annotations

import re
from typing import Optional

import tldextract

from ..schema.forensic_report import ExtractedDomain, HeaderAnalysis, ExtractedUrl
from ..utils.helpers import has_homoglyph, is_typosquat


class DomainExtractor:
    def extract(
        self,
        headers: HeaderAnalysis,
        urls: list[ExtractedUrl],
        text_body: Optional[str],
        html_body: Optional[str],
    ) -> list[ExtractedDomain]:
        """
        Collect unique domains from:
          - Email address header fields (From, To, Reply-To, Return-Path)
          - URLs already extracted
          - Body text (inline domain mentions)
        """
        seen: dict[str, ExtractedDomain] = {}

        def _add(domain: str, source: str):
            if not domain or domain in seen:
                return
            ex = tldextract.extract(domain)
            reg = getattr(ex, "top_domain_under_public_suffix", None) or ex.registered_domain or domain
            ed = ExtractedDomain(
                domain=domain,
                registered_domain=reg or None,
                tld=ex.suffix or None,
                subdomain=ex.subdomain or None,
                source=source,
                homoglyph_suspected=has_homoglyph(domain),
                typosquat_suspected=is_typosquat(domain),
            )
            seen[domain] = ed

        # From email header addresses
        for addr in _all_email_addresses(headers):
            if "@" in addr:
                domain = addr.split("@", 1)[1].lower().strip()
                _add(domain, "header")

        # From URLs
        for u in urls:
            if u.domain:
                _add(u.domain, "url")

        # From body text — domain-like patterns
        body = (text_body or "") + " " + (html_body or "")
        for domain in _find_domains_in_text(body):
            _add(domain, "body")

        return list(seen.values())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|edu|gov|io|co|uk|de|ru|cn|info|biz|xyz|tk|ml|"
    r"ga|cf|top|work|online|site|click|link|app|dev|cloud)\b",
    re.IGNORECASE,
)


def _find_domains_in_text(text: str) -> list[str]:
    return list({m.lower() for m in _DOMAIN_RE.findall(text)})


def _all_email_addresses(h: HeaderAnalysis) -> list[str]:
    addrs = []
    if h.from_address:
        addrs.append(h.from_address)
    if h.reply_to:
        addrs.append(h.reply_to)
    if h.return_path:
        addrs.append(h.return_path)
    addrs.extend(h.to)
    addrs.extend(h.cc)
    return [a for a in addrs if a]
