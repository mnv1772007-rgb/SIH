"""
IP Extractor — finds all IP addresses in headers, body, and SMTP hop chain.
SIH 26106 — IronPulse | Role 1
"""

from __future__ import annotations

from typing import Optional

from ..schema.forensic_report import ExtractedIp, IpType, SmtpHop
from ..utils.helpers import extract_ips_from_text, classify_ip


class IpExtractor:
    def extract(
        self,
        text_body: Optional[str],
        html_body: Optional[str],
        smtp_path: list[SmtpHop],
        raw_headers: str = "",
    ) -> list[ExtractedIp]:
        """
        Collect all unique IPs from:
          - Raw header block
          - SMTP relay path (already parsed hops)
          - Text/HTML body
        """
        seen: dict[str, ExtractedIp] = {}

        def _add(ip: str, source: str):
            if ip in seen:
                return
            ip_type = IpType(classify_ip(ip))
            seen[ip] = ExtractedIp(ip=ip, ip_type=ip_type, source=source)

        # From SMTP path (most authoritative)
        for hop in smtp_path:
            if hop.from_ip:
                _add(hop.from_ip, "smtp_path")

        # Raw header block
        if raw_headers:
            for ip in extract_ips_from_text(raw_headers):
                _add(ip, "header")

        # Text body
        if text_body:
            for ip in extract_ips_from_text(text_body):
                _add(ip, "body")

        # HTML body
        if html_body:
            for ip in extract_ips_from_text(html_body):
                _add(ip, "body")

        return list(seen.values())
