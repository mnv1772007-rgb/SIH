"""
DMARC Checker — fetches and evaluates the DMARC policy for a domain.
SIH 26106 — IronPulse | Role 1

Evaluates:
  - _dmarc.<domain> TXT record presence
  - Policy: p=none/quarantine/reject
  - SPF and DKIM alignment
  - Subdomain policy (sp=)
  - Report URIs (rua=, ruf=)
"""

from __future__ import annotations

import email.message
import re
from typing import Optional

import dns.resolver
import dns.exception

from ..schema.forensic_report import (
    DmarcResult_, DmarcResult, DmarcPolicy, SpfResult, DkimResult
)


class DmarcChecker:
    def __init__(self, timeout: float = 5.0):
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout

    def check(
        self,
        from_domain: str,
        spf_result: SpfResult,
        spf_domain: Optional[str],
        dkim_result: DkimResult,
        dkim_domain: Optional[str],
    ) -> DmarcResult_:
        """
        Evaluate DMARC for the From: domain.

        Args:
            from_domain:  Domain from the From: header (the organizational domain)
            spf_result:   Result from SPF check
            spf_domain:   Domain that passed/failed SPF (Return-Path domain)
            dkim_result:  Result from DKIM check
            dkim_domain:  d= domain from DKIM-Signature
        """
        result = DmarcResult_(domain=from_domain)

        # 1. Fetch DMARC record
        record, error = self._fetch_dmarc(from_domain)
        if error:
            result.result = DmarcResult.NONE
            result.error  = error
            return result

        if not record:
            result.result = DmarcResult.NONE
            result.error  = f"No DMARC record at _dmarc.{from_domain}"
            return result

        result.record = record
        tags = _parse_tags(record)

        # 2. Parse policy
        result.policy           = _parse_policy(tags.get("p"))
        result.subdomain_policy = _parse_policy(tags.get("sp"))
        result.pct              = _parse_pct(tags.get("pct"))
        result.rua              = _parse_uris(tags.get("rua", ""))
        result.ruf              = _parse_uris(tags.get("ruf", ""))

        aspf = tags.get("aspf", "r").lower()  # r=relaxed (default), s=strict
        adkim = tags.get("adkim", "r").lower()

        # 3. SPF alignment
        spf_aligned = _check_alignment(from_domain, spf_domain, aspf)
        result.spf_alignment = "pass" if (spf_result == SpfResult.PASS and spf_aligned) else "fail"

        # 4. DKIM alignment
        dkim_aligned = _check_alignment(from_domain, dkim_domain, adkim)
        result.dkim_alignment = "pass" if (dkim_result == DkimResult.PASS and dkim_aligned) else "fail"

        # 5. DMARC result: pass if either SPF or DKIM aligned
        if result.spf_alignment == "pass" or result.dkim_alignment == "pass":
            result.result = DmarcResult.PASS
        else:
            result.result = DmarcResult.FAIL

        return result

    # ------------------------------------------------------------------

    def _fetch_dmarc(self, domain: str) -> tuple[str | None, str | None]:
        """Try _dmarc.<domain> then _dmarc.<org_domain>."""
        for target in [domain, _org_domain(domain)]:
            dns_name = f"_dmarc.{target}"
            try:
                answers = self._resolver.resolve(dns_name, "TXT")
                for rdata in answers:
                    txt = "".join(
                        s.decode() if isinstance(s, bytes) else s
                        for s in rdata.strings
                    )
                    if txt.strip().lower().startswith("v=dmarc1"):
                        return txt, None
            except dns.resolver.NXDOMAIN:
                continue
            except dns.resolver.NoAnswer:
                continue
            except dns.exception.Timeout:
                return None, f"DNS timeout querying {dns_name}"
            except Exception as e:
                return None, str(e)
        return None, None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for m in re.finditer(r"(\w+)\s*=\s*([^;]+)", record):
        tags[m.group(1).strip().lower()] = m.group(2).strip()
    return tags


def _parse_policy(value: str | None) -> DmarcPolicy | None:
    if not value:
        return None
    v = value.strip().lower()
    return {"none": DmarcPolicy.NONE,
            "quarantine": DmarcPolicy.QUARANTINE,
            "reject": DmarcPolicy.REJECT}.get(v)


def _parse_pct(value: str | None) -> int | None:
    if not value:
        return 100
    try:
        return int(value.strip())
    except ValueError:
        return None


def _parse_uris(value: str) -> list[str]:
    return [u.strip() for u in value.split(",") if u.strip()]


def _check_alignment(from_domain: str, auth_domain: str | None, mode: str) -> bool:
    """
    Check SPF/DKIM alignment.
    Relaxed (r): auth_domain must share the same organizational domain.
    Strict  (s): auth_domain must exactly match from_domain.
    """
    if not auth_domain:
        return False
    if mode == "s":
        return from_domain.lower() == auth_domain.lower()
    # Relaxed: compare org domains
    return _org_domain(from_domain) == _org_domain(auth_domain)


def _org_domain(domain: str) -> str:
    """Return the organizational domain (last two labels)."""
    parts = domain.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain
