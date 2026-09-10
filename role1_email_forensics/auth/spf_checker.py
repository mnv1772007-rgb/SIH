"""
SPF Checker — DNS-based SPF record resolution and validation.
SIH 26106 — IronPulse | Role 1

Validates the sending IP against the domain's SPF record.
Returns: pass / fail / softfail / neutral / none / temperror / permerror
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

import dns.resolver
import dns.exception

from ..schema.forensic_report import SpfResult_
from ..schema.forensic_report import SpfResult as SpfResultEnum


# Max DNS lookups per RFC 7208 §4.6.4
_MAX_LOOKUPS = 10


class SpfChecker:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout

    def check(self, sender_domain: str, sender_ip: str) -> SpfResult_:
        """
        Evaluate SPF for (sender_domain, sender_ip).

        Returns a SpfResult_ with result, domain, ip_checked, raw record.
        """
        result = SpfResult_(domain=sender_domain, ip_checked=sender_ip)

        # 1. Fetch SPF TXT record
        record, error = self._fetch_spf_record(sender_domain)
        if error:
            result.result = SpfResultEnum.TEMPERROR if "timeout" in error.lower() else SpfResultEnum.NONE
            result.explanation = error
            return result

        if not record:
            result.result = SpfResultEnum.NONE
            result.explanation = "No SPF record found"
            return result

        result.record = record

        # 2. Evaluate
        outcome, explanation = self._evaluate(record, sender_ip, sender_domain, lookups=[0])
        result.result      = outcome
        result.explanation = explanation
        return result

    # ------------------------------------------------------------------

    def _fetch_spf_record(self, domain: str) -> tuple[str | None, str | None]:
        try:
            answers = self._resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s
                              for s in rdata.strings)
                if txt.lower().startswith("v=spf1"):
                    return txt, None
            return None, None
        except dns.resolver.NXDOMAIN:
            return None, f"NXDOMAIN for {domain}"
        except dns.resolver.NoAnswer:
            return None, None
        except dns.exception.Timeout:
            return None, f"DNS timeout querying {domain}"
        except Exception as e:
            return None, str(e)

    def _evaluate(
        self,
        record: str,
        ip: str,
        domain: str,
        lookups: list[int],
    ) -> tuple[SpfResultEnum, str]:
        """Parse and evaluate SPF mechanisms left-to-right."""

        mechanisms = record.split()[1:]  # skip v=spf1

        for mech in mechanisms:
            qualifier = "+"  # default pass
            if mech[0] in ("+", "-", "~", "?"):
                qualifier = mech[0]
                mech = mech[1:]

            mech_lower = mech.lower()

            if mech_lower == "all":
                return _qualifier_to_result(qualifier), f"Matched 'all' mechanism"

            elif mech_lower == "a" or mech_lower.startswith("a:") or mech_lower.startswith("a/"):
                target = mech[2:] if ":" in mech else domain
                if self._match_a(target, ip, lookups):
                    return _qualifier_to_result(qualifier), f"Matched 'a' mechanism for {target}"

            elif mech_lower.startswith("mx") :
                target = mech[3:] if mech_lower.startswith("mx:") else domain
                if self._match_mx(target, ip, lookups):
                    return _qualifier_to_result(qualifier), f"Matched 'mx' mechanism for {target}"

            elif mech_lower.startswith("ip4:"):
                cidr = mech[4:]
                if self._match_ip4(cidr, ip):
                    return _qualifier_to_result(qualifier), f"Matched ip4:{cidr}"

            elif mech_lower.startswith("ip6:"):
                cidr = mech[4:]
                if self._match_ip6(cidr, ip):
                    return _qualifier_to_result(qualifier), f"Matched ip6:{cidr}"

            elif mech_lower.startswith("include:"):
                included_domain = mech[8:]
                lookups[0] += 1
                if lookups[0] > _MAX_LOOKUPS:
                    return SpfResultEnum.PERMERROR, "Too many DNS lookups (>10)"
                sub_record, err = self._fetch_spf_record(included_domain)
                if err or not sub_record:
                    continue
                sub_result, _ = self._evaluate(sub_record, ip, included_domain, lookups)
                if sub_result == SpfResultEnum.PASS:
                    return _qualifier_to_result(qualifier), f"Matched include:{included_domain}"

            elif mech_lower.startswith("redirect="):
                redirect_domain = mech[9:]
                lookups[0] += 1
                if lookups[0] > _MAX_LOOKUPS:
                    return SpfResultEnum.PERMERROR, "Too many DNS lookups (>10)"
                sub_record, err = self._fetch_spf_record(redirect_domain)
                if err:
                    return SpfResultEnum.TEMPERROR, err
                if not sub_record:
                    return SpfResultEnum.PERMERROR, f"No SPF on redirect domain {redirect_domain}"
                return self._evaluate(sub_record, ip, redirect_domain, lookups)

            elif mech_lower == "ptr":
                # RFC 7208 discourages ptr; skip
                pass

            elif mech_lower.startswith("exists:"):
                # exists mechanism — skip for now (rare)
                pass

        # No match
        return SpfResultEnum.NEUTRAL, "No mechanism matched"

    # ------------------------------------------------------------------

    def _match_ip4(self, cidr: str, ip: str) -> bool:
        try:
            if "/" not in cidr:
                return str(ipaddress.ip_address(cidr)) == ip
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

    def _match_ip6(self, cidr: str, ip: str) -> bool:
        try:
            if "/" not in cidr:
                return str(ipaddress.ip_address(cidr)) == ip
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

    def _match_a(self, domain: str, ip: str, lookups: list[int]) -> bool:
        lookups[0] += 1
        try:
            answers = self._resolver.resolve(domain, "A")
            return any(str(r) == ip for r in answers)
        except Exception:
            return False

    def _match_mx(self, domain: str, ip: str, lookups: list[int]) -> bool:
        lookups[0] += 1
        try:
            mx_answers = self._resolver.resolve(domain, "MX")
            for mx in mx_answers:
                mx_host = str(mx.exchange).rstrip(".")
                try:
                    a_answers = self._resolver.resolve(mx_host, "A")
                    if any(str(r) == ip for r in a_answers):
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False


# ---------------------------------------------------------------------------

def _qualifier_to_result(q: str) -> SpfResultEnum:
    return {
        "+": SpfResultEnum.PASS,
        "-": SpfResultEnum.FAIL,
        "~": SpfResultEnum.SOFTFAIL,
        "?": SpfResultEnum.NEUTRAL,
    }.get(q, SpfResultEnum.NEUTRAL)
