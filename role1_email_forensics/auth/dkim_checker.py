"""
DKIM Checker — verifies DKIM-Signature header cryptographic integrity.
SIH 26106 — IronPulse | Role 1

Uses dkimpy for verification when available; falls back to manual DNS + cryptography
for environments where dkimpy is unavailable.

Checks:
  - Signature presence
  - DNS key record retrieval
  - RSA / Ed25519 signature validity
  - Header + body hash correctness
"""

from __future__ import annotations

import base64
import email.message
import re
from typing import Optional

import dns.resolver
import dns.exception

from ..schema.forensic_report import DkimResult_, DkimResult


class DkimChecker:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout

    def check(self, msg: email.message.Message, raw_email: bytes) -> DkimResult_:
        """
        Verify the DKIM-Signature of the email.

        Args:
            msg:       Parsed email.message.Message
            raw_email: Raw bytes of the original email (required for signature verification)

        Returns:
            DkimResult_ with result, domain, selector, algorithm, key_bits, error
        """
        result = DkimResult_()

        sig_header = msg.get("DKIM-Signature", "")
        if not sig_header:
            result.result = DkimResult.NONE
            result.error  = "No DKIM-Signature header found"
            return result

        # Parse DKIM-Signature tag=value pairs
        tags = _parse_dkim_tags(sig_header)
        result.domain   = tags.get("d")
        result.selector = tags.get("s")
        result.algorithm = tags.get("a")

        # ------------------------------------------------------------------
        # Try dkimpy first (most reliable)
        # ------------------------------------------------------------------
        try:
            import dkim  # type: ignore
            valid = dkim.verify(raw_email, timeout=self.timeout)
            result.result    = DkimResult.PASS if valid else DkimResult.FAIL
            result.body_hash = tags.get("bh")
            if not valid:
                result.error = "Signature verification failed"
            # Try to get key bits
            key_bits = self._get_key_bits(result.selector, result.domain)
            if key_bits:
                result.key_bits = key_bits
            return result
        except ImportError:
            pass  # dkimpy not installed — fall through to manual check
        except Exception as e:
            result.result = DkimResult.FAIL
            result.error  = f"dkimpy error: {e}"
            return result

        # ------------------------------------------------------------------
        # Manual verification fallback
        # ------------------------------------------------------------------
        return self._manual_verify(tags, raw_email, result)

    # ------------------------------------------------------------------

    def _manual_verify(
        self, tags: dict[str, str], raw_email: bytes, result: DkimResult_
    ) -> DkimResult_:
        """
        Manual DKIM verification:
        1. Fetch the public key from DNS
        2. Decode the signature value
        3. Reconstruct signed data
        4. Verify with cryptography library
        """
        selector = tags.get("s")
        domain   = tags.get("d")
        alg      = tags.get("a", "rsa-sha256").lower()
        sig_b64  = (tags.get("b") or "").replace(" ", "").replace("\t", "")
        bh       = tags.get("bh")
        result.body_hash = bh

        if not selector or not domain:
            result.result = DkimResult.FAIL
            result.error  = "Missing 'd' or 's' tag in DKIM-Signature"
            return result

        # Fetch DNS key record
        dns_name = f"{selector}._domainkey.{domain}"
        try:
            answers = self._resolver.resolve(dns_name, "TXT")
            key_record = ""
            for rdata in answers:
                key_record = "".join(
                    s.decode() if isinstance(s, bytes) else s
                    for s in rdata.strings
                )
                if "p=" in key_record:
                    break
        except dns.resolver.NXDOMAIN:
            result.result = DkimResult.FAIL
            result.error  = f"NXDOMAIN for DKIM key record {dns_name}"
            return result
        except dns.exception.Timeout:
            result.result = DkimResult.NONE
            result.error  = "DNS timeout fetching DKIM key"
            return result
        except Exception as e:
            result.result = DkimResult.NONE
            result.error  = str(e)
            return result

        # Parse key record tags
        key_tags = _parse_dkim_tags(key_record)
        p = key_tags.get("p", "").replace(" ", "").replace("\t", "")

        if not p:
            result.result = DkimResult.FAIL
            result.error  = "Key record has empty p= (key revoked)"
            return result

        try:
            pub_key_der = base64.b64decode(p)
        except Exception:
            result.result = DkimResult.FAIL
            result.error  = "Could not base64-decode public key"
            return result

        # Determine key bits
        try:
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            pub_key = load_der_public_key(pub_key_der)
            if hasattr(pub_key, "key_size"):
                result.key_bits = pub_key.key_size
        except Exception:
            pass

        # Decode signature bytes
        try:
            sig_bytes = base64.b64decode(sig_b64)
        except Exception:
            result.result = DkimResult.FAIL
            result.error  = "Could not base64-decode signature"
            return result

        # We can report key info but full manual crypto verification
        # requires reconstructing the canonicalized header/body.
        # For the SIH demo: report as "unverified" with key info present.
        result.result = DkimResult.NONE
        result.error  = (
            "dkimpy not installed; manual full verification unavailable. "
            "Key record fetched successfully — install dkimpy for full verification."
        )
        return result

    def _get_key_bits(self, selector: str | None, domain: str | None) -> int | None:
        if not selector or not domain:
            return None
        try:
            dns_name = f"{selector}._domainkey.{domain}"
            answers  = self._resolver.resolve(dns_name, "TXT")
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                tags = _parse_dkim_tags(txt)
                p = tags.get("p", "").replace(" ", "")
                if p:
                    from cryptography.hazmat.primitives.serialization import load_der_public_key
                    pub_key = load_der_public_key(base64.b64decode(p))
                    if hasattr(pub_key, "key_size"):
                        return pub_key.key_size
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_dkim_tags(header: str) -> dict[str, str]:
    """Parse DKIM tag=value; pairs from a header or TXT record."""
    tags: dict[str, str] = {}
    for m in re.finditer(r"(\w+)\s*=\s*([^;]+)", header):
        tags[m.group(1).strip()] = m.group(2).strip()
    return tags
