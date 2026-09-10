"""
Origin Inferencer — identifies the probable sending infrastructure.
SIH 26106 — IronPulse | Role 1

Strategy:
  1. Walk the SMTP hop chain from hop 1 (sender-side) forward.
  2. Find the first hop with a PUBLIC IP that is NOT one of the
     recipient's known mail servers (i.e., not the "by" host).
  3. Perform ASN/Org lookup on that IP using ipwhois.
  4. Mark confidence based on hop position and data quality.

⚠️  DISCLAIMER:
  The IP identified here is the probable SENDING MTA infrastructure —
  the mail server that injected the email into the internet.
  This is NOT the attacker's physical location or identity.
  IP geolocation and ASN data are probabilistic estimates.
"""

from __future__ import annotations

from typing import Optional

from ..schema.forensic_report import OriginInference, OriginConfidence, SmtpHop
from ..utils.helpers import classify_ip


# Cloud/hosting ASN name fragments (heuristic)
_CLOUD_KEYWORDS = {
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
    "linode", "vultr", "hetzner", "ovh", "cloudflare", "fastly",
    "akamai", "rackspace", "alibaba", "tencent",
}

_VPN_KEYWORDS = {
    "vpn", "nordvpn", "expressvpn", "mullvad", "protonvpn",
    "private internet", "pia ", "surfshark", "cyberghost",
    "anonymizer", "hide.me",
}


class OriginInferencer:
    def infer(self, smtp_path: list[SmtpHop]) -> OriginInference:
        """
        Determine the probable origin (first external MTA).

        Looks for the first hop that has a public from_ip.
        Falls back to hop 1's from_host if no IP is available.
        """
        result = OriginInference()

        if not smtp_path:
            result.confidence = OriginConfidence.LOW
            result.error = "No SMTP relay path available"  # type: ignore[attr-defined]
            return result

        # Find first hop with a public IP
        candidate_hop: SmtpHop | None = None
        for hop in smtp_path:
            if hop.from_ip and classify_ip(hop.from_ip) == "public":
                candidate_hop = hop
                break

        if not candidate_hop:
            # Fallback: use hop 1 host info only
            hop0 = smtp_path[0]
            result.probable_sending_host = hop0.from_host
            result.confidence             = OriginConfidence.LOW
            return result

        result.probable_sending_ip   = candidate_hop.from_ip
        result.probable_sending_host = candidate_hop.from_host

        # Confidence: higher if it's hop 1 (closest to sender)
        hop_pos = candidate_hop.hop
        if hop_pos == 1:
            result.confidence = OriginConfidence.HIGH
        elif hop_pos == 2:
            result.confidence = OriginConfidence.MEDIUM
        else:
            result.confidence = OriginConfidence.LOW

        # IP enrichment via ipwhois
        if result.probable_sending_ip:
            self._enrich_ip(result, result.probable_sending_ip)

        return result

    # ------------------------------------------------------------------

    def _enrich_ip(self, result: OriginInference, ip: str) -> None:
        try:
            from ipwhois import IPWhois
            obj  = IPWhois(ip)
            data = obj.lookup_rdap(depth=1, retry_count=2)

            asn_data = data.get("asn_description", "") or ""
            result.asn       = f"AS{data.get('asn', '')}" if data.get("asn") else None
            result.asn_org   = asn_data
            result.country_code = data.get("asn_country_code")

            # Try reverse DNS
            result.rdns = self._rdns(ip)

            # Heuristic: is this a cloud provider?
            org_lower = asn_data.lower()
            result.is_cloud_provider = any(k in org_lower for k in _CLOUD_KEYWORDS)
            result.is_vpn_suspected  = any(k in org_lower for k in _VPN_KEYWORDS)

            # Country name from network objects
            network = data.get("network", {}) or {}
            country = network.get("country") or result.country_code
            result.country_name = country

            # ISP
            objects = data.get("objects", {}) or {}
            for obj_key, obj_val in objects.items():
                contact = (obj_val or {}).get("contact", {}) or {}
                name = contact.get("name")
                if name:
                    result.isp = name
                    break

        except ImportError:
            pass  # ipwhois not installed
        except Exception as e:
            # Non-fatal: enrich what we can
            pass

    @staticmethod
    def _rdns(ip: str) -> str | None:
        try:
            import dns.resolver
            import dns.reversename
            rev = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev, "PTR", lifetime=3)
            return str(answers[0]).rstrip(".")
        except Exception:
            return None
