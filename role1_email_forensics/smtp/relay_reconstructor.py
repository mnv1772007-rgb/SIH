"""
SMTP Relay Reconstructor — parses all Received: headers into an ordered hop chain.
SIH 26106 — IronPulse | Role 1

Received headers are added outermost-first (last hop at top), so we reverse them
to get chronological order (sender → recipient).

Each hop captures:
  from <host> [<ip>]  by <host>  with <protocol>  id <queue-id>  for <rcpt>  ; <timestamp>

Anomaly flags raised:
  - time_skew         : timestamp delta > 300 seconds between hops
  - private_ip        : RFC-1918 IP in a public relay chain
  - protocol_mismatch : unexpected protocol (e.g. HTTP instead of SMTP)
  - timestamp_missing : no parseable timestamp in Received header
"""

from __future__ import annotations

import email.message
import re
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from typing import Optional

from ..schema.forensic_report import SmtpHop
from ..utils.helpers import classify_ip, RECEIVED_IP_RE, extract_ips_from_text


# Regex to parse Received header components
_FROM_RE   = re.compile(r"from\s+([\w.\-\[\]]+)", re.IGNORECASE)
_BY_RE     = re.compile(r"by\s+([\w.\-]+)", re.IGNORECASE)
_WITH_RE   = re.compile(r"with\s+([\w]+(?:TPS?|SMTP[SA]?|HTTP|LMTP)?)", re.IGNORECASE)
_ID_RE     = re.compile(r"\bid\s+([\w.\-]+)", re.IGNORECASE)
_FOR_RE    = re.compile(r"for\s+<([^>]+)>", re.IGNORECASE)
_DATE_RE   = re.compile(r";\s*(.+)$", re.MULTILINE)

_SUSPICIOUS_PROTOCOLS = {"HTTP", "HTTPS", "FTP"}


def reconstruct_relay_path(msg: email.message.Message) -> list[SmtpHop]:
    """
    Parse all Received: headers and return an ordered list of SmtpHop objects.

    Hop 1 = closest to original sender (after reversing the header list).
    """
    raw_received = msg.get_all("Received") or []

    # Received headers are stacked outermost-first, so reverse for chronological order
    raw_received = list(reversed(raw_received))

    hops: list[SmtpHop] = []
    prev_ts: datetime | None = None

    for idx, raw in enumerate(raw_received, start=1):
        hop = _parse_received_header(raw, idx)

        # Time delta between hops
        if hop.timestamp:
            try:
                ts = datetime.fromisoformat(hop.timestamp.replace("Z", "+00:00"))
                if prev_ts:
                    delta = (ts - prev_ts).total_seconds()
                    hop.delay_seconds = round(delta, 1)
                    if abs(delta) > 300:
                        hop.flags.append("time_skew")
                prev_ts = ts
            except Exception:
                pass

        hops.append(hop)

    return hops


# ---------------------------------------------------------------------------
# Per-header parsing
# ---------------------------------------------------------------------------

def _parse_received_header(raw: str, hop_idx: int) -> SmtpHop:
    # Collapse multi-line folded header
    raw = re.sub(r"\r?\n[ \t]+", " ", raw).strip()

    hop = SmtpHop(hop=hop_idx, raw_header=raw)

    # from host [ip]
    m = _FROM_RE.search(raw)
    if m:
        from_part = m.group(1)
        hop.from_host = from_part

    # Extract IP from brackets in from clause: from mail.example.com ([1.2.3.4])
    ips_found = extract_ips_from_text(raw)
    public_ips = [ip for ip in ips_found if classify_ip(ip) == "public"]
    internal_ips = [ip for ip in ips_found if classify_ip(ip) in ("private", "loopback", "link-local", "reserved")]

    if public_ips:
        hop.from_ip = public_ips[0]
    elif internal_ips:
        hop.from_ip = internal_ips[0]
        hop.flags.append("private_ip")
    elif ips_found:
        hop.from_ip = ips_found[0]

    # by host
    m = _BY_RE.search(raw)
    if m:
        hop.by_host = m.group(1)

    # with protocol
    m = _WITH_RE.search(raw)
    if m:
        proto = m.group(1).upper()
        hop.with_protocol = proto
        if proto in _SUSPICIOUS_PROTOCOLS:
            hop.flags.append("protocol_mismatch")

    # id (queue ID)
    m = _ID_RE.search(raw)
    if m:
        hop.id = m.group(1)

    # for <rcpt>
    m = _FOR_RE.search(raw)
    if m:
        hop.for_address = m.group(1)

    # timestamp (after the semicolon at the end)
    m = _DATE_RE.search(raw)
    if m:
        date_str = m.group(1).strip()
        parsed_ts = _parse_ts(date_str)
        if parsed_ts:
            hop.timestamp = parsed_ts
        else:
            hop.flags.append("timestamp_missing")
    else:
        hop.flags.append("timestamp_missing")

    return hop


def _parse_ts(raw: str) -> str | None:
    """Parse a Received: timestamp into ISO 8601 UTC."""
    raw = raw.strip()
    # Remove trailing comment in parens: "Mon, 1 Jan 2024 10:00:00 +0000 (UTC)"
    raw = re.sub(r"\s*\([^)]*\)\s*$", "", raw).strip()
    try:
        dt = parsedate_to_datetime(raw)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None
