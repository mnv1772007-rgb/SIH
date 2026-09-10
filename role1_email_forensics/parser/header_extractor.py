"""
Header Extractor — parses and normalizes all email header fields.
SIH 26106 — IronPulse | Role 1

Extracts:
  From, To, CC, BCC, Reply-To, Return-Path, Subject, Date,
  Message-ID, In-Reply-To, References, X-Originating-IP,
  X-Mailer, X-Spam-*, MIME-Version, Content-Type, custom X-* headers

Detects:
  - From vs Reply-To domain mismatch
  - From vs Return-Path domain mismatch
  - Display-name spoofing (name contains @ sign)
"""

from __future__ import annotations

import email.message
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime, getaddresses

from ..schema.forensic_report import HeaderAnalysis
from ..utils.helpers import decode_mime_words, extract_email_address, get_domain


# Headers we handle explicitly — everything else goes into custom_headers
_KNOWN_HEADERS = {
    "from", "to", "cc", "bcc", "reply-to", "return-path",
    "subject", "date", "message-id", "in-reply-to", "references",
    "x-originating-ip", "x-mailer", "user-agent",
    "x-spam-status", "x-spam-score", "x-spam-flag",
    "mime-version", "content-type", "received",
    "dkim-signature", "arc-seal", "arc-message-signature",
    "arc-authentication-results", "authentication-results",
}


def extract_headers(msg: email.message.Message) -> HeaderAnalysis:
    """Extract and normalize all relevant headers into a HeaderAnalysis object."""

    ha = HeaderAnalysis()

    # ------------------------------------------------------------------ From
    raw_from = msg.get("From", "") or msg.get("from", "") or msg.get("Sender", "")
    display_name, from_addr = extract_email_address(raw_from)
    if not from_addr:
        _, fallback_addr = extract_email_address(msg.get("Sender", "") or msg.get("Return-Path", "") or msg.get("reply-to", ""))
        from_addr = fallback_addr
    ha.from_address       = from_addr
    ha.from_display_name  = display_name

    # ------------------------------------------------------------------ To / CC / BCC
    ha.to  = _parse_address_list(msg.get_all("To", []) or msg.get_all("to", []))
    ha.cc  = _parse_address_list(msg.get_all("CC", []) or msg.get_all("cc", []))
    ha.bcc = _parse_address_list(msg.get_all("BCC", []) or msg.get_all("bcc", []))

    # ------------------------------------------------------------------ Reply-To
    raw_rt = msg.get("Reply-To", "") or msg.get("reply-to", "")
    _, ha.reply_to = extract_email_address(raw_rt)

    # ------------------------------------------------------------------ Return-Path
    raw_rp = msg.get("Return-Path", "") or msg.get("return-path", "")
    _, ha.return_path = extract_email_address(raw_rp)

    # ------------------------------------------------------------------ Subject
    raw_subj = msg.get("Subject", "") or msg.get("subject", "")
    ha.subject = decode_mime_words(raw_subj).strip() or None

    # ------------------------------------------------------------------ Date → UTC ISO 8601
    raw_date = msg.get("Date", "")
    if raw_date:
        ha.date = _parse_date_to_utc(raw_date)

    # ------------------------------------------------------------------ Message-ID
    ha.message_id  = _clean_angle(msg.get("Message-ID"))
    ha.in_reply_to = _clean_angle(msg.get("In-Reply-To"))

    # ------------------------------------------------------------------ References
    refs_raw = msg.get("References", "")
    ha.references = re.findall(r"<[^>]+>", refs_raw)

    # ------------------------------------------------------------------ X-Originating-IP
    xip = msg.get("X-Originating-IP", "") or msg.get("X-Origin-IP", "")
    ha.x_originating_ip = xip.strip().strip("[]") or None

    # ------------------------------------------------------------------ X-Mailer / User-Agent
    ha.x_mailer = (
        msg.get("X-Mailer")
        or msg.get("User-Agent")
        or msg.get("X-Newsreader")
    )

    # ------------------------------------------------------------------ X-Spam
    ha.x_spam_status = msg.get("X-Spam-Status") or msg.get("X-Spam-Flag")
    score_raw = msg.get("X-Spam-Score", "")
    if score_raw:
        try:
            ha.x_spam_score = float(score_raw.strip())
        except ValueError:
            pass

    # ------------------------------------------------------------------ MIME / Content-Type
    ha.mime_version = msg.get("MIME-Version")
    ha.content_type = msg.get("Content-Type")

    # ------------------------------------------------------------------ Custom X-* headers
    for key in msg.keys():
        lower = key.lower()
        if lower not in _KNOWN_HEADERS and lower.startswith("x-"):
            # Keep the latest value for duplicate headers
            ha.custom_headers[key] = decode_mime_words(msg.get(key, ""))

    # ------------------------------------------------------------------ Anomaly detection
    from_domain    = get_domain(ha.from_address)
    rt_domain      = get_domain(ha.reply_to)
    rp_domain      = get_domain(ha.return_path)

    if from_domain and rt_domain and from_domain != rt_domain:
        ha.from_reply_to_mismatch = True

    if from_domain and rp_domain and from_domain != rp_domain:
        ha.from_return_path_mismatch = True

    # Display name spoofing: "alice@evil.com <bob@legit.com>"
    if ha.from_display_name and "@" in ha.from_display_name:
        ha.display_name_spoofing_suspected = True

    return ha


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_address_list(raw_list: list[str]) -> list[str]:
    """Parse a list of raw To/CC/BCC header values into clean email addresses."""
    if not raw_list:
        return []
    decoded = [decode_mime_words(r) for r in raw_list]
    pairs = getaddresses(decoded)
    return [addr for _, addr in pairs if addr]


def _parse_date_to_utc(raw: str) -> str | None:
    """Parse an email Date header string into ISO 8601 UTC."""
    try:
        dt = parsedate_to_datetime(raw)
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return raw.strip() or None


def _clean_angle(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    m = re.search(r"<([^>]+)>", value)
    return m.group(1) if m else value
