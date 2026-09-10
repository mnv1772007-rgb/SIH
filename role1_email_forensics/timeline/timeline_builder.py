"""
role1_email_forensics/timeline/timeline_builder.py
Forensic timeline reconstruction.
SIH 26106 - IronPulse | Role 1

Builds a list of chronological forensic events from a ForensicReport.
Each event has: timestamp, category, event_type, description, severity, metadata.
All timestamps are ISO-8601 strings. Unknown timestamps use the report analyzed_at time.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_iso(value: Any) -> str:
    """Return a best-effort ISO timestamp string."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if isinstance(value, str) and value:
        return value
    return ""


def build_timeline(report: Any) -> list[dict[str, Any]]:
    """
    Build a forensic timeline from a ForensicReport object.
    Returns events sorted by timestamp (ascending). Events without a known
    timestamp are placed at the end, using the report analysis time.
    """
    events: list[dict[str, Any]] = []
    fallback_ts = _safe_iso(getattr(report, "analyzed_at", None)) or _now_iso()

    # ---- 1. Email compose / send time (Date header) -----------------------
    header_date = _safe_iso(getattr(report.headers, "date", None))
    events.append({
        "timestamp": header_date or fallback_ts,
        "category": "email",
        "event_type": "EMAIL_COMPOSED",
        "description": (
            f"Email composed by {report.headers.from_address or 'unknown sender'} "
            f"with subject: {(report.headers.subject or 'No Subject')[:60]}"
        ),
        "severity": "info",
        "metadata": {
            "from": report.headers.from_address,
            "subject": report.headers.subject,
            "message_id": report.headers.message_id,
        },
    })

    # ---- 2. SMTP hop events -----------------------------------------------
    hops = sorted(
        getattr(report, "smtp_path", []),
        key=lambda h: getattr(h, "hop", 0),
    )
    for hop in hops:
        hop_ts = _safe_iso(getattr(hop, "timestamp", None)) or fallback_ts
        flags = getattr(hop, "flags", [])
        hop_label = getattr(hop, "by_host", None) or getattr(hop, "from_host", None) or f"Relay-{hop.hop}"
        delay = getattr(hop, "delay_seconds", None)
        severity = "info"
        if "time_skew" in flags:
            severity = "medium"
        if "private_ip" in flags:
            severity = "low"

        desc = f"Email relayed via SMTP hop {hop.hop}: {hop_label}"
        if delay is not None and delay > 300:
            desc += f" (delay: {delay}s — time skew detected)"
        elif delay is not None:
            desc += f" (delay: {delay}s)"

        events.append({
            "timestamp": hop_ts,
            "category": "smtp",
            "event_type": f"SMTP_HOP_{hop.hop}",
            "description": desc,
            "severity": severity,
            "metadata": {
                "hop": hop.hop,
                "from_host": getattr(hop, "from_host", None),
                "from_ip": getattr(hop, "from_ip", None),
                "by_host": getattr(hop, "by_host", None),
                "protocol": getattr(hop, "with_protocol", None),
                "delay_seconds": delay,
                "flags": flags,
            },
        })

    # ---- 3. Authentication verdicts ---------------------------------------
    spf_result = str(getattr(report.auth.spf, "result", "none"))
    if hasattr(report.auth.spf.result, "value"):
        spf_result = report.auth.spf.result.value
    spf_fail = spf_result in ("fail", "softfail")

    events.append({
        "timestamp": fallback_ts,
        "category": "auth",
        "event_type": "SPF_CHECK",
        "description": f"SPF check result: {spf_result.upper()} for domain {getattr(report.auth.spf, 'domain', 'unknown')}",
        "severity": "high" if spf_result == "fail" else ("medium" if spf_result == "softfail" else "info"),
        "metadata": {
            "result": spf_result,
            "domain": getattr(report.auth.spf, "domain", None),
            "ip": getattr(report.auth.spf, "ip_checked", None),
            "record": getattr(report.auth.spf, "record", None),
        },
    })

    dkim_result = str(getattr(report.auth.dkim, "result", "none"))
    if hasattr(report.auth.dkim.result, "value"):
        dkim_result = report.auth.dkim.result.value

    events.append({
        "timestamp": fallback_ts,
        "category": "auth",
        "event_type": "DKIM_CHECK",
        "description": f"DKIM signature check: {dkim_result.upper()} (selector={getattr(report.auth.dkim, 'selector', 'N/A')})",
        "severity": "high" if dkim_result == "fail" else "info",
        "metadata": {
            "result": dkim_result,
            "selector": getattr(report.auth.dkim, "selector", None),
            "error": getattr(report.auth.dkim, "error", None),
        },
    })

    dmarc_result = str(getattr(report.auth.dmarc, "result", "none"))
    if hasattr(report.auth.dmarc.result, "value"):
        dmarc_result = report.auth.dmarc.result.value

    events.append({
        "timestamp": fallback_ts,
        "category": "auth",
        "event_type": "DMARC_CHECK",
        "description": f"DMARC policy check: {dmarc_result.upper()} (policy={getattr(report.auth.dmarc, 'policy', 'none')})",
        "severity": "high" if dmarc_result == "fail" else "info",
        "metadata": {
            "result": dmarc_result,
            "policy": str(getattr(report.auth.dmarc, "policy", "none")),
            "domain": getattr(report.auth.dmarc, "domain", None),
        },
    })

    # ---- 4. Header anomalies ---------------------------------------------
    h = report.headers
    if getattr(h, "from_reply_to_mismatch", False):
        events.append({
            "timestamp": fallback_ts,
            "category": "header",
            "event_type": "REPLY_TO_MISMATCH",
            "description": f"Reply-To domain mismatch detected: From={h.from_address}, Reply-To={h.reply_to}",
            "severity": "medium",
            "metadata": {"from": h.from_address, "reply_to": h.reply_to},
        })

    if getattr(h, "from_return_path_mismatch", False):
        events.append({
            "timestamp": fallback_ts,
            "category": "header",
            "event_type": "RETURN_PATH_MISMATCH",
            "description": f"Return-Path mismatch: From={h.from_address}, Return-Path={h.return_path}",
            "severity": "medium",
            "metadata": {"from": h.from_address, "return_path": h.return_path},
        })

    if getattr(h, "display_name_spoofing_suspected", False):
        events.append({
            "timestamp": fallback_ts,
            "category": "header",
            "event_type": "DISPLAY_NAME_SPOOFING",
            "description": f"Display-name identity spoofing suspected: '{h.from_display_name}'",
            "severity": "high",
            "metadata": {"display_name": h.from_display_name},
        })

    # ---- 5. IOC discoveries -----------------------------------------------
    for url_obj in getattr(report.iocs, "urls", []):
        if getattr(url_obj, "suspicious", False):
            events.append({
                "timestamp": fallback_ts,
                "category": "ioc",
                "event_type": "SUSPICIOUS_URL_FOUND",
                "description": f"Suspicious URL extracted from email body: {getattr(url_obj, 'defanged', url_obj.url)}",
                "severity": "high",
                "metadata": {
                    "url": getattr(url_obj, "url", None),
                    "defanged": getattr(url_obj, "defanged", None),
                    "domain": getattr(url_obj, "domain", None),
                },
            })

    for att in getattr(report.iocs, "attachments", []):
        sev = "critical" if getattr(att, "is_executable", False) else "medium"
        events.append({
            "timestamp": fallback_ts,
            "category": "ioc",
            "event_type": "ATTACHMENT_FOUND",
            "description": f"Attachment detected: {att.filename} ({att.content_type})",
            "severity": sev,
            "metadata": {
                "filename": att.filename,
                "content_type": att.content_type,
                "size_bytes": getattr(att, "size_bytes", None),
                "sha256": getattr(att, "sha256", None),
                "is_executable": getattr(att, "is_executable", False),
            },
        })

    # ---- 6. Origin / IP event -------------------------------------------
    origin_ip = getattr(report.origin, "probable_sending_ip", None)
    if origin_ip:
        country = getattr(report.origin, "country_name", None) or getattr(report.origin, "country_code", "Unknown")
        is_tor = getattr(report.origin, "is_tor", False)
        is_vpn = getattr(report.origin, "is_vpn_suspected", False)
        sev = "critical" if is_tor else ("high" if is_vpn else "info")
        desc = f"Email origin IP identified: {origin_ip} ({country})"
        if is_tor:
            desc += " — Tor exit node"
        if is_vpn:
            desc += " — VPN/anonymizer suspected"
        events.append({
            "timestamp": fallback_ts,
            "category": "origin",
            "event_type": "ORIGIN_IP_IDENTIFIED",
            "description": desc,
            "severity": sev,
            "metadata": {
                "ip": origin_ip,
                "country": country,
                "asn": getattr(report.origin, "asn", None),
                "is_tor": is_tor,
                "is_vpn": is_vpn,
            },
        })

    # ---- 7. Analysis completion event ------------------------------------
    events.append({
        "timestamp": fallback_ts,
        "category": "system",
        "event_type": "FORENSIC_ANALYSIS_COMPLETE",
        "description": "Forensic analysis pipeline completed. Report generated.",
        "severity": "info",
        "metadata": {"report_id": getattr(report, "report_id", None)},
    })

    # ---- Sort by timestamp (non-empty timestamps first, then empties) ----
    def sort_key(e: dict) -> str:
        ts = e.get("timestamp") or "9999"
        return ts

    events.sort(key=sort_key)
    return events
