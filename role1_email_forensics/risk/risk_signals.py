"""
Risk Signal Engine — generates risk signals from forensic analysis results.
SIH 26106 — IronPulse | Role 1

This module evaluates the parsed forensic data and produces structured
RiskSignal objects that Role 2 (AI/ML) and Role 6 (Dashboard) consume.
"""

from __future__ import annotations

from ..schema.forensic_report import (
    ForensicReport, RiskSignal, RiskLevel,
    SpfResult, DkimResult, DmarcResult,
)
from ..utils.helpers import make_signal_id


def generate_risk_signals(report: ForensicReport) -> list[RiskSignal]:
    """Evaluate the report and return a list of risk signals."""
    signals: list[RiskSignal] = []

    # ---------------------------------------------------------------- Auth signals
    spf = report.auth.spf
    if spf.result in (SpfResult.FAIL, SpfResult.SOFTFAIL):
        signals.append(RiskSignal(
            signal_id=make_signal_id("auth"),
            level=RiskLevel.HIGH if spf.result == SpfResult.FAIL else RiskLevel.MEDIUM,
            category="auth",
            description=f"SPF {spf.result.value.upper()} — sending IP not authorized by domain",
            evidence={"spf_result": spf.result.value, "domain": spf.domain, "ip": spf.ip_checked},
        ))
    if spf.result == SpfResult.NONE:
        signals.append(RiskSignal(
            signal_id=make_signal_id("auth"),
            level=RiskLevel.LOW,
            category="auth",
            description="No SPF record published — cannot validate sender",
            evidence={"domain": spf.domain},
        ))

    dkim = report.auth.dkim
    if dkim.result == DkimResult.FAIL:
        signals.append(RiskSignal(
            signal_id=make_signal_id("auth"),
            level=RiskLevel.HIGH,
            category="auth",
            description="DKIM signature verification FAILED — message may be tampered",
            evidence={"domain": dkim.domain, "selector": dkim.selector, "error": dkim.error},
        ))
    if dkim.result == DkimResult.NONE:
        signals.append(RiskSignal(
            signal_id=make_signal_id("auth"),
            level=RiskLevel.LOW,
            category="auth",
            description="No DKIM signature found",
            evidence={"domain": report.headers.from_address},
        ))

    dmarc = report.auth.dmarc
    if dmarc.result == DmarcResult.FAIL:
        signals.append(RiskSignal(
            signal_id=make_signal_id("auth"),
            level=RiskLevel.HIGH,
            category="auth",
            description=f"DMARC FAILED — policy={dmarc.policy}",
            evidence={"policy": str(dmarc.policy), "spf_align": dmarc.spf_alignment,
                      "dkim_align": dmarc.dkim_alignment},
        ))
    if dmarc.result == DmarcResult.NONE:
        signals.append(RiskSignal(
            signal_id=make_signal_id("auth"),
            level=RiskLevel.LOW,
            category="auth",
            description="No DMARC record — domain has no email policy enforcement",
            evidence={"domain": dmarc.domain},
        ))

    # DKIM weak key
    if dkim.key_bits and dkim.key_bits < 1024:
        signals.append(RiskSignal(
            signal_id=make_signal_id("auth"),
            level=RiskLevel.MEDIUM,
            category="auth",
            description=f"DKIM key is weak ({dkim.key_bits} bits < 1024)",
            evidence={"key_bits": dkim.key_bits},
        ))

    # ---------------------------------------------------------------- Header signals
    h = report.headers
    if h.from_reply_to_mismatch:
        signals.append(RiskSignal(
            signal_id=make_signal_id("header"),
            level=RiskLevel.MEDIUM,
            category="header",
            description="From domain ≠ Reply-To domain — potential reply hijacking",
            evidence={"from": h.from_address, "reply_to": h.reply_to},
        ))
    if h.from_return_path_mismatch:
        signals.append(RiskSignal(
            signal_id=make_signal_id("header"),
            level=RiskLevel.MEDIUM,
            category="header",
            description="From domain ≠ Return-Path domain — potential spoofing",
            evidence={"from": h.from_address, "return_path": h.return_path},
        ))
    if h.display_name_spoofing_suspected:
        signals.append(RiskSignal(
            signal_id=make_signal_id("header"),
            level=RiskLevel.HIGH,
            category="header",
            description="Display name contains '@' — possible identity spoofing",
            evidence={"display_name": h.from_display_name},
        ))
    if h.x_spam_status and ("yes" in str(h.x_spam_status).lower() or (h.x_spam_score and h.x_spam_score >= 5.0)):
        signals.append(RiskSignal(
            signal_id=make_signal_id("header"),
            level=RiskLevel.HIGH,
            category="header",
            description=f"Upstream MTA flagged message as spam (score={h.x_spam_score or h.x_spam_status})",
            evidence={"x_spam_status": h.x_spam_status, "x_spam_score": h.x_spam_score},
        ))
    if h.x_priority and str(h.x_priority).strip().startswith("1"):
        signals.append(RiskSignal(
            signal_id=make_signal_id("header"),
            level=RiskLevel.MEDIUM,
            category="header",
            description="Message marked with highest priority flag (urgency coercion tactic)",
            evidence={"x_priority": h.x_priority},
        ))

    # ---------------------------------------------------------------- SMTP path signals
    for hop in report.smtp_path:
        if "time_skew" in hop.flags:
            signals.append(RiskSignal(
                signal_id=make_signal_id("smtp"),
                level=RiskLevel.MEDIUM,
                category="smtp",
                description=f"Time skew >5 min at hop {hop.hop} ({hop.delay_seconds}s)",
                evidence={"hop": hop.hop, "delay_seconds": hop.delay_seconds,
                          "from": hop.from_host, "by": hop.by_host},
            ))
        if "private_ip" in hop.flags:
            signals.append(RiskSignal(
                signal_id=make_signal_id("smtp"),
                level=RiskLevel.LOW,
                category="smtp",
                description=f"Private IP found in public SMTP relay chain at hop {hop.hop}",
                evidence={"hop": hop.hop, "ip": hop.from_ip},
            ))
        if "protocol_mismatch" in hop.flags:
            signals.append(RiskSignal(
                signal_id=make_signal_id("smtp"),
                level=RiskLevel.MEDIUM,
                category="smtp",
                description=f"Non-SMTP protocol at hop {hop.hop}: {hop.with_protocol}",
                evidence={"hop": hop.hop, "protocol": hop.with_protocol},
            ))

    # ---------------------------------------------------------------- IOC signals
    for url in report.iocs.urls:
        if url.suspicious:
            signals.append(RiskSignal(
                signal_id=make_signal_id("ioc"),
                level=RiskLevel.HIGH,
                category="ioc",
                description=f"Suspicious URL detected: {url.defanged}",
                evidence={"url": url.defanged, "domain": url.domain, "source": url.source},
            ))

    for dom in report.iocs.domains:
        if dom.homoglyph_suspected:
            signals.append(RiskSignal(
                signal_id=make_signal_id("ioc"),
                level=RiskLevel.HIGH,
                category="ioc",
                description=f"Homoglyph/IDN lookalike domain: {dom.domain}",
                evidence={"domain": dom.domain},
            ))
        if dom.typosquat_suspected:
            signals.append(RiskSignal(
                signal_id=make_signal_id("ioc"),
                level=RiskLevel.HIGH,
                category="ioc",
                description=f"Possible typosquatting domain: {dom.domain}",
                evidence={"domain": dom.domain},
            ))

    for att in report.iocs.attachments:
        if att.is_executable:
            signals.append(RiskSignal(
                signal_id=make_signal_id("ioc"),
                level=RiskLevel.CRITICAL,
                category="ioc",
                description=f"Executable attachment: {att.filename}",
                evidence={"filename": att.filename, "sha256": att.sha256,
                          "content_type": att.content_type},
            ))
        elif att.is_archive or att.is_office_doc:
            signals.append(RiskSignal(
                signal_id=make_signal_id("ioc"),
                level=RiskLevel.MEDIUM,
                category="ioc",
                description=f"Potentially risky attachment: {att.filename}",
                evidence={"filename": att.filename, "sha256": att.sha256},
            ))

    # ---------------------------------------------------------------- Origin signals
    origin = report.origin
    if origin.is_cloud_provider:
        signals.append(RiskSignal(
            signal_id=make_signal_id("origin"),
            level=RiskLevel.INFO,
            category="origin",
            description="Probable sending infrastructure is a cloud/hosting provider",
            evidence={"ip": origin.probable_sending_ip, "org": origin.asn_org},
        ))
    if origin.is_vpn_suspected:
        signals.append(RiskSignal(
            signal_id=make_signal_id("origin"),
            level=RiskLevel.MEDIUM,
            category="origin",
            description="Probable sending IP associated with VPN/anonymization service",
            evidence={"ip": origin.probable_sending_ip, "org": origin.asn_org},
        ))
    if origin.is_tor:
        signals.append(RiskSignal(
            signal_id=make_signal_id("origin"),
            level=RiskLevel.HIGH,
            category="origin",
            description="Probable sending IP is a Tor exit node",
            evidence={"ip": origin.probable_sending_ip},
        ))

    return signals
