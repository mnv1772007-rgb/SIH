"""
role1_email_forensics/risk/explainable_scorer.py
Deterministic, explainable risk scoring engine.
SIH 26106 - IronPulse | Role 1

Scoring contract:
- Every point has a verifiable forensic reason.
- Missing auth (SPF/DKIM/DMARC NONE) -> 0 pts.
- API_ERROR / TIMEOUT / NOT_CONFIGURED / UNAVAILABLE -> 0 pts.
- NOT_FOUND -> 0 pts  (absence of evidence != malice).
- Score capped [0, 100], deterministic & reproducible.
"""
from __future__ import annotations
import logging
from typing import Any

try:
    from ..schema.forensic_report import (
        ForensicReport, SpfResult, DkimResult, DmarcResult,
    )
except ImportError:
    # allow standalone testing
    ForensicReport = object
    SpfResult = type('SpfResult', (), {'FAIL': 'fail', 'SOFTFAIL': 'softfail', 'PASS': 'pass', 'NONE': 'none'})()
    DkimResult = type('DkimResult', (), {'FAIL': 'fail', 'PASS': 'pass', 'NONE': 'none'})()
    DmarcResult = type('DmarcResult', (), {'FAIL': 'fail', 'PASS': 'pass', 'NONE': 'none'})()

logger = logging.getLogger(__name__)

# Statuses that NEVER contribute risk points
_ZERO_RISK_STATUSES = {
    "api_error", "error", "timeout", "not_configured", "disabled",
    "unavailable", "not_found", "skipped", "empty", "not_checked",
    "pending", "unknown",
}


def _is_confirmed_malicious(result: dict) -> bool:
    """Return True only when threat intel definitively confirms malicious."""
    if not isinstance(result, dict):
        return False
    status = str(result.get("status", "")).lower()
    if status in _ZERO_RISK_STATUSES:
        return False
    return bool(result.get("malicious"))


def compute_explainable_score(report: Any) -> dict[str, Any]:
    """
    Compute a deterministic, explainable risk score from a ForensicReport.
    Returns a structured dict with score, level, breakdown, evidence, and verdict.
    """
    breakdown: list[dict] = []
    factors: list[str] = []
    primary_evidence: list[str] = []
    confirmed_points: float = 0.0
    telemetry_count: int = 0
    total_sources: int = 6  # auth(3) + abuseipdb + vt_urls + vt_hashes

    def add(factor: str, category: str, points: float, reason: str, evid: str | None = None):
        nonlocal confirmed_points
        if points > 0:
            breakdown.append({
                "factor": factor,
                "category": category,
                "points": round(points),
                "reason": reason,
            })
            factors.append(factor.replace(" ", "_").upper())
            if evid:
                primary_evidence.append(evid)
            confirmed_points += points

    # ---- 1. Email Authentication ------------------------------------------
    spf = report.auth.spf
    if spf.result == SpfResult.FAIL:
        add("SPF FAIL", "auth", 15,
            f"Sending IP not authorised by SPF (domain={spf.domain}, ip={spf.ip_checked})",
            f"SPF FAIL - IP {spf.ip_checked} rejected by {spf.domain}")
        telemetry_count += 1
    elif spf.result == SpfResult.SOFTFAIL:
        add("SPF SOFTFAIL", "auth", 8,
            f"Sending IP weakly rejected by SPF ~all (domain={spf.domain})",
            f"SPF SOFTFAIL - {spf.domain}")
        telemetry_count += 1
    elif spf.result == SpfResult.PASS:
        telemetry_count += 1
    # NONE -> no record, 0 pts

    dkim = report.auth.dkim
    if dkim.result == DkimResult.FAIL:
        add("DKIM FAIL", "auth", 15,
            f"DKIM signature failed (selector={dkim.selector}, error={dkim.error})",
            "DKIM FAIL - message integrity cannot be confirmed")
        telemetry_count += 1
    elif dkim.result == DkimResult.PASS:
        telemetry_count += 1

    dmarc = report.auth.dmarc
    if dmarc.result == DmarcResult.FAIL:
        add("DMARC FAIL", "auth", 15,
            f"DMARC policy failed (policy={dmarc.policy}, domain={dmarc.domain})",
            f"DMARC FAIL - {dmarc.domain}")
        telemetry_count += 1
    elif dmarc.result == DmarcResult.PASS:
        telemetry_count += 1

    # ---- 2. Header Anomalies ----------------------------------------------
    h = report.headers
    if h.from_reply_to_mismatch:
        add("REPLY-TO MISMATCH", "header", 10,
            f"From != Reply-To (from={h.from_address}, reply_to={h.reply_to})",
            f"Reply-To mismatch: {h.from_address} vs {h.reply_to}")
    if h.from_return_path_mismatch:
        add("RETURN-PATH MISMATCH", "header", 8,
            f"From != Return-Path (from={h.from_address}, return_path={h.return_path})",
            f"Return-Path mismatch: {h.from_address}")
    if h.display_name_spoofing_suspected:
        add("DISPLAY NAME SPOOFING", "header", 12,
            f"Display name contains '@' - identity spoofing tactic (name={h.from_display_name})",
            f"Spoofed display name: {h.from_display_name}")

    # ---- 3. IOC Signals ---------------------------------------------------
    suspicious_urls = [u for u in report.iocs.urls if u.suspicious]
    if suspicious_urls:
        pts = min(20, 10 * len(suspicious_urls))
        add("SUSPICIOUS URL(S)", "ioc", pts,
            f"{len(suspicious_urls)} suspicious URL(s) embedded: {[u.defanged for u in suspicious_urls[:2]]}",
            f"Suspicious URL: {suspicious_urls[0].defanged}")

    homoglyph = [d for d in report.iocs.domains if d.homoglyph_suspected]
    if homoglyph:
        add("HOMOGLYPH DOMAIN", "ioc", 12,
            f"Lookalike/IDN domain(s): {[d.domain for d in homoglyph[:2]]}",
            f"Homoglyph domain: {homoglyph[0].domain}")

    typosquat = [d for d in report.iocs.domains if d.typosquat_suspected]
    if typosquat:
        add("TYPOSQUAT DOMAIN", "ioc", 10,
            f"Typosquatting domain(s): {[d.domain for d in typosquat[:2]]}",
            f"Typosquatting domain: {typosquat[0].domain}")

    for att in report.iocs.attachments:
        if att.is_executable:
            add("EXECUTABLE ATTACHMENT", "ioc", 20,
                f"Executable attachment present: {att.filename}",
                f"Executable attachment: {att.filename}")
            break

    # ---- 4. Origin --------------------------------------------------------
    origin = report.origin
    if origin.is_tor:
        add("TOR EXIT NODE", "origin", 15,
            f"Sending IP {origin.probable_sending_ip} is a Tor exit node",
            f"Tor exit node: {origin.probable_sending_ip}")
    if origin.is_vpn_suspected:
        add("VPN/ANONYMIZER", "origin", 8,
            f"Sending IP {origin.probable_sending_ip} linked to VPN/anonymizer",
            None)

    # ---- 5. Threat Intel --------------------------------------------------
    ti = getattr(report, "threat_intelligence", {}) or {}

    # AbuseIPDB
    abuse_res = ti.get("abuseipdb") if isinstance(ti, dict) else None
    if isinstance(abuse_res, dict) and abuse_res.get("status") == "available":
        score_val = int(abuse_res.get("abuse_confidence_score", 0))
        if score_val >= 75:
            add("MALICIOUS IP (AbuseIPDB)", "origin", 15,
                f"IP {origin.probable_sending_ip}: {score_val}% abuse confidence, {abuse_res.get('total_reports',0)} reports",
                f"AbuseIPDB: {score_val}% abuse confidence")
            telemetry_count += 1
        elif score_val >= 25:
            add("SUSPICIOUS IP (AbuseIPDB)", "origin", 8,
                f"IP {origin.probable_sending_ip}: {score_val}% abuse confidence",
                None)
            telemetry_count += 1
        else:
            telemetry_count += 1

    # VirusTotal URLs
    vt_data = ti.get("virustotal", {}) if isinstance(ti, dict) else {}
    if not isinstance(vt_data, dict):
        vt_data = {}
    vt_urls = vt_data.get("urls", [])
    vt_hashes = vt_data.get("hashes", [])

    mal_vt_urls = [r for r in vt_urls if _is_confirmed_malicious(r)]
    if mal_vt_urls:
        add("VIRUSTOTAL MALICIOUS URL", "threat_intel", 20,
            f"{len(mal_vt_urls)} URL(s) confirmed malicious by VirusTotal",
            f"VT malicious URL: {str(mal_vt_urls[0].get('url',''))[:60]}")
        telemetry_count += 1
    elif any(r.get("status") == "available" for r in vt_urls):
        telemetry_count += 1

    # VirusTotal Hashes
    mal_vt_hashes = [r for r in vt_hashes if _is_confirmed_malicious(r)]
    if mal_vt_hashes:
        add("VIRUSTOTAL MALICIOUS ATTACHMENT", "threat_intel", 20,
            f"{len(mal_vt_hashes)} attachment hash(es) confirmed malicious by VirusTotal",
            f"VT malicious attachment ({mal_vt_hashes[0].get('malicious_count',0)} engines)")
        telemetry_count += 1
    elif any(r.get("status") == "available" for r in vt_hashes):
        telemetry_count += 1

    # URLScan
    urlscan_results = ti.get("urlscan", []) if isinstance(ti, dict) else []
    mal_urlscan = [r for r in urlscan_results if _is_confirmed_malicious(r)]
    if mal_urlscan and not mal_vt_urls:  # avoid double-counting
        add("URLSCAN MALICIOUS URL", "threat_intel", 15,
            f"URL malicious on urlscan.io (score={mal_urlscan[0].get('score',0)})",
            "URLScan.io confirmed malicious URL")

    # ---- 6. Score & Level -------------------------------------------------
    risk_score = max(0, min(100, round(confirmed_points)))
    if risk_score >= 85:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    confidence = round(min(1.0, telemetry_count / max(total_sources, 1)), 2)

    # ---- 7. Verdict -------------------------------------------------------
    has_auth_fail = any(f["factor"] in ("SPF FAIL", "DKIM FAIL", "DMARC FAIL") for f in breakdown)
    has_malicious = any(f["category"] in ("threat_intel", "ioc") for f in breakdown)

    if risk_level == "CRITICAL":
        verdict = ("CRITICAL RISK - CONFIRMED MALICIOUS INDICATORS" if has_malicious
                   else "CRITICAL RISK - MULTIPLE AUTH & HEADER ANOMALIES")
    elif risk_level == "HIGH":
        if has_auth_fail and has_malicious:
            verdict = "HIGH RISK - PHISHING INDICATORS WITH AUTH FAILURE"
        elif has_malicious:
            verdict = "HIGH RISK - SUSPICIOUS INFRASTRUCTURE DETECTED"
        elif has_auth_fail:
            verdict = "HIGH RISK - AUTHENTICATION ANOMALY"
        else:
            verdict = "HIGH RISK - MULTIPLE THREAT INDICATORS"
    elif risk_level == "MEDIUM":
        verdict = "MEDIUM RISK - SUSPICIOUS INDICATORS REQUIRE REVIEW"
    else:
        verdict = ("LOW RISK - NO THREAT INDICATORS DETECTED" if not breakdown
                   else "LOW RISK - MINOR ANOMALIES DETECTED")

    # ---- 8. Actions -------------------------------------------------------
    if risk_level in ("CRITICAL", "HIGH"):
        actions = [
            "Do not click any embedded links or open attachments.",
            "Quarantine the email and report to security operations.",
            "Verify sender identity through an out-of-band channel.",
            "Investigate associated infrastructure (IPs, domains, URLs).",
        ]
        if has_auth_fail:
            actions.append("Review SPF/DKIM/DMARC DNS records for the sender domain.")
    elif risk_level == "MEDIUM":
        actions = [
            "Review email carefully before clicking links or responding.",
            "Verify sender identity if an unexpected request is made.",
            "Report to security if behaviour appears unusual.",
        ]
    else:
        actions = [
            "Email appears low risk based on available forensic evidence.",
            "Exercise standard caution with links and attachments.",
        ]

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "verdict": verdict,
        "risk_factors": list(dict.fromkeys(factors)),  # deduplicated, ordered
        "risk_breakdown": breakdown,
        "primary_evidence": primary_evidence[:5],
        "recommended_actions": actions,
        "limitations": (
            "Score based on observable forensic signals only. Does not constitute legal proof. "
            "IP geolocation and threat-intelligence data are probabilistic. "
            "Missing auth records (SPF/DKIM/DMARC NONE) do not indicate malicious origin. "
            "Unavailable/unconfigured threat-intel contributes zero risk points."
        ),
    }
