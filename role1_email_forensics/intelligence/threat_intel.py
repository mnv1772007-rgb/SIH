"""
Threat Intelligence & AI Enrichment Module.
SIH 26106 — IronPulse | Role 1

Integrates 6 external services:
1. VirusTotal API (Hashes, URLs, Domains, IPs)
2. URLScan API (URL scans and verdicts)
3. AbuseIPDB API (IP abuse confidence score & reports)
4. IPinfo / Geolocation API (Accurate IP geolocation & ASN)
5. NVIDIA NIM Nemotron LLM (Automated threat reasoning & hypothesis)
6. Google Gemini AI (Threat narrative analysis & phishing intent)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from typing import Any, Optional
import requests
from dotenv import load_dotenv

from ..schema.forensic_report import ForensicReport, RiskLevel, RiskSignal
from ..utils.helpers import classify_ip

LOGGER = logging.getLogger("threat_intel")

# Auto-load .env
load_dotenv()

# Forensic schema keys used to identify the best JSON candidate from LLM output
_FORENSIC_KEYS = {
    "classification", "risk_score", "confidence",
    "executive_summary", "attack_hypothesis", "recommended_actions",
}


def _extract_best_json(text: str, provider: str, model: str) -> dict[str, Any]:
    """
    Robustly extract a JSON object from LLM output.

    Handles:
    - Plain JSON responses
    - ```json ... ``` fenced code blocks
    - Chain-of-thought / thinking-mode models (e.g. Nemotron) that emit prose
      and numbered reasoning steps BEFORE the final JSON block.

    Strategy: collect ALL valid top-level JSON objects found in the text, then
    pick the one that best matches the forensic schema (most expected keys).
    Falls back to raw-text summary so the report always has something.
    """
    cleaned = text.strip()

    # Step 1 — prefer an explicit ```json ... ``` fence
    fence_match = re.search(r"```(?:json)?\s*\n?(\{.*?\})\s*\n?```", cleaned, re.DOTALL)
    if fence_match:
        try:
            data = json.loads(fence_match.group(1).strip())
            data.update({"status": "available", "provider": provider, "model": model})
            return data
        except Exception:
            pass

    # Step 2 — try the whole string verbatim
    try:
        data = json.loads(cleaned)
        data.update({"status": "available", "provider": provider, "model": model})
        return data
    except Exception:
        pass

    # Step 3 — extract ALL valid top-level JSON objects anywhere in the text
    candidates: list[dict] = []
    pos = 0
    while pos < len(cleaned):
        start = cleaned.find("{", pos)
        if start == -1:
            break
        depth = 0
        end = -1
        for i in range(start, len(cleaned)):
            ch = cleaned[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end == -1:
            break
        snippet = cleaned[start:end + 1]
        try:
            obj = json.loads(snippet)
            if isinstance(obj, dict):
                candidates.append(obj)
        except Exception:
            pass
        pos = end + 1

    if candidates:
        # Pick the candidate with the most forensic-schema keys
        best = max(candidates, key=lambda d: len(_FORENSIC_KEYS & set(d.keys())))
        best.update({"status": "available", "provider": provider, "model": model})
        return best

    # Step 4 — fallback: return raw text so the report still has context
    return {
        "status": "available",
        "provider": provider,
        "model": model,
        "executive_summary": cleaned[:600],
        "raw_response": cleaned[:1000],
    }


class ThreatIntelClient:
    """Client for querying external threat intelligence APIs."""

    def __init__(self):
        vt_primary = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        vt_backup = os.getenv("VIRUSTOTAL_BACKUP_API_KEY", "").strip()
        self.virustotal_keys = [k for k in [vt_primary, vt_backup] if k]
        self.virustotal_key = self.virustotal_keys[0] if self.virustotal_keys else ""
        self.urlscan_key = os.getenv("URLSCAN_API_KEY", "").strip()
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        self.geo_token = (os.getenv("GEOLOCATION_API_KEY") or os.getenv("IPINFO_TOKEN", "")).strip()
        self.nemotron_key = (os.getenv("NEMOTRONS_API_KEY") or os.getenv("NEMOTRON_API_KEY", "")).strip()
        self.nemotron_model = os.getenv("NEMOTRON_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b").strip()
        self.gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-3.6-flash").strip()

    def _vt_get(self, path: str) -> requests.Response | None:
        """Query VirusTotal with automatic failover across configured keys."""
        last_resp = None
        for key in self.virustotal_keys:
            try:
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/{path}",
                    headers={"x-apikey": key, "Accept": "application/json"},
                    timeout=8,
                )
                if resp.status_code == 429:
                    last_resp = resp
                    continue  # Rate limited, try backup key
                return resp
            except Exception:
                continue
        return last_resp

    # ── 1. Geolocation / IPinfo ─────────────────────────────────────────────

    def geolocate_ip(self, ip: str) -> dict[str, Any]:
        """Geolocate an IP using IPinfo."""
        if not ip or classify_ip(ip) != "public":
            return {"status": "skipped", "reason": "Non-public IP"}
        if not self.geo_token:
            return {"status": "not_configured"}

        try:
            res = requests.get(
                f"https://ipinfo.io/{ip}/json",
                params={"token": self.geo_token},
                timeout=8,
            )
            if res.status_code == 200:
                data = res.json()
                loc = data.get("loc", "")
                lat, lon = None, None
                if loc and "," in loc:
                    parts = loc.split(",")
                    lat, lon = float(parts[0]), float(parts[1])

                return {
                    "status": "available",
                    "ip": ip,
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "loc": loc,
                    "latitude": lat,
                    "longitude": lon,
                    "org": data.get("org"),
                    "postal": data.get("postal"),
                    "timezone": data.get("timezone"),
                }
            return {"status": "error", "code": res.status_code}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # ── 2. AbuseIPDB ────────────────────────────────────────────────────────

    def check_abuseipdb(self, ip: str) -> dict[str, Any]:
        """Check IP reputation and abuse confidence on AbuseIPDB."""
        if not ip or classify_ip(ip) != "public":
            return {"status": "skipped", "reason": "Non-public IP"}
        if not self.abuseipdb_key:
            return {"status": "not_configured"}

        try:
            res = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=8,
            )
            if res.status_code == 200:
                data = res.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                return {
                    "status": "available",
                    "ip": ip,
                    "abuse_confidence_score": score,
                    "total_reports": data.get("totalReports", 0),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "country_code": data.get("countryCode"),
                    "usage_type": data.get("usageType"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "malicious": score >= 25,
                }
            return {"status": "error", "code": res.status_code}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # ── 3. VirusTotal ───────────────────────────────────────────────────────

    def check_virustotal_hash(self, file_hash: str) -> dict[str, Any]:
        """Check file hash on VirusTotal."""
        if not file_hash or not self.virustotal_keys:
            return {"status": "not_configured" if not self.virustotal_keys else "empty"}

        try:
            res = self._vt_get(f"files/{file_hash}")
            if res is None:
                return {"status": "unavailable"}
            if res.status_code == 200:
                data = res.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                return {
                    "status": "available",
                    "hash": file_hash,
                    "malicious": malicious > 0,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": stats.get("harmless", 0),
                    "undetected_count": stats.get("undetected", 0),
                    "type_description": attrs.get("type_description"),
                    "meaningful_name": attrs.get("meaningful_name"),
                }
            if res.status_code == 404:
                return {"status": "not_found", "hash": file_hash, "malicious": False}
            return {"status": "error", "code": res.status_code}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def check_virustotal_url(self, url: str) -> dict[str, Any]:
        """Check URL on VirusTotal."""
        if not url or not self.virustotal_keys:
            return {"status": "not_configured" if not self.virustotal_keys else "empty"}

        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            res = self._vt_get(f"urls/{url_id}")
            if res is None:
                return {"status": "unavailable"}
            if res.status_code == 200:
                data = res.json().get("data", {})
                stats = data.get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                return {
                    "status": "available",
                    "url": url,
                    "malicious": malicious > 0,
                    "malicious_count": malicious,
                    "suspicious_count": stats.get("suspicious", 0),
                    "harmless_count": stats.get("harmless", 0),
                }
            if res.status_code == 404:
                return {"status": "not_found", "url": url, "malicious": False}
            return {"status": "error", "code": res.status_code}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # ── 4. URLScan ──────────────────────────────────────────────────────────

    def check_urlscan(self, url: str) -> dict[str, Any]:
        """Search existing URLScan intelligence for a URL."""
        if not url or not self.urlscan_key:
            return {"status": "not_configured" if not self.urlscan_key else "empty"}

        try:
            query = f'page.url:"{url}"'
            res = requests.get(
                "https://urlscan.io/api/v1/search/",
                headers={"API-Key": self.urlscan_key},
                params={"q": query, "size": 1},
                timeout=8,
            )
            if res.status_code == 200:
                results = res.json().get("results", [])
                if results:
                    first = results[0]
                    page = first.get("page", {})
                    verdicts = first.get("verdicts", {}).get("overall", {})
                    malicious = verdicts.get("malicious", False)
                    return {
                        "status": "available",
                        "url": url,
                        "malicious": malicious,
                        "score": verdicts.get("score", 0),
                        "categories": verdicts.get("categories", []),
                        "screenshot": first.get("screenshot"),
                        "domain": page.get("domain"),
                        "ip": page.get("ip"),
                    }
                return {"status": "not_found", "url": url, "malicious": False}
            return {"status": "error", "code": res.status_code}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # ── 5. NVIDIA NIM Nemotron LLM ──────────────────────────────────────────

    def analyze_nemotron(self, context_summary: dict[str, Any]) -> dict[str, Any]:
        """Generate AI threat assessment using NVIDIA NIM Nemotron."""
        if not self.nemotron_key:
            return {"status": "not_configured"}

        system_prompt = (
            "You are an email threat forensic investigator. "
            "Respond with ONLY a raw JSON object — no thinking, no reasoning steps, no explanation, "
            "no markdown, no prose before or after. The JSON must have exactly these keys: "
            "classification (one of: benign, suspicious, phishing, bec, malware), "
            "risk_score (integer 0-100), "
            "confidence (float 0.0-1.0), "
            "executive_summary (string, 2-3 sentences), "
            "attack_hypothesis (string), "
            "recommended_actions (array of strings). "
            "Start your response with '{' and end with '}'."
        )

        user_content = (
            f"Analyze this email and output the JSON:\n"
            f"From: {context_summary.get('from_address')}\n"
            f"Subject: {context_summary.get('subject')}\n"
            f"SPF={context_summary.get('spf')}, DKIM={context_summary.get('dkim')}, DMARC={context_summary.get('dmarc')}\n"
            f"Sending IP: {context_summary.get('sending_ip')} ({context_summary.get('geo_country')})\n"
            f"URLs: {context_summary.get('urls_count')}, Attachments: {context_summary.get('attachments_count')}\n"
            f"Risk Signals: {context_summary.get('risk_signals')}"
        )

        for _attempt in range(2):
            try:
                res = requests.post(
                    "https://integrate.api.nvidia.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self.nemotron_key}", "Content-Type": "application/json"},
                    json={
                        "model": self.nemotron_model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_content},
                        ],
                        "max_tokens": 1000,
                        "temperature": 0.1,
                    },
                    timeout=50,
                )
                if res.status_code == 200:
                    raw_text = res.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                    return _extract_best_json(raw_text, provider="NVIDIA Nemotron", model=self.nemotron_model)
                return {"status": "error", "provider": "NVIDIA Nemotron", "code": res.status_code, "text": res.text[:200]}
            except requests.Timeout:
                if _attempt == 0:
                    LOGGER.warning("Nemotron timeout on attempt 1, retrying...")
                    continue
                return {"status": "error", "provider": "NVIDIA Nemotron", "error": "Request timed out after retries"}
            except Exception as e:
                return {"status": "error", "provider": "NVIDIA Nemotron", "error": str(e)}
        return {"status": "error", "provider": "NVIDIA Nemotron", "error": "All retries exhausted"}

    # ── 6. Google Gemini AI ─────────────────────────────────────────────────

    def analyze_gemini(self, context_summary: dict[str, Any]) -> dict[str, Any]:
        """Generate AI threat assessment using Google Gemini."""
        if not self.gemini_key:
            return {"status": "not_configured"}

        prompt = (
            "You are a cybersecurity email threat analyst. Analyze the following email forensic evidence "
            "and output a strictly valid JSON object with the following schema:\n"
            "{\n"
            '  "classification": "phishing" | "bec" | "malware" | "suspicious" | "benign",\n'
            '  "risk_score": <number 0-100>,\n'
            '  "confidence": <number 0.0-1.0>,\n'
            '  "executive_summary": "<string>",\n'
            '  "attack_hypothesis": "<string>",\n'
            '  "phishing_tactics": ["<tactic 1>", "..."],\n'
            '  "recommended_actions": ["<action 1>", "..."]\n'
            "}\n\n"
            f"Forensic Evidence:\n"
            f"- From: {context_summary.get('from_address')}\n"
            f"- Subject: {context_summary.get('subject')}\n"
            f"- Auth: SPF={context_summary.get('spf')}, DKIM={context_summary.get('dkim')}, DMARC={context_summary.get('dmarc')}\n"
            f"- Sender Infrastructure IP: {context_summary.get('sending_ip')} ({context_summary.get('geo_country')})\n"
            f"- URLs: {context_summary.get('urls_count')}\n"
            f"- Attachments: {context_summary.get('attachments_count')}\n"
            f"- Risk Signals: {context_summary.get('risk_signals')}\n"
        )

        for _attempt in range(2):
            try:
                url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{self.gemini_model}:generateContent?key={self.gemini_key}"
                )
                res = requests.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
                    },
                    timeout=45,
                )
                if res.status_code == 200:
                    raw_text = (
                        res.json()
                        .get("candidates", [{}])[0]
                        .get("content", {})
                        .get("parts", [{}])[0]
                        .get("text", "")
                        .strip()
                    )
                    return _extract_best_json(raw_text, provider="Google Gemini", model=self.gemini_model)
                return {"status": "error", "provider": "Google Gemini", "code": res.status_code, "text": res.text[:200]}
            except requests.Timeout:
                if _attempt == 0:
                    LOGGER.warning("Gemini timeout on attempt 1, retrying...")
                    continue
                return {"status": "error", "provider": "Google Gemini", "error": "Request timed out after retries"}
            except Exception as e:
                return {"status": "error", "provider": "Google Gemini", "error": str(e)}
        return {"status": "error", "provider": "Google Gemini", "error": "All retries exhausted"}


# ── Report Enrichment Pipeline ──────────────────────────────────────────────

def enrich_report(report: ForensicReport, client: Optional[ThreatIntelClient] = None) -> ForensicReport:
    """
    Enrich a ForensicReport with live threat intelligence and AI reasoning.
    Preserves non-breaking fallback if keys are missing or services fail.
    """
    if client is None:
        client = ThreatIntelClient()

    ti_summary: dict[str, Any] = {
        "geolocation": None,
        "abuseipdb": None,
        "virustotal": {"hashes": [], "urls": [], "sending_ip": None},
        "urlscan": [],
    }

    # 1. Enrich Origin Sending IP
    sending_ip = report.origin.probable_sending_ip
    if sending_ip and classify_ip(sending_ip) == "public":
        # Geolocation
        geo = client.geolocate_ip(sending_ip)
        if geo.get("status") == "available":
            report.origin.city = geo.get("city")
            report.origin.region = geo.get("region")
            report.origin.country_name = geo.get("country") or report.origin.country_name
            report.origin.isp = geo.get("org") or report.origin.isp
            report.origin.latitude = geo.get("latitude")
            report.origin.longitude = geo.get("longitude")
            ti_summary["geolocation"] = geo

        # AbuseIPDB
        abuse = client.check_abuseipdb(sending_ip)
        if abuse.get("status") == "available":
            report.origin.abuse_score = abuse.get("abuse_confidence_score")
            report.origin.threat_intel["abuseipdb"] = abuse
            ti_summary["abuseipdb"] = abuse
            if abuse.get("malicious"):
                report.risk_signals.append(
                    RiskSignal(
                        signal_id="TI_ABUSEIPDB_HIGH_SCORE",
                        level=RiskLevel.HIGH if abuse.get("abuse_confidence_score", 0) < 75 else RiskLevel.CRITICAL,
                        category="origin",
                        description=f"Sending IP {sending_ip} has {abuse.get('abuse_confidence_score')}% abuse confidence on AbuseIPDB",
                        evidence={"ip": sending_ip, "abuse_score": abuse.get("abuse_confidence_score"), "reports": abuse.get("total_reports")},
                    )
                )

    # 2. VirusTotal file hash lookups for attachments
    for att in report.iocs.attachments:
        if att.sha256:
            vt_res = client.check_virustotal_hash(att.sha256)
            ti_summary["virustotal"]["hashes"].append(vt_res)
            if vt_res.get("malicious"):
                report.risk_signals.append(
                    RiskSignal(
                        signal_id="TI_VIRUSTOTAL_MALICIOUS_ATTACHMENT",
                        level=RiskLevel.CRITICAL,
                        category="ioc",
                        description=f"Attachment '{att.filename}' flagged as malicious by {vt_res.get('malicious_count')} VirusTotal engines",
                        evidence={"filename": att.filename, "sha256": att.sha256, "detections": vt_res.get("malicious_count")},
                    )
                )

    # 3. URL Scanning (urlscan.io + VirusTotal) — up to 5 URLs
    for u in report.iocs.urls[:5]:
        vt_u = client.check_virustotal_url(u.url)
        ti_summary["virustotal"]["urls"].append(vt_u)
        if vt_u.get("malicious"):
            u.suspicious = True
            report.risk_signals.append(
                RiskSignal(
                    signal_id="TI_VIRUSTOTAL_MALICIOUS_URL",
                    level=RiskLevel.HIGH,
                    category="ioc",
                    description=f"URL '{u.defanged}' flagged as malicious by VirusTotal",
                    evidence={"url": u.defanged, "detections": vt_u.get("malicious_count")},
                )
            )

        us_res = client.check_urlscan(u.url)
        ti_summary["urlscan"].append(us_res)
        if us_res.get("malicious"):
            u.suspicious = True
            report.risk_signals.append(
                RiskSignal(
                    signal_id="TI_URLSCAN_MALICIOUS_URL",
                    level=RiskLevel.HIGH,
                    category="ioc",
                    description=f"URL '{u.defanged}' flagged malicious on urlscan.io (score: {us_res.get('score')})",
                    evidence={"url": u.defanged, "score": us_res.get("score"), "categories": us_res.get("categories")},
                )
            )

    report.threat_intelligence = ti_summary

    # 4. AI Forensic Assessment — Nemotron primary, Gemini fallback
    context_summary = {
        "from_address": report.headers.from_address,
        "subject": report.headers.subject,
        "spf": report.auth.spf.result.value,
        "dkim": report.auth.dkim.result.value,
        "dmarc": report.auth.dmarc.result.value,
        "sending_ip": report.origin.probable_sending_ip,
        "geo_country": report.origin.country_name,
        "urls_count": len(report.iocs.urls),
        "attachments_count": len(report.iocs.attachments),
        "risk_signals": [s.description for s in report.risk_signals],
    }

    ai_res: dict[str, Any] = {}

    # Primary: Google Gemini (fast, clean JSON output)
    if client.gemini_key:
        ai_res = client.analyze_gemini(context_summary)

    # Secondary: NVIDIA Nemotron (optional, additional perspective if Gemini failed)
    if (not ai_res or ai_res.get("status") != "available") and client.nemotron_key:
        LOGGER.info("Gemini unavailable/failed — trying Nemotron fallback")
        ai_res = client.analyze_nemotron(context_summary)

    report.ai_assessment = ai_res
    return report
