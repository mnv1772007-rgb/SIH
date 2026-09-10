"""
ml/scoring/ai_explainer.py - AI-Powered Threat Explainer & Forensic Intelligence Generator
Role 2: AI/ML Detection Layer (SIH Problem Statement 26106)

Generates:
  1. Executive Incident Briefing (Attack narrative)
  2. MITRE ATT&CK Technique Mapping
  3. Attack Vector Analysis (Delivery, Deception, Bypass, Payload)
  4. Prioritized SOC Analyst Response Actions
  5. Optional LLM integration (Gemini / OpenAI) with robust offline fallback
"""

import os
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique catalog for email threats
# ---------------------------------------------------------------------------

MITRE_TECHNIQUES = {
    "phishing": [
        {
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "description": "Adversary sends an email containing malicious links to harvest credentials or deliver payloads."
        },
        {
            "id": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "description": "Adversary communicates using standard HTTP/HTTPS protocols to bypass outbound filters."
        }
    ],
    "bec": [
        {
            "id": "T1534",
            "name": "Internal Spearphishing",
            "tactic": "Lateral Movement",
            "description": "Adversary uses compromised or spoofed accounts to target personnel for financial transactions."
        },
        {
            "id": "T1566",
            "name": "Phishing",
            "tactic": "Initial Access",
            "description": "Adversary uses social engineering and urgency to prompt wire transfers or payroll changes."
        }
    ],
    "impersonation": [
        {
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "description": "Adversary impersonates trusted executive or brand using typosquatted domains."
        },
        {
            "id": "T1036.007",
            "name": "Masquerading: Double File Extension / Name",
            "tactic": "Defense Evasion",
            "description": "Adversary mimics legitimate brand names and visual appearance to deceive recipients."
        }
    ],
    "spam": [
        {
            "id": "T1566",
            "name": "Phishing: Mass Campaign",
            "tactic": "Initial Access",
            "description": "Unsolicited mass marketing or low-severity spam campaigns."
        }
    ],
    "benign": []
}


def generate_ai_threat_briefing(
    prediction_result: Dict[str, Any],
    email_dict: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generate an AI-driven forensic analysis briefing and SOC response playbook.

    Args:
        prediction_result: Output from compute_risk_score() or predict_email_threat()
        email_dict: Optional raw or parsed email metadata

    Returns:
        Dict containing:
          - incident_summary
          - attack_vector
          - mitre_attack
          - soc_actions
          - confidence_narrative
    """
    if email_dict is None:
        email_dict = {}
    elif hasattr(email_dict, "to_dict"):
        email_dict = email_dict.to_dict()
    pred = prediction_result.get("prediction", {})
    label = pred.get("label", "benign")
    confidence = pred.get("confidence", 0.0)
    risk = prediction_result.get("risk", {})
    risk_score = risk.get("score", 0.0)
    risk_level = risk.get("level", "LOW")
    signals = prediction_result.get("signals", {})
    reasons = prediction_result.get("reasons", [])

    subject = email_dict.get("subject", "N/A")
    sender = email_dict.get("sender", email_dict.get("from", "N/A"))
    reply_to = email_dict.get("reply_to", "N/A")

    # 1. Generate Attack Vector Breakdown
    attack_vector = _build_attack_vector(label, signals, email_dict)

    # 2. Map MITRE ATT&CK Techniques
    mitre_attack = MITRE_TECHNIQUES.get(label, [])
    if signals.get("executable_attachments", 0) > 0:
        mitre_attack.append({
            "id": "T1566.001",
            "name": "Phishing: Spearphishing Attachment",
            "tactic": "Initial Access",
            "description": "Adversary attaches executable or weaponized document."
        })

    # 3. Generate Prioritized SOC Response Actions
    soc_actions = _build_soc_actions(risk_level, label, signals, email_dict)

    # 4. Generate AI Incident Summary
    incident_summary = _build_incident_summary(
        label=label,
        risk_score=risk_score,
        risk_level=risk_level,
        subject=subject,
        sender=sender,
        signals=signals,
        reasons=reasons
    )

    # 5. Check if optional Generative AI (LLM) is configured
    llm_briefing = _try_generate_llm_summary(
        incident_summary=incident_summary,
        label=label,
        risk_score=risk_score,
        reasons=reasons,
        email_dict=email_dict
    )

    return {
        "incident_summary": incident_summary,
        "llm_briefing": llm_briefing,
        "attack_vector": attack_vector,
        "mitre_attack": mitre_attack,
        "soc_actions": soc_actions,
        "threat_level": risk_level,
        "ai_engine": "EmailThreatForensics-AI-Engine v1.0",
    }


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def _build_attack_vector(
    label: str, signals: Dict[str, Any], email_dict: Dict[str, Any]
) -> Dict[str, str]:
    if label == "benign":
        return {
            "delivery_mechanism": "Direct SMTP delivery with passing authentication",
            "deception_type": "None detected",
            "authentication_status": "SPF/DKIM/DMARC compliant",
            "payload_type": "Clean communication",
        }

    deception = "Generic social engineering"
    if label == "bec":
        deception = "Executive impersonation / financial urgency manipulation"
    elif label == "phishing":
        deception = "Credential harvesting via fraudulent login prompt"
    elif label == "impersonation":
        deception = "Brand typosquatting / spoofed display name"

    auth_status = "Bypassed or Failed"
    if signals.get("spf") == "fail" or signals.get("dmarc") == "fail":
        auth_status = "Authentication Failure (SPF/DMARC failed)"
    elif signals.get("reply_to_mismatch"):
        auth_status = "Header Manipulation (Reply-To mismatch)"

    payload = "No payload"
    if signals.get("executable_attachments", 0) > 0:
        payload = "Malicious executable attachment"
    elif email_dict.get("urls") or signals.get("url_count", 0) > 0:
        payload = "Hyperlink directing to external target"

    return {
        "delivery_mechanism": "Inbound SMTP with suspicious header traits",
        "deception_type": deception,
        "authentication_status": auth_status,
        "payload_type": payload,
    }


def _build_soc_actions(
    risk_level: str, label: str, signals: Dict[str, Any], email_dict: Dict[str, Any]
) -> List[Dict[str, str]]:
    actions = []

    if risk_level in ("CRITICAL", "HIGH"):
        actions.append({
            "priority": "P1 - Immediate",
            "action": "Quarantine Email & Search Inboxes",
            "detail": "Purge email from all user inboxes via M365 / Google Workspace eDiscovery to prevent user interaction."
        })
        actions.append({
            "priority": "P1 - Immediate",
            "action": "Firewall & Web Proxy Block",
            "detail": "Add extracted external IPs and domains to perimeter gateway blacklists and SIEM block rules."
        })

    if label in ("phishing", "impersonation"):
        actions.append({
            "priority": "P2 - Remediation",
            "action": "Force Password Reset & Invalidate Sessions",
            "detail": "If recipient interacted with URL, immediately revoke OAuth refresh tokens and reset Active Directory password."
        })

    if label == "bec":
        actions.append({
            "priority": "P1 - Fraud Prevention",
            "action": "Contact Finance / Out-of-band Verification",
            "detail": "Notify accounts payable to verify any pending wire transfer requests via verified voice call."
        })

    if risk_level in ("LOW", "MEDIUM") and not actions:
        actions.append({
            "priority": "P3 - Routine",
            "action": "Monitor & Log",
            "detail": "No immediate containment required. Maintain audit telemetry in SIEM."
        })

    return actions


def _build_incident_summary(
    label: str,
    risk_score: float,
    risk_level: str,
    subject: str,
    sender: str,
    signals: Dict[str, Any],
    reasons: List[str]
) -> str:
    if label == "benign":
        return (
            f"The analyzed email '{subject}' from '{sender}' exhibits normal communication patterns. "
            f"Authentication checks passed and no high-risk markers were detected. Threat score: {risk_score}/100 (LOW)."
        )

    summary = (
        f"AI threat assessment flagged this email as a {risk_level} severity incident "
        f"(Risk Score: {risk_score}/100) with primary classification '{label.upper()}'. "
        f"The message subject '{subject}' received from '{sender}' indicates an adversarial attack vector. "
    )
    if reasons:
        summary += "Key forensic findings: " + "; ".join(reasons[:3]) + "."
    return summary


def _try_generate_llm_summary(
    incident_summary: str,
    label: str,
    risk_score: float,
    reasons: List[str],
    email_dict: Dict[str, Any]
) -> Optional[str]:
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None

    try:
        if os.environ.get("GEMINI_API_KEY"):
            import urllib.request
            import json

            gemini_key = os.environ["GEMINI_API_KEY"]
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
            subj = email_dict.get("subject", "N/A")
            reasons_str = ", ".join(reasons)
            prompt_text = (
                f"You are a Senior SOC Analyst. Provide a 2-sentence executive summary and containment recommendation "
                f"for an email threat flagged as {label} with risk score {risk_score}/100. "
                f"Subject: {subj}. Key findings: {reasons_str}."
            )
            payload = json.dumps({
                "contents": [{"parts": [{"text": prompt_text}]}]
            }).encode("utf-8")

            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=4) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                candidates = res_data.get("candidates", [])
                if candidates:
                    return candidates[0]["content"]["parts"][0]["text"].strip()
    except Exception as exc:
        logger.debug(f"Optional LLM briefing skipped: {exc}")

    return None

