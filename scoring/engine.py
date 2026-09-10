"""
ml/scoring/engine.py - Risk scoring engine for email threat assessment
Author: BTech Cyber Security Student

Produces a normalized risk score 0-100 from:
  - ML model class probabilities
  - Security signals (SPF/DKIM/DMARC)
  - Structural indicators (URLs, attachments, mismatch)
  - Optional threat intelligence signals (from Role 3)

Risk levels:
  0-24  = LOW
  25-49 = MEDIUM
  50-74 = HIGH
  75-100 = CRITICAL

Output contract (JSON-serializable dict):
{
  "schema_version": "1.0",
  "prediction": {
    "label": "phishing",
    "confidence": 0.94,
    "probabilities": { "benign": 0.02, "spam": 0.01, ... }
  },
  "risk": {
    "score": 91,
    "level": "CRITICAL"
  },
  "signals": { "spf": "fail", "dkim": "fail", ... },
  "reasons": ["High phishing probability", ...],
  "model": { "name": "email-threat-baseline", "version": "1.0" }
}
"""

import logging
from typing import Dict, List, Optional, Any

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Risk level thresholds (configurable)
# ---------------------------------------------------------------------------

DEFAULT_THRESHOLDS = {
    "LOW": (0, 25),
    "MEDIUM": (25, 50),
    "HIGH": (50, 75),
    "CRITICAL": (75, 100),
}

# ---------------------------------------------------------------------------
# Per-signal bonus weights (all sum at most to ~55 bonus points)
# These supplement the ML probability score (which contributes up to 70 pts)
# ---------------------------------------------------------------------------

SIGNAL_WEIGHTS = {
    "spf_fail": 10,
    "spf_softfail": 5,
    "dkim_fail": 10,
    "dmarc_fail": 10,
    "reply_to_mismatch": 8,
    "return_path_mismatch": 5,
    "ip_based_urls": 8,
    "has_credentials_in_url": 10,
    "executable_attachments": 12,
    "html_destination_mismatch": 7,
    "display_name_privileged": 5,
    "body_wire_transfer_mention": 8,
    "body_gift_card_mention": 6,
    # Threat intelligence signals (from Role 3, optional)
    "url_reputation_malicious": 15,
    "domain_reputation_malicious": 12,
    "ip_reputation_malicious": 10,
}

# Max cap so scores stay within [0, 100]
_MAX_SCORE = 100.0
_ML_MAX_CONTRIBUTION = 70.0  # ML component can contribute up to 70 points
_SIGNAL_MAX_CONTRIBUTION = 50.0  # Signals can contribute up to 50 points


def compute_risk_score(
    probabilities: Dict[str, float],
    features: Dict[str, Any],
    threat_intel: Optional[Dict[str, Any]] = None,
    thresholds: Optional[Dict[str, tuple]] = None,
    weights: Optional[Dict[str, float]] = None,
) -> Dict:
    """
    Compute a normalized risk score and generate an explanation.

    Args:
        probabilities: Dict mapping class name → probability (from ML model)
                       e.g. {"benign": 0.05, "phishing": 0.85, ...}
        features: Dict of extracted email features (from extract_all_features)
        threat_intel: Optional dict of threat intelligence signals from Role 3
                      e.g. {"url_reputation": "malicious", "domain_reputation": "clean"}
        thresholds: Optional dict overriding DEFAULT_THRESHOLDS
        weights: Optional dict overriding SIGNAL_WEIGHTS

    Returns:
        Full risk assessment dict matching the JSON contract.
    """
    thresholds = thresholds or DEFAULT_THRESHOLDS
    sig_weights = weights or SIGNAL_WEIGHTS
    threat_intel = threat_intel or {}

    # --- 1. Determine ML prediction ---
    if not probabilities:
        probabilities = {"benign": 1.0}

    # Normalize probabilities (in case they don't sum to 1)
    total_prob = sum(probabilities.values())
    if total_prob > 0:
        probabilities = {k: v / total_prob for k, v in probabilities.items()}

    # Best label
    predicted_label = max(probabilities, key=probabilities.get)
    confidence = float(probabilities[predicted_label])

    # "Threat probability" = 1 - benign probability
    benign_prob = float(probabilities.get("benign", 0.0))
    threat_prob = float(np.clip(1.0 - benign_prob, 0.0, 1.0))

    # --- 2. ML contribution to risk score ---
    ml_score = threat_prob * _ML_MAX_CONTRIBUTION

    # --- 3. Signal-based bonus ---
    signal_score = 0.0
    reasons: List[str] = []
    active_signals: Dict[str, Any] = {}

    # Auth signals
    spf = str(features.get("spf", "") or "").lower()
    dkim = str(features.get("dkim", "") or "").lower()
    dmarc = str(features.get("dmarc", "") or "").lower()

    # Map raw auth strings to feature names
    if spf == "fail" or float(features.get("spf_fail", 0)) == 1.0:
        signal_score += sig_weights.get("spf_fail", 0)
        reasons.append("SPF authentication failed")
        active_signals["spf"] = "fail"
    elif spf == "softfail" or float(features.get("spf_softfail", 0)) == 1.0:
        signal_score += sig_weights.get("spf_softfail", 0)
        reasons.append("SPF soft-fail (partial authentication failure)")
        active_signals["spf"] = "softfail"
    elif spf == "pass":
        active_signals["spf"] = "pass"

    if dkim == "fail" or float(features.get("dkim_fail", 0)) == 1.0:
        signal_score += sig_weights.get("dkim_fail", 0)
        reasons.append("DKIM signature verification failed")
        active_signals["dkim"] = "fail"
    elif dkim == "pass":
        active_signals["dkim"] = "pass"

    if dmarc == "fail" or float(features.get("dmarc_fail", 0)) == 1.0:
        signal_score += sig_weights.get("dmarc_fail", 0)
        reasons.append("DMARC policy check failed")
        active_signals["dmarc"] = "fail"
    elif dmarc == "pass":
        active_signals["dmarc"] = "pass"

    # Domain mismatch signals
    if float(features.get("reply_to_mismatch", 0)) == 1.0:
        signal_score += sig_weights.get("reply_to_mismatch", 0)
        reasons.append("Reply-To domain differs from sender domain")
        active_signals["domain_mismatch"] = True

    if float(features.get("return_path_mismatch", 0)) == 1.0:
        signal_score += sig_weights.get("return_path_mismatch", 0)
        reasons.append("Return-Path domain differs from sender domain")

    # URL signals
    url_count = int(features.get("url_count", 0))
    active_signals["url_count"] = url_count

    if float(features.get("ip_based_urls", 0)) > 0:
        signal_score += sig_weights.get("ip_based_urls", 0)
        reasons.append(f"IP-based URL(s) detected ({int(features.get('ip_based_urls', 0))})")
        active_signals["ip_based_url"] = True

    if float(features.get("has_credentials_in_url", 0)) == 1.0:
        signal_score += sig_weights.get("has_credentials_in_url", 0)
        reasons.append("URL contains embedded credentials")
        active_signals["credentials_in_url"] = True

    if float(features.get("html_destination_mismatch", 0)) == 1.0:
        signal_score += sig_weights.get("html_destination_mismatch", 0)
        reasons.append("HTML link text does not match destination URL")
        active_signals["html_link_mismatch"] = True

    # Attachment signals
    exec_attach = int(features.get("executable_attachments", 0))
    if exec_attach > 0:
        signal_score += sig_weights.get("executable_attachments", 0)
        reasons.append(f"Executable attachment(s) detected ({exec_attach})")
        active_signals["executable_attachments"] = exec_attach

    # BEC / impersonation signals
    if float(features.get("display_name_privileged", 0)) == 1.0:
        signal_score += sig_weights.get("display_name_privileged", 0)
        reasons.append("Sender uses an executive/privileged display name")
        active_signals["privileged_display_name"] = True

    if float(features.get("body_wire_transfer_mention", 0)) == 1.0:
        signal_score += sig_weights.get("body_wire_transfer_mention", 0)
        reasons.append("Email body references wire transfer")

    if float(features.get("body_gift_card_mention", 0)) == 1.0:
        signal_score += sig_weights.get("body_gift_card_mention", 0)
        reasons.append("Email body references gift cards (common BEC pattern)")

    # Threat intelligence signals from Role 3 (optional, consumed as features)
    url_rep = str(threat_intel.get("url_reputation", "")).lower()
    if url_rep == "malicious":
        signal_score += sig_weights.get("url_reputation_malicious", 0)
        reasons.append("Threat intelligence: URL flagged as malicious")
        active_signals["url_reputation"] = "malicious"
    elif url_rep:
        active_signals["url_reputation"] = url_rep

    domain_rep = str(threat_intel.get("domain_reputation", "")).lower()
    if domain_rep == "malicious":
        signal_score += sig_weights.get("domain_reputation_malicious", 0)
        reasons.append("Threat intelligence: Domain flagged as malicious")
        active_signals["domain_reputation"] = "malicious"
    elif domain_rep:
        active_signals["domain_reputation"] = domain_rep

    ip_rep = str(threat_intel.get("ip_reputation", "")).lower()
    if ip_rep == "malicious":
        signal_score += sig_weights.get("ip_reputation_malicious", 0)
        reasons.append("Threat intelligence: IP flagged as malicious")
        active_signals["ip_reputation"] = "malicious"
    elif ip_rep:
        active_signals["ip_reputation"] = ip_rep

    # Cap signal score
    signal_score = min(signal_score, _SIGNAL_MAX_CONTRIBUTION)

    # --- 4. Combine scores ---
    total_score = float(np.clip(ml_score + signal_score, 0.0, _MAX_SCORE))

    # --- 5. ML-class specific reasons ---
    if confidence >= 0.6:
        label_reasons = {
            "phishing": "High phishing probability detected by ML model",
            "spam": "High spam probability detected by ML model",
            "bec": "High Business Email Compromise (BEC) probability detected",
            "impersonation": "High impersonation probability detected by ML model",
        }
        reason = label_reasons.get(predicted_label)
        if reason:
            reasons.insert(0, reason)

    # --- 6. Keyword-based reasons ---
    urgency_hits = int(features.get("urgency_keyword_hits", 0))
    financial_hits = int(features.get("financial_keyword_hits", 0))
    credential_hits = int(features.get("credential_keyword_hits", 0))

    if urgency_hits > 0:
        reasons.append(f"Urgency language detected ({urgency_hits} indicator(s))")
    if financial_hits > 0:
        reasons.append(f"Financial language detected ({financial_hits} indicator(s))")
    if credential_hits > 0:
        reasons.append(f"Credential-related language detected ({credential_hits} indicator(s))")

    # Deduplicate reasons while preserving order
    seen = set()
    unique_reasons = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            unique_reasons.append(r)

    # If no specific reason was generated
    if not unique_reasons:
        if total_score < 25:
            unique_reasons.append("No significant threat indicators detected")
        else:
            unique_reasons.append("Elevated risk based on ML model prediction")

    # --- 7. Risk level ---
    risk_level = _score_to_level(total_score, thresholds)

    return {
        "schema_version": "1.0",
        "prediction": {
            "label": predicted_label,
            "confidence": round(confidence, 4),
            "probabilities": {k: round(float(v), 4) for k, v in probabilities.items()},
        },
        "risk": {
            "score": round(total_score, 1),
            "level": risk_level,
        },
        "signals": active_signals,
        "reasons": unique_reasons,
        "model": {
            "name": "email-threat-baseline",
            "version": "1.0",
        },
    }


def _score_to_level(score: float, thresholds: Dict[str, tuple]) -> str:
    """Map a numeric score to a risk level string."""
    for level, (low, high) in sorted(thresholds.items(), key=lambda x: x[1][1], reverse=True):
        if score >= low:
            return level
    return "LOW"


def score_from_ml_result(
    ml_result: Dict,
    features: Dict,
    threat_intel: Optional[Dict] = None,
) -> Dict:
    """
    Convenience wrapper: takes the output of EmailThreatClassifier.predict_single()
    and returns the full risk assessment dict.

    Args:
        ml_result: Dict with keys: label, confidence, probabilities
        features: Dict of extracted features
        threat_intel: Optional threat intelligence signals

    Returns:
        Full risk assessment dict (matching JSON contract)
    """
    return compute_risk_score(
        probabilities=ml_result.get("probabilities", {}),
        features=features,
        threat_intel=threat_intel,
    )
