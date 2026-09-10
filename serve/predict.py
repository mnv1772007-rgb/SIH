"""
ml/serve/predict.py - Clean prediction service for email threat detection
Author: BTech Cyber Security Student

This module exposes a single clean function: predict_email_threat()
that can be called from:
  - Role 5's FastAPI backend
  - The integration test
  - The serve/api.py endpoint
  - Command-line scripts

It does NOT create a FastAPI app (that lives in serve/api.py).
It handles model loading once and caches it for subsequent calls.

Usage:
    from ml.serve.predict import predict_email_threat

    result = predict_email_threat({
        "subject": "Urgent: Verify your account",
        "body": "Click here to verify: http://192.168.1.1/verify",
        "sender": "admin@phish.com",
        "reply_to": "attacker@gmail.com",
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
    })
    print(result["risk"]["level"])   # 'CRITICAL'
    print(result["risk"]["score"])   # 91.5
    print(result["reasons"])         # ['High phishing probability', ...]
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Model singleton — loaded once, reused for all predictions
# ---------------------------------------------------------------------------

_model = None
_model_load_attempted = False


def _get_model():
    """
    Load and cache the trained EmailThreatClassifier.
    Returns None if model hasn't been trained yet (graceful fallback).
    """
    global _model, _model_load_attempted

    if _model_load_attempted:
        return _model

    _model_load_attempted = True

    try:
        from ml.models.baseline import EmailThreatClassifier
        _model = EmailThreatClassifier.load()
        logger.info(f"ML model loaded. Classes: {_model.classes_}")
    except FileNotFoundError:
        logger.warning(
            "Trained model not found. Run training pipeline first. "
            "Predictions will use heuristic fallback."
        )
        _model = None
    except Exception as exc:
        logger.error(f"Failed to load ML model: {exc}")
        _model = None

    return _model


def reset_model_cache():
    """Force reload model on next prediction call (useful for testing)."""
    global _model, _model_load_attempted
    _model = None
    _model_load_attempted = False


# ---------------------------------------------------------------------------
# Main prediction function
# ---------------------------------------------------------------------------

def predict_email_threat(
    email: Dict[str, Any],
    threat_intel: Optional[Dict[str, Any]] = None,
) -> Dict:
    """
    Classify an email and return a full risk assessment.

    This is the MAIN entry point for Role 2. Call this from the backend.

    Args:
        email: Dict containing email fields. Accepted keys (all optional):
            - subject (str)
            - body / body_text (str)
            - sender / from (str)    ← 'from' is also accepted
            - reply_to (str)
            - return_path (str)
            - spf (str): 'pass', 'fail', 'softfail', etc.
            - dkim (str)
            - dmarc (str)
            - arc (str)
            - urls (str | list)     ← pipe-separated or list
            - header_risk_tally (int)
            - attachment_count (int)
            - executable_attachments (int)
            - html_destination_mismatch (int)
            - evidence_tally (float)
            - label (str)           ← ignored during inference

        threat_intel: Optional threat intelligence signals from Role 3.
            Example: {"url_reputation": "malicious", "domain_reputation": "suspicious"}

    Returns:
        Dict matching the ML JSON contract:
        {
          "schema_version": "1.0",
          "prediction": {"label": ..., "confidence": ..., "probabilities": {...}},
          "risk": {"score": ..., "level": ...},
          "signals": {...},
          "reasons": [...],
          "model": {"name": ..., "version": ...}
        }
    """
    # Normalize 'from' field (Python keyword conflict workaround)
    if "from" in email and "sender" not in email:
        email = dict(email)
        email["sender"] = email.pop("from")

    # Extract features
    from ml.features.extract import extract_all_features
    from ml.data.ingest import dict_to_ml_row

    try:
        row = dict_to_ml_row(email)
        features = extract_all_features(row)
    except Exception as exc:
        logger.error(f"Feature extraction failed: {exc}")
        return _error_response(str(exc))

    # Get ML probabilities
    model = _get_model()

    if model is not None:
        try:
            X = pd.DataFrame([features])
            proba_array = model.predict_proba(X)[0]
            classes = model.classes_
            probabilities = {cls: float(p) for cls, p in zip(classes, proba_array)}
        except Exception as exc:
            logger.error(f"Model prediction failed: {exc}")
            probabilities = _heuristic_probabilities(features)
    else:
        # No trained model — use heuristic fallback
        logger.info("Using heuristic fallback (model not trained)")
        probabilities = _heuristic_probabilities(features)

    # Compute risk score
    from ml.scoring.engine import compute_risk_score
    result = compute_risk_score(
        probabilities=probabilities,
        features={**features, **_extract_raw_auth(email)},
        threat_intel=threat_intel,
    )

    # Attach AI-powered forensic briefing & SOC actions
    try:
        from ml.scoring.ai_explainer import generate_ai_threat_briefing
        result["ai_analysis"] = generate_ai_threat_briefing(result, email_dict=email)
    except Exception as exc:
        logger.exception(f"AI briefing generation failed: {exc}")

    return result



def _extract_raw_auth(email: Dict) -> Dict:
    """Pass raw SPF/DKIM/DMARC strings to the risk engine for signal matching."""
    return {
        "spf": str(email.get("spf", "") or "").lower(),
        "dkim": str(email.get("dkim", "") or "").lower(),
        "dmarc": str(email.get("dmarc", "") or "").lower(),
    }


def _heuristic_probabilities(features: Dict) -> Dict[str, float]:
    """
    Heuristic probability fallback when no trained model is available.
    Uses security signals to estimate threat probabilities.
    This is NOT a real model — it's a safety net only.
    """
    threat_score = 0.0

    # Auth failures
    threat_score += float(features.get("spf_fail", 0)) * 0.15
    threat_score += float(features.get("dkim_fail", 0)) * 0.15
    threat_score += float(features.get("dmarc_fail", 0)) * 0.15

    # URL / structural signals
    threat_score += min(float(features.get("url_count", 0)) * 0.05, 0.15)
    threat_score += float(features.get("ip_based_urls", 0)) * 0.15
    threat_score += float(features.get("reply_to_mismatch", 0)) * 0.10

    # Keywords
    urgency = float(features.get("urgency_keyword_hits", 0))
    credential = float(features.get("credential_keyword_hits", 0))
    threat_score += min(urgency * 0.03 + credential * 0.05, 0.15)

    threat_score = float(np.clip(threat_score, 0.0, 0.90))
    benign_prob = 1.0 - threat_score

    # Simple distribution across threat classes
    phishing_p = threat_score * 0.5
    spam_p = threat_score * 0.2
    bec_p = threat_score * 0.15
    impersonation_p = threat_score * 0.15

    # Normalize
    total = benign_prob + phishing_p + spam_p + bec_p + impersonation_p
    if total > 0:
        benign_prob /= total
        phishing_p /= total
        spam_p /= total
        bec_p /= total
        impersonation_p /= total

    return {
        "benign": round(benign_prob, 4),
        "phishing": round(phishing_p, 4),
        "spam": round(spam_p, 4),
        "bec": round(bec_p, 4),
        "impersonation": round(impersonation_p, 4),
    }


def _error_response(error_message: str) -> Dict:
    """Return a safe error response dict."""
    return {
        "schema_version": "1.0",
        "error": error_message,
        "prediction": {
            "label": "unknown",
            "confidence": 0.0,
            "probabilities": {},
        },
        "risk": {
            "score": 0.0,
            "level": "LOW",
        },
        "signals": {},
        "reasons": ["Error during prediction — see error field for details"],
        "model": {
            "name": "email-threat-baseline",
            "version": "1.0",
        },
    }


# ---------------------------------------------------------------------------
# Batch prediction
# ---------------------------------------------------------------------------

def predict_batch(
    emails: List[Dict[str, Any]],
    threat_intel_list: Optional[List[Optional[Dict]]] = None,
) -> List[Dict]:
    """
    Predict threats for a batch of emails.

    Args:
        emails: List of email dicts
        threat_intel_list: Optional list of threat intel dicts (same length as emails)

    Returns:
        List of risk assessment dicts
    """
    if threat_intel_list is None:
        threat_intel_list = [None] * len(emails)

    results = []
    for email, ti in zip(emails, threat_intel_list):
        try:
            results.append(predict_email_threat(email, threat_intel=ti))
        except Exception as exc:
            logger.error(f"Batch prediction failed for email: {exc}")
            results.append(_error_response(str(exc)))

    return results
