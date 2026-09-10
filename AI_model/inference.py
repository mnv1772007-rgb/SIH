"""Cached, fail-soft inference for trained local ML baselines."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib

from AI_model.preprocessing import normalise_text


MODELS_DIR = Path(__file__).resolve().parent / "models"
EMAIL_MODEL_PATH = MODELS_DIR / "email_classifier.joblib"
URL_MODEL_PATH = MODELS_DIR / "url_classifier.joblib"


@lru_cache(maxsize=1)
def _email_model() -> dict[str, Any] | None:
    if not EMAIL_MODEL_PATH.is_file():
        return None
    try:
        value = joblib.load(EMAIL_MODEL_PATH)
        return value if isinstance(value, dict) and "pipeline" in value else None
    except Exception:
        return None


@lru_cache(maxsize=1)
def _url_model() -> dict[str, Any] | None:
    if not URL_MODEL_PATH.is_file():
        return None
    try:
        value = joblib.load(URL_MODEL_PATH)
        return value if isinstance(value, dict) and "pipeline" in value else None
    except Exception:
        return None


def _check_enabled() -> bool:
    return os.getenv("ML_MODEL_ENABLED", "false").lower() == "true"


def _normalize_email(text: str) -> str:
    """Normalize email text for classification."""
    return normalise_text(text)


def _normalize_url(text: str) -> str:
    """Normalize URL text for classification (less aggressive)."""
    import re
    # Keep URL structure but lowercase
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _run_inference(model_data: dict[str, Any], text: str, normalize_fn) -> dict[str, Any]:
    """Run inference on a loaded model."""
    if not _check_enabled():
        return {"status": "disabled", "predicted_class": "unknown", "confidence": 0.0, "model_available": False}

    if model_data is None:
        return {"status": "not_trained", "predicted_class": "unknown", "confidence": 0.0, "model_available": False}

    normalized = normalize_fn(text)
    if len(normalized) < 10:
        return {"status": "insufficient_text", "predicted_class": "unknown", "confidence": 0.0, "model_available": True}

    pipeline = model_data["pipeline"]
    metadata = model_data.get("metadata", {})

    try:
        probabilities = pipeline.predict_proba([normalized])[0]
        classes = [str(c) for c in pipeline.classes_]
    except Exception as e:
        return {"status": "inference_error", "predicted_class": "unknown", "confidence": 0.0, "model_available": True, "error": str(e)}

    index = max(range(len(probabilities)), key=probabilities.__getitem__)
    confidence = float(probabilities[index])
    predicted_class = classes[index]

    # All class probabilities
    all_probs = {classes[i]: round(float(probabilities[i]), 4) for i in range(len(probabilities))}

    # Confidence level
    if confidence >= 0.85:
        confidence_level = "high"
    elif confidence >= 0.65:
        confidence_level = "medium"
    else:
        confidence_level = "low"

    return {
        "status": "available",
        "predicted_class": predicted_class,
        "confidence": round(confidence, 4),
        "confidence_level": confidence_level,
        "all_probabilities": all_probs,
        "model_version": metadata.get("trained_at", "unknown"),
        "model_name": metadata.get("model_name", "unknown"),
        "supported_labels": metadata.get("label_set", classes),
        "missing_labels": metadata.get("missing_labels", []),
        "model_available": True,
        "note": "Model confidence describes classification confidence, not attacker confidence. This is one forensic signal among many.",
    }


def classify_email(text: str) -> dict[str, Any]:
    """Classify email text (subject + body). Returns multi-class prediction with confidence."""
    if not _check_enabled():
        return {"status": "disabled", "predicted_class": "unknown", "confidence": 0.0, "model_available": False}
    return _run_inference(_email_model(), text, _normalize_email)


def classify_url(text: str) -> dict[str, Any]:
    """Classify URL text (url + domain + path). Returns multi-class prediction with confidence."""
    if not _check_enabled():
        return {"status": "disabled", "predicted_class": "unknown", "confidence": 0.0, "model_available": False}
    return _run_inference(_url_model(), text, _normalize_url)


def classify_email_from_parts(subject: str, body_text: str, body_html: str) -> dict[str, Any]:
    """Classify email from parts (used by analysis service)."""
    combined = f"{subject or ''} {body_text or ''} {body_html or ''}"
    return classify_email(combined)


def classify_url_from_parts(url: str, domain: str, path: str) -> dict[str, Any]:
    """Classify URL from parts (used by analysis service)."""
    combined = f"{url} {domain} {path}"
    return classify_url(combined)


def get_model_info() -> dict[str, Any]:
    """Get information about loaded models."""
    email_model = _email_model()
    url_model = _url_model()

    return {
        "email_classifier": {
            "available": email_model is not None,
            "model_name": email_model.get("metadata", {}).get("model_name") if email_model else None,
            "trained_at": email_model.get("metadata", {}).get("trained_at") if email_model else None,
            "labels": email_model.get("metadata", {}).get("label_set") if email_model else [],
            "missing_labels": email_model.get("metadata", {}).get("missing_labels") if email_model else [],
        },
        "url_classifier": {
            "available": url_model is not None,
            "model_name": url_model.get("metadata", {}).get("model_name") if url_model else None,
            "trained_at": url_model.get("metadata", {}).get("trained_at") if url_model else None,
            "labels": url_model.get("metadata", {}).get("label_set") if url_model else [],
            "missing_labels": url_model.get("metadata", {}).get("missing_labels") if url_model else [],
        },
        "ml_enabled": _check_enabled(),
    }


# Backward compatibility alias for existing tests
def classify_text(text: str) -> dict[str, Any]:
    """Legacy alias for classify_email - maintains backward compatibility."""
    result = classify_email(text)
    # Convert new format to old format for compatibility
    if result.get("status") == "available":
        return {
            "status": "available",
            "label": result.get("predicted_class", "unknown"),
            "confidence": result.get("confidence"),
            "confidence_level": result.get("confidence_level", "unknown"),
        }
    return {
        "status": result.get("status", "unavailable"),
        "label": "unknown",
        "confidence": None,
        "confidence_level": "unknown",
    }


if __name__ == "__main__":
    # Simple CLI test
    import sys
    if len(sys.argv) > 1:
        text = " ".join(sys.argv[1:])
        if "http" in text:
            result = classify_url(text)
        else:
            result = classify_email(text)
        print(json.dumps(result, indent=2))
    else:
        info = get_model_info()
        print(json.dumps(info, indent=2))
