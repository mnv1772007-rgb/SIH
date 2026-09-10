"""
ml/serve/api.py - FastAPI prediction endpoint for email threat detection
Author: BTech Cyber Security Student

Exposes a /predict REST endpoint that:
  - Accepts parsed email features as JSON
  - Returns threat classification + risk score

NOTE: This is Role 2's standalone ML API.
      If Role 5 already owns a central FastAPI app, import predict_email_threat()
      directly from ml.serve.predict instead of running this as a separate service.

Fixed:
  - 'from' Python keyword conflict → renamed to 'sender' in Pydantic model
  - Wrong import (tally_to_unified_score → from ml.serve.predict)
  - TOP_N_FEATURES referenced before import → moved to top
  - Duplicate model loading → delegates to ml.serve.predict (singleton)
  - Broken BEC predict_proba shape indexing
  - predict_proba called twice unnecessarily
"""

import time
import uuid
import logging
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field, ConfigDict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import the clean prediction service
from ml.serve.predict import predict_email_threat, reset_model_cache
from ml.eval.metrics import TOP_N_FEATURES


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------

class EmailPredictRequest(BaseModel):
    """
    Email features for threat prediction.

    Field 'sender' corresponds to the email From header.
    ('from' is a Python keyword and cannot be used as a Pydantic field name.)
    """
    email_id: str = Field(default="", description="Optional email identifier")
    sender: str = Field(default="", description="Sender (From) address")
    from_domain: str = Field(default="", description="Extracted sender domain")
    reply_to: str = Field(default="", description="Reply-To header value")
    reply_to_domain: str = Field(default="", description="Extracted Reply-To domain")
    return_path: str = Field(default="", description="Return-Path header")
    return_path_domain: str = Field(default="", description="Extracted Return-Path domain")
    subject: str = Field(default="", description="Email subject line")
    body: str = Field(default="", description="Email body text (plaintext)")
    body_text: str = Field(default="", description="Alias for body (for backwards compat)")
    body_length: int = Field(default=0, description="Body character count")

    # Authentication
    spf: str = Field(default="", description="SPF result: pass/fail/softfail/neutral")
    dkim: str = Field(default="", description="DKIM result: pass/fail")
    dmarc: str = Field(default="", description="DMARC result: pass/fail")
    arc: str = Field(default="", description="ARC result")

    # Header analysis
    header_findings: List[Any] = Field(default_factory=list)
    header_risk_tally: int = Field(default=0, ge=0)

    # URLs
    url_count: int = Field(default=0, ge=0)
    urls: str = Field(default="", description="Pipe-separated URL list")
    html_link_count: int = Field(default=0, ge=0)
    html_destination_mismatch: int = Field(default=0, ge=0, le=1)

    # IPs
    ip_count: int = Field(default=0, ge=0)
    private_ips: int = Field(default=0, ge=0)

    # Attachments
    attachment_count: int = Field(default=0, ge=0)
    executable_attachments: int = Field(default=0, ge=0)

    # Evidence (from Role 1)
    evidence_tally: float = Field(default=0.0, ge=0.0)
    evidence_risk_category: str = Field(default="")

    # Threat intelligence signals (from Role 3, optional)
    threat_intel: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional threat intelligence signals (url_reputation, domain_reputation, ip_reputation)"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "subject": "Urgent: Verify your account",
                "body": "Your account will be suspended. Verify now: http://192.168.1.1/verify",
                "sender": "admin@phishingsite.com",
                "reply_to": "attacker@gmail.com",
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
                "urls": "http://192.168.1.1/verify",
                "url_count": 1,
            }
        }
    )


# Backwards compatibility alias for existing callers/tests
EmailFeatures = EmailPredictRequest


class PredictionResponse(BaseModel):
    """Full threat prediction response."""
    schema_version: str
    prediction: Dict[str, Any]
    risk: Dict[str, Any]
    signals: Dict[str, Any]
    reasons: List[str]
    model: Dict[str, str]
    ai_analysis: Optional[Dict[str, Any]] = None
    processing_time_ms: float = 0.0
    email_id: str = ""


# ---------------------------------------------------------------------------
# Lifespan (replaces deprecated @app.on_event("startup"))
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    """Pre-load the ML model on startup."""
    from ml.serve.predict import _get_model
    model = _get_model()
    if model:
        logger.info(f"ML model ready. Classes: {model.classes_}")
    else:
        logger.warning(
            "ML model not trained yet. /predict will use heuristic fallback "
            "until a model is trained and saved."
        )
    yield


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Email Threat Detection API (Role 2 - ML)",
    version="1.0.0",
    description=(
        "AI/ML email threat classification and risk scoring. "
        "Classifies emails as benign, spam, phishing, BEC, or impersonation "
        "and produces a normalized 0-100 risk score."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    from ml.serve.predict import _model
    model_ready = _model is not None and _model._is_trained

    return {
        "status": "healthy",
        "model_loaded": model_ready,
        "model_version": "1.0.0",
        "classes": getattr(_model, "classes_", []) if model_ready else [],
        "note": "Model uses heuristic fallback if not trained" if not model_ready else "Ready",
    }


@app.post("/predict", response_model=PredictionResponse)
async def predict_endpoint(request: EmailPredictRequest):
    """
    Predict email threat category and risk score.

    Accepts parsed email features and returns:
    - Threat classification (benign/spam/phishing/bec/impersonation)
    - Confidence and per-class probabilities
    - Normalized risk score 0-100
    - Risk level (LOW/MEDIUM/HIGH/CRITICAL)
    - Human-readable reasons
    - Security signals detected

    The model works with partial information — missing fields use safe defaults.
    """
    start_time = time.time()

    # Build email dict from request
    # Handle body alias
    body = request.body or request.body_text

    email_dict = {
        "sender": request.sender,
        "reply_to": request.reply_to,
        "return_path": request.return_path,
        "subject": request.subject,
        "body": body,
        "body_text": body,
        "spf": request.spf,
        "dkim": request.dkim,
        "dmarc": request.dmarc,
        "arc": request.arc,
        "urls": request.urls,
        "url_count": request.url_count,
        "html_link_count": request.html_link_count,
        "html_destination_mismatch": request.html_destination_mismatch,
        "ip_count": request.ip_count,
        "private_ips": request.private_ips,
        "attachment_count": request.attachment_count,
        "executable_attachments": request.executable_attachments,
        "header_risk_tally": request.header_risk_tally,
        "header_findings": request.header_findings,
        "evidence_tally": request.evidence_tally,
        "evidence_risk_category": request.evidence_risk_category,
    }

    try:
        result = predict_email_threat(
            email=email_dict,
            threat_intel=request.threat_intel,
        )
    except Exception as exc:
        logger.error(f"Prediction error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Prediction failed: {exc}")

    # Add timing and email_id
    processing_ms = round((time.time() - start_time) * 1000, 2)
    email_id = request.email_id or str(uuid.uuid4())[:8]

    return PredictionResponse(
        schema_version=result.get("schema_version", "1.0"),
        prediction=result.get("prediction", {}),
        risk=result.get("risk", {}),
        signals=result.get("signals", {}),
        reasons=result.get("reasons", [])[:TOP_N_FEATURES],
        model=result.get("model", {}),
        processing_time_ms=processing_ms,
        email_id=email_id,
    )


@app.post("/predict/raw")
async def predict_raw_endpoint(email_dict: Dict[str, Any]):
    """
    Predict from a raw email dict (less strict validation).
    Accepts any dict with email fields.
    """
    start_time = time.time()

    try:
        result = predict_email_threat(email=email_dict)
    except Exception as exc:
        logger.error(f"Raw prediction error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

    result["processing_time_ms"] = round((time.time() - start_time) * 1000, 2)
    return result


# ---------------------------------------------------------------------------
# Development runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")