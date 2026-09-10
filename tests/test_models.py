import pytest
from pydantic import ValidationError
from app.models.integration_contract import (
    EmailAnalysisIngestPayload,
    EmailData,
    IOCIP,
    DetectionData,
)


def test_valid_ingest_payload():
    payload = {
        "schema_version": "1.0",
        "analysis_id": "analysis-123",
        "email": {
            "email_id": "email-abc",
            "message_id": "<msg@example.com>",
            "subject": "Urgent Verification",
            "sender": "sec@evil-domain.com",
            "recipient": "user@target.org",
            "timestamp": "2026-09-10T04:30:00Z",
        },
        "authentication": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "iocs": {
            "domains": [{"value": "evil-domain.com"}],
            "ips": [{"value": "198.51.100.10"}],
            "urls": [{"value": "https://evil-domain.com/login"}],
            "hashes": [{"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
        },
        "detection": {"classification": "phishing", "risk_score": 0.88, "confidence": 0.92},
    }
    model = EmailAnalysisIngestPayload.model_validate(payload)
    assert model.email.email_id == "email-abc"
    assert model.email.sender_domain == "evil-domain.com"
    assert model.iocs.ips[0].value == "198.51.100.10"
    assert model.detection.risk_score == 0.88


def test_invalid_ip_rejection():
    with pytest.raises(ValidationError):
        IOCIP(value="300.400.500.600")


def test_risk_score_clamping():
    det = DetectionData(risk_score=1.5, confidence=-0.2)
    assert det.risk_score == 1.0
    assert det.confidence == 0.0


def test_backward_compatibility_flat_payload():
    legacy_payload = {
        "email": {
            "message_id": "<legacy-123@xyz.com>",
            "subject": "Legacy subject",
            "sender": "test@sender-domain.com",
            "recipients": ["victim@company.com"],
            "timestamp": "2026-09-10T05:00:00Z",
        },
        "iocs": {
            "domains": ["sender-domain.com", "relay.org"],
            "ips": ["198.51.100.99"],
            "urls": ["http://relay.org/action"],
            "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        },
        "risk_score": 0.82,
    }
    model = EmailAnalysisIngestPayload.model_validate(legacy_payload)
    assert model.email.email_id is not None
    assert model.email.sender_domain == "sender-domain.com"
    assert len(model.iocs.domains) == 2
    assert model.detection.risk_score == 0.82
