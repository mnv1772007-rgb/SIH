from unittest.mock import patch
from app.services.confidence_analyzer import confidence_analyzer
from app.models.graph_models import ConfidenceLevel


def test_confidence_calculation_with_telemetry():
    mock_telemetry = {
        "campaign": {"campaign_id": "camp-test-01", "risk_score": 0.90},
        "emails": [
            {
                "email_id": "e1",
                "subject": "Urgent verification required",
                "timestamp": "2026-09-10T08:00:00Z",
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
                "classification": "phishing",
            },
            {
                "email_id": "e2",
                "subject": "Urgent verification notice",
                "timestamp": "2026-09-10T08:25:00Z",
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
                "classification": "phishing",
            },
        ],
        "campaign_domains": ["phish-portal.com"],
        "campaign_ips": ["198.51.100.25"],
        "campaign_urls": ["https://phish-portal.com/login"],
        "campaign_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    }

    with patch.object(confidence_analyzer, "_fetch_campaign_telemetry", return_value=mock_telemetry):
        result = confidence_analyzer.calculate_attribution_confidence("camp-test-01")

        assert result is not None
        assert 0.0 <= result.confidence <= 1.0
        assert result.level in [ConfidenceLevel.HIGH, ConfidenceLevel.VERY_HIGH, ConfidenceLevel.MEDIUM]
        assert result.breakdown.infrastructure > 0.5
        assert result.breakdown.temporal > 0.7
        assert len(result.evidence) > 0
        assert len(result.limitations) > 0
        # Verify strict non-attribution policy text
        assert "attacker" not in result.methodology_disclaimer.lower() or "not be interpreted as proof" in result.methodology_disclaimer
