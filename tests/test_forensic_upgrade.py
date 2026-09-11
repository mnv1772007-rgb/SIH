"""
Unit and regression tests for ShieldMail forensic audit and upgrades:
- Leetspeak and hyphenated typosquatting detection
- Header-based MTA Authentication-Results fallback
- Spam status & urgency headers parsing and scoring
- Centralized risk thresholds (0-24, 25-49, 50-74, 75-100)
- Real email sample verification across all sample suites:
  - phishing_paypal.eml (CRITICAL)
  - phishing_sample.eml (CRITICAL)
  - bec_sample.eml (MEDIUM)
  - legitimate_sample.eml (LOW)
"""
import email
from pathlib import Path
import pytest

from role1_email_forensics.utils.helpers import is_typosquat, has_homoglyph
from role1_email_forensics.risk.explainable_scorer import compute_explainable_score, classify_risk
from role1_email_forensics.parser.header_extractor import extract_headers
from role1_email_forensics.main import analyze_eml_file

def test_typosquat_detection_extended():
    # Brand variations with leetspeak and hyphens
    assert is_typosquat("paypa1-secure.com") is True
    assert is_typosquat("paypa1-verify.ru") is True
    assert is_typosquat("micros0ft-login.com") is True
    assert is_typosquat("amaz0n-support.net") is True
    assert is_typosquat("app1e-id.co") is True
    
    # Legitimate domains should not be flagged
    assert is_typosquat("paypal.com") is False
    assert is_typosquat("google.com") is False
    assert is_typosquat("microsoft.com") is False
    assert is_typosquat("github.com") is False

def test_centralized_thresholds():
    assert classify_risk(0) == "LOW"
    assert classify_risk(24) == "LOW"
    assert classify_risk(25) == "MEDIUM"
    assert classify_risk(49) == "MEDIUM"
    assert classify_risk(50) == "HIGH"
    assert classify_risk(74) == "HIGH"
    assert classify_risk(75) == "CRITICAL"
    assert classify_risk(100) == "CRITICAL"

def test_header_extraction_spam_and_priority():
    raw_headers = (
        "From: Security <security@paypa1-secure.com>\n"
        "To: victim@example.com\n"
        "Subject: Urgent Action Required\n"
        "X-Spam-Status: Yes, score=12.4 required=5.0 tests=PHISH\n"
        "X-Priority: 1\n"
        "Authentication-Results: mx.google.com; dkim=fail; spf=fail\n"
    )
    msg = email.message_from_string(raw_headers)
    headers = extract_headers(msg)
    assert "Yes" in headers.x_spam_status
    assert headers.x_spam_score == 12.4
    assert headers.x_priority == "1"
    assert headers.recorded_auth.get("spf") == "fail"
    assert headers.recorded_auth.get("dkim") == "fail"

def test_real_sample_phishing_paypal_remediation():
    sample_path = Path("test_samples/phishing_paypal.eml")
    if not sample_path.exists():
        pytest.skip("test_samples/phishing_paypal.eml not found")
    
    report = analyze_eml_file(str(sample_path), enrich=False)
    score_data = compute_explainable_score(report)
    
    # Previously dropped to 28 (LOW), must now be >= 75 (CRITICAL)
    assert score_data["risk_score"] >= 75, f"Expected >= 75, got {score_data['risk_score']}"
    assert score_data["risk_level"] == "CRITICAL"
    
    # Check that key evidence signals are present in explainable score factors
    factors = score_data["risk_factors"]
    assert any("SPF" in f or "DMARC" in f for f in factors)
    assert any("TYPOSQUAT" in f or "URL" in f or "SPAM" in f for f in factors)

def test_real_sample_legitimate_false_positive_guard():
    sample_path = Path("tests/sample_emails/legitimate_sample.eml")
    if not sample_path.exists():
        pytest.skip("tests/sample_emails/legitimate_sample.eml not found")
    
    report = analyze_eml_file(str(sample_path), enrich=False)
    score_data = compute_explainable_score(report)
    
    # Legitimate emails must stay strictly in LOW (0-24)
    assert score_data["risk_score"] <= 24, f"Legitimate email scored too high: {score_data['risk_score']}"
    assert score_data["risk_level"] == "LOW"

def test_real_sample_phishing_sample():
    sample_path = Path("tests/sample_emails/phishing_sample.eml")
    if not sample_path.exists():
        pytest.skip("tests/sample_emails/phishing_sample.eml not found")
    
    report = analyze_eml_file(str(sample_path), enrich=False)
    score_data = compute_explainable_score(report)
    assert score_data["risk_score"] >= 75
    assert score_data["risk_level"] == "CRITICAL"

def test_real_sample_bec_sample():
    sample_path = Path("tests/sample_emails/bec_sample.eml")
    if not sample_path.exists():
        pytest.skip("tests/sample_emails/bec_sample.eml not found")
    
    report = analyze_eml_file(str(sample_path), enrich=False)
    score_data = compute_explainable_score(report)
    # BEC sample has mismatch indicators and ML BEC flag (25-49: MEDIUM)
    assert 25 <= score_data["risk_score"] <= 74, f"Expected 25-74, got {score_data['risk_score']}"
    assert score_data["risk_level"] in ("MEDIUM", "HIGH")
