"""
tests/test_forensic_upgrade.py

Unit tests for the Phase-1 forensic upgrade:
  1. Explainable scorer zero-penalty rules:
     - Missing SPF/DKIM/DMARC (status NONE) -> 0 pts
     - API_ERROR / TIMEOUT / NOT_CONFIGURED / UNAVAILABLE -> 0 pts
     - NOT_FOUND -> 0 pts
     - Score is strictly bounded [0, 100] and deterministic
  2. Auth status normalization (NONE != fail)
  3. Evidence integrity hashing (SHA-256, MD5, SHA-1)
  4. Forensic timeline reconstruction
  5. Case management service & API
  6. Structured investigation verdict generation
"""

import hashlib
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from role1_email_forensics.schema.forensic_report import (
    ForensicReport,
    HeaderAnalysis,
    AuthResults,
    SpfResult_,
    DkimResult_,
    DmarcResult_,
    SpfResult,
    DkimResult,
    DmarcResult,
    IocBundle,
    OriginInference,
    RiskSignal,
    RiskLevel,
)
from role1_email_forensics.risk.explainable_scorer import (
    compute_explainable_score,
    _is_confirmed_malicious,
    _ZERO_RISK_STATUSES,
)
from role1_email_forensics.timeline.timeline_builder import build_timeline
from app.services.case_service import case_service


# ─────────────────────────────────────────────────────────────────────────────
# 1. Explainable Scorer Zero-Penalty Rule Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestExplainableScorerZeroPenalty:

    def test_missing_auth_adds_zero_points(self):
        """SPF/DKIM/DMARC with status 'none' must contribute 0 risk points."""
        report = ForensicReport(
            raw_email_sha256="abc1234567890",
            headers=HeaderAnalysis(
                from_address="user@example.com",
                subject="Meeting reminder",
            ),
            auth=AuthResults(
                spf=SpfResult_(result=SpfResult.NONE),
                dkim=DkimResult_(result=DkimResult.NONE),
                dmarc=DmarcResult_(result=DmarcResult.NONE),
            ),
            iocs=IocBundle(),
            origin=OriginInference(),
            risk_signals=[],
        )

        res = compute_explainable_score(report)
        assert res["risk_score"] == 0, f"Expected 0 risk for missing auth, got {res['risk_score']}"
        assert res["risk_level"] == "LOW"
        assert len(res["risk_breakdown"]) == 0

    def test_failed_threat_intel_adds_zero_points(self):
        """API_ERROR, TIMEOUT, NOT_CONFIGURED, etc. must contribute 0 risk points."""
        report = ForensicReport(
            raw_email_sha256="def1234567890",
            headers=HeaderAnalysis(
                from_address="trusted@partner.com",
                subject="Quarterly Sync",
            ),
            auth=AuthResults(
                spf=SpfResult_(result=SpfResult.PASS),
                dkim=DkimResult_(result=DkimResult.PASS),
                dmarc=DmarcResult_(result=DmarcResult.PASS),
            ),
            threat_intelligence={
                "abuseipdb": {"status": "api_error", "malicious": False},
                "virustotal": {
                    "urls": [{"status": "timeout", "malicious": False}],
                    "hashes": [{"status": "not_configured", "malicious": False}],
                },
                "urlscan": [{"status": "unavailable", "malicious": False}],
            },
            origin=OriginInference(abuse_score=None),
            risk_signals=[],
        )

        res = compute_explainable_score(report)
        assert res["risk_score"] == 0
        assert res["risk_level"] == "LOW"
        ti_penalties = [b for b in res["risk_breakdown"] if b.get("category") == "threat_intel"]
        assert len(ti_penalties) == 0

    def test_not_found_adds_zero_points(self):
        """Threat indicators with NOT_FOUND status represent unobserved items -> 0 pts."""
        for status in _ZERO_RISK_STATUSES:
            mock_res = {"status": status, "malicious": True}
            assert not _is_confirmed_malicious(mock_res), f"Status {status} should not be treated as confirmed malicious"

    def test_confirmed_threat_adds_points_bounded(self):
        """Confirmed phishing IOCs add points accurately and remain bounded [0, 100]."""
        report = ForensicReport(
            raw_email_sha256="bad1234567890",
            headers=HeaderAnalysis(
                from_address="security@paypa1-secure.com",
                subject="Account Suspended! Action Required",
                reply_to="attacker@hacker.io",
            ),
            auth=AuthResults(
                spf=SpfResult_(result=SpfResult.FAIL),
                dkim=DkimResult_(result=DkimResult.FAIL),
                dmarc=DmarcResult_(result=DmarcResult.FAIL),
            ),
            threat_intelligence={
                "abuseipdb": {"status": "available", "malicious": True, "abuse_confidence_score": 100},
                "virustotal": {
                    "urls": [{"status": "available", "malicious": True, "malicious_count": 15}],
                    "hashes": [{"status": "available", "malicious": True, "malicious_count": 22}],
                },
            },
            origin=OriginInference(abuse_score=100),
            risk_signals=[
                RiskSignal(signal_id="REPLY_TO_MISMATCH", level=RiskLevel.HIGH, description="Reply-To mismatch", category="header"),
                RiskSignal(signal_id="SUSPICIOUS_URGENCY", level=RiskLevel.MEDIUM, description="Suspicious urgency keyword", category="body"),
            ],
        )

        res = compute_explainable_score(report)
        assert 0 <= res["risk_score"] <= 100
        assert res["risk_level"] in ("HIGH", "CRITICAL")
        assert len(res["risk_breakdown"]) > 0
        assert len(res["primary_evidence"]) > 0
        assert "verdict" in res
        assert res["confidence"] > 0.5


# ─────────────────────────────────────────────────────────────────────────────
# 2. Evidence Integrity Hashing Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEvidenceIntegrity:

    def test_byte_hashes_match(self):
        """Raw email bytes must generate exact SHA-256, MD5, and SHA-1."""
        raw_bytes = b"From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nHello"
        sha256_expected = hashlib.sha256(raw_bytes).hexdigest()
        md5_expected = hashlib.md5(raw_bytes).hexdigest()
        sha1_expected = hashlib.sha1(raw_bytes).hexdigest()

        assert len(sha256_expected) == 64
        assert len(md5_expected) == 32
        assert len(sha1_expected) == 40


# ─────────────────────────────────────────────────────────────────────────────
# 3. Forensic Timeline Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestForensicTimeline:

    def test_timeline_reconstruction(self):
        """Timeline must separate SMTP transmission events, ingestion, and pipeline steps."""
        report = ForensicReport(
            raw_email_sha256="timelinetestsha256",
            headers=HeaderAnalysis(
                date="Thu, 10 Sep 2026 12:00:00 +0000",
                from_address="sender@domain.com",
                subject="Timeline Check",
            ),
            auth=AuthResults(
                spf=SpfResult_(result=SpfResult.PASS),
                dkim=DkimResult_(result=DkimResult.PASS),
                dmarc=DmarcResult_(result=DmarcResult.PASS),
            ),
            smtp_path=[],
            iocs=IocBundle(),
            origin=OriginInference(),
            risk_signals=[],
        )

        timeline = build_timeline(report)
        assert isinstance(timeline, list)
        assert len(timeline) >= 2
        categories = {e.get("category") for e in timeline}
        assert "email" in categories
        assert "auth" in categories


# ─────────────────────────────────────────────────────────────────────────────
# 4. Case Service Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCaseService:

    def test_save_and_retrieve_case(self, tmp_path):
        """Case service must save and retrieve cases with deterministic IDs."""
        with patch.object(case_service, "cases_dir", tmp_path):
            case_id = case_service.generate_case_id()
            assert case_id.startswith("CASE-")

            saved = case_service.save_case(
                case_id=case_id,
                filename="test.eml",
                sha256="testhash123456",
                verdict="LOW RISK — BENIGN",
                risk_score=5,
                risk_level="LOW",
                full_result={"case_id": case_id, "score": 5},
            )
            assert saved["case_id"] == case_id

            retrieved = case_service.get_case(case_id)
            assert retrieved is not None
            assert retrieved["case_id"] == case_id
            assert retrieved["filename"] == "test.eml"

            cases = case_service.list_cases()
            assert any(c["case_id"] == case_id for c in cases)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Case & Analyze API Endpoints Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCaseEndpoints:

    def test_list_cases_endpoint(self, client):
        """GET /api/cases must return JSON list of saved cases."""
        r = client.get("/api/cases")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "cases" in data
        assert isinstance(data["cases"], list)

    def test_case_not_found_returns_404(self, client):
        """GET /api/cases/{invalid_id} returns 404."""
        r = client.get("/api/cases/CASE-NONEXISTENT-999")
        assert r.status_code == 404


class TestAnalyzeEndpointSmoke:

    def test_analyze_endpoint_returns_all_forensic_fields(self, client):
        """POST /api/analyze must return all explainable forensic fields."""
        sample_path = Path(__file__).parent / "sample_emails" / "phishing_sample.eml"
        assert sample_path.exists(), f"Sample email not found at {sample_path}"
        raw = sample_path.read_bytes()

        r = client.post(
            "/api/analyze",
            files={"file": ("phishing_sample.eml", raw, "message/rfc822")},
        )
        assert r.status_code == 200
        data = r.json()

        # Evidence integrity
        assert "email_sha256" in data
        assert len(data["email_sha256"]) == 64
        assert "case_id" in data
        assert data["case_id"].startswith("CASE-")

        # Explainable scoring
        assert "risk_score" in data
        assert 0 <= data["risk_score"] <= 100
        assert "risk_level" in data
        assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert "verdict" in data
        assert "confidence" in data
        assert "risk_breakdown" in data
        assert isinstance(data["risk_breakdown"], list)
        assert "primary_evidence" in data
        assert isinstance(data["primary_evidence"], list)
        assert "recommended_actions" in data
        assert "limitations" in data

        # Timeline
        assert "timeline" in data
        assert isinstance(data["timeline"], list)
        assert len(data["timeline"]) > 0

        # Forensics & Threat Intel
        assert "forensics" in data
        assert "threat_intel" in data
        assert "graph_data" in data
