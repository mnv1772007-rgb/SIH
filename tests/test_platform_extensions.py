"""Contract tests for the unified platform extensions and safe optional features."""

from __future__ import annotations

import os
from pathlib import Path

os.environ["THREAT_INTELLIGENCE_ENABLED"] = "false"
os.environ["PHISHTANK_ENABLED"] = "false"
os.environ["NEO4J_ENABLED"] = "false"
os.environ["ML_MODEL_ENABLED"] = "false"

from fastapi.testclient import TestClient

from AI_model.inference import classify_text
from Backend.main import app
from Backend.services.analysis_service import AnalysisService
from Backend.services.case_store import CaseStore
from phishtank_client import check_url


ROOT = Path(__file__).resolve().parents[1]


def _message(subject: str, body: str, headers: str = "") -> bytes:
    return f"""From: sender@example.test
To: analyst@example.test
Subject: {subject}
{headers}MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

{body}
""".encode()


def test_authentication_forensics_distinguishes_evidence_from_signature(tmp_path):
    service = AnalysisService(ROOT, CaseStore(tmp_path / "cases.sqlite3"))
    raw = _message(
        "Authentication test",
        "Hello",
        "Authentication-Results: mx.example.test;\n spf=pass smtp.mailfrom=example.test; dkim=temperror header.d=example.test;\n dmarc=none header.from=example.test\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=selector;\n"
        "Received-SPF: pass (example.test: domain of sender@example.test designates 192.0.2.10 as permitted sender)\n",
    )
    report = service.analyze(raw, "auth.eml")

    assert report["authentication"]["spf"] == {"result": "pass", "status": "PASS", "display_status": "PASS", "source": "Authentication-Results"}
    assert report["authentication"]["dkim"]["display_status"] == "FAIL"
    assert report["authentication"]["dmarc"]["display_status"] == "NOT PRESENT"
    assert report["authentication"]["dkim_signature_present"] is True
    assert report["authentication"]["dkim"]["source"] == "Authentication-Results"


def test_received_spf_is_used_only_when_authentication_results_lacks_spf(tmp_path):
    service = AnalysisService(ROOT, CaseStore(tmp_path / "cases.sqlite3"))
    report = service.analyze(
        _message("SPF fallback", "Hello", "Received-SPF: softfail (example.test: policy)\n"),
        "received-spf.eml",
    )

    assert report["authentication"]["spf"]["result"] == "softfail"
    assert report["authentication"]["spf"]["source"] == "Received-SPF"
    assert report["authentication"]["dkim"]["display_status"] == "NOT PRESENT"


def test_correlation_requires_meaningful_shared_evidence(tmp_path):
    service = AnalysisService(ROOT, CaseStore(tmp_path / "cases.sqlite3"))
    first = service.analyze(_message("A", "https://campaign.example/offer"), "first.eml")
    second = service.analyze(_message("B", "https://campaign.example/offer"), "second.eml")

    correlation = second["campaign_correlation"]
    assert correlation["status"] == "possible_cluster"
    assert correlation["campaign_id"].startswith("campaign_")
    assert correlation["matches"][0]["strength"] >= 4
    assert any(item.startswith("url:") for item in correlation["shared_indicators"])
    assert first["campaign_correlation"]["status"] == "no_related_cases"


def test_platform_api_samples_compare_and_multi_format_export():
    client = TestClient(app)
    samples = client.get("/api/samples")
    assert samples.status_code == 200
    assert "sample.eml" in {item["name"] for item in samples.json()["samples"]}

    first = client.post("/api/analyze/raw", json={"raw_email": _message("Comparison A", "https://same.example/a").decode(), "source_name": "comparison-a.eml"})
    second = client.post("/api/analyze/raw", json={"raw_email": _message("Comparison B", "https://same.example/a").decode(), "source_name": "comparison-b.eml"})
    assert first.status_code == second.status_code == 200
    first_id, second_id = first.json()["case"]["case_id"], second.json()["case"]["case_id"]
    try:
        comparison = client.get("/api/cases/compare", params=[("case_ids", first_id), ("case_ids", second_id)])
        assert comparison.status_code == 200, comparison.text
        assert any(item.startswith("url:") for item in comparison.json()["shared_indicators"])
        assert client.get("/api/campaigns").status_code == 200
        assert client.get("/api/dashboard/stats").status_code == 200
        assert client.get("/api/threat-intel/same.example").status_code == 200
        json_export = client.post(f"/api/reports/{first_id}/export", json={"format": "json"})
        html_export = client.post(f"/api/reports/{first_id}/export", json={"format": "html"})
        assert json_export.status_code == html_export.status_code == 200
        assert json_export.json()["case"]["case_id"] == first_id
        assert "<html" in html_export.text.lower()
    finally:
        client.delete(f"/api/cases/{first_id}")
        client.delete(f"/api/cases/{second_id}")


def test_optional_model_and_phishtank_are_non_network_and_non_verdicting_by_default():
    assert classify_text("urgent account verification required") == {
        "status": "disabled", "label": "unknown", "confidence": None, "confidence_level": "unknown",
    }
    result = check_url("https://indicator.example/path")
    assert result["status"] == "disabled"
    assert result["source"] == "PhishTank"
