import os
from pathlib import Path

# Tests must never spend the developer's API quota or send local samples to an
# optional provider merely because a real .env is present on the workstation.
os.environ["THREAT_INTELLIGENCE_ENABLED"] = "false"

from fastapi.testclient import TestClient

from Backend.main import app
from Backend.services.analysis_service import AnalysisError, AnalysisService
from Backend.services.case_store import CaseStore


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_service_produces_unified_explainable_response(tmp_path):
    service = AnalysisService(ROOT, CaseStore(tmp_path / "cases.sqlite3"))
    report = service.analyze((SAMPLES / "html_sample.eml").read_bytes(), "html_sample.eml")

    assert report["case"]["case_id"].startswith("case_")
    assert report["verdict"]["risk_score"] > 0
    assert report["authentication"]["spf"]["result"] == "not_found"
    assert report["html_analysis"][0]["destination_mismatch"] is True
    assert report["graph"]["storage"] == "generated_json_fallback"
    assert report["risk_factors"]


def test_phishing_attachment_and_infrastructure_fallbacks(tmp_path):
    service = AnalysisService(ROOT, CaseStore(tmp_path / "cases.sqlite3"))
    raw = b"""From: CEO <ceo@example.com>
To: analyst@example.net
Reply-To: cashout@example.net
Subject: Urgent invoice payment
Authentication-Results: mx.example.net; spf=fail dkim=fail dmarc=fail
Received: from mail.example.org (8.8.8.8) by mx.example.net; Fri, 1 Jan 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=mail

--mail
Content-Type: text/html; charset=utf-8

Act now to verify your account. <a href="https://fake.example/login">https://bank.example</a>
--mail
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--mail--
"""
    report = service.analyze(raw, "phishing.eml")

    assert report["verdict"]["risk_level"] == "CRITICAL"
    assert report["attachments"][0]["is_executable_extension"] is True
    assert report["ip_analysis"][0]["is_global"] is True
    assert report["geolocation"][0]["status"] == "disabled"
    assert report["urls"][0]["threat_intelligence"]["virustotal"]["status"] == "disabled"
    assert report["html_analysis"][0]["destination_mismatch"] is True


def test_service_rejects_non_email_input(tmp_path):
    service = AnalysisService(ROOT, CaseStore(tmp_path / "cases.sqlite3"))
    try:
        service.analyze(b"this is not an RFC822 message")
    except AnalysisError as error:
        assert "RFC822" in str(error)
    else:
        raise AssertionError("Non-email input should be rejected")


def test_api_raw_case_and_graph_lifecycle():
    client = TestClient(app)
    raw = (SAMPLES / "sample.eml").read_text(encoding="utf-8")
    response = client.post("/api/analyze/raw", json={"raw_email": raw, "source_name": "sample.eml"})
    assert response.status_code == 200, response.text
    report = response.json()
    case_id = report["case"]["case_id"]
    assert client.get("/health").json()["status"] == "healthy"
    assert client.get(f"/api/cases/{case_id}").status_code == 200
    assert client.get(f"/api/graph/{case_id}").json()["nodes"]
    assert client.get(f"/api/reports/{case_id}").status_code == 200
    assert client.get("/api/graph/campaigns").status_code == 200
    assert client.delete(f"/api/cases/{case_id}").status_code == 200


def test_dashboard_docs_and_sample_load_flow():
    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert "Email Threat Forensics" in client.get("/").text
    assert client.get("/script.js").status_code == 200
    assert client.get("/style.css").status_code == 200
    assert client.get("/docs").status_code == 200
    sample = client.get("/api/sample")
    assert sample.status_code == 200
    payload = sample.json()
    assert payload["source_name"] == "sample.eml"
    assert payload["raw_email"].startswith("From:")
    report = client.post("/api/analyze/raw", json=payload)
    assert report.status_code == 200, report.text
    assert client.delete(f"/api/cases/{report.json()['case']['case_id']}").status_code == 200


def test_api_upload_and_invalid_extension():
    client = TestClient(app)
    data = (SAMPLES / "sample.eml").read_bytes()
    response = client.post("/api/analyze", files={"file": ("sample.eml", data, "message/rfc822")})
    assert response.status_code == 200, response.text
    case_id = response.json()["case"]["case_id"]
    assert client.post("/api/analyze", files={"file": ("invalid.txt", data, "text/plain")}).status_code == 422
    assert client.delete(f"/api/cases/{case_id}").status_code == 200
