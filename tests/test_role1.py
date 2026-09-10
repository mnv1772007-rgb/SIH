"""
Role 1 Test Suite — Email Forensics & Protocol Module
SIH 26106 — IronPulse

Tests:
  - EML parsing (bytes + file)
  - Header extraction (From, Reply-To, anomaly flags)
  - SMTP relay reconstruction
  - IOC extraction (URLs, IPs, domains)
  - Auth result structure
  - Origin inference
  - Risk signal generation
  - Full pipeline (analyze_eml_file)
  - FastAPI endpoint (async)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# ── Pipeline entry point ────────────────────────────────────────────────────
from role1_email_forensics.main import analyze_eml_file, analyze_eml_bytes
from role1_email_forensics.schema.forensic_report import (
    ForensicReport, SpfResult, DkimResult, DmarcResult, ArcResult,
    RiskLevel,
)
from role1_email_forensics.parser.eml_parser       import parse_eml_bytes
from role1_email_forensics.parser.header_extractor import extract_headers
from role1_email_forensics.parser.body_extractor   import extract_body
from role1_email_forensics.smtp.relay_reconstructor import reconstruct_relay_path
from role1_email_forensics.ioc.url_extractor       import UrlExtractor
from role1_email_forensics.ioc.ip_extractor        import IpExtractor
from role1_email_forensics.ioc.domain_extractor    import DomainExtractor
from role1_email_forensics.utils.helpers           import (
    decode_mime_words, classify_ip, defang_url, is_typosquat, has_homoglyph,
)

# ── Sample email paths ──────────────────────────────────────────────────────
SAMPLES = Path(__file__).parent / "sample_emails"
PHISHING   = SAMPLES / "phishing_sample.eml"
BEC        = SAMPLES / "bec_sample.eml"
LEGITIMATE = SAMPLES / "legitimate_sample.eml"


# ===========================================================================
# Helpers
# ===========================================================================

def load_sample(path: Path) -> bytes:
    return path.read_bytes()


# ===========================================================================
# 1. Utilities
# ===========================================================================

class TestHelpers:
    def test_decode_mime_words_plain(self):
        assert decode_mime_words("Hello World") == "Hello World"

    def test_decode_mime_words_base64(self):
        # "[ACTION REQUIRED] Your PayPal account has been limited!"
        encoded = "=?UTF-8?B?W0FDVElPTiBSRVFVSVJFRF0gWW91ciBQYXlQYWwgYWNjb3VudCBoYXMgYmVlbiBsaW1pdGVkIQ==?="
        decoded = decode_mime_words(encoded)
        assert "ACTION REQUIRED" in decoded
        assert "PayPal" in decoded

    def test_classify_ip_public(self):
        assert classify_ip("8.8.8.8") == "public"

    def test_classify_ip_private(self):
        assert classify_ip("192.168.1.1") == "private"
        assert classify_ip("10.0.0.1")    == "private"
        assert classify_ip("172.16.0.1")  == "private"

    def test_classify_ip_loopback(self):
        assert classify_ip("127.0.0.1") == "loopback"

    def test_defang_url(self):
        defanged = defang_url("https://evil.com/steal")
        assert "hxxps" in defanged
        assert "[.]" in defanged

    def test_is_typosquat_paypal(self):
        assert is_typosquat("paypa1.com") is True    # 1 edit
        assert is_typosquat("google.com") is False    # exact match → not typosquat

    def test_has_homoglyph(self):
        # Cyrillic 'а' in "аpple" looks like Latin 'a'
        assert has_homoglyph("аpple.com") is True
        assert has_homoglyph("apple.com") is False


# ===========================================================================
# 2. EML Parser
# ===========================================================================

class TestEmlParser:
    def test_parse_phishing_bytes(self):
        raw = load_sample(PHISHING)
        msg, sha256, size = parse_eml_bytes(raw)
        assert msg is not None
        assert len(sha256) == 64
        assert size > 0

    def test_sha256_deterministic(self):
        raw = load_sample(PHISHING)
        _, sha1, _ = parse_eml_bytes(raw)
        _, sha2, _ = parse_eml_bytes(raw)
        assert sha1 == sha2


# ===========================================================================
# 3. Header Extractor
# ===========================================================================

class TestHeaderExtractor:
    def test_phishing_from_address(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        headers = extract_headers(msg)
        assert headers.from_address is not None
        assert "paypa1.com" in headers.from_address  # typosquat domain

    def test_phishing_reply_to_mismatch(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        headers = extract_headers(msg)
        # From: paypa1.com but Reply-To: evil-login-verify.tk
        assert headers.from_reply_to_mismatch is True

    def test_phishing_subject_decoded(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        headers = extract_headers(msg)
        assert headers.subject is not None
        assert "PayPal" in headers.subject or "ACTION REQUIRED" in headers.subject

    def test_bec_reply_to_gmail(self):
        raw = load_sample(BEC)
        msg, _, _ = parse_eml_bytes(raw)
        headers = extract_headers(msg)
        assert headers.reply_to is not None
        assert "gmail.com" in headers.reply_to
        assert headers.from_reply_to_mismatch is True

    def test_bec_return_path_mismatch(self):
        raw = load_sample(BEC)
        msg, _, _ = parse_eml_bytes(raw)
        headers = extract_headers(msg)
        # From: legitcorp-fianance.com, Return-Path: legitcorp-finance.com
        assert headers.from_return_path_mismatch is True

    def test_legitimate_headers(self):
        raw = load_sample(LEGITIMATE)
        msg, _, _ = parse_eml_bytes(raw)
        headers = extract_headers(msg)
        assert headers.from_address is not None
        assert "google.com" in headers.from_address
        assert headers.from_reply_to_mismatch is False

    def test_message_id_present(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        headers = extract_headers(msg)
        assert headers.message_id is not None

    def test_x_originating_ip(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        headers = extract_headers(msg)
        assert headers.x_originating_ip == "45.142.212.100"


# ===========================================================================
# 4. SMTP Relay Reconstruction
# ===========================================================================

class TestSmtpRelayReconstructor:
    def test_phishing_hop_count(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        hops = reconstruct_relay_path(msg)
        assert len(hops) >= 2

    def test_hop_numbering(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        hops = reconstruct_relay_path(msg)
        for i, hop in enumerate(hops, start=1):
            assert hop.hop == i

    def test_hop1_from_ip(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        hops = reconstruct_relay_path(msg)
        # Hop 1 should be from the external sending server
        assert hops[0].from_ip is not None

    def test_private_ip_flag(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        hops = reconstruct_relay_path(msg)
        # One hop should have private_ip flag (127.0.0.1 in phishing sample)
        all_flags = [f for hop in hops for f in hop.flags]
        assert "private_ip" in all_flags

    def test_legitimate_hops(self):
        raw = load_sample(LEGITIMATE)
        msg, _, _ = parse_eml_bytes(raw)
        hops = reconstruct_relay_path(msg)
        assert len(hops) >= 1


# ===========================================================================
# 5. IOC Extractors
# ===========================================================================

class TestUrlExtractor:
    def test_phishing_urls_found(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        body = extract_body(msg)
        ex = UrlExtractor()
        urls = ex.extract(body.text_plain, body.text_html)
        assert len(urls) > 0

    def test_suspicious_url_flagged(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        body = extract_body(msg)
        ex = UrlExtractor()
        urls = ex.extract(body.text_plain, body.text_html)
        suspicious = [u for u in urls if u.suspicious]
        assert len(suspicious) > 0

    def test_bare_ip_url_suspicious(self):
        ex = UrlExtractor()
        urls = ex.extract("Click here: http://45.142.212.100/malware.php", None)
        assert any(u.suspicious for u in urls)

    def test_url_defanged(self):
        ex = UrlExtractor()
        urls = ex.extract("https://evil.com/page", None)
        assert all("hxxps" in u.defanged for u in urls if "https" in u.url)


class TestIpExtractor:
    def test_phishing_ips_extracted(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        hops = reconstruct_relay_path(msg)
        body = extract_body(msg)
        raw_headers = "\n".join(f"{k}: {v}" for k, v in msg.items())
        ex = IpExtractor()
        ips = ex.extract(body.text_plain, body.text_html, hops, raw_headers)
        public_ips = [ip for ip in ips if ip.ip_type.value == "public"]
        assert len(public_ips) > 0

    def test_ip_types(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        hops = reconstruct_relay_path(msg)
        ex = IpExtractor()
        ips = ex.extract(None, None, hops, "")
        types = {ip.ip_type.value for ip in ips}
        assert "public" in types or "private" in types


class TestDomainExtractor:
    def test_phishing_typosquat_detected(self):
        raw = load_sample(PHISHING)
        msg, _, _ = parse_eml_bytes(raw)
        body = extract_body(msg)
        headers = extract_headers(msg)
        ex_url = UrlExtractor()
        urls = ex_url.extract(body.text_plain, body.text_html)
        ex = DomainExtractor()
        domains = ex.extract(headers, urls, body.text_plain, body.text_html)
        typosquats = [d for d in domains if d.typosquat_suspected]
        # "paypa1.com" should be detected as typosquat of "paypal"
        assert len(typosquats) > 0

    def test_bec_domain_extracted(self):
        raw = load_sample(BEC)
        msg, _, _ = parse_eml_bytes(raw)
        body = extract_body(msg)
        headers = extract_headers(msg)
        ex = DomainExtractor()
        domains = ex.extract(headers, [], body.text_plain, body.text_html)
        domain_names = [d.domain for d in domains]
        assert any("legitcorp" in d for d in domain_names)


# ===========================================================================
# 6. Full Pipeline
# ===========================================================================

class TestFullPipeline:
    def test_phishing_pipeline(self):
        report = analyze_eml_file(PHISHING)
        assert isinstance(report, ForensicReport)
        assert report.raw_email_sha256 is not None
        assert report.headers.from_address is not None
        assert len(report.smtp_path) >= 1
        assert len(report.iocs.urls) > 0
        assert len(report.risk_signals) > 0

    def test_bec_pipeline(self):
        report = analyze_eml_file(BEC)
        assert isinstance(report, ForensicReport)
        # BEC has reply-to mismatch → risk signal expected
        reply_to_signals = [
            s for s in report.risk_signals
            if "Reply-To" in s.description or "return" in s.description.lower()
        ]
        assert len(reply_to_signals) > 0

    def test_legitimate_pipeline(self):
        report = analyze_eml_file(LEGITIMATE)
        assert isinstance(report, ForensicReport)
        # Should have fewer/no critical risk signals
        critical = [s for s in report.risk_signals if s.level == RiskLevel.CRITICAL]
        assert len(critical) == 0

    def test_report_serialization(self):
        report = analyze_eml_file(PHISHING)
        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert "report_id" in parsed
        assert "headers" in parsed
        assert "auth" in parsed
        assert "smtp_path" in parsed
        assert "iocs" in parsed
        assert "origin" in parsed
        assert "risk_signals" in parsed

    def test_report_roundtrip(self):
        report = analyze_eml_file(PHISHING)
        json_str = report.to_json()
        report2 = ForensicReport.from_json(json_str)
        assert report.report_id == report2.report_id
        assert report.raw_email_sha256 == report2.raw_email_sha256

    def test_bytes_vs_file_identical(self):
        raw = PHISHING.read_bytes()
        report_file  = analyze_eml_file(PHISHING)
        report_bytes = analyze_eml_bytes(raw, filename=PHISHING.name)
        assert report_file.raw_email_sha256 == report_bytes.raw_email_sha256

    def test_auth_fields_present(self):
        report = analyze_eml_file(PHISHING)
        assert report.auth.spf.result is not None
        assert report.auth.dkim.result is not None
        assert report.auth.dmarc.result is not None
        assert report.auth.arc.result is not None

    def test_origin_note_present(self):
        """Ensure attribution disclaimer is always in the report."""
        report = analyze_eml_file(PHISHING)
        assert "infrastructure" in report.origin.note.lower()
        assert "NOT" in report.origin.note


# ===========================================================================
# 7. FastAPI Endpoint
# ===========================================================================

@pytest.mark.asyncio
class TestFastApiEndpoint:
    async def test_health_endpoint(self):
        from fastapi.testclient import TestClient
        from role1_email_forensics.main import create_app

        app = create_app()
        client = TestClient(app)
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    async def test_analyze_endpoint_phishing(self):
        from fastapi.testclient import TestClient
        from role1_email_forensics.main import create_app

        app = create_app()
        client = TestClient(app)
        raw = PHISHING.read_bytes()
        r = client.post(
            "/api/v1/analyze",
            files={"file": ("phishing_sample.eml", raw, "message/rfc822")},
        )
        assert r.status_code == 200
        data = r.json()
        assert "report_id" in data
        assert "risk_signals" in data
        assert len(data["risk_signals"]) > 0
