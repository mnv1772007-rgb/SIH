"""Regression coverage for evidence-tiered URL verdicting."""

from __future__ import annotations

from pathlib import Path

import pytest

import urlhaus_client
import urlscan_client
import virustotal_client
from Backend.services.analysis_service import AnalysisService
from Backend.services.case_store import CaseStore


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(ROOT, CaseStore(tmp_path / "cases.sqlite3"))


def analyze_link(service: AnalysisService, url: str, *, subject: str = "Notification") -> dict:
    raw = f"""From: Notifications <notify@example.test>
To: analyst@example.test
Subject: {subject}
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body><a href=\"{url}\">Open notification</a></body></html>
""".encode()
    return service.analyze(raw, "url-regression.eml")


def test_legitimate_https_url_with_long_query_string_is_informational(service):
    url = "https://newsletter.example/campaign/announcement?" + "&".join(
        f"parameter_{number}=value_{number:02d}" for number in range(14)
    )
    report = analyze_link(service, url)
    result = report["urls"][0]

    assert result["classification"] == "informational"
    assert result["risk_contribution"] == 0
    assert result["normalized_url"] == url
    assert result["query_parameters"]
    assert report["verdict"]["classification"] == "no_high_risk_signal"


def test_legitimate_marketing_tracking_url_is_not_a_threat(service):
    url = "https://offers.example/products/new?utm_source=email&utm_medium=campaign&utm_campaign=autumn&gclid=abc123"
    result = analyze_link(service, url)["urls"][0]

    assert result["classification"] == "informational"
    assert result["risk_contribution"] == 0
    assert result["features"]["has_tracking_parameters"] is True


def test_legitimate_social_notification_does_not_use_domain_whitelisting(service):
    # This representative social-network notification contains the exact kinds
    # of tracking and generic vocabulary that previously caused escalation.
    # No production rule identifies or whitelists this domain.
    url = "https://www.linkedin.com/comm/track?trk=email_notification_security_update&context=network_message&midToken=token&lipi=token"
    report = analyze_link(service, url, subject="You have a new network notification")
    result = report["urls"][0]

    assert result["classification"] == "informational"
    assert result["risk_contribution"] == 0
    assert {"message", "network", "notification", "security", "update"}.issubset(result["features"]["generic_terms"])
    assert report["verdict"]["classification"] == "no_high_risk_signal"
    assert report["authentication"]["spf"]["display_status"] == "NOT PRESENT"


def test_confirmed_phishing_structure_requires_independent_dangerous_signals(service):
    url = "https://user:pass@0x7f000001:8443/verify?password=stolen&redirect=https%3A%2F%2Fexample.org"
    report = analyze_link(service, url, subject="Please verify")
    result = report["urls"][0]

    assert result["classification"] == "malicious"
    assert result["verdict_basis"] == "strong_combination_of_independent_structural_indicators"
    assert result["risk_contribution"] >= 65
    assert report["verdict"]["classification"] == "malicious"


def test_malicious_feed_match_is_strong_evidence(service, tmp_path):
    url = "https://phishing.example/known-bad"
    feed = tmp_path / "openphish-feed.txt"
    feed.write_text(url + "\n", encoding="utf-8")
    service.openphish_path = feed

    result = analyze_link(service, url)["urls"][0]

    assert result["threat_intelligence"]["openphish"]["status"] == "match"
    assert result["classification"] == "malicious"
    assert result["reputation"] == "malicious"
    assert result["risk_contribution"] >= 80


def test_suspicious_only_virustotal_result_is_not_promoted_to_malicious(service, monkeypatch):
    monkeypatch.setattr(virustotal_client, "lookup_url", lambda url: {
        "source": "VirusTotal", "status": "success", "url": url,
        "last_analysis_stats": {"malicious": 0, "suspicious": 2},
    })
    monkeypatch.setattr(urlscan_client, "search_urlscan", lambda domain: {
        "source": "urlscan", "status": "success", "domain": domain, "results": [],
    })
    monkeypatch.setattr(urlhaus_client, "check_urlhaus", lambda url: {
        "source": "URLhaus", "status": "success", "url": url, "query_status": "no_results",
    })

    result = analyze_link(service, "https://www.linkedin.com/comm/track?trk=notification")["urls"][0]

    assert result["threat_intelligence"]["virustotal"]["malicious"] is False
    assert result["threat_intelligence"]["virustotal"]["suspicious"] is True
    assert result["classification"] == "potentially_suspicious"
    assert result["classification"] != "malicious"


def test_suspicious_credential_harvesting_shape_is_not_automatically_malicious(service):
    url = "https://portal.example/account/verify?password=entered-by-user"
    report = analyze_link(service, url)
    result = report["urls"][0]

    assert result["classification"] == "suspicious"
    assert result["classification"] != "malicious"
    assert result["features"]["has_sensitive_query_parameters"] is True
    assert report["verdict"]["classification"] == "suspicious"


@pytest.mark.parametrize("url", ["javascript:alert('owned')", "data:text/html;base64,PHNjcmlwdD4="])
def test_unsafe_schemes_are_malicious(url, service):
    result = analyze_link(service, url)["urls"][0]

    assert result["classification"] == "malicious"
    assert result["verdict_basis"] == "dangerous_scheme"


def test_private_ip_url_is_suspicious_not_a_reputation_match(service):
    result = analyze_link(service, "https://192.168.10.20/update")["urls"][0]

    assert result["classification"] == "suspicious"
    assert result["classification"] != "malicious"
    assert result["features"]["ip_is_private"] is True
    assert result["reputation"] == "not_available"


def test_punycode_hostname_is_suspicious_not_malicious_by_itself(service):
    result = analyze_link(service, "https://xn--pple-43d.example/login")["urls"][0]

    assert result["classification"] == "suspicious"
    assert result["classification"] != "malicious"
    assert result["features"]["has_punycode"] is True


def test_many_query_parameters_and_tracking_tokens_remain_informational(service):
    url = "https://events.example/register?" + "&".join(
        ["trk=email", "utm_source=notification", "midToken=opaque-token"]
        + [f"field{number}=value{number}" for number in range(10)]
    )
    result = analyze_link(service, url)["urls"][0]

    assert result["classification"] == "informational"
    assert result["risk_contribution"] == 0
    assert result["features"]["query_parameter_count"] == 13


def test_unknown_url_state_is_available_for_non_web_link(service):
    result = analyze_link(service, "mailto:security@example.test")["urls"][0]

    assert result["classification"] == "unknown"
    assert result["risk_contribution"] == 0
