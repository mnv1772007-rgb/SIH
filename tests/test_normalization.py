import pytest
from app.models.integration_contract import (
    normalize_domain,
    normalize_ip,
    normalize_url,
    compute_url_hash,
    normalize_hash,
    normalize_timestamp,
)


def test_domain_normalization():
    assert normalize_domain("EVIL-EXAMPLE.COM") == "evil-example.com"
    assert normalize_domain("  sub.Phish-Domain.org/login/index.html  ") == "sub.phish-domain.org"
    assert normalize_domain("https://MALICIOUS.xyz:8080/path") == "malicious.xyz"
    assert normalize_domain(None) is None
    assert normalize_domain("") is None


def test_ip_normalization():
    assert normalize_ip("198.51.100.25") == "198.51.100.25"
    assert normalize_ip("  203.0.113.1  ") == "203.0.113.1"
    assert normalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"

    with pytest.raises(ValueError, match="Invalid IP address format"):
        normalize_ip("999.999.999.999")

    with pytest.raises(ValueError, match="Invalid IP address format"):
        normalize_ip("not-an-ip")


def test_url_normalization():
    assert normalize_url("HTTP://EVIL.COM/Path/Login") == "http://evil.com/Path/Login"
    assert normalize_url("evil.com/test") == "http://evil.com/test"
    url_hash = compute_url_hash("http://evil.com/test")
    assert len(url_hash) == 64
    assert url_hash.isalnum()


def test_hash_normalization():
    valid_sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    assert normalize_hash(valid_sha256) == valid_sha256.lower()

    with pytest.raises(ValueError, match="Invalid cryptographic hash"):
        normalize_hash("not_a_valid_hex_hash!@#$")


def test_timestamp_normalization():
    ts = normalize_timestamp("2026-09-10T08:30:00Z")
    assert "2026-09-10T08:30:00+00:00" in ts or "2026-09-10T08:30:00Z" in ts
