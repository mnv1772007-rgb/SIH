"""Comprehensive test suite for Module 3: Threat Intelligence & Data.

Tests all components:
- IOC Normalizer & Canonicalization
- In-memory TTL Cache
- Provider adapters (VirusTotal, AbuseIPDB, URLhaus, PhishTank, OTX, GreyNoise, URLScan)
- Multi-provider Consensus Aggregator
- ThreatIntelService orchestrator
- API Endpoints (/api/threat-intel/*)
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from main import app
from threat_intel import (
    IOCNormalizer,
    NormalizedIOC,
    ThreatIntelCache,
    ThreatIntelService,
    aggregate_results,
    normalize_ioc,
)
from threat_intel.providers import (
    abuseipdb,
    greynoise,
    otx,
    phishtank,
    urlhaus,
    urlscan,
    virustotal,
)
from threat_intel.schema import (
    make_disabled_result,
    make_not_configured_result,
    make_provider_result,
    make_unavailable_result,
)


class TestIOCNormalizer(unittest.TestCase):
    """Test indicator normalization and validation."""

    def test_ip_normalization(self):
        # IPv4 global
        res = normalize_ioc("8.8.8.8", ioc_type="ip")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.type, "ip")
        self.assertEqual(res.value, "8.8.8.8")
        self.assertTrue(res.metadata.get("is_global"))

        # IPv4 private
        res_priv = normalize_ioc("192.168.1.1")
        self.assertTrue(res_priv.is_valid)
        self.assertEqual(res_priv.type, "ip")
        self.assertTrue(res_priv.metadata.get("is_private"))

        # Invalid IP
        res_invalid = normalize_ioc("999.999.999.999", ioc_type="ip")
        self.assertFalse(res_invalid.is_valid)

    def test_domain_normalization(self):
        res = normalize_ioc("  EXAMPLE.COM.  ", ioc_type="domain")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.value, "example.com")

        # Reject IP as domain
        res_ip_as_domain = normalize_ioc("1.1.1.1", ioc_type="domain")
        self.assertFalse(res_ip_as_domain.is_valid)

    def test_url_normalization(self):
        res = normalize_ioc("HTTP://Example.COM:80/path?b=2&a=1#frag")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.type, "url")
        self.assertTrue(res.value.startswith("http://example.com/path"))

    def test_hash_normalization(self):
        md5_raw = "D41D8CD98F00B204E9800998ECF8427E"
        res = normalize_ioc(md5_raw)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.type, "hash")
        self.assertEqual(res.value, md5_raw.lower())
        self.assertEqual(res.metadata.get("algorithm"), "md5")

        sha256_raw = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        res256 = normalize_ioc(sha256_raw)
        self.assertTrue(res256.is_valid)
        self.assertEqual(res256.metadata.get("algorithm"), "sha256")

    def test_email_normalization(self):
        res = normalize_ioc("Alice.Smith+test@EXAMPLE.COM")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.type, "email")
        self.assertEqual(res.value, "alice.smith+test@example.com")

    def test_batch_normalization_deduplication(self):
        normalizer = IOCNormalizer()
        batch = [
            {"value": "8.8.8.8", "type": "ip"},
            {"value": "  8.8.8.8  ", "type": "ip"},
            {"value": "EXAMPLE.COM"},
            {"value": "example.com", "type": "domain"},
        ]
        results = normalizer.normalize_batch(batch)
        self.assertEqual(len(results), 2)
        values = {r.value for r in results}
        self.assertIn("8.8.8.8", values)
        self.assertIn("example.com", values)


class TestThreatIntelCache(unittest.TestCase):
    """Test TTL caching logic."""

    def setUp(self):
        self.cache = ThreatIntelCache(success_ttl=10, failure_ttl=2)

    def test_cache_set_and_get(self):
        sample = make_provider_result(
            provider="TestProvider",
            ioc_type="ip",
            ioc_value="1.1.1.1",
            status="success",
            malicious=False,
        )
        self.cache.set("ip", "1.1.1.1", "TestProvider", sample)
        cached = self.cache.get("ip", "1.1.1.1", "TestProvider")
        self.assertIsNotNone(cached)
        self.assertTrue(cached.get("cached"))
        self.assertEqual(cached.get("status"), "success")

    def test_cache_miss(self):
        cached = self.cache.get("ip", "2.2.2.2", "TestProvider")
        self.assertIsNone(cached)

    def test_cache_invalidation(self):
        sample = make_provider_result(
            provider="TestProvider",
            ioc_type="ip",
            ioc_value="1.1.1.1",
            status="success",
        )
        self.cache.set("ip", "1.1.1.1", "TestProvider", sample)
        self.cache.invalidate("ip", "1.1.1.1", "TestProvider")
        self.assertIsNone(self.cache.get("ip", "1.1.1.1", "TestProvider"))


class TestAggregator(unittest.TestCase):
    """Test consensus verdict and provenance aggregation."""

    def test_consensus_malicious_overrides_clean(self):
        res1 = make_provider_result(
            provider="ProviderA",
            ioc_type="ip",
            ioc_value="1.2.3.4",
            status="success",
            malicious=False,
        )
        res2 = make_provider_result(
            provider="ProviderB",
            ioc_type="ip",
            ioc_value="1.2.3.4",
            status="success",
            malicious=True,
            confidence=0.85,
            categories=["c2"],
        )
        agg = aggregate_results("ip", "1.2.3.4", [res1, res2])
        self.assertEqual(agg["verdict"], "malicious")
        self.assertTrue(agg["is_threat"])
        self.assertIn("ProviderB", agg["malicious_sources"])
        self.assertIn("c2", agg["categories"])

    def test_consensus_all_unavailable_is_unknown_not_clean(self):
        res1 = make_not_configured_result("ProviderA", "ip", "1.2.3.4")
        res2 = make_unavailable_result("ProviderB", "ip", "1.2.3.4", "timeout")
        agg = aggregate_results("ip", "1.2.3.4", [res1, res2])
        self.assertEqual(agg["verdict"], "unknown")
        self.assertFalse(agg["is_threat"])
        self.assertEqual(agg["confidence"], 0.0)

    def test_consensus_confirmed_clean(self):
        res1 = make_provider_result(
            provider="ProviderA",
            ioc_type="domain",
            ioc_value="safe.org",
            status="success",
            malicious=False,
            suspicious=False,
        )
        res2 = make_provider_result(
            provider="ProviderB",
            ioc_type="domain",
            ioc_value="safe.org",
            status="not_found",
            malicious=False,
        )
        agg = aggregate_results("domain", "safe.org", [res1, res2])
        self.assertEqual(agg["verdict"], "clean")
        self.assertFalse(agg["is_threat"])
        self.assertGreater(agg["confidence"], 0.0)


class TestProvidersFailSoft(unittest.TestCase):
    """Verify that all providers handle unconfigured / disabled states without exceptions."""

    def setUp(self):
        self._orig_flag = os.environ.get("THREAT_INTELLIGENCE_ENABLED")
        os.environ["THREAT_INTELLIGENCE_ENABLED"] = "true"

    def tearDown(self):
        if self._orig_flag is not None:
            os.environ["THREAT_INTELLIGENCE_ENABLED"] = self._orig_flag
        else:
            os.environ.pop("THREAT_INTELLIGENCE_ENABLED", None)

    @patch("threat_intel.providers.virustotal.is_threat_intel_enabled", return_value=False)
    def test_virustotal_disabled(self, _):
        res = virustotal.lookup_ip("8.8.8.8")
        self.assertEqual(res["status"], "disabled")


    @patch("threat_intel.providers.virustotal.get_api_key", return_value=None)
    def test_virustotal_not_configured(self, _):
        res = virustotal.lookup_ip("8.8.8.8")
        self.assertEqual(res["status"], "not_configured")

    @patch("threat_intel.providers.abuseipdb.get_api_key", return_value=None)
    def test_abuseipdb_not_configured(self, _):
        res = abuseipdb.lookup_ip("8.8.8.8")
        self.assertEqual(res["status"], "not_configured")

    @patch("threat_intel.providers.urlhaus.get_api_key", return_value=None)
    def test_urlhaus_not_configured(self, _):
        res = urlhaus.lookup_url("http://test.com")
        self.assertEqual(res["status"], "not_configured")

    def test_phishtank_requires_double_opt_in(self):
        # Default environment should not have opt-in
        with patch.dict("os.environ", {"PHISHTANK_ENABLED": "false"}, clear=False):
            res = phishtank.lookup_url("http://test.com")
            self.assertEqual(res["status"], "disabled")

    @patch("threat_intel.providers.greynoise.get_api_key", return_value=None)
    def test_greynoise_not_configured(self, _):
        res = greynoise.lookup_ip("8.8.8.8")
        self.assertEqual(res["status"], "not_configured")

    @patch("threat_intel.providers.urlscan.get_api_key", return_value=None)
    def test_urlscan_not_configured(self, _):
        res = urlscan.lookup_domain("example.com")
        self.assertEqual(res["status"], "not_configured")

    @patch("threat_intel.providers.otx.get_api_key", return_value=None)
    def test_otx_not_configured(self, _):
        res = otx.lookup_ip("8.8.8.8")
        self.assertEqual(res["status"], "not_configured")


class TestThreatIntelService(unittest.TestCase):
    """Test the high-level enrichment service."""

    def setUp(self):
        self.service = ThreatIntelService()

    def test_invalid_ioc_lookup(self):
        res = self.service.lookup_ioc("not an indicator!!!", ioc_type="ip")
        self.assertEqual(res["verdict"], "unknown")
        self.assertIn("error", res)

    def test_batch_lookup(self):
        iocs = [
            {"value": "1.1.1.1", "type": "ip"},
            {"value": "example.org", "type": "domain"},
        ]
        results = self.service.lookup_batch(iocs)
        self.assertEqual(len(results), 2)

    def test_email_enrichment(self):
        data = {
            "ips": ["8.8.8.8"],
            "urls": ["https://example.com/test"],
            "domains": ["example.com"],
            "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
        }
        res = self.service.enrich_email_indicators(data)
        self.assertIn("summary", res)
        self.assertEqual(res["summary"]["total_indicators"], 4)
        self.assertEqual(len(res["ips"]), 1)
        self.assertEqual(len(res["urls"]), 1)
        self.assertEqual(len(res["domains"]), 1)
        self.assertEqual(len(res["hashes"]), 1)


class TestThreatIntelAPI(unittest.TestCase):
    """Test FastAPI endpoints for Threat Intelligence."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_lookup_endpoint(self):
        resp = self.client.post(
            "/api/threat-intel/lookup",
            json={"indicator": "8.8.8.8", "ioc_type": "ip"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("verdict", data)
        self.assertIn("provenance", data)

    def test_batch_endpoint(self):
        resp = self.client.post(
            "/api/threat-intel/batch",
            json={
                "indicators": [
                    {"value": "1.1.1.1", "type": "ip"},
                    {"value": "test.com", "type": "domain"},
                ]
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("total"), 2)

    def test_cache_stats_endpoint(self):
        resp = self.client.get("/api/threat-intel/cache/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total_entries", data)
        self.assertIn("max_entries", data)


if __name__ == "__main__":
    unittest.main()
