"""Central, fail-soft email-analysis orchestration service.

The service consumes bytes only; it never follows links or connects to the
mail-server infrastructure found in an email. Optional enrichment calls query
fixed third-party intelligence APIs and are disabled unless configured.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
from copy import deepcopy
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from attachment_analyzer import analyze_attachment
from domain_analyzer import analyze_domain
from header_analyzer import analyze_headers
from html_analyzer import analyze_html_link, extract_html_links
from ip_analyzer import analyze_ip
from nlp_analyzer import analyze_email_nlp
from received_analyzer import analyze_received_headers, build_relay_path, find_origin_candidates
from risk_analyzer import calculate_header_risk
from url_analyzer import analyze_url
from url_normalizer import normalize_url

from .case_store import CaseStore
from .graph_service import build_graph
from .neo4j_service import persist_graph

LOGGER = logging.getLogger(__name__)
URL_PATTERN = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
AUTH_PATTERN = re.compile(
    r"\b(?P<method>spf|dkim|dmarc)=(?P<result>pass|fail|softfail|neutral|none|"
    r"temperror|permerror|bestguesspass|quarantine|reject)\b",
    re.IGNORECASE,
)
RISK_WEIGHTS = {"low": 5, "medium": 12, "high": 20, "critical": 30}


class AnalysisError(ValueError):
    """Raised when submitted bytes are not meaningful RFC822 email input."""


class AnalysisService:
    def __init__(self, project_root: Path, case_store: CaseStore) -> None:
        self.project_root = project_root
        self.case_store = case_store
        configured_feed = os.getenv("OPENPHISH_FEED_PATH")
        self.openphish_path = Path(configured_feed) if configured_feed else project_root / "data" / "openphish_feed.txt"
        self._openphish_indicators: set[str] | None = None
        self._openphish_status: str | None = None
        self._url_intelligence_cache: dict[str, dict[str, Any]] = {}

    def analyze(self, raw_email: bytes, source_name: str = "raw-email.eml") -> dict[str, Any]:
        if not raw_email or not raw_email.strip():
            raise AnalysisError("Email content is empty.")
        if len(raw_email) > 10 * 1024 * 1024:
            raise AnalysisError("Email exceeds the 10 MiB analysis limit.")

        message = BytesParser(policy=policy.default).parsebytes(raw_email)
        if not list(message.keys()) and b":" not in raw_email[:8192]:
            raise AnalysisError("Input does not contain RFC822 email headers.")

        email_hash = hashlib.sha256(raw_email).hexdigest()
        email_id = f"email_{email_hash[:20]}"
        case_id = f"case_{email_hash[:20]}"
        stages: list[dict[str, str]] = []
        errors: list[dict[str, str]] = []

        def stage(name: str, status: str = "completed") -> None:
            stages.append({"name": name, "status": status})

        email_details = self._email_details(message)
        stage("Parsing email")

        auth_status, raw_authentication, auth_sources = self._authentication(message)
        authentication = {
            "raw": raw_authentication or "Not available",
            "authentication_results": [str(value) for value in message.get_all("Authentication-Results", [])],
            "received_spf": [str(value) for value in message.get_all("Received-SPF", [])],
            "dkim_signature_present": bool(message.get_all("DKIM-Signature", [])),
            "dkim_signature_count": len(message.get_all("DKIM-Signature", [])),
            **{
                method: {
                    "result": result,
                    # Keep the parser result for investigators, but provide a
                    # single presentation-safe value so clients never render
                    # "not_found not_found".
                    "status": self._authentication_display_status(result),
                    "display_status": self._authentication_display_status(result),
                    "source": auth_sources[method],
                }
                for method, result in auth_status.items()
            },
        }
        stage("Validating authentication")

        header_analysis = self._safe_engine(
            "header_analysis", errors, lambda: analyze_headers(message), {"findings": []}
        )
        received_headers = [str(value) for value in message.get_all("Received", [])]
        relay_hops = self._safe_engine(
            "received_header_analysis", errors, lambda: analyze_received_headers(received_headers), []
        )
        header_risk = self._safe_engine(
            "legacy_header_risk",
            errors,
            lambda: calculate_header_risk(header_analysis, auth_status),
            {"score": 0, "risk_level": "LOW", "reasons": []},
        )
        header_forensics = {
            **header_analysis,
            "received_chain": received_headers,
            "relay_hops": relay_hops,
            "relay_path": build_relay_path(relay_hops),
            "origin_candidates": find_origin_candidates(relay_hops),
            "probable_source_infrastructure": self._probable_origin(relay_hops),
            "legacy_header_risk": header_risk,
        }
        stage("Extracting headers")

        text_body, html_body = self._bodies(message)
        html_links = self._safe_engine(
            "html_link_extraction", errors, lambda: extract_html_links(html_body), []
        ) if html_body else []
        html_analysis = [
            self._safe_engine("html_link_analysis", errors, lambda link=link: analyze_html_link(link), {})
            for link in html_links
        ]
        stage("Analyzing HTML content")

        urls = self._analyze_urls(text_body, html_analysis, errors)
        stage("Extracting and analyzing URLs")

        nlp_analysis = self._analyze_nlp(email_details, text_body, html_body)
        model_analysis = self._model_analysis(email_details, text_body, html_body, errors)
        nlp_analysis["model_analysis"] = model_analysis
        stage("Analyzing content with deterministic NLP rules")

        attachments = self._attachments(message, errors)
        stage("Analyzing attachments")

        ip_values = self._extract_ips(text_body, received_headers)
        ip_analysis = [analyze_ip(ip) for ip in ip_values]
        stage("Tracing IP infrastructure")

        domain_intelligence = self._domain_intelligence(urls, errors)
        geolocation = self._geolocate_ips(ip_analysis, errors)
        ip_threat_intelligence = self._ip_threat_intelligence(ip_analysis, errors)
        stage("Performing optional infrastructure enrichment")

        related = self._related_cases(urls, ip_analysis, attachments, email_details, header_forensics, case_id)
        campaign_correlation = self._campaign_correlation(related)
        stage("Correlating campaigns")

        findings, factors = self._collect_findings(
            header_analysis, auth_status, urls, html_analysis, nlp_analysis, model_analysis, attachments, ip_threat_intelligence
        )
        verdict = self._risk_verdict(factors, nlp_analysis)
        recommendations = self._recommendations(verdict, findings)
        threat_intelligence = self._threat_summary(urls, ip_threat_intelligence)

        report: dict[str, Any] = {
            "case": {
                "case_id": case_id,
                "email_id": email_id,
                "email_hash": email_hash,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "source_name": source_name,
                "engine_version": "2.0.0",
            },
            "verdict": verdict,
            "email": email_details,
            "authentication": authentication,
            "header_analysis": header_forensics,
            "nlp_analysis": nlp_analysis,
            "urls": urls,
            "html_analysis": html_analysis,
            "attachments": attachments,
            "ip_analysis": ip_analysis,
            "geolocation": geolocation,
            "domain_intelligence": domain_intelligence,
            "threat_intelligence": threat_intelligence,
            "campaign_correlation": campaign_correlation,
            "findings": findings,
            "risk_factors": factors,
            "recommendations": recommendations,
            "evidence": {
                "email_hash": email_hash,
                "analysis_method": "Static forensic checks, deterministic lexical rules, optional offline ML baselines (email + URL classifiers); email URLs and attachments are never executed.",
                "module_errors": errors,
            },
            "analysis_stages": stages,
        }
        report["graph"] = build_graph(report)
        report["graph"]["neo4j_status"] = persist_graph(report["graph"])
        stage("Building investigation graph")
        stage("Generating forensic report")
        self.case_store.save(report)
        return report

    @staticmethod
    def _safe_engine(name: str, errors: list[dict[str, str]], operation: Any, fallback: Any) -> Any:
        try:
            return operation()
        except Exception as error:  # fail soft: one enrichment must not discard evidence
            LOGGER.warning("%s failed: %s", name, error)
            errors.append({"module": name, "message": str(error)})
            return fallback

    @staticmethod
    def _email_details(message: Any) -> dict[str, Any]:
        display_name, address = parseaddr(message.get("From", ""))
        return {
            "from": message.get("From"),
            "from_address": address or None,
            "from_display_name": display_name or None,
            "to": message.get("To"),
            "cc": message.get("Cc"),
            "bcc": message.get("Bcc"),
            "subject": message.get("Subject"),
            "date": message.get("Date"),
            "reply_to": message.get("Reply-To"),
            "return_path": message.get("Return-Path"),
            "message_id": message.get("Message-ID"),
        }

    @staticmethod
    def _authentication(message: Any) -> tuple[dict[str, str], str, dict[str, str]]:
        authentication_results = [str(value) for value in message.get_all("Authentication-Results", [])]
        received_spf = [str(value) for value in message.get_all("Received-SPF", [])]
        raw = "\n".join(authentication_results)
        results = {"spf": "not_found", "dkim": "not_found", "dmarc": "not_found"}
        sources = {method: "not_present" for method in results}
        for match in AUTH_PATTERN.finditer(raw):
            method = match.group("method").lower()
            results[method] = match.group("result").lower()
            sources[method] = "Authentication-Results"
        # Received-SPF is common on messages where a full Authentication-
        # Results header was not preserved. It only supplies SPF evidence and
        # never implies anything about DKIM or DMARC.
        if results["spf"] == "not_found":
            for header in received_spf:
                match = re.match(r"\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", header, re.IGNORECASE)
                if match:
                    results["spf"] = match.group(1).lower()
                    sources["spf"] = "Received-SPF"
                    break
        return results, raw, sources

    @staticmethod
    def _authentication_display_status(result: str | None) -> str:
        """Map parser/provider values to the compact dashboard vocabulary."""
        value = str(result or "").strip().lower()
        if value in {"pass", "bestguesspass"}:
            return "PASS"
        if value in {"fail", "softfail", "permerror", "temperror", "quarantine", "reject"}:
            return "FAIL"
        if value in {"not_found", "none", ""}:
            return "NOT PRESENT"
        if value in {"not_checked", "not_configured", "disabled"}:
            return "NOT CHECKED"
        return "UNKNOWN"

    @staticmethod
    def _bodies(message: Any) -> tuple[str, str]:
        plain, html = [], []
        parts = message.walk() if message.is_multipart() else [message]
        for part in parts:
            if part.get_content_disposition() == "attachment":
                continue
            content_type = part.get_content_type()
            if content_type not in {"text/plain", "text/html"}:
                continue
            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            (html if content_type == "text/html" else plain).append(str(content))
        return "\n".join(plain), "\n".join(html)

    def _analyze_urls(self, text_body: str, html_links: list[dict[str, Any]], errors: list[dict[str, str]]) -> list[dict[str, Any]]:
        candidates = [match.rstrip(".,;:!?)]") for match in URL_PATTERN.findall(text_body)]
        candidates.extend(link.get("actual_url", "") for link in html_links)
        seen: set[str] = set()
        results: list[dict[str, Any]] = []
        for raw_url in candidates:
            raw_url = str(raw_url).strip()
            if not raw_url or raw_url in seen:
                continue
            seen.add(raw_url)
            try:
                parsed = urlparse(raw_url)
                parsed_domain = parsed.hostname or ""
            except ValueError as error:
                errors.append({"module": "url_parser", "message": str(error)})
                parsed = urlparse("")
                parsed_domain = ""
            normalized = normalize_url(raw_url) if parsed.scheme.lower() in {"http", "https"} else None
            try:
                # Use the original indicator for feature extraction so embedded
                # credentials and unsafe schemes cannot disappear in normalization.
                features = analyze_url(raw_url)
            except (ValueError, AttributeError) as error:
                errors.append({"module": "url_analyzer", "message": str(error)})
                features = {"url": raw_url, "domain": parsed.hostname or "", "analysis_error": str(error)}
            domain = (parsed_domain or features.get("domain") or "").lower()
            openphish = self._check_openphish(normalized or raw_url)
            intelligence = self._url_threat_intelligence(normalized, domain, errors)
            assessment = self._assess_url(features, openphish, intelligence)
            # The full per-indicator record is returned to the analyst. This
            # concise log lets service operators trace a verdict without
            # treating unavailable intelligence as an implicit match.
            LOGGER.info(
                "URL assessment raw=%r normalized=%r verdict=%s contribution=%s indicators=%s",
                raw_url,
                normalized,
                assessment["classification"],
                assessment["risk_contribution"],
                assessment["indicators"],
            )
            results.append({
                "url": raw_url,
                "normalized_url": normalized,
                "domain": domain or None,
                "hostname": features.get("hostname") or domain or None,
                "scheme": features.get("scheme"),
                "path": features.get("path"),
                "query_parameters": features.get("query_parameters", []),
                "port": features.get("port"),
                "features": features,
                "classification": assessment["classification"],
                "verdict_basis": assessment["verdict_basis"],
                "risk_contribution": assessment["risk_contribution"],
                "indicator_details": assessment["indicators"],
                # Retained for the existing UI/API contract. Unlike the old
                # implementation, this list is not independently scored.
                "static_reasons": [indicator["reason"] for indicator in assessment["indicators"]],
                "reputation": assessment["reputation"],
                "threat_intelligence": {"openphish": openphish, **intelligence},
                "redirect_analysis": {"status": "not_followed", "reason": "Links are never fetched to prevent SSRF."},
            })
        return results

    @staticmethod
    def _assess_url(features: dict[str, Any], openphish: dict[str, Any], intelligence: dict[str, Any]) -> dict[str, Any]:
        """Turn URL observations into an explainable, evidence-tiered verdict.

        The score is local to the URL. Observations such as a long URL or a
        tracking token intentionally contribute zero: they are preserved for
        review but cannot cause an email-level escalation by themselves.
        """
        indicators: list[dict[str, Any]] = []

        def add(name: str, tier: str, reason: str, contribution: int = 0, source: str | None = None) -> None:
            indicators.append({
                "indicator": name,
                "tier": tier,
                "reason": reason,
                "contribution": contribution,
                **({"source": source} if source else {}),
            })

        if features.get("parse_error"):
            add("url_parse_error", "observation", "URL could not be fully parsed; no threat conclusion was drawn.")
        if features.get("is_long_url"):
            add("long_url", "observation", "URL is long; length alone is not a malicious indicator.")
        if features.get("query_parameter_count", 0) >= 6:
            add("many_query_parameters", "observation", "URL has many query parameters; this is common in tracking links.")
        if features.get("has_tracking_parameters"):
            parameters = ", ".join(features.get("tracking_parameters", []))
            add("tracking_parameters", "observation", f"Tracking parameter(s) observed: {parameters}; tracking is not a threat verdict.")
        if features.get("has_encoded_characters"):
            add("encoded_characters", "observation", "URL contains percent-encoding; encoding alone is not a threat verdict.")
        if features.get("generic_terms"):
            terms = ", ".join(features.get("generic_terms", []))
            add("generic_lexical_terms", "observation", f"Generic URL term(s) observed: {terms}; lexical terms alone are not proof of phishing.")
        if features.get("contextual_terms"):
            terms = ", ".join(features.get("contextual_terms", []))
            add("financial_or_transaction_terms", "weak_indicator", f"Financial or transaction URL term(s) observed: {terms}.", 3)

        if features.get("has_unsafe_scheme"):
            add("dangerous_scheme", "confirmed_threat", f"Uses the unsafe {features.get('scheme')}: URI scheme.", 80)
        if features.get("has_credentials"):
            add("embedded_credentials", "strong_indicator", "Contains embedded URL credentials, a credential-obfuscation structure.", 30)
        if features.get("has_sensitive_query_parameters"):
            parameters = ", ".join(features.get("sensitive_query_parameters", []))
            add("sensitive_query_parameters", "strong_indicator", f"URL exposes sensitive field-like query parameter(s): {parameters}.", 25)
        elif features.get("has_credential_terms"):
            terms = ", ".join(features.get("credential_terms", []))
            add("credential_lexical_terms", "weak_indicator", f"Credential-related URL term(s) observed: {terms}.", 5)

        if features.get("has_ip_address") or features.get("has_ipv6_address"):
            if features.get("ip_is_private") or features.get("ip_is_loopback") or features.get("ip_is_reserved"):
                add("private_or_reserved_ip_url", "strong_indicator", "Uses a private, loopback, or reserved IP address as the URL host.", 32)
            else:
                add("ip_based_url", "indicator", "Uses an IP address instead of a domain.", 18)
        if features.get("has_decimal_ip"):
            add("decimal_ip_hostname", "strong_indicator", "Uses a decimal-encoded IP hostname.", 25)
        if features.get("has_hexadecimal_ip"):
            add("hexadecimal_ip_hostname", "strong_indicator", "Uses a hexadecimal-encoded IP hostname.", 25)
        if features.get("has_punycode"):
            add("punycode_hostname", "indicator", "Contains a Punycode/IDN hostname requiring analyst review.", 22)
        if features.get("has_homoglyph_characters"):
            add("unicode_hostname", "indicator", "Contains non-ASCII hostname characters that may be homoglyphs.", 25)
        if features.get("invalid_port"):
            add("invalid_port", "indicator", "Uses an invalid destination port.", 18)
        elif features.get("has_suspicious_port"):
            add("non_standard_port", "weak_indicator", "Uses a non-standard destination port.", 8)
        if features.get("is_shortened_url"):
            add("shortened_url", "weak_indicator", "Uses a shortened URL; the final destination was not fetched.", 4)
        if features.get("has_open_redirect_pattern"):
            add("redirect_parameter", "weak_indicator", "Contains an open-redirect style parameter; destination was not followed.", 4)

        intelligence_records = [("OpenPhish local feed", openphish)] + [
            (str(item.get("source") or source), item)
            for source, item in intelligence.items() if isinstance(item, dict)
        ]
        confirmed_intelligence = False
        for source, record in intelligence_records:
            status = str(record.get("status", "unknown"))
            if record.get("malicious"):
                contribution = 80 if "OpenPhish" in source else 72
                add("threat_intelligence_match", "confirmed_threat", f"{source} reported a malicious URL indicator (status: {status}).", contribution, source)
                confirmed_intelligence = True
            elif record.get("suspicious"):
                add("threat_intelligence_suspicion", "indicator", f"{source} reported suspicious detections but no confirmed malicious result.", 16, source)
            else:
                add("threat_intelligence_result", "information", f"{source} result: {status}.", 0, source)

        risk_bearing = [item for item in indicators if item["contribution"] > 0]
        score = min(100, sum(item["contribution"] for item in risk_bearing))
        confirmed = confirmed_intelligence or any(item["indicator"] == "dangerous_scheme" for item in indicators)
        structural_signals = [
            item for item in risk_bearing
            if item["indicator"] in {
                "embedded_credentials", "private_or_reserved_ip_url", "decimal_ip_hostname",
                "hexadecimal_ip_hostname", "punycode_hostname", "unicode_hostname", "invalid_port",
                "sensitive_query_parameters", "ip_based_url",
            }
        ]
        if confirmed:
            classification, basis = "malicious", "verified_threat_intelligence" if confirmed_intelligence else "dangerous_scheme"
        elif score >= 65 and len(structural_signals) >= 3:
            classification, basis = "malicious", "strong_combination_of_independent_structural_indicators"
        elif score >= 20:
            classification, basis = "suspicious", "multiple_or_structural_static_indicators"
        elif score > 0:
            classification, basis = "potentially_suspicious", "weak_static_indicator"
        elif features.get("scheme") not in {"http", "https"} or not features.get("hostname"):
            classification, basis = "unknown", "unsupported_or_incomplete_url"
        elif any(item["tier"] == "observation" for item in indicators):
            classification, basis = "informational", "non_malicious_url_observations"
        elif features.get("scheme") in {"http", "https"} and features.get("hostname"):
            classification, basis = "clean", "no_static_or_verified_threat_evidence_observed"

        if confirmed_intelligence:
            reputation = "malicious"
        elif any(record.get("suspicious") for _, record in intelligence_records):
            reputation = "suspicious"
        elif any(str(record.get("status", "")).lower() == "success" for _, record in intelligence_records):
            reputation = "no_malicious_match_reported"
        else:
            reputation = "not_available"
        return {
            "classification": classification,
            "verdict_basis": basis,
            "risk_contribution": score,
            "indicators": indicators,
            "reputation": reputation,
        }

    def _check_openphish(self, url: str) -> dict[str, Any]:
        if self._openphish_indicators is None:
            try:
                self._openphish_indicators = {
                    line.strip().rstrip("/") for line in self.openphish_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if line.strip().startswith(("http://", "https://"))
                }
                self._openphish_status = "available"
            except OSError as error:
                self._openphish_indicators = set()
                self._openphish_status = "feed_unavailable" if os.getenv("OPENPHISH_FEED_PATH") else "not_configured"
                LOGGER.info("OpenPhish local feed unavailable at %s: %s", self.openphish_path, error)
        matched = url.rstrip("/") in self._openphish_indicators
        return {
            "source": "OpenPhish local feed",
            "status": "match" if matched else ("not_found" if self._openphish_status == "available" else self._openphish_status),
            "malicious": matched,
            "note": "A feed miss, missing feed, or unavailable feed is not a safety verdict.",
        }

    def _url_threat_intelligence(self, url: str | None, domain: str, errors: list[dict[str, str]]) -> dict[str, Any]:
        if not url:
            return {"virustotal": {"status": "not_applicable"}, "urlscan": {"status": "not_applicable"}, "urlhaus": {"status": "not_applicable"}, "phishtank": {"status": "not_applicable"}}
        if url in self._url_intelligence_cache:
            return deepcopy(self._url_intelligence_cache[url])
        from phishtank_client import check_url as check_phishtank
        from virustotal_client import lookup_url
        from urlhaus_client import check_urlhaus
        from urlscan_client import search_urlscan

        vt = self._safe_engine("virustotal", errors, lambda: lookup_url(url), {"source": "VirusTotal", "status": "unavailable"})
        if isinstance(vt, dict):
            stats = vt.get("last_analysis_stats") or {}
            def detection_count(name: str) -> int:
                try:
                    return max(0, int(stats.get(name, 0) or 0))
                except (TypeError, ValueError):
                    return 0

            malicious_count = detection_count("malicious")
            suspicious_count = detection_count("suspicious")
            # A provider "not found", an unavailable provider, or a provider's
            # suspicious-only count is never silently promoted to malicious.
            vt["malicious"] = malicious_count > 0
            vt["suspicious"] = malicious_count == 0 and suspicious_count > 0
            vt["reputation_result"] = (
                "malicious" if vt["malicious"] else "suspicious" if vt["suspicious"]
                else "no_detection" if vt.get("status") == "success" else "not_available"
            )
        scan = self._safe_engine("urlscan", errors, lambda: search_urlscan(domain), {"source": "urlscan", "status": "unavailable"})
        if isinstance(scan, dict):
            scan["malicious"] = False  # historical presence alone is not a verdict
            scan["suspicious"] = False
            scan["reputation_result"] = "historical_presence_only" if scan.get("status") == "success" else "not_available"
        haus = self._safe_engine("urlhaus", errors, lambda: check_urlhaus(url), {"source": "URLhaus", "status": "unavailable"})
        if isinstance(haus, dict):
            haus["malicious"] = str(haus.get("query_status", "")).lower() in {"ok", "malicious"}
            haus["suspicious"] = False
            haus["reputation_result"] = "malicious" if haus["malicious"] else (
                "no_detection" if haus.get("status") == "success" else "not_available"
            )
        tank = self._safe_engine("phishtank", errors, lambda: check_phishtank(url), {"source": "PhishTank", "status": "unavailable"})
        if isinstance(tank, dict):
            tank["malicious"] = bool(tank.get("in_database") and tank.get("verified") and tank.get("valid"))
            tank["suspicious"] = bool(tank.get("in_database") and not tank["malicious"])
            tank["reputation_result"] = "malicious" if tank["malicious"] else "suspicious" if tank["suspicious"] else (
                "no_detection" if tank.get("status") == "success" else "not_available"
            )
        result = {"virustotal": vt, "urlscan": scan, "urlhaus": haus, "phishtank": tank}
        self._url_intelligence_cache[url] = deepcopy(result)
        return result

    @staticmethod
    def _analyze_nlp(email_details: dict[str, Any], text_body: str, html_body: str) -> dict[str, Any]:
        content = f"{email_details.get('subject') or ''}\n{text_body}\n{AnalysisService._strip_html(html_body)}"
        patterns = {
            "urgency": (r"\b(urgent|immediately|act now|within \d+ hours?|final warning)\b", "Urgency language"),
            "credential_theft": (r"\b(password|login|sign in|credential|verify (?:your )?account)\b", "Credential/account-verification language"),
            "payment_fraud": (r"\b(invoice|wire transfer|bank details|payment|gift card)\b", "Payment-diversion language"),
            "executive_impersonation": (r"\b(ceo|cfo|managing director|executive)\b", "Executive-impersonation vocabulary"),
            "account_scam": (r"\b(suspended|locked|unusual activity|security alert|reset your)\b", "Account-security-scam language"),
        }
        indicators = [
            {"type": name, "evidence": description, "matches": len(re.findall(pattern, content, re.IGNORECASE))}
            for name, (pattern, description) in patterns.items() if re.search(pattern, content, re.IGNORECASE)
        ]
        if len(indicators) >= 3:
            classification = "phishing_like"
        elif indicators:
            classification = "suspicious_content"
        else:
            classification = "no_rule_match"
        legacy = analyze_email_nlp(
            email_data=email_details,
            body_text=text_body,
            html_body=html_body,
            subject=str(email_details.get("subject") or ""),
        )
        known_types = {item["type"] for item in indicators}
        for finding in legacy.get("nlp_findings", []):
            finding_type = str(finding.get("type") or "legacy_nlp_signal")
            if finding_type not in known_types:
                indicators.append({
                    "type": finding_type,
                    "evidence": str(finding.get("message") or "Legacy NLP signal"),
                    "matches": 1,
                })
                known_types.add(finding_type)
        return {
            "classification": classification,
            "confidence": min(95, 35 + len(indicators) * 15) if indicators else 15,
            "indicators": indicators,
            "explanation": "Deterministic lexical-rule analysis; no trained ML/NLP model is configured.",
            "methodology": "rule_based",
            "legacy_analysis": legacy,
        }

    @staticmethod
    def _model_analysis(email_details: dict[str, Any], text_body: str, html_body: str, errors: list[dict[str, str]]) -> dict[str, Any]:
        """Run the optional, pre-trained local models as supporting evidence only."""
        from AI_model.inference import classify_email_from_parts, classify_url_from_parts

        subject = email_details.get('subject') or ''
        combined_email = f"{subject}\n{text_body}\n{AnalysisService._strip_html(html_body)}"
        email_result = AnalysisService._safe_engine(
            "ml_email_inference",
            errors,
            lambda: classify_email_from_parts(subject, text_body, html_body),
            {"status": "unavailable", "predicted_class": "unknown", "confidence": 0.0, "model_available": False},
        )

        # Also run URL classifier on extracted URLs if available
        # This is done per-URL in _analyze_urls, but we can add a summary here
        url_results = []
        # Note: URL classification happens during URL analysis phase

        return {
            "email_classifier": email_result,
            "url_classifier_summary": url_results,
        }

    @staticmethod
    def _attachments(message: Any, errors: list[dict[str, str]]) -> list[dict[str, Any]]:
        attachments = []
        for part in message.iter_attachments():
            item = AnalysisService._safe_engine("attachment_analysis", errors, lambda part=part: analyze_attachment(part), {})
            payload = part.get_payload(decode=True) or b""
            item["sha256"] = hashlib.sha256(payload).hexdigest() if payload else None
            attachments.append(item)
        return attachments

    @staticmethod
    def _extract_ips(body: str, headers: list[str]) -> list[str]:
        candidates = re.findall(r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}|(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", body + "\n" + "\n".join(headers))
        values: list[str] = []
        for candidate in candidates:
            try:
                normalized = str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
            if normalized not in values:
                values.append(normalized)
        return values

    def _domain_intelligence(self, urls: list[dict[str, Any]], errors: list[dict[str, str]]) -> list[dict[str, Any]]:
        domains = list(dict.fromkeys(item["domain"] for item in urls if item.get("domain")))
        results = []
        network_enabled = os.getenv("NETWORK_ENRICHMENT_ENABLED", "false").lower() == "true"
        for domain in domains:
            result: dict[str, Any] = {"domain": domain, "static_analysis": analyze_domain(domain)}
            if network_enabled:
                from dns_analyzer import query_dns
                from rdap_analyzer import lookup_rdap
                result["dns"] = self._safe_engine("dns_intelligence", errors, lambda domain=domain: query_dns(domain), {"status": "unavailable"})
                result["rdap"] = self._safe_engine("rdap_intelligence", errors, lambda domain=domain: lookup_rdap(domain), {"status": "unavailable"})
            else:
                result["dns"] = {"status": "disabled", "reason": "Set NETWORK_ENRICHMENT_ENABLED=true to enable DNS/RDAP lookups."}
                result["rdap"] = {"status": "disabled", "reason": "Set NETWORK_ENRICHMENT_ENABLED=true to enable DNS/RDAP lookups."}
            results.append(result)
        return results

    def _ip_threat_intelligence(self, ips: list[dict[str, Any]], errors: list[dict[str, str]]) -> list[dict[str, Any]]:
        from abuseipdb_client import check_ip
        results = []
        for ip in ips:
            if not ip.get("is_global"):
                results.append({"source": "AbuseIPDB", "status": "not_applicable", "ip": ip.get("ip"), "reason": "Only public IPs are checked."})
                continue
            result = self._safe_engine("abuseipdb", errors, lambda ip=ip: check_ip(ip["ip"]), {"source": "AbuseIPDB", "status": "unavailable", "ip": ip["ip"]})
            if isinstance(result, dict):
                result["malicious"] = (result.get("abuse_confidence_score") or 0) >= 50
            results.append(result)
        return results

    def _geolocate_ips(self, ips: list[dict[str, Any]], errors: list[dict[str, str]]) -> list[dict[str, Any]]:
        token = os.getenv("IPINFO_TOKEN")
        records = []
        for ip in ips:
            value = ip.get("ip")
            if not ip.get("is_global"):
                records.append({"ip": value, "status": "not_applicable", "reason": "Only public IPs can have meaningful infrastructure geolocation."})
            elif os.getenv("THREAT_INTELLIGENCE_ENABLED", "true").lower() != "true":
                records.append({"ip": value, "status": "disabled", "source": "IPinfo", "reason": "Set THREAT_INTELLIGENCE_ENABLED=true to enable optional intelligence lookups."})
            elif not token:
                records.append({"ip": value, "status": "not_configured", "source": "IPinfo", "disclaimer": "Approximate infrastructure location, not a person's location."})
            else:
                records.append(self._safe_engine("ip_geolocation", errors, lambda value=value, token=token: self._ipinfo_lookup(value, token), {"ip": value, "status": "unavailable", "source": "IPinfo"}))
        return records

    @staticmethod
    def _ipinfo_lookup(ip: str, token: str) -> dict[str, Any]:
        response = requests.get(f"https://ipinfo.io/{ip}/json", params={"token": token}, timeout=8)
        response.raise_for_status()
        data = response.json()
        return {
            "ip": ip, "status": "available", "source": "IPinfo", "country": data.get("country"),
            "region": data.get("region"), "city": data.get("city"), "isp": data.get("org"),
            "asn": data.get("asn", {}).get("asn") if isinstance(data.get("asn"), dict) else None,
            "hosting_provider": None, "proxy_vpn_indicator": "unknown",
            "disclaimer": "Approximate infrastructure location, not a person's location.",
        }

    @staticmethod
    def _probable_origin(relay_hops: list[dict[str, Any]]) -> dict[str, Any] | None:
        candidates = find_origin_candidates(relay_hops)
        best = next((candidate for candidate in candidates if candidate.get("is_global")), None)
        if not best:
            return None
        return {"ip": best["ip"], "confidence": "limited", "wording": "probable source infrastructure"}

    @staticmethod
    def _correlation_indicators(urls: list[dict[str, Any]], ips: list[dict[str, Any]], attachments: list[dict[str, Any]], email: dict[str, Any], headers: dict[str, Any]) -> set[str]:
        """Build evidence tokens for association, not a claim of common control."""
        indicators = {f"domain:{item['domain']}" for item in urls if item.get("domain")}
        indicators.update(f"url:{item.get('normalized_url') or item['url']}" for item in urls if item.get("url"))
        indicators.update(f"ip:{item['ip']}" for item in ips if item.get("ip") and item.get("is_global"))
        indicators.update(f"attachment:{item['sha256']}" for item in attachments if item.get("sha256"))
        for value in (email.get("from_address"), email.get("reply_to")):
            _, address = parseaddr(str(value or ""))
            if address:
                indicators.add(f"address:{address.lower()}")
        for hop in headers.get("relay_hops", []):
            for server in (hop.get("from_server"), hop.get("to_server")):
                if server:
                    indicators.add(f"mail_server:{str(server).lower()}")
        return indicators

    def _related_cases(self, urls: list[dict[str, Any]], ips: list[dict[str, Any]], attachments: list[dict[str, Any]], email: dict[str, Any], headers: dict[str, Any], current_case_id: str) -> list[dict[str, Any]]:
        indicators = self._correlation_indicators(urls, ips, attachments, email, headers)
        matches = []
        for report in self.case_store.all_reports():
            if report.get("case", {}).get("case_id") == current_case_id:
                continue
            other = self._correlation_indicators(
                report.get("urls", []), report.get("ip_analysis", []), report.get("attachments", []),
                report.get("email", {}), report.get("header_analysis", {}),
            )
            shared = sorted(indicators & other)
            if shared:
                reasons = [self._correlation_reason(item) for item in shared]
                strength = sum(self._correlation_weight(item) for item in shared)
                matches.append({"case_id": report["case"]["case_id"], "shared_indicators": shared, "reasons": reasons, "strength": strength})
        return matches

    @staticmethod
    def _correlation_weight(indicator: str) -> int:
        return {
            "attachment": 5, "url": 4, "address": 3, "ip": 3,
            "domain": 2, "mail_server": 1,
        }.get(indicator.partition(":")[0], 0)

    @staticmethod
    def _correlation_reason(indicator: str) -> str:
        prefix, _, value = indicator.partition(":")
        labels = {
            "attachment": "shared attachment SHA-256", "url": "shared normalized URL",
            "address": "shared sender or Reply-To address", "ip": "shared public infrastructure IP",
            "domain": "shared domain", "mail_server": "shared relay server",
        }
        return f"{labels.get(prefix, 'shared evidence')}: {value}"

    @staticmethod
    def _campaign_correlation(related: list[dict[str, Any]]) -> dict[str, Any]:
        indicators = sorted({indicator for match in related for indicator in match["shared_indicators"]})
        if not indicators:
            return {"status": "no_related_cases", "related_case_ids": [], "matches": [], "strength": "none"}
        best_strength = max(match["strength"] for match in related)
        meaningful = any(
            any(item.startswith(("attachment:", "url:")) for item in match["shared_indicators"])
            or match["strength"] >= 5
            for match in related
        )
        strength = "strong" if best_strength >= 8 else "moderate" if best_strength >= 5 else "weak"
        response = {
            "status": "possible_cluster" if meaningful else "associated_evidence",
            "related_case_ids": [match["case_id"] for match in related],
            "matches": related,
            "shared_indicators": indicators,
            "strength": strength,
            "note": "Correlation identifies possible association from shared evidence; it does not establish a confirmed attacker or attribution.",
        }
        if meaningful:
            fingerprint = hashlib.sha256("|".join(indicators).encode()).hexdigest()[:12]
            response["campaign_id"] = f"campaign_{fingerprint}"
        return response

    @staticmethod
    def _collect_findings(header: dict[str, Any], auth: dict[str, str], urls: list[dict[str, Any]], html: list[dict[str, Any]], nlp: dict[str, Any], model: dict[str, Any], attachments: list[dict[str, Any]], ip_intel: list[dict[str, Any]]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
        findings: list[dict[str, str]] = []
        factors: list[dict[str, Any]] = []

        def add(category: str, factor: str, severity: str, evidence: str, *, weight: int | None = None, evidence_tier: str = "indicator", url_verdict: str | None = None) -> None:
            confidence = "high" if evidence_tier == "confirmed_threat" or severity in {"high", "critical"} else "medium"
            findings.append({"category": category, "type": factor.lower().replace(" ", "_"), "severity": severity, "evidence": evidence, "confidence": confidence})
            factors.append({
                "factor": factor,
                "weight": RISK_WEIGHTS[severity] if weight is None else weight,
                "reason": evidence,
                "category": category,
                "evidence_tier": evidence_tier,
                **({"url_verdict": url_verdict} if url_verdict else {}),
            })

        for item in header.get("findings", []):
            add("header", item.get("type", "header_anomaly"), item.get("severity", "low"), item.get("message", "Header anomaly detected."))
        for method, result in auth.items():
            if result in {"fail", "softfail", "permerror", "temperror", "quarantine", "reject"}:
                severity = "high" if result in {"fail", "permerror", "reject"} else "medium"
                add("authentication", f"{method.upper()} {result}", severity, f"{method.upper()} authentication result is {result}.")
        for item in urls:
            contribution = int(item.get("risk_contribution") or 0)
            url_verdict = str(item.get("classification") or "unknown")
            if not contribution:
                continue
            if url_verdict == "malicious":
                basis = str(item.get("verdict_basis") or "strong URL evidence").replace("_", " ")
                factor = "Confirmed URL threat" if basis == "verified threat intelligence" else "Dangerous URL structure"
                tier = "confirmed_threat" if factor == "Confirmed URL threat" else "strong_combination"
                add(
                    "threat_intelligence" if factor == "Confirmed URL threat" else "url",
                    factor,
                    "critical",
                    f"URL verdict is malicious because of {basis}: {item['url']}",
                    weight=max(45, contribution),
                    evidence_tier=tier,
                    url_verdict=url_verdict,
                )
            elif url_verdict == "suspicious":
                add(
                    "url", "Suspicious URL structure", "high",
                    f"URL has multiple or structural risk indicators: {item['url']}",
                    weight=contribution,
                    evidence_tier="suspicion",
                    url_verdict=url_verdict,
                )
            else:
                add(
                    "url", "Potential URL risk indicator", "low",
                    f"URL has a weak static indicator requiring context: {item['url']}",
                    weight=contribution,
                    evidence_tier="weak_indicator",
                    url_verdict=url_verdict,
                )
        for item in html:
            if item.get("destination_mismatch"):
                add("html", "Destination mismatch", "high", f"Visible destination {item.get('visible_domain')} differs from actual destination {item.get('actual_domain')}.")
        for indicator in nlp.get("indicators", []):
            add("nlp", indicator["type"].replace("_", " ").title(), "medium", indicator["evidence"])

        # ML Email Classifier (multi-class)
        email_ml = model.get("email_classifier", {})
        if email_ml.get("status") == "available" and email_ml.get("model_available"):
            predicted = email_ml.get("predicted_class", "unknown")
            confidence = email_ml.get("confidence", 0.0)
            confidence_level = email_ml.get("confidence_level", "low")

            # Only add as finding if confidence is reasonable and prediction is not benign
            if predicted != "benign" and confidence >= 0.65:
                severity = "medium" if confidence >= 0.85 else "low"
                add(
                    "ml", f"ML email classification: {predicted}", severity,
                    f"Local ML model predicted '{predicted}' with {confidence:.2f} confidence ({confidence_level}); supporting evidence only.",
                    weight=5 if severity == "medium" else 3,
                    evidence_tier="model_support",
                )
            elif predicted == "benign" and confidence >= 0.85:
                # High-confidence benign is a negative signal (reduces risk)
                add(
                    "ml", "ML email classification: benign", "low",
                    f"Local ML model predicted 'benign' with high confidence ({confidence:.2f}); supporting evidence only.",
                    weight=-3,  # Negative weight reduces risk score
                    evidence_tier="model_support",
                )

        # ML URL Classifier summary (per-URL details are in url analysis)
        url_ml_summary = model.get("url_classifier_summary", [])
        if url_ml_summary:
            for url_result in url_ml_summary:
                if url_result.get("status") == "available":
                    predicted = url_result.get("predicted_class", "unknown")
                    confidence = url_result.get("confidence", 0.0)
                    if predicted in {"malicious", "phishing"} and confidence >= 0.7:
                        add(
                            "ml", f"ML URL classification: {predicted}", "low",
                            f"Local ML model predicted URL as '{predicted}' with {confidence:.2f} confidence; supporting evidence only.",
                            weight=3, evidence_tier="model_support",
                        )
        for attachment in attachments:
            if attachment.get("is_executable_extension"):
                add("attachment", "Executable attachment", "critical", f"Attachment has executable/script extension: {attachment.get('filename') or 'unnamed'}")
            if attachment.get("mime_extension_mismatch"):
                add("attachment", "Attachment MIME mismatch", "high", f"Attachment MIME type does not match extension: {attachment.get('filename') or 'unnamed'}")
        for item in ip_intel:
            if item.get("malicious"):
                add("infrastructure", "IP reputation alert", "high", f"AbuseIPDB reported a high abuse confidence for {item.get('ip')}.")
        return findings, factors

    @staticmethod
    def _risk_verdict(factors: list[dict[str, Any]], nlp: dict[str, Any]) -> dict[str, Any]:
        score = min(100, sum(int(factor["weight"]) for factor in factors))
        if score <= 20:
            level = "LOW"
        elif score <= 40:
            level = "GUARDED"
        elif score <= 60:
            level = "MEDIUM"
        elif score <= 80:
            level = "HIGH"
        else:
            level = "CRITICAL"
        if any(factor.get("evidence_tier") in {"confirmed_threat", "strong_combination"} for factor in factors):
            classification = "malicious"
        elif nlp["classification"] == "phishing_like" or any(factor.get("url_verdict") in {"suspicious", "potentially_suspicious"} for factor in factors):
            classification = "suspicious"
        elif factors:
            classification = "potentially_suspicious"
        else:
            classification = "no_high_risk_signal"
        confidence = min(99, 30 + len(factors) * 9 + (10 if nlp["indicators"] else 0))
        return {"classification": classification, "risk_level": level, "risk_score": score, "confidence": confidence, "factors": factors}

    @staticmethod
    def _recommendations(verdict: dict[str, Any], findings: list[dict[str, str]]) -> list[str]:
        recommendations = ["Preserve the original email and headers as forensic evidence; do not interact with embedded links or attachments."]
        categories = {finding["category"] for finding in findings}
        if "authentication" in categories or "header" in categories:
            recommendations.append("Validate the sender through a trusted channel and review SPF, DKIM, DMARC alignment before responding.")
        if {"url", "html", "threat_intelligence"} & categories:
            recommendations.append("Block or isolate the suspicious URL indicators pending analyst validation; do not browse them from an analyst workstation.")
        if "attachment" in categories:
            recommendations.append("Quarantine the attachment and analyze it only in an approved isolated environment.")
        if verdict["risk_level"] in {"HIGH", "CRITICAL"}:
            recommendations.append("Escalate this case to the incident-response workflow and search mail telemetry for matching indicators.")
        return recommendations

    @staticmethod
    def _threat_summary(urls: list[dict[str, Any]], ip_intel: list[dict[str, Any]]) -> dict[str, Any]:
        source_results: list[dict[str, Any]] = []
        for url in urls:
            for source, result in url.get("threat_intelligence", {}).items():
                if isinstance(result, dict):
                    source_results.append({"indicator": url["url"], "source": source, "status": result.get("status", "unknown"), "malicious": result.get("malicious", False)})
        source_results.extend({"indicator": item.get("ip"), "source": "abuseipdb", "status": item.get("status"), "malicious": item.get("malicious", False)} for item in ip_intel)
        return {"status": "completed", "results": source_results, "note": "Unavailable, unconfigured, and not-found results are not safety verdicts."}

    @staticmethod
    def _strip_html(value: str) -> str:
        return re.sub(r"<[^>]+>", " ", value)
