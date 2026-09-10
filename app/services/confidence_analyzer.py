import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from app.services.neo4j_service import neo4j_service
from app.models.graph_models import (
    AttributionConfidenceResponse,
    ConfidenceBreakdown,
    ConfidenceLevel,
)
from app.config import (
    CONF_WEIGHT_INFRA,
    CONF_WEIGHT_TEMPORAL,
    CONF_WEIGHT_BEHAVIOR,
    CONF_WEIGHT_CONTENT,
    CONF_LEVEL_LOW,
    CONF_LEVEL_MED,
    CONF_LEVEL_HIGH,
    ATTRIBUTION_DISCLAIMER,
)

logger = logging.getLogger(__name__)


class ConfidenceAnalyzer:
    def __init__(self):
        self.neo4j = neo4j_service

    def calculate_attribution_confidence(self, campaign_id: str) -> Optional[AttributionConfidenceResponse]:
        """
        Calculates explainable forensic correlation confidence for a detected campaign.
        Measures probability that observed threats share common infrastructure/operations.
        Strictly disclaims physical attacker identity attribution.
        """
        campaign_data = self._fetch_campaign_telemetry(campaign_id)
        if not campaign_data:
            return None

        emails = campaign_data.get("emails", [])
        if not emails:
            # Fallback for empty campaign
            return AttributionConfidenceResponse(
                campaign_id=campaign_id,
                confidence=0.30,
                level=ConfidenceLevel.LOW,
                breakdown=ConfidenceBreakdown(
                    infrastructure=0.30,
                    temporal=0.30,
                    behavioral=0.30,
                    content=0.30,
                ),
                evidence=["Single unverified incident with insufficient telemetry"],
                limitations=[
                    "Lack of multiple observations prevents multi-point correlation",
                    ATTRIBUTION_DISCLAIMER,
                ],
                methodology_disclaimer=ATTRIBUTION_DISCLAIMER,
            )

        # 1. Infrastructure Linkage Score
        infra_score, infra_evidence = self._score_infrastructure(campaign_data)

        # 2. Temporal Pattern Score
        temporal_score, temp_evidence = self._score_temporal(emails)

        # 3. Behavioral Consistency Score
        behavior_score, behav_evidence = self._score_behavior(emails)

        # 4. Content / Subject Similarity Score
        content_score, content_evidence = self._score_content(emails)

        # Weighted composite score
        overall = (
            (infra_score * CONF_WEIGHT_INFRA)
            + (temporal_score * CONF_WEIGHT_TEMPORAL)
            + (behavior_score * CONF_WEIGHT_BEHAVIOR)
            + (content_score * CONF_WEIGHT_CONTENT)
        )
        overall = round(max(0.0, min(1.0, overall)), 2)

        # Map to configured discrete levels
        if overall >= CONF_LEVEL_HIGH:
            level = ConfidenceLevel.VERY_HIGH
        elif overall >= CONF_LEVEL_MED:
            level = ConfidenceLevel.HIGH
        elif overall >= CONF_LEVEL_LOW:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        all_evidence = infra_evidence + temp_evidence + behav_evidence + content_evidence

        limitations = [
            "Shared infrastructure (IPs/nameservers) may represent multi-tenant cloud hosting or compromised relays",
            "IP geolocation identifies routing infrastructure, not the physical location or identity of threat actors",
            "Header-based indicators may be partially spoofed if cryptographic verification (DKIM/DMARC) is absent",
            "Correlation confidence indicates operational linkage between observations, not legal proof of authorship",
        ]

        return AttributionConfidenceResponse(
            campaign_id=campaign_id,
            confidence=overall,
            level=level,
            breakdown=ConfidenceBreakdown(
                infrastructure=round(infra_score, 2),
                temporal=round(temporal_score, 2),
                behavioral=round(behavior_score, 2),
                content=round(content_score, 2),
            ),
            evidence=all_evidence,
            limitations=limitations,
            methodology_disclaimer=ATTRIBUTION_DISCLAIMER,
        )

    def _fetch_campaign_telemetry(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        if not self.neo4j.is_connected():
            return None

        query = """
            MATCH (c:Campaign {campaign_id: $campaign_id})
            OPTIONAL MATCH (e:Email)-[:MEMBER_OF]->(c)
            OPTIONAL MATCH (c)-[:USES_DOMAIN]->(cd:Domain)
            OPTIONAL MATCH (c)-[:USES_IP]->(ci:IP)
            OPTIONAL MATCH (c)-[:USES_URL]->(cu:URL)
            OPTIONAL MATCH (c)-[:USES_HASH]->(ch:Hash)
            RETURN c,
                   collect(DISTINCT {
                       email_id: e.email_id,
                       subject: e.subject,
                       sender: e.sender,
                       sender_domain: e.sender_domain,
                       timestamp: e.timestamp,
                       risk_score: e.risk_score,
                       spf: e.spf,
                       dkim: e.dkim,
                       dmarc: e.dmarc,
                       classification: e.classification
                   }) as emails,
                   collect(DISTINCT cd.name) as campaign_domains,
                   collect(DISTINCT ci.address) as campaign_ips,
                   collect(DISTINCT cu.url) as campaign_urls,
                   collect(DISTINCT ch.value) as campaign_hashes
        """
        results = self.neo4j.run_query(query, {"campaign_id": campaign_id})
        if not results or not results[0].get("c"):
            return None

        r = results[0]
        # Clean up empty emails if optional match returned [None]
        emails = [e for e in r.get("emails", []) if e.get("email_id")]
        return {
            "campaign": r["c"],
            "emails": emails,
            "campaign_domains": [d for d in r.get("campaign_domains", []) if d],
            "campaign_ips": [i for i in r.get("campaign_ips", []) if i],
            "campaign_urls": [u for u in r.get("campaign_urls", []) if u],
            "campaign_hashes": [h for h in r.get("campaign_hashes", []) if h],
        }

    def _score_infrastructure(self, data: Dict[str, Any]) -> Tuple[float, List[str]]:
        ips = data.get("campaign_ips", [])
        domains = data.get("campaign_domains", [])
        urls = data.get("campaign_urls", [])
        hashes = data.get("campaign_hashes", [])
        emails = data.get("emails", [])

        evidence = []
        score = 0.2
        if len(emails) >= 2:
            if ips:
                score += min(0.35, len(ips) * 0.18)
                evidence.append(f"Observed shared hosting infrastructure: {len(ips)} IP address(es) reused across campaign")
            if domains:
                score += min(0.30, len(domains) * 0.15)
                evidence.append(f"Shared domain infrastructure: {len(domains)} domain(s) linked to campaign messages")
            if urls:
                score += min(0.25, len(urls) * 0.15)
                evidence.append(f"Identical phishing/malicious destination URLs embedded across messages: {len(urls)} URL(s)")
            if hashes:
                score += min(0.20, len(hashes) * 0.15)
                evidence.append(f"Matching cryptographic file attachment hashes: {len(hashes)} unique payload(s)")
        else:
            evidence.append("Single threat message observed; limited infrastructure reuse confirmed")

        return min(1.0, max(0.1, score)), evidence

    def _score_temporal(self, emails: List[Dict[str, Any]]) -> Tuple[float, List[str]]:
        if len(emails) < 2:
            return 0.3, ["Single timestamp observed; burst pattern not measurable"]

        parsed_ts = []
        for e in emails:
            ts_val = e.get("timestamp")
            if ts_val:
                try:
                    dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                    parsed_ts.append(dt)
                except Exception:
                    pass

        if len(parsed_ts) < 2:
            return 0.4, ["Incomplete timestamp metadata; using conservative temporal baseline"]

        parsed_ts.sort()
        total_span_hours = (parsed_ts[-1] - parsed_ts[0]).total_seconds() / 3600.0

        if total_span_hours <= 2.0:
            score = 0.95
            evidence = [f"Coordinated high-velocity burst: all {len(emails)} messages sent within {total_span_hours:.1f} hours"]
        elif total_span_hours <= 24.0:
            score = 0.85
            evidence = [f"Correlated temporal window: {len(emails)} messages transmitted within a 24-hour cycle ({total_span_hours:.1f} hours span)"]
        elif total_span_hours <= 72.0:
            score = 0.65
            evidence = [f"Multi-day campaign pacing: activity observed across {total_span_hours / 24.0:.1f} days"]
        else:
            score = 0.40
            evidence = [f"Dispersed temporal distribution: activity spans {total_span_hours / 24.0:.1f} days"]

        return score, evidence

    def _score_behavior(self, emails: List[Dict[str, Any]]) -> Tuple[float, List[str]]:
        if len(emails) < 2:
            return 0.3, ["Single behavioral sample"]

        spf_fails = sum(1 for e in emails if e.get("spf") in {"fail", "softfail"})
        dkim_fails = sum(1 for e in emails if e.get("dkim") == "fail")
        dmarc_fails = sum(1 for e in emails if e.get("dmarc") == "fail")
        total = len(emails)

        evidence = []
        score = 0.5
        if spf_fails == total or dmarc_fails == total:
            score += 0.35
            evidence.append(f"Homogeneous email authentication failure profile: {spf_fails}/{total} SPF and {dmarc_fails}/{total} DMARC failures")
        elif spf_fails > 0:
            score += 0.2
            evidence.append(f"Consistent spoofing indicators: {spf_fails}/{total} messages failed sender authentication")

        classifications = {e.get("classification") for e in emails if e.get("classification")}
        if len(classifications) == 1:
            score += 0.15
            evidence.append(f"Uniform threat intent classification: {list(classifications)[0]}")

        return min(1.0, max(0.2, score)), evidence

    def _score_content(self, emails: List[Dict[str, Any]]) -> Tuple[float, List[str]]:
        subjects = [e.get("subject", "").strip().lower() for e in emails if e.get("subject")]
        if len(subjects) < 2:
            return 0.3, ["Insufficient subject diversity for content similarity evaluation"]

        word_sets = [set(s.split()) for s in subjects if s]
        if len(word_sets) < 2:
            return 0.3, ["Empty or unparsed subject lines"]

        total_jaccard = 0.0
        pairs = 0
        for i in range(len(word_sets)):
            for j in range(i + 1, len(word_sets)):
                union = word_sets[i] | word_sets[j]
                if union:
                    total_jaccard += len(word_sets[i] & word_sets[j]) / len(union)
                pairs += 1

        avg_similarity = (total_jaccard / pairs) if pairs > 0 else 0.0

        if avg_similarity >= 0.7:
            evidence = [f"Strong lexical template alignment: subject line similarity {avg_similarity:.2f}"]
            score = 0.90
        elif avg_similarity >= 0.4:
            evidence = [f"Moderate thematic overlap in subject lines: similarity {avg_similarity:.2f}"]
            score = 0.65
        else:
            evidence = [f"Distinct or polymorphic subject lines observed: similarity {avg_similarity:.2f}"]
            score = 0.35

        return score, evidence

    def get_full_report(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Generates comprehensive forensic campaign intelligence report."""
        confidence_result = self.calculate_attribution_confidence(campaign_id)
        if not confidence_result:
            return None

        telemetry = self._fetch_campaign_telemetry(campaign_id)
        if not telemetry:
            return None

        campaign = telemetry["campaign"]
        return {
            "campaign_id": campaign_id,
            "campaign_name": campaign.get("name"),
            "risk_score": campaign.get("risk_score"),
            "email_count": len(telemetry.get("emails", [])),
            "first_seen": campaign.get("first_seen"),
            "last_seen": campaign.get("last_seen"),
            "attribution_confidence": confidence_result.model_dump(),
            "infrastructure_inventory": {
                "domains": telemetry.get("campaign_domains", []),
                "ips": telemetry.get("campaign_ips", []),
                "urls": telemetry.get("campaign_urls", []),
                "hashes": telemetry.get("campaign_hashes", []),
            },
            "analyzed_emails": [
                {
                    "email_id": e.get("email_id"),
                    "subject": e.get("subject"),
                    "sender": e.get("sender"),
                    "timestamp": e.get("timestamp"),
                    "risk_score": e.get("risk_score"),
                }
                for e in telemetry.get("emails", [])
            ],
            "forensic_disclaimer": ATTRIBUTION_DISCLAIMER,
        }


confidence_analyzer = ConfidenceAnalyzer()