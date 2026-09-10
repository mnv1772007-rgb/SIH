import logging
from typing import Dict, Any, Tuple
from app.services.neo4j_service import neo4j_service
from app.models.integration_contract import (
    EmailAnalysisIngestPayload,
    normalize_domain,
    compute_url_hash,
)
from app.models.graph_models import IngestionResult

logger = logging.getLogger(__name__)


class GraphBuilder:
    def __init__(self):
        self.neo4j = neo4j_service

    def build_from_email_analysis(self, payload: Any) -> IngestionResult:
        """
        Idempotently ingests an analyzed email payload into Neo4j graph intelligence.
        Supports both validated EmailAnalysisIngestPayload and raw dictionary payloads.
        """
        if not isinstance(payload, EmailAnalysisIngestPayload):
            payload = EmailAnalysisIngestPayload.model_validate(payload)

        email = payload.email
        auth = payload.authentication
        iocs = payload.iocs
        detection = payload.detection or None
        risk_score = detection.risk_score if detection else 0.0

        nodes_created = 0
        nodes_matched = 0
        rels_created = 0
        rels_matched = 0

        def track_node(res_tuple: Tuple[Dict[str, Any], bool]):
            nonlocal nodes_created, nodes_matched
            _, was_created = res_tuple
            if was_created:
                nodes_created += 1
            else:
                nodes_matched += 1

        def track_rel(res_tuple: Tuple[bool, bool]):
            nonlocal rels_created, rels_matched
            success, was_created = res_tuple
            if success:
                if was_created:
                    rels_created += 1
                else:
                    rels_matched += 1

        # 1. Merge (:Email)
        email_props = {
            "email_id": email.email_id,
            "message_id": email.message_id or email.email_id,
            "subject": email.subject or "",
            "sender": email.sender or "",
            "sender_domain": email.sender_domain or "",
            "recipient": email.recipient or (email.recipients[0] if email.recipients else ""),
            "recipients": email.recipients,
            "timestamp": email.timestamp or "",
            "risk_score": risk_score,
            "is_malicious": risk_score > 0.6,
            "classification": detection.classification if detection else "suspicious",
            "spf": auth.spf if auth else "unknown",
            "dkim": auth.dkim if auth else "unknown",
            "dmarc": auth.dmarc if auth else "unknown",
        }
        track_node(self.neo4j.merge_node("Email", "email_id", email.email_id, email_props))

        # 2. Sender Domain & SENT_FROM relationship
        if email.sender_domain:
            track_node(
                self.neo4j.merge_node(
                    "Domain",
                    "name",
                    email.sender_domain,
                    {"name": email.sender_domain, "risk_score": risk_score},
                )
            )
            track_rel(
                self.neo4j.merge_relationship(
                    "Email", "email_id", email.email_id,
                    "Domain", "name", email.sender_domain,
                    "SENT_FROM",
                )
            )

        # 3. IOC Domains & CONTAINS_DOMAIN
        for d in iocs.domains:
            if d.value:
                track_node(
                    self.neo4j.merge_node(
                        "Domain",
                        "name",
                        d.value,
                        {"name": d.value, "source": d.source, "risk_score": risk_score},
                    )
                )
                track_rel(
                    self.neo4j.merge_relationship(
                        "Email", "email_id", email.email_id,
                        "Domain", "name", d.value,
                        "CONTAINS_DOMAIN",
                    )
                )

        # 4. IOC URLs, CONTAINS_URL & HOSTED_ON_DOMAIN
        for u in iocs.urls:
            if u.value:
                url_hash = u.url_hash or compute_url_hash(u.value)
                track_node(
                    self.neo4j.merge_node(
                        "URL",
                        "url_hash",
                        url_hash,
                        {
                            "url": u.value,
                            "url_hash": url_hash,
                            "domain": u.domain or "",
                            "risk_score": risk_score,
                            "is_phishing": risk_score > 0.6,
                        },
                    )
                )
                track_rel(
                    self.neo4j.merge_relationship(
                        "Email", "email_id", email.email_id,
                        "URL", "url_hash", url_hash,
                        "CONTAINS_URL",
                    )
                )
                if u.domain:
                    track_node(
                        self.neo4j.merge_node(
                            "Domain", "name", u.domain,
                            {"name": u.domain, "risk_score": risk_score},
                        )
                    )
                    track_rel(
                        self.neo4j.merge_relationship(
                            "URL", "url_hash", url_hash,
                            "Domain", "name", u.domain,
                            "HOSTED_ON_DOMAIN",
                        )
                    )

        # 5. IOC IPs, RESOLVES_TO & BELONGS_TO_ASN
        for ip_ioc in iocs.ips:
            if ip_ioc.value:
                ip_props = {
                    "address": ip_ioc.value,
                    "asn": ip_ioc.asn or "",
                    "country": ip_ioc.country or "",
                    "risk_score": risk_score,
                }
                track_node(self.neo4j.merge_node("IP", "address", ip_ioc.value, ip_props))

                if ip_ioc.asn:
                    track_node(
                        self.neo4j.merge_node("ASN", "number", ip_ioc.asn, {"number": ip_ioc.asn})
                    )
                    track_rel(
                        self.neo4j.merge_relationship(
                            "IP", "address", ip_ioc.value,
                            "ASN", "number", ip_ioc.asn,
                            "BELONGS_TO_ASN",
                        )
                    )

        # Map IP -> Domain resolutions
        if iocs.ip_domain_mapping:
            for ip_val, dom_val in iocs.ip_domain_mapping.items():
                clean_d = normalize_domain(dom_val)
                if clean_d and ip_val:
                    track_node(
                        self.neo4j.merge_node("Domain", "name", clean_d, {"name": clean_d})
                    )
                    track_node(
                        self.neo4j.merge_node("IP", "address", ip_val, {"address": ip_val})
                    )
                    track_rel(
                        self.neo4j.merge_relationship(
                            "Domain", "name", clean_d,
                            "IP", "address", ip_val,
                            "RESOLVES_TO",
                        )
                    )

        # 6. IOC Hashes & CONTAINS_HASH
        for h in iocs.hashes:
            if h.value:
                track_node(
                    self.neo4j.merge_node(
                        "Hash",
                        "value",
                        h.value,
                        {
                            "value": h.value,
                            "type": h.type or "sha256",
                            "filename": h.filename or "",
                            "risk_score": risk_score,
                            "is_malicious": risk_score > 0.6,
                        },
                    )
                )
                track_rel(
                    self.neo4j.merge_relationship(
                        "Email", "email_id", email.email_id,
                        "Hash", "value", h.value,
                        "CONTAINS_HASH",
                    )
                )

        logger.info(
            "Ingested analysis %s (email %s): nodes created=%d, matched=%d, rels created=%d, matched=%d",
            payload.analysis_id,
            email.email_id,
            nodes_created,
            nodes_matched,
            rels_created,
            rels_matched,
        )

        return IngestionResult(
            analysis_id=payload.analysis_id,
            email_id=email.email_id,
            nodes_created=nodes_created,
            nodes_matched=nodes_matched,
            relationships_created=rels_created,
            relationships_matched=rels_matched,
        )


graph_builder = GraphBuilder()