import hashlib
import logging
from typing import Dict, List, Set, Any, Optional, Tuple
from datetime import datetime
import networkx as nx

from app.services.neo4j_service import neo4j_service
from app.config import (
    WEIGHT_IOC_OVERLAP,
    WEIGHT_INFRA_OVERLAP,
    WEIGHT_SUBJECT_SIMILARITY,
    WEIGHT_TEMPORAL,
    WEIGHT_BEHAVIOR,
)

logger = logging.getLogger(__name__)


class CampaignClustering:
    def __init__(self):
        self.neo4j = neo4j_service

    def get_all_emails_with_indicators(self, email_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Retrieves emails and their connected graph indicators from Neo4j."""
        if not self.neo4j.is_connected():
            return []

        filter_clause = "WHERE e.email_id IN $email_ids" if email_ids else ""
        query = f"""
            MATCH (e:Email)
            {filter_clause}
            OPTIONAL MATCH (e)-[:SENT_FROM]->(sd:Domain)
            OPTIONAL MATCH (e)-[:CONTAINS_DOMAIN]->(cd:Domain)
            OPTIONAL MATCH (e)-[:CONTAINS_URL]->(u:URL)
            OPTIONAL MATCH (e)-[:CONTAINS_HASH]->(h:Hash)
            OPTIONAL MATCH (cd)-[:RESOLVES_TO]->(ip1:IP)
            OPTIONAL MATCH (sd)-[:RESOLVES_TO]->(ip2:IP)
            RETURN e.email_id as email_id,
                   e.subject as subject,
                   e.sender as sender,
                   e.sender_domain as sender_domain,
                   e.timestamp as timestamp,
                   e.risk_score as risk_score,
                   e.classification as classification,
                   e.spf as spf,
                   e.dkim as dkim,
                   e.dmarc as dmarc,
                   collect(DISTINCT cd.name) as domains,
                   collect(DISTINCT u.url) as urls,
                   collect(DISTINCT h.value) as hashes,
                   collect(DISTINCT coalesce(ip1.address, ip2.address)) as ips
        """
        results = self.neo4j.run_query(query, {"email_ids": email_ids or []})
        clean_results = []
        for r in results:
            clean_results.append({
                "email_id": r.get("email_id"),
                "subject": r.get("subject") or "",
                "sender": r.get("sender") or "",
                "sender_domain": r.get("sender_domain") or "",
                "timestamp": r.get("timestamp") or "",
                "risk_score": float(r.get("risk_score") or 0.0),
                "classification": r.get("classification") or "unknown",
                "spf": r.get("spf") or "unknown",
                "dkim": r.get("dkim") or "unknown",
                "dmarc": r.get("dmarc") or "unknown",
                "domains": [d for d in r.get("domains", []) if d],
                "urls": [u for u in r.get("urls", []) if u],
                "hashes": [h for h in r.get("hashes", []) if h],
                "ips": [ip for ip in r.get("ips", []) if ip],
            })
        return clean_results

    def compute_similarity(self, e1: Dict[str, Any], e2: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        """
        Computes explainable weighted similarity between two analyzed emails.
        Returns: (similarity_score, breakdown_dict)
        """
        # 1. IOC Overlap (URLs and Hashes)
        urls1, urls2 = set(e1.get("urls", [])), set(e2.get("urls", []))
        hashes1, hashes2 = set(e1.get("hashes", [])), set(e2.get("hashes", []))
        shared_urls = urls1 & urls2
        shared_hashes = hashes1 & hashes2

        ioc_union = (urls1 | urls2) | (hashes1 | hashes2)
        ioc_score = (len(shared_urls) + len(shared_hashes)) / len(ioc_union) if ioc_union else 0.0

        # 2. Infrastructure Overlap (Domains and IPs)
        doms1 = set(e1.get("domains", []))
        if e1.get("sender_domain"):
            doms1.add(e1["sender_domain"])
        doms2 = set(e2.get("domains", []))
        if e2.get("sender_domain"):
            doms2.add(e2["sender_domain"])

        ips1, ips2 = set(e1.get("ips", [])), set(e2.get("ips", []))
        shared_domains = doms1 & doms2
        shared_ips = ips1 & ips2

        infra_union = (doms1 | doms2) | (ips1 | ips2)
        infra_score = (len(shared_domains) + len(shared_ips)) / len(infra_union) if infra_union else 0.0

        # If emails share an exact malicious IP or domain, grant strong infrastructural linkage
        if shared_ips or (shared_domains and not any(d in {"gmail.com", "outlook.com", "yahoo.com"} for d in shared_domains)):
            infra_score = max(infra_score, 0.8)

        # 3. Content / Subject Similarity
        sub1 = set(e1.get("subject", "").lower().split())
        sub2 = set(e2.get("subject", "").lower().split())
        sub_union = sub1 | sub2
        subject_score = (len(sub1 & sub2) / len(sub_union)) if sub_union else 0.0

        # 4. Temporal Proximity
        temporal_score = 0.5
        ts1_str = e1.get("timestamp")
        ts2_str = e2.get("timestamp")
        if ts1_str and ts2_str:
            try:
                dt1 = datetime.fromisoformat(ts1_str.replace("Z", "+00:00"))
                dt2 = datetime.fromisoformat(ts2_str.replace("Z", "+00:00"))
                diff_hours = abs((dt1 - dt2).total_seconds()) / 3600.0
                if diff_hours <= 1.0:
                    temporal_score = 1.0
                elif diff_hours <= 24.0:
                    temporal_score = 0.85
                elif diff_hours <= 72.0:
                    temporal_score = 0.6
                else:
                    temporal_score = 0.3
            except Exception:
                pass

        # 5. Behavior & Authentication Patterns
        behavior_score = 0.0
        auth_matches = 0
        if e1.get("spf") == e2.get("spf") and e1.get("spf") != "unknown":
            auth_matches += 1
        if e1.get("dmarc") == e2.get("dmarc") and e1.get("dmarc") != "unknown":
            auth_matches += 1
        if e1.get("classification") == e2.get("classification"):
            auth_matches += 1
        behavior_score = auth_matches / 3.0

        # Weighted total
        total_score = (
            (ioc_score * WEIGHT_IOC_OVERLAP)
            + (infra_score * WEIGHT_INFRA_OVERLAP)
            + (subject_score * WEIGHT_SUBJECT_SIMILARITY)
            + (temporal_score * WEIGHT_TEMPORAL)
            + (behavior_score * WEIGHT_BEHAVIOR)
        )

        breakdown = {
            "ioc_score": round(ioc_score, 3),
            "infra_score": round(infra_score, 3),
            "subject_score": round(subject_score, 3),
            "temporal_score": round(temporal_score, 3),
            "behavior_score": round(behavior_score, 3),
            "shared_domains": list(shared_domains),
            "shared_ips": list(shared_ips),
            "shared_urls": list(shared_urls),
            "shared_hashes": list(shared_hashes),
        }

        return round(min(1.0, max(0.0, total_score)), 3), breakdown

    def cluster_campaigns(
        self,
        similarity_threshold: float = 0.45,
        min_cluster_size: int = 2,
        email_ids: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Performs explainable campaign clustering using NetworkX community / connected component analysis.
        Persists detected campaigns into Neo4j and attaches member relationships.
        """
        emails = self.get_all_emails_with_indicators(email_ids)
        if len(emails) < min_cluster_size:
            return []

        # Build similarity graph
        G = nx.Graph()
        for e in emails:
            G.add_node(e["email_id"], data=e)

        pairwise_evidence: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for i in range(len(emails)):
            for j in range(i + 1, len(emails)):
                sim, breakdown = self.compute_similarity(emails[i], emails[j])
                if sim >= similarity_threshold:
                    id_a = emails[i]["email_id"]
                    id_b = emails[j]["email_id"]
                    G.add_edge(id_a, id_b, weight=sim)
                    pairwise_evidence[(id_a, id_b)] = breakdown

        # Extract connected components (campaign clusters)
        components = [c for c in nx.connected_components(G) if len(c) >= min_cluster_size]

        created_campaigns = []
        for cluster_members in components:
            cluster_emails = [G.nodes[eid]["data"] for eid in cluster_members]
            campaign = self._persist_campaign(cluster_emails, pairwise_evidence)
            created_campaigns.append(campaign)

        return created_campaigns

    def _persist_campaign(
        self,
        cluster_emails: List[Dict[str, Any]],
        pairwise_evidence: Dict[Tuple[str, str], Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Creates or updates a Campaign node in Neo4j with full IOC linkages and explainable reasons."""
        email_ids = sorted([e["email_id"] for e in cluster_emails])

        # Stable deterministic campaign ID
        hash_seed = "-".join(email_ids)
        campaign_id = "camp-" + hashlib.sha256(hash_seed.encode("utf-8")).hexdigest()[:12]

        # Aggregate shared indicators (observed across >= 2 emails in the cluster)
        all_doms: Dict[str, int] = {}
        all_ips: Dict[str, int] = {}
        all_urls: Dict[str, int] = {}
        all_hashes: Dict[str, int] = {}
        valid_ts = []
        risk_scores = []

        for e in cluster_emails:
            risk_scores.append(e.get("risk_score", 0.0))
            if e.get("timestamp"):
                valid_ts.append(e["timestamp"])
            doms = set(e.get("domains", []))
            if e.get("sender_domain"):
                doms.add(e["sender_domain"])
            for d in doms:
                all_doms[d] = all_doms.get(d, 0) + 1
            for ip in e.get("ips", []):
                all_ips[ip] = all_ips.get(ip, 0) + 1
            for u in e.get("urls", []):
                all_urls[u] = all_urls.get(u, 0) + 1
            for h in e.get("hashes", []):
                all_hashes[h] = all_hashes.get(h, 0) + 1

        shared_domains = [d for d, count in all_doms.items() if count >= 2 or len(cluster_emails) == 1]
        shared_ips = [ip for ip, count in all_ips.items() if count >= 2 or len(cluster_emails) == 1]
        shared_urls = [u for u, count in all_urls.items() if count >= 2 or len(cluster_emails) == 1]
        shared_hashes = [h for h, count in all_hashes.items() if count >= 2 or len(cluster_emails) == 1]

        first_seen = min(valid_ts) if valid_ts else datetime.utcnow().isoformat() + "Z"
        last_seen = max(valid_ts) if valid_ts else first_seen
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.5

        # Explainable reasons
        reasons = []
        total_n = len(cluster_emails)
        if shared_domains:
            reasons.append(f"{len(shared_domains)} domain(s) shared across campaign emails (e.g. {shared_domains[:2]})")
        if shared_ips:
            reasons.append(f"{len(shared_ips)} IP(s) observed across multiple emails in campaign (e.g. {shared_ips[:2]})")
        if shared_urls:
            reasons.append(f"{len(shared_urls)} common malicious/phishing URL(s) detected")
        if shared_hashes:
            reasons.append(f"{len(shared_hashes)} identical payload/attachment hash(es) identified")
        reasons.append(f"Campaign activity spans {total_n} correlated messages with average risk score of {avg_risk:.2f}")

        # Baseline campaign confidence
        conf_infra = min(1.0, (len(shared_domains) * 0.3 + len(shared_ips) * 0.4 + len(shared_hashes) * 0.3))
        campaign_confidence = round(min(1.0, max(0.4, (conf_infra * 0.6) + (avg_risk * 0.4))), 2)

        # Merge Campaign Node
        props = {
            "campaign_id": campaign_id,
            "name": f"Correlated Campaign ({campaign_id})",
            "email_count": total_n,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "risk_score": round(avg_risk, 3),
            "confidence": campaign_confidence,
            "description": f"Automated cluster of {total_n} emails sharing infrastructure and IOC signatures.",
        }
        self.neo4j.merge_node("Campaign", "campaign_id", campaign_id, props)

        # Link MEMBER_OF and Campaign infrastructure
        for eid in email_ids:
            self.neo4j.merge_relationship(
                "Email", "email_id", eid,
                "Campaign", "campaign_id", campaign_id,
                "MEMBER_OF",
            )

        for d in shared_domains:
            self.neo4j.merge_node("Domain", "name", d, {"name": d})
            self.neo4j.merge_relationship(
                "Campaign", "campaign_id", campaign_id,
                "Domain", "name", d,
                "USES_DOMAIN",
            )

        for ip in shared_ips:
            self.neo4j.merge_node("IP", "address", ip, {"address": ip})
            self.neo4j.merge_relationship(
                "Campaign", "campaign_id", campaign_id,
                "IP", "address", ip,
                "USES_IP",
            )

        for u in shared_urls:
            from app.models.integration_contract import compute_url_hash
            u_hash = compute_url_hash(u)
            self.neo4j.merge_node("URL", "url_hash", u_hash, {"url": u, "url_hash": u_hash})
            self.neo4j.merge_relationship(
                "Campaign", "campaign_id", campaign_id,
                "URL", "url_hash", u_hash,
                "USES_URL",
            )

        for h in shared_hashes:
            self.neo4j.merge_node("Hash", "value", h, {"value": h})
            self.neo4j.merge_relationship(
                "Campaign", "campaign_id", campaign_id,
                "Hash", "value", h,
                "USES_HASH",
            )

        return {
            "campaign_id": campaign_id,
            "email_count": total_n,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "risk_score": round(avg_risk, 3),
            "shared_indicators": {
                "domains": shared_domains,
                "ips": shared_ips,
                "urls": shared_urls,
                "hashes": shared_hashes,
            },
            "confidence": campaign_confidence,
            "reasons": reasons,
        }

    def get_campaign_details(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves full campaign details and shared infrastructure."""
        if not self.neo4j.is_connected():
            return None

        query = """
            MATCH (c:Campaign {campaign_id: $campaign_id})
            OPTIONAL MATCH (e:Email)-[:MEMBER_OF]->(c)
            OPTIONAL MATCH (c)-[:USES_DOMAIN]->(d:Domain)
            OPTIONAL MATCH (c)-[:USES_IP]->(ip:IP)
            OPTIONAL MATCH (c)-[:USES_URL]->(u:URL)
            OPTIONAL MATCH (c)-[:USES_HASH]->(h:Hash)
            RETURN c,
                   collect(DISTINCT e.email_id) as email_ids,
                   collect(DISTINCT d.name) as domains,
                   collect(DISTINCT ip.address) as ips,
                   collect(DISTINCT u.url) as urls,
                   collect(DISTINCT h.value) as hashes
        """
        results = self.neo4j.run_query(query, {"campaign_id": campaign_id})
        if not results or not results[0].get("c"):
            return None

        row = results[0]
        c = row["c"]
        return {
            "campaign_id": campaign_id,
            "name": c.get("name"),
            "email_count": c.get("email_count", len(row.get("email_ids", []))),
            "first_seen": c.get("first_seen"),
            "last_seen": c.get("last_seen"),
            "risk_score": c.get("risk_score"),
            "confidence": c.get("confidence"),
            "emails": row.get("email_ids", []),
            "shared_indicators": {
                "domains": row.get("domains", []),
                "ips": row.get("ips", []),
                "urls": row.get("urls", []),
                "hashes": row.get("hashes", []),
            },
        }

    def list_all_campaigns(self) -> List[Dict[str, Any]]:
        if not self.neo4j.is_connected():
            return []
        query = """
            MATCH (c:Campaign)
            OPTIONAL MATCH (e:Email)-[:MEMBER_OF]->(c)
            RETURN c.campaign_id as campaign_id,
                   c.name as name,
                   count(DISTINCT e) as email_count,
                   c.first_seen as first_seen,
                   c.last_seen as last_seen,
                   c.risk_score as risk_score,
                   c.confidence as confidence
            ORDER BY c.confidence DESC, c.first_seen DESC
        """
        return self.neo4j.run_query(query)


campaign_clustering = CampaignClustering()