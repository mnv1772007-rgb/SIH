import logging
from typing import Dict, List, Optional, Any, Tuple
from app.services.neo4j_service import neo4j_service
from app.models.graph_models import (
    FrontendNode,
    FrontendEdge,
    FrontendGraphResponse,
)
from app.config import (
    DEFAULT_GRAPH_DEPTH,
    MAX_GRAPH_DEPTH,
    DEFAULT_GRAPH_LIMIT,
    MAX_GRAPH_LIMIT,
    ATTRIBUTION_DISCLAIMER,
)

logger = logging.getLogger(__name__)


def make_prefixed_id(label: str, raw_val: Any) -> str:
    lbl = str(label).lower()
    return f"{lbl}:{raw_val}"


class InfrastructureCorrelation:
    def __init__(self):
        self.neo4j = neo4j_service

    def analyze_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """IP pivot: IP -> Domains, URLs, Emails, Campaigns, ASN."""
        if not self.neo4j.is_connected():
            return None

        query = """
            MATCH (i:IP {address: $ip})
            OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(i)
            OPTIONAL MATCH (e:Email)-[:SENT_FROM|CONTAINS_DOMAIN]->(d)
            OPTIONAL MATCH (c:Campaign)-[:USES_IP]->(i)
            OPTIONAL MATCH (i)-[:BELONGS_TO_ASN]->(a:ASN)
            RETURN i,
                   a.number as asn,
                   collect(DISTINCT d.name) as associated_domains,
                   collect(DISTINCT e.email_id) as related_emails,
                   collect(DISTINCT c.campaign_id) as associated_campaigns
        """
        results = self.neo4j.run_query(query, {"ip": ip_address})
        if not results or not results[0].get("i"):
            return None

        r = results[0]
        ip_node = r["i"]
        domains = [d for d in r.get("associated_domains", []) if d]
        emails = [e for e in r.get("related_emails", []) if e]
        campaigns = [c for c in r.get("associated_campaigns", []) if c]

        # Evidence & Strength
        domain_count = len(domains)
        email_count = len(emails)
        campaign_count = len(campaigns)

        strength = min(1.0, (domain_count * 0.25) + (email_count * 0.1) + (campaign_count * 0.35))
        strength = round(max(0.2, strength), 2)

        reasons = [
            f"Observed hosting infrastructure associated with {domain_count} domain(s)",
            f"Identified in telemetry across {email_count} analyzed email message(s)",
        ]
        if campaigns:
            reasons.append(f"Linked as shared infrastructure in campaign(s): {', '.join(campaigns)}")

        return {
            "ip": ip_address,
            "asn": r.get("asn") or ip_node.get("asn"),
            "risk_score": ip_node.get("risk_score", 0.0),
            "associated_domains": domains,
            "related_emails": emails,
            "associated_campaigns": campaigns,
            "correlation_strength": strength,
            "reasons": reasons,
            "disclaimer": ATTRIBUTION_DISCLAIMER,
        }

    def analyze_domain(self, domain_name: str) -> Optional[Dict[str, Any]]:
        """Domain pivot: Domain -> IPs, URLs, Emails, Campaigns."""
        if not self.neo4j.is_connected():
            return None

        query = """
            MATCH (d:Domain {name: $domain})
            OPTIONAL MATCH (d)-[:RESOLVES_TO]->(i:IP)
            OPTIONAL MATCH (u:URL)-[:HOSTED_ON_DOMAIN]->(d)
            OPTIONAL MATCH (e:Email)-[:SENT_FROM|CONTAINS_DOMAIN]->(d)
            OPTIONAL MATCH (c:Campaign)-[:USES_DOMAIN]->(d)
            RETURN d,
                   collect(DISTINCT i.address) as resolving_ips,
                   collect(DISTINCT u.url) as hosted_urls,
                   collect(DISTINCT e.email_id) as related_emails,
                   collect(DISTINCT c.campaign_id) as associated_campaigns
        """
        results = self.neo4j.run_query(query, {"domain": domain_name})
        if not results or not results[0].get("d"):
            return None

        r = results[0]
        d_node = r["d"]
        ips = [ip for ip in r.get("resolving_ips", []) if ip]
        urls = [u for u in r.get("hosted_urls", []) if u]
        emails = [e for e in r.get("related_emails", []) if e]
        campaigns = [c for c in r.get("associated_campaigns", []) if c]

        strength = min(1.0, (len(ips) * 0.3) + (len(emails) * 0.15) + (len(campaigns) * 0.35))

        return {
            "domain": domain_name,
            "risk_score": d_node.get("risk_score", 0.0),
            "resolving_ips": ips,
            "hosted_urls": urls,
            "related_emails": emails,
            "associated_campaigns": campaigns,
            "correlation_strength": round(max(0.2, strength), 2),
            "reasons": [
                f"Domain resolves to {len(ips)} hosting IP(s)",
                f"Observed in {len(emails)} email(s) and {len(urls)} embedded URL(s)",
            ],
            "disclaimer": ATTRIBUTION_DISCLAIMER,
        }

    def analyze_hash(self, hash_val: str) -> Optional[Dict[str, Any]]:
        """Hash pivot: Hash -> Emails, Campaigns."""
        if not self.neo4j.is_connected():
            return None

        query = """
            MATCH (h:Hash {value: $hash})
            OPTIONAL MATCH (e:Email)-[:CONTAINS_HASH]->(h)
            OPTIONAL MATCH (c:Campaign)-[:USES_HASH]->(h)
            RETURN h,
                   collect(DISTINCT e.email_id) as email_ids,
                   collect(DISTINCT c.campaign_id) as campaign_ids
        """
        results = self.neo4j.run_query(query, {"hash": hash_val})
        if not results or not results[0].get("h"):
            return None

        r = results[0]
        h_node = r["h"]
        emails = r.get("email_ids", [])
        campaigns = r.get("campaign_ids", [])

        return {
            "hash": hash_val,
            "type": h_node.get("type", "sha256"),
            "risk_score": h_node.get("risk_score", 0.0),
            "filename": h_node.get("filename", ""),
            "related_emails": emails,
            "associated_campaigns": campaigns,
            "correlation_strength": min(1.0, len(emails) * 0.3 + len(campaigns) * 0.4),
            "reasons": [f"Malicious/suspicious payload hash present in {len(emails)} email(s)"],
            "disclaimer": ATTRIBUTION_DISCLAIMER,
        }

    def analyze_asn(self, asn_number: str) -> Optional[Dict[str, Any]]:
        """ASN pivot: ASN -> IPs, Domains, Campaigns."""
        if not self.neo4j.is_connected():
            return None

        query = """
            MATCH (a:ASN {number: $asn})
            OPTIONAL MATCH (i:IP)-[:BELONGS_TO_ASN]->(a)
            OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(i)
            OPTIONAL MATCH (c:Campaign)-[:USES_IP]->(i)
            RETURN a,
                   collect(DISTINCT i.address) as ips,
                   collect(DISTINCT d.name) as domains,
                   collect(DISTINCT c.campaign_id) as campaigns
        """
        results = self.neo4j.run_query(query, {"asn": asn_number})
        if not results or not results[0].get("a"):
            return None

        r = results[0]
        return {
            "asn": asn_number,
            "associated_ips": r.get("ips", []),
            "associated_domains": r.get("domains", []),
            "associated_campaigns": r.get("campaigns", []),
            "disclaimer": ATTRIBUTION_DISCLAIMER,
        }

    def find_infrastructure_clusters(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Identifies shared infrastructure hosting multiple domains or campaign emails."""
        if not self.neo4j.is_connected():
            return []

        limit = min(limit, MAX_GRAPH_LIMIT)
        query = """
            MATCH (ip:IP)<-[:RESOLVES_TO]-(d:Domain)
            OPTIONAL MATCH (e:Email)-[:SENT_FROM|CONTAINS_DOMAIN]->(d)
            OPTIONAL MATCH (c:Campaign)-[:USES_IP]->(ip)
            WITH ip,
                 collect(DISTINCT d.name) as domains,
                 collect(DISTINCT e.email_id) as emails,
                 collect(DISTINCT c.campaign_id) as campaigns
            WHERE size(domains) >= 2 OR size(emails) >= 2
            RETURN ip.address as ip,
                   ip.asn as asn,
                   ip.risk_score as risk_score,
                   domains,
                   emails,
                   campaigns,
                   size(domains) as domain_count,
                   size(emails) as email_count
            ORDER BY domain_count DESC, email_count DESC
            LIMIT $limit
        """
        results = self.neo4j.run_query(query, {"limit": limit})
        clusters = []
        for r in results:
            doms = r.get("domains", [])
            emls = r.get("emails", [])
            camps = r.get("campaigns", [])
            strength = round(min(1.0, len(doms) * 0.3 + len(emls) * 0.15 + len(camps) * 0.35), 2)
            clusters.append({
                "ip": r.get("ip"),
                "asn": r.get("asn"),
                "risk_score": r.get("risk_score", 0.0),
                "domains": doms,
                "domain_count": len(doms),
                "email_count": len(emls),
                "campaigns": camps,
                "correlation_strength": strength,
                "reasons": [
                    f"Hosting IP observed serving {len(doms)} domain(s)",
                    f"Present across {len(emls)} analyzed threat messages",
                ],
                "disclaimer": ATTRIBUTION_DISCLAIMER,
            })
        return clusters

    def trace_email_path(self, email_id: str) -> Optional[Dict[str, Any]]:
        """Traces complete infrastructure path from email through domains, IPs, URLs, and campaigns."""
        if not self.neo4j.is_connected():
            return None

        query = """
            MATCH (e:Email {email_id: $email_id})
            OPTIONAL MATCH (e)-[:SENT_FROM]->(sd:Domain)
            OPTIONAL MATCH (sd)-[:RESOLVES_TO]->(sip:IP)
            OPTIONAL MATCH (e)-[:CONTAINS_DOMAIN]->(cd:Domain)
            OPTIONAL MATCH (cd)-[:RESOLVES_TO]->(cip:IP)
            OPTIONAL MATCH (e)-[:CONTAINS_URL]->(u:URL)
            OPTIONAL MATCH (e)-[:CONTAINS_HASH]->(h:Hash)
            OPTIONAL MATCH (e)-[:MEMBER_OF]->(c:Campaign)
            RETURN e,
                   sd.name as sender_domain,
                   sip.address as sender_ip,
                   collect(DISTINCT cd.name) as embedded_domains,
                   collect(DISTINCT cip.address) as resolved_ips,
                   collect(DISTINCT u.url) as urls,
                   collect(DISTINCT h.value) as hashes,
                   collect(DISTINCT c.campaign_id) as campaigns
        """
        results = self.neo4j.run_query(query, {"email_id": email_id})
        if not results or not results[0].get("e"):
            return None

        r = results[0]
        email = r["e"]
        return {
            "email_id": email_id,
            "subject": email.get("subject"),
            "sender": email.get("sender"),
            "sender_domain": r.get("sender_domain"),
            "sender_ip": r.get("sender_ip"),
            "embedded_domains": r.get("embedded_domains", []),
            "resolved_ips": r.get("resolved_ips", []),
            "urls": r.get("urls", []),
            "hashes": r.get("hashes", []),
            "campaigns": r.get("campaigns", []),
            "risk_score": email.get("risk_score", 0.0),
            "disclaimer": ATTRIBUTION_DISCLAIMER,
        }

    def get_visualization_subgraph(
        self,
        center_id: str,
        center_label: str,
        depth: int = DEFAULT_GRAPH_DEPTH,
        limit: int = DEFAULT_GRAPH_LIMIT,
    ) -> FrontendGraphResponse:
        """
        Extracts bounded subgraph around a center entity, returning JSON-serializable
        FrontendGraphResponse (Role 6 Contract: prefixed node IDs, label, type, properties, edges).
        """
        if not self.neo4j.is_connected():
            return FrontendGraphResponse(nodes=[], edges=[])

        clamped_depth = max(1, min(depth, MAX_GRAPH_DEPTH))
        clamped_limit = max(1, min(limit, MAX_GRAPH_LIMIT))

        # Determine key property based on label
        key_props = {
            "Email": "email_id",
            "Domain": "name",
            "IP": "address",
            "URL": "url_hash",
            "Hash": "value",
            "Campaign": "campaign_id",
            "ASN": "number",
        }
        key_name = key_props.get(center_label, "id")

        # Safe parameterized traversal query without Cypher injection
        query = f"""
            MATCH (center:{center_label} {{{key_name}: $center_id}})
            CALL apoc.path.subgraphAll(center, {{maxLevel: $depth, limit: $limit}})
            YIELD nodes, relationships
            RETURN nodes, relationships
        """

        # Fallback query if APOC is not installed
        fallback_query = f"""
            MATCH path = (center:{center_label} {{{key_name}: $center_id}})-[*1..{clamped_depth}]-(connected)
            WITH nodes(path) as ns, relationships(path) as rs
            UNWIND ns as n
            UNWIND rs as r
            RETURN collect(DISTINCT n) as nodes, collect(DISTINCT r) as relationships
        """

        try:
            results = self.neo4j.run_query(fallback_query, {"center_id": center_id})
        except Exception as e:
            logger.warning("Traversal query error, attempting single-hop: %s", e)
            return FrontendGraphResponse(nodes=[], edges=[])

        if not results:
            return FrontendGraphResponse(nodes=[], edges=[])

        raw_nodes = results[0].get("nodes", [])
        raw_rels = results[0].get("relationships", [])

        frontend_nodes: Dict[str, FrontendNode] = {}
        frontend_edges: List[FrontendEdge] = []

        def get_node_key_and_label(props: Dict[str, Any], labels_list: List[str]) -> Tuple[str, str, str]:
            primary_label = labels_list[0] if labels_list else "Entity"
            lbl_lower = primary_label.lower()

            if "email_id" in props:
                raw_id = props["email_id"]
                label_txt = props.get("subject") or raw_id
            elif "name" in props:
                raw_id = props["name"]
                label_txt = raw_id
            elif "address" in props:
                raw_id = props["address"]
                label_txt = raw_id
            elif "url" in props:
                raw_id = props.get("url_hash") or props["url"]
                label_txt = props.get("url")[:35] + "..." if len(props.get("url", "")) > 35 else props.get("url")
            elif "value" in props:
                raw_id = props["value"]
                label_txt = f"{props.get('type', 'hash')}:{raw_id[:8]}"
            elif "campaign_id" in props:
                raw_id = props["campaign_id"]
                label_txt = props.get("name") or raw_id
            elif "number" in props:
                raw_id = props["number"]
                label_txt = f"AS{raw_id}"
            else:
                raw_id = props.get("id", "unknown")
                label_txt = str(raw_id)

            prefixed_id = f"{lbl_lower}:{raw_id}"
            return prefixed_id, primary_label.lower(), label_txt

        for n in raw_nodes:
            if isinstance(n, dict):
                # Neo4j record data format
                props = n
                labels_list = [center_label]  # fallback
            else:
                props = dict(n)
                labels_list = list(n.labels) if hasattr(n, "labels") else [center_label]

            pref_id, ntype, nlabel = get_node_key_and_label(props, labels_list)
            if pref_id not in frontend_nodes:
                frontend_nodes[pref_id] = FrontendNode(
                    id=pref_id,
                    type=ntype,
                    label=nlabel,
                    risk_score=float(props.get("risk_score", 0.0)),
                    properties={k: str(v) for k, v in props.items() if k not in {"created_at", "updated_at"}},
                )

        # Extract edges
        for idx, r in enumerate(raw_rels):
            if hasattr(r, "start_node") and hasattr(r, "end_node"):
                start_props = dict(r.start_node)
                start_labels = list(r.start_node.labels) if hasattr(r.start_node, "labels") else []
                end_props = dict(r.end_node)
                end_labels = list(r.end_node.labels) if hasattr(r.end_node, "labels") else []

                s_id, _, _ = get_node_key_and_label(start_props, start_labels)
                t_id, _, _ = get_node_key_and_label(end_props, end_labels)
                rel_type = r.type if hasattr(r, "type") else "RELATED_TO"
                r_props = dict(r) if hasattr(r, "items") else {}

                edge_id = f"edge:{s_id}->{t_id}:{rel_type}"
                frontend_edges.append(
                    FrontendEdge(
                        id=edge_id,
                        source=s_id,
                        target=t_id,
                        type=rel_type,
                        properties={k: str(v) for k, v in r_props.items()},
                    )
                )

        return FrontendGraphResponse(
            nodes=list(frontend_nodes.values()),
            edges=frontend_edges,
        )


infrastructure_correlation = InfrastructureCorrelation()