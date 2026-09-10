"""Build a portable investigation graph when Neo4j is not configured."""

from __future__ import annotations

from typing import Any

from Graph.graph_schema import NODE_TYPES


def build_graph(report: dict[str, Any]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    known_nodes: set[str] = set()

    def node(node_id: str, label: str, node_type: str, **properties: Any) -> None:
        if node_id in known_nodes:
            return
        known_nodes.add(node_id)
        nodes.append({"id": node_id, "label": label, "type": node_type, "properties": properties})

    def edge(source: str, target: str, relationship: str) -> None:
        edges.append({"id": f"{source}|{relationship}|{target}", "source": source, "target": target, "relationship": relationship})

    case_id = report["case"]["case_id"]
    email_id = report["case"]["email_id"]
    case_node = f"case:{case_id}"
    email_node = f"email:{email_id}"
    node(case_node, case_id, NODE_TYPES["CASE"], risk_level=report["verdict"]["risk_level"])
    node(email_node, report["email"].get("subject") or "Email", NODE_TYPES["EMAIL"])
    edge(case_node, email_node, "CONTAINS")

    for field, relationship, label in (("from", "SENT_FROM", "Sender"), ("reply_to", "REPLIES_TO", "ReplyTo")):
        address = report["email"].get(field)
        if address:
            address_node = f"address:{address.lower()}"
            node(address_node, address, NODE_TYPES["SENDER"] if label == "Sender" else NODE_TYPES["REPLY_TO"])
            edge(email_node, address_node, relationship)

    for item in report.get("urls", []):
        url = item.get("url")
        domain = item.get("domain")
        if not url:
            continue
        url_node = f"url:{url}"
        node(url_node, url, NODE_TYPES["URL"], classification=item.get("classification"))
        edge(email_node, url_node, "HAS_URL")
        if domain:
            domain_node = f"domain:{domain}"
            node(domain_node, domain, NODE_TYPES["DOMAIN"])
            edge(url_node, domain_node, "HOSTED_ON")

    for item in report.get("ip_analysis", []):
        ip = item.get("ip")
        if not ip:
            continue
        ip_node = f"ip:{ip}"
        node(ip_node, ip, NODE_TYPES["IP"], is_global=item.get("is_global"))
        edge(email_node, ip_node, "RECEIVED_BY")

    for hop in report.get("header_analysis", {}).get("relay_hops", []):
        hop_id = f"relay:{email_id}:{hop.get('header_order')}"
        node(hop_id, f"Relay hop {hop.get('header_order')}", NODE_TYPES["RELAY_HOP"], header_order=hop.get("header_order"))
        edge(email_node, hop_id, "TRAVERSED")
        for field, relationship in (("from_server", "RELAYED_FROM"), ("to_server", "RELAYED_TO")):
            server = hop.get(field)
            if server:
                server_id = f"mail-server:{str(server).lower()}"
                node(server_id, str(server), NODE_TYPES["MAIL_SERVER"])
                edge(hop_id, server_id, relationship)

    for item in report.get("geolocation", []):
        if item.get("status") not in {"available", "success"} or not item.get("ip"):
            continue
        label = ", ".join(part for part in (item.get("city"), item.get("region"), item.get("country")) if part) or "Approximate network location"
        geo_id = f"geolocation:{item['ip']}"
        node(geo_id, label, NODE_TYPES["GEOLOCATION"], ip=item["ip"], asn=item.get("asn"), isp=item.get("isp"))
        edge(f"ip:{item['ip']}", geo_id, "HAS_GEOLOCATION")

    for item in report.get("threat_intelligence", {}).get("results", []):
        source, indicator = item.get("source"), item.get("indicator")
        if not source or not indicator:
            continue
        intelligence_id = f"threat-intel:{source}:{indicator}"
        node(intelligence_id, str(source), NODE_TYPES["THREAT_INTEL"], status=item.get("status"), malicious=item.get("malicious", False))
        url_id, ip_id = f"url:{indicator}", f"ip:{indicator}"
        if url_id in known_nodes:
            edge(url_id, intelligence_id, "ENRICHED_BY")
        elif ip_id in known_nodes:
            edge(ip_id, intelligence_id, "ENRICHED_BY")

    for attachment in report.get("attachments", []):
        attachment_id = attachment.get("sha256") or attachment.get("filename")
        if attachment_id:
            node(f"attachment:{attachment_id}", attachment.get("filename") or "Unnamed attachment", NODE_TYPES["ATTACHMENT"])
            edge(email_node, f"attachment:{attachment_id}", "HAS_ATTACHMENT")

    correlation = report.get("campaign_correlation", {})
    cluster_id = correlation.get("campaign_id")
    if cluster_id:
        cluster_node = f"campaign:{cluster_id}"
        node(cluster_node, cluster_id, NODE_TYPES["CAMPAIGN_CLUSTER"], related_cases=correlation.get("related_case_ids", []))
        edge(case_node, cluster_node, "PART_OF_CAMPAIGN")

    return {
        "storage": "generated_json_fallback",
        "neo4j_status": "not_configured",
        "nodes": nodes,
        "edges": edges,
    }
