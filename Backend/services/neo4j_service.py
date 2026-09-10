"""Optional, parameterized Neo4j persistence for the portable case graph."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any


@lru_cache(maxsize=1)
def _driver() -> Any | None:
    if os.getenv("NEO4J_ENABLED", "false").lower() != "true":
        return None
    uri = os.getenv("NEO4J_URI")
    if not uri:
        return None
    try:
        from neo4j import GraphDatabase

        return GraphDatabase.driver(
            uri,
            auth=(os.getenv("NEO4J_USERNAME", "neo4j"), os.getenv("NEO4J_PASSWORD", "")),
            connection_timeout=5,
        )
    except Exception:
        return None


def persist_graph(graph: dict[str, Any]) -> str:
    """Persist graph entities when configured; retain the JSON graph on failure."""
    driver = _driver()
    if driver is None:
        if os.getenv("NEO4J_ENABLED", "false").lower() != "true":
            return "disabled"
        return "not_configured" if not os.getenv("NEO4J_URI") else "unavailable"
    try:
        with driver.session() as session:
            for node in graph.get("nodes", []):
                session.run(
                    "MERGE (n:ForensicEntity {id: $id}) "
                    "SET n.label = $label, n.node_type = $node_type, n.properties = $properties",
                    id=node["id"], label=node.get("label"), node_type=node.get("type"), properties=node.get("properties", {}),
                )
            allowed_relationships = {
                "CONTAINS", "SENT_FROM", "REPLIES_TO", "HAS_URL", "HOSTED_ON", "RECEIVED_BY", "HAS_ATTACHMENT",
                "PART_OF_CAMPAIGN", "TRAVERSED", "RELAYED_FROM", "RELAYED_TO", "HAS_GEOLOCATION", "ENRICHED_BY",
            }
            for edge in graph.get("edges", []):
                relationship = str(edge.get("relationship"))
                if relationship not in allowed_relationships:
                    continue
                session.run(
                    f"MATCH (source:ForensicEntity {{id: $source}}), (target:ForensicEntity {{id: $target}}) "
                    f"MERGE (source)-[r:{relationship} {{id: $id}}]->(target)",
                    source=edge["source"], target=edge["target"], id=edge["id"],
                )
        return "stored"
    except Exception:
        return "unavailable"
