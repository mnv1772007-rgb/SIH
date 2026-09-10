import logging
from typing import Optional, List, Dict, Any, Tuple
from neo4j import GraphDatabase, Driver
from app.config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

logger = logging.getLogger(__name__)

# Strict allowlists preventing Cypher label or relationship type injection
VALID_LABELS = {"Email", "Domain", "IP", "URL", "Hash", "Campaign", "ASN"}
VALID_REL_TYPES = {
    "SENT_FROM",
    "CONTAINS_DOMAIN",
    "CONTAINS_URL",
    "HOSTED_ON_DOMAIN",
    "RESOLVES_TO",
    "BELONGS_TO_ASN",
    "CONTAINS_HASH",
    "MEMBER_OF",
    "USES_DOMAIN",
    "USES_IP",
    "USES_URL",
    "USES_HASH",
    "SAME_INFRASTRUCTURE",
}


class Neo4jService:
    def __init__(self):
        self.driver: Optional[Driver] = None
        self.connected: bool = False

    def connect(self) -> bool:
        try:
            self.driver = GraphDatabase.driver(
                NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)
            )
            # Verify connectivity
            self.driver.verify_connectivity()
            self.connected = True
            logger.info("Successfully connected to Neo4j at %s", NEO4J_URI)
            self.init_schema()
            return True
        except Exception as e:
            self.connected = False
            logger.warning("Neo4j connection failed (%s). Operating in degraded/offline mode.", e)
            return False

    def close(self):
        if self.driver:
            try:
                self.driver.close()
            except Exception:
                pass
            self.connected = False
            logger.info("Neo4j connection closed")

    def is_connected(self) -> bool:
        return self.connected and self.driver is not None

    def run_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if not self.is_connected():
            logger.warning("Query attempted while Neo4j is not connected: %s", query[:60])
            return []
        try:
            with self.driver.session() as session:
                result = session.run(query, parameters or {})
                return [record.data() for record in result]
        except Exception as e:
            logger.error("Neo4j query execution error: %s | Query: %s", e, query[:100])
            raise

    def init_schema(self):
        """Idempotently creates uniqueness constraints and indexes on startup."""
        if not self.is_connected():
            return

        constraints = [
            "CREATE CONSTRAINT email_id_unique IF NOT EXISTS FOR (e:Email) REQUIRE e.email_id IS UNIQUE",
            "CREATE CONSTRAINT domain_name_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
            "CREATE CONSTRAINT ip_address_unique IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
            "CREATE CONSTRAINT url_hash_unique IF NOT EXISTS FOR (u:URL) REQUIRE u.url_hash IS UNIQUE",
            "CREATE CONSTRAINT hash_value_unique IF NOT EXISTS FOR (h:Hash) REQUIRE h.value IS UNIQUE",
            "CREATE CONSTRAINT campaign_id_unique IF NOT EXISTS FOR (c:Campaign) REQUIRE c.campaign_id IS UNIQUE",
            "CREATE CONSTRAINT asn_number_unique IF NOT EXISTS FOR (a:ASN) REQUIRE a.number IS UNIQUE",
        ]

        indexes = [
            "CREATE INDEX email_timestamp_idx IF NOT EXISTS FOR (e:Email) ON (e.timestamp)",
            "CREATE INDEX email_risk_score_idx IF NOT EXISTS FOR (e:Email) ON (e.risk_score)",
            "CREATE INDEX domain_risk_score_idx IF NOT EXISTS FOR (d:Domain) ON (d.risk_score)",
            "CREATE INDEX ip_risk_score_idx IF NOT EXISTS FOR (i:IP) ON (i.risk_score)",
            "CREATE INDEX campaign_confidence_idx IF NOT EXISTS FOR (c:Campaign) ON (c.confidence)",
        ]

        try:
            with self.driver.session() as session:
                for c in constraints:
                    session.run(c)
                for idx in indexes:
                    session.run(idx)
            logger.info("Neo4j schema constraints and indexes verified")
        except Exception as e:
            logger.warning("Could not initialize Neo4j schema constraints: %s", e)

    def merge_node(
        self, label: str, key: str, value: Any, properties: Optional[Dict[str, Any]] = None
    ) -> Tuple[Dict[str, Any], bool]:
        """
        Merges a node idempotently.
        Returns: (node_dict, was_created)
        """
        if label not in VALID_LABELS:
            raise ValueError(f"Invalid node label: '{label}'")

        # Parameterized safe Cypher execution
        query = f"""
            MERGE (n:{label} {{{key}: $value}})
            ON CREATE SET n += $props, n.created_at = datetime()
            ON MATCH SET n += $props, n.updated_at = datetime()
            RETURN n, (n.created_at = n.updated_at OR n.updated_at IS NULL) as was_created
        """
        params = {"value": value, "props": properties or {}}
        results = self.run_query(query, params)
        if results:
            return results[0].get("n", {}), bool(results[0].get("was_created", False))
        return {}, False

    def merge_relationship(
        self,
        source_label: str,
        source_key: str,
        source_val: Any,
        target_label: str,
        target_key: str,
        target_val: Any,
        rel_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, bool]:
        """
        Merges a directed relationship idempotently.
        Returns: (success, was_created)
        """
        if source_label not in VALID_LABELS or target_label not in VALID_LABELS:
            raise ValueError(f"Invalid node labels: '{source_label}', '{target_label}'")
        if rel_type not in VALID_REL_TYPES:
            raise ValueError(f"Invalid relationship type: '{rel_type}'")

        query = f"""
            MATCH (a:{source_label} {{{source_key}: $source_val}})
            MATCH (b:{target_label} {{{target_key}: $target_val}})
            MERGE (a)-[r:{rel_type}]->(b)
            ON CREATE SET r += $props, r.created_at = datetime()
            ON MATCH SET r += $props, r.updated_at = datetime()
            RETURN type(r) as rel_type, (r.created_at = r.updated_at OR r.updated_at IS NULL) as was_created
        """
        params = {
            "source_val": source_val,
            "target_val": target_val,
            "props": properties or {},
        }
        results = self.run_query(query, params)
        if results:
            return True, bool(results[0].get("was_created", False))
        return False, False

    def find_node(self, label: str, key: str, value: Any) -> Optional[Dict[str, Any]]:
        if label not in VALID_LABELS:
            raise ValueError(f"Invalid node label: '{label}'")
        query = f"MATCH (n:{label} {{{key}: $value}}) RETURN n LIMIT 1"
        results = self.run_query(query, {"value": value})
        return results[0].get("n") if results else None

    def get_graph_stats(self) -> Dict[str, Any]:
        """Returns total counts and breakdown in a fast, aggregated single query."""
        if not self.is_connected():
            return {
                "total_nodes": 0,
                "total_relationships": 0,
                "nodes_by_type": {lbl: 0 for lbl in VALID_LABELS},
                "relationships_by_type": {rel: 0 for rel in VALID_REL_TYPES},
                "status": "offline",
            }

        stats = {
            "total_nodes": 0,
            "total_relationships": 0,
            "nodes_by_type": {lbl: 0 for lbl in VALID_LABELS},
            "relationships_by_type": {rel: 0 for rel in VALID_REL_TYPES},
        }

        try:
            node_query = """
                MATCH (n)
                RETURN labels(n)[0] as label, count(n) as count
            """
            for row in self.run_query(node_query):
                lbl = row.get("label")
                cnt = row.get("count", 0)
                if lbl in stats["nodes_by_type"]:
                    stats["nodes_by_type"][lbl] = cnt
                    stats["total_nodes"] += cnt

            rel_query = """
                MATCH ()-[r]->()
                RETURN type(r) as rel_type, count(r) as count
            """
            for row in self.run_query(rel_query):
                rt = row.get("rel_type")
                cnt = row.get("count", 0)
                if rt in stats["relationships_by_type"]:
                    stats["relationships_by_type"][rt] = cnt
                    stats["total_relationships"] += cnt

        except Exception as e:
            logger.error("Error retrieving graph stats: %s", e)

        return stats

    def delete_all(self, confirm: bool = False) -> bool:
        """Safe dev/demo-only graph reset with explicit confirmation guard."""
        if not confirm:
            raise ValueError("Destructive clear requested without explicit confirmation flag confirm=True.")
        if not self.is_connected():
            return False
        self.run_query("MATCH (n) DETACH DELETE n")
        logger.warning("Graph database reset: all nodes and relationships deleted.")
        return True


neo4j_service = Neo4jService()