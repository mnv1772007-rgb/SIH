import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from app.api.deps import verify_api_key, success_response, error_response
from app.services.neo4j_service import neo4j_service
from app.services.graph_builder import graph_builder
from app.services.infrastructure_correlation import infrastructure_correlation
from app.models.integration_contract import EmailAnalysisIngestPayload
from app.config import DEFAULT_GRAPH_DEPTH, MAX_GRAPH_DEPTH, DEFAULT_GRAPH_LIMIT, MAX_GRAPH_LIMIT

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["Graph & Ingestion"])


@router.get("/stats")
async def get_stats(_: str = Depends(verify_api_key)):
    """Retrieves high-level Neo4j graph entity and relationship counts."""
    stats = neo4j_service.get_graph_stats()
    return success_response(stats)


@router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_analysis(
    payload: EmailAnalysisIngestPayload, _: str = Depends(verify_api_key)
):
    """
    Idempotently ingests normalized email threat intelligence into the forensic knowledge graph.
    Connects Email -> Domain -> IP -> URL -> Hash -> ASN entities.
    """
    try:
        result = graph_builder.build_from_email_analysis(payload)
        return success_response(result.model_dump())
    except Exception as e:
        logger.error("Ingestion failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to ingest threat intelligence payload: {str(e)}",
        )


@router.get("/email/{email_id}/path")
async def get_email_path(email_id: str, _: str = Depends(verify_api_key)):
    """Traces full sender and embedded infrastructure path for an analyzed email."""
    path = infrastructure_correlation.trace_email_path(email_id)
    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email '{email_id}' was not found in the threat graph",
        )
    return success_response(path)


@router.get("/path")
async def query_email_path(email_id: str = Query(...), _: str = Depends(verify_api_key)):
    """Alternative query parameter path tracer: /api/v1/graph/path?email_id=..."""
    path = infrastructure_correlation.trace_email_path(email_id)
    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email '{email_id}' was not found in the threat graph",
        )
    return success_response(path)


@router.get("/email/{email_id}")
async def get_email_subgraph(
    email_id: str,
    depth: int = Query(DEFAULT_GRAPH_DEPTH, ge=1, le=MAX_GRAPH_DEPTH),
    limit: int = Query(DEFAULT_GRAPH_LIMIT, ge=1, le=MAX_GRAPH_LIMIT),
    _: str = Depends(verify_api_key),
):
    """Returns frontend-compatible visualization subgraph centered on an Email node."""
    subgraph = infrastructure_correlation.get_visualization_subgraph(
        email_id, "Email", depth, limit
    )
    if not subgraph.nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email entity '{email_id}' not found",
        )
    return success_response(subgraph.model_dump())


@router.get("/domain/{domain}")
async def get_domain_subgraph(
    domain: str,
    depth: int = Query(DEFAULT_GRAPH_DEPTH, ge=1, le=MAX_GRAPH_DEPTH),
    limit: int = Query(DEFAULT_GRAPH_LIMIT, ge=1, le=MAX_GRAPH_LIMIT),
    _: str = Depends(verify_api_key),
):
    """Returns frontend-compatible visualization subgraph centered on a Domain node."""
    subgraph = infrastructure_correlation.get_visualization_subgraph(
        domain, "Domain", depth, limit
    )
    if not subgraph.nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain entity '{domain}' not found",
        )
    return success_response(subgraph.model_dump())


@router.get("/ip/{ip_address}")
async def get_ip_subgraph(
    ip_address: str,
    depth: int = Query(DEFAULT_GRAPH_DEPTH, ge=1, le=MAX_GRAPH_DEPTH),
    limit: int = Query(DEFAULT_GRAPH_LIMIT, ge=1, le=MAX_GRAPH_LIMIT),
    _: str = Depends(verify_api_key),
):
    """Returns frontend-compatible visualization subgraph centered on an IP node."""
    subgraph = infrastructure_correlation.get_visualization_subgraph(
        ip_address, "IP", depth, limit
    )
    if not subgraph.nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP entity '{ip_address}' not found",
        )
    return success_response(subgraph.model_dump())


@router.get("/hash/{hash_value}")
async def get_hash_subgraph(
    hash_value: str,
    depth: int = Query(DEFAULT_GRAPH_DEPTH, ge=1, le=MAX_GRAPH_DEPTH),
    limit: int = Query(DEFAULT_GRAPH_LIMIT, ge=1, le=MAX_GRAPH_LIMIT),
    _: str = Depends(verify_api_key),
):
    """Returns frontend-compatible visualization subgraph centered on a Hash node."""
    subgraph = infrastructure_correlation.get_visualization_subgraph(
        hash_value, "Hash", depth, limit
    )
    if not subgraph.nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Hash entity '{hash_value}' not found",
        )
    return success_response(subgraph.model_dump())


@router.get("/all")
async def get_all_graph(
    limit: int = Query(50, ge=1, le=MAX_GRAPH_LIMIT),
    skip: int = Query(0, ge=0),
    _: str = Depends(verify_api_key),
):
    """Bounded retrieval of the global threat graph for initial frontend canvas rendering."""
    if not neo4j_service.is_connected():
        return success_response({"nodes": [], "edges": []})

    query = """
        MATCH (n)
        WITH n SKIP $skip LIMIT $limit
        OPTIONAL MATCH (n)-[r]->(m)
        RETURN collect(DISTINCT n) as nodes, collect(DISTINCT r) as relationships
    """
    results = neo4j_service.run_query(query, {"skip": skip, "limit": limit})
    if not results:
        return success_response({"nodes": [], "edges": []})

    from app.services.infrastructure_correlation import make_prefixed_id
    from app.models.graph_models import FrontendNode, FrontendEdge

    nodes = []
    edges = []
    for n in results[0].get("nodes", []):
        props = dict(n) if hasattr(n, "items") else n
        lbl = list(n.labels)[0] if hasattr(n, "labels") and n.labels else "Entity"
        key_id = props.get("email_id") or props.get("name") or props.get("address") or props.get("value") or props.get("url_hash") or props.get("campaign_id") or "unknown"
        pref_id = f"{lbl.lower()}:{key_id}"
        nodes.append({
            "id": pref_id,
            "type": lbl.lower(),
            "label": props.get("subject") or props.get("name") or props.get("address") or key_id,
            "risk_score": float(props.get("risk_score", 0.0)),
            "properties": {k: str(v) for k, v in props.items()},
        })

    for r in results[0].get("relationships", []):
        if hasattr(r, "start_node") and hasattr(r, "end_node"):
            s_props = dict(r.start_node)
            s_lbl = list(r.start_node.labels)[0] if hasattr(r.start_node, "labels") else "Entity"
            s_key = s_props.get("email_id") or s_props.get("name") or s_props.get("address") or s_props.get("value") or s_props.get("url_hash") or s_props.get("campaign_id") or "unknown"

            t_props = dict(r.end_node)
            t_lbl = list(r.end_node.labels)[0] if hasattr(r.end_node, "labels") else "Entity"
            t_key = t_props.get("email_id") or t_props.get("name") or t_props.get("address") or t_props.get("value") or t_props.get("url_hash") or t_props.get("campaign_id") or "unknown"

            edges.append({
                "id": f"edge:{s_lbl.lower()}:{s_key}->{t_lbl.lower()}:{t_key}:{r.type}",
                "source": f"{s_lbl.lower()}:{s_key}",
                "target": f"{t_lbl.lower()}:{t_key}",
                "type": r.type,
                "properties": {},
            })

    return success_response({"nodes": nodes, "edges": edges})


@router.delete("/all")
async def clear_graph(
    confirm: bool = Query(False, description="Must be explicitly set to true"),
    _: str = Depends(verify_api_key),
):
    """Dev/Demo utility to reset graph database. Requires confirm=true."""
    if not confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Safety guard: You must specify ?confirm=true to clear the graph.",
        )
    neo4j_service.delete_all(confirm=True)
    return success_response({"status": "cleared", "message": "Graph successfully cleared."})
