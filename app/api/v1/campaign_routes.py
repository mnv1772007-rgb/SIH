import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from app.api.deps import verify_api_key, success_response
from app.services.campaign_clustering import campaign_clustering
from app.services.confidence_analyzer import confidence_analyzer
from app.services.infrastructure_correlation import infrastructure_correlation
from app.config import DEFAULT_GRAPH_DEPTH, MAX_GRAPH_DEPTH, DEFAULT_GRAPH_LIMIT, MAX_GRAPH_LIMIT

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/campaigns", tags=["Campaign Correlation & Attribution"])


class ClusterRequest(BaseModel):
    similarity_threshold: float = 0.45
    min_cluster_size: int = 2
    email_ids: Optional[List[str]] = None


@router.post("/cluster")
async def trigger_clustering(
    request: Optional[ClusterRequest] = None,
    similarity_threshold: Optional[float] = Query(None),
    _: str = Depends(verify_api_key),
):
    """
    Executes explainable multi-feature campaign clustering.
    Evaluates IOC overlap, infrastructure linkage, subject similarity, and temporal proximity.
    """
    threshold = request.similarity_threshold if request else (similarity_threshold or 0.45)
    min_size = request.min_cluster_size if request else 2
    email_ids = request.email_ids if request else None

    campaigns = campaign_clustering.cluster_campaigns(
        similarity_threshold=threshold,
        min_cluster_size=min_size,
        email_ids=email_ids,
    )
    return success_response(campaigns)


@router.get("")
async def list_campaigns(_: str = Depends(verify_api_key)):
    """Lists all discovered threat campaigns ordered by confidence and recency."""
    campaigns = campaign_clustering.list_all_campaigns()
    return success_response(campaigns)


@router.get("/{campaign_id}/confidence")
async def get_campaign_confidence(campaign_id: str, _: str = Depends(verify_api_key)):
    """
    Returns explainable attribution confidence score and factor breakdown.
    Reports operational linkage only; strictly disclaims physical attacker attribution.
    """
    confidence = confidence_analyzer.calculate_attribution_confidence(campaign_id)
    if not confidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign '{campaign_id}' not found",
        )
    return success_response(confidence.model_dump())


@router.get("/{campaign_id}/report")
async def get_campaign_report(campaign_id: str, _: str = Depends(verify_api_key)):
    """Generates complete forensic campaign intelligence report."""
    report = confidence_analyzer.get_full_report(campaign_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign '{campaign_id}' not found",
        )
    return success_response(report)


@router.get("/{campaign_id}/graph")
async def get_campaign_graph(
    campaign_id: str,
    depth: int = Query(DEFAULT_GRAPH_DEPTH, ge=1, le=MAX_GRAPH_DEPTH),
    limit: int = Query(DEFAULT_GRAPH_LIMIT, ge=1, le=MAX_GRAPH_LIMIT),
    _: str = Depends(verify_api_key),
):
    """Returns frontend graph visualization data for the campaign."""
    subgraph = infrastructure_correlation.get_visualization_subgraph(
        campaign_id, "Campaign", depth, limit
    )
    if not subgraph.nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign entity '{campaign_id}' not found",
        )
    return success_response(subgraph.model_dump())


@router.get("/{campaign_id}")
async def get_campaign_details(campaign_id: str, _: str = Depends(verify_api_key)):
    """Retrieves specific campaign details and shared IOC inventory."""
    details = campaign_clustering.get_campaign_details(campaign_id)
    if not details:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign '{campaign_id}' not found",
        )
    return success_response(details)
