import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from app.api.deps import verify_api_key, success_response
from app.services.infrastructure_correlation import infrastructure_correlation
from app.config import DEFAULT_GRAPH_LIMIT, MAX_GRAPH_LIMIT

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/infrastructure", tags=["Infrastructure Correlation & Pivots"])


@router.get("/clusters")
async def get_infrastructure_clusters(
    limit: int = Query(20, ge=1, le=MAX_GRAPH_LIMIT),
    _: str = Depends(verify_api_key),
):
    """
    Identifies shared hosting infrastructure clusters (IPs hosting multiple suspicious domains or emails).
    Reveals shared adversary infrastructure without making physical location attribution claims.
    """
    clusters = infrastructure_correlation.find_infrastructure_clusters(limit)
    return success_response(clusters)


@router.get("/ip/{ip_address}")
async def analyze_ip_infrastructure(
    ip_address: str, _: str = Depends(verify_api_key)
):
    """
    Performs IP infrastructure pivot: returns associated domains, emails, campaigns, ASN,
    correlation strength, and evidence reasons.
    """
    analysis = infrastructure_correlation.analyze_ip(ip_address)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address '{ip_address}' not found in the threat graph",
        )
    return success_response(analysis)


@router.get("/domain/{domain}")
async def analyze_domain_infrastructure(
    domain: str, _: str = Depends(verify_api_key)
):
    """
    Performs Domain infrastructure pivot: returns resolving IPs, hosted URLs, emails,
    associated campaigns, and correlation strength.
    """
    analysis = infrastructure_correlation.analyze_domain(domain)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{domain}' not found in the threat graph",
        )
    return success_response(analysis)


@router.get("/asn/{asn}")
async def analyze_asn_infrastructure(
    asn: str, _: str = Depends(verify_api_key)
):
    """Performs ASN infrastructure pivot: returns associated IPs, domains, and campaigns."""
    analysis = infrastructure_correlation.analyze_asn(asn)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ASN '{asn}' not found in the threat graph",
        )
    return success_response(analysis)
