"""
app/api/case_routes.py
Case management API endpoints.
SIH 26106 - IronPulse | Role 1
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from app.services.case_service import case_service

router = APIRouter()


@router.get("")
@router.get("/")
def list_cases(limit: int = Query(50, ge=1, le=200)):
    """List recent forensic investigation cases."""
    cases = case_service.list_cases(limit=limit)
    return {"status": "ok", "total": len(cases), "cases": cases}


@router.get("/{case_id}")
def get_case_details(case_id: str):
    """Retrieve full analysis dossier and graph for a case."""
    case = case_service.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return {"status": "ok", "case": case}


@router.get("/{case_id}/report")
def get_case_report(case_id: str):
    """Retrieve structured investigation report data for export."""
    case = case_service.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    
    data = case.get("data", {})
    return {
        "title": "Structured Forensic Investigation Report",
        "case_id": case_id,
        "filename": case.get("filename"),
        "sha256": case.get("sha256"),
        "created_at": case.get("created_at"),
        "verdict": case.get("verdict"),
        "risk_score": case.get("risk_score"),
        "risk_level": case.get("risk_level"),
        "primary_evidence": data.get("primary_evidence", []),
        "risk_breakdown": data.get("risk_breakdown", []),
        "recommended_actions": data.get("recommended_actions", []),
        "limitations": data.get("limitations", []),
        "forensics": data.get("forensics", {}),
        "threat_intel": data.get("threat_intel", {}),
        "timeline": data.get("timeline", []),
        "disclaimer": (
            "This report documents deterministic cryptographic and protocol observations. "
            "Attribution of physical location or perpetrator identity is probabilistic "
            "and does not constitute legal proof."
        ),
    }
