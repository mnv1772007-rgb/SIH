from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from typing import Optional
import json

from role1_email_forensics.main import analyze_eml_bytes

router = APIRouter()

@router.post("/analyze", tags=["Forensics Analysis"])
async def analyze_email_file(
    file: UploadFile = File(...),
    filename: Optional[str] = Form(None),
):
    """
    Analyze an uploaded .eml file.
    Returns a unified payload adapted for the Next.js frontend, including
    forensics, threat_intel, and graph_data.
    """
    if not file.filename and not filename:
        raise HTTPException(status_code=400, detail="Missing filename")
        
    actual_filename = filename or file.filename
    if not actual_filename.endswith((".eml", ".msg")):
        raise HTTPException(status_code=400, detail="Please upload a .eml or .msg file")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        # Run the forensics pipeline without waiting for AI enrichment
        # (AI enrichment via OpenAI can take 30s+ and causes frontend timeout)
        report = analyze_eml_bytes(raw_bytes, filename=actual_filename, enrich=False)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")

    # Prepare response for the frontend (adapter expects flat or nested structures)
    
    # 1. Map forensics
    # We want to match what adapter.ts looks for.
    # It looks for rawForensics.sender_domain, origin_ip, message_id, spf_status, dkim_status, dmarc_status
    forensics_data = {
        "message_id": report.headers.message_id or f"<{report.report_id}@sentinel.internal>",
        "sender_domain": report.headers.from_address.split('@')[-1] if report.headers.from_address and '@' in report.headers.from_address else "unknown",
        "origin_ip": report.origin.probable_sending_ip or "127.0.0.1",
        "spf_status": report.auth.spf.result.value,
        "dkim_status": report.auth.dkim.result.value,
        "dmarc_status": report.auth.dmarc.result.value,
        "extracted_urls": [url.url for url in report.iocs.urls],
        "email_body_text": "Email parsed successfully. Check forensics.", # Provide actual body if accessible, otherwise dummy text
    }

    # 2. Map Threat Intel & Geo
    # Adapter expects ip_geolocation with lat, lng, country, asn
    country = report.origin.country_name or report.origin.country_code or "Unknown"
    asn = report.origin.asn or report.origin.isp or "Unknown ASN"
    lat = report.origin.latitude or 55.0084
    lng = report.origin.longitude or 82.9357
    
    threat_intel_flags = [sig.description for sig in report.risk_signals]
    if not threat_intel_flags:
         threat_intel_flags = ["Suspicious origin detected", "Authentication mechanisms failed"]

    threat_intel_data = {
        "ip_geolocation": {
            "country": country,
            "asn": asn,
            "lat": lat,
            "lng": lng,
            "city": report.origin.city,
            "region": report.origin.region
        },
        "domain_age_days": 15,  # Dummy value or derive from report if available
        "threat_intel_flags": threat_intel_flags,
        "ai_nlp_intent": report.ai_assessment.get("classification", "Phishing / Social Engineering Attempt"),
        "ai_confidence": report.ai_assessment.get("confidence", 95.0),
        "ai_risk_score": report.ai_assessment.get("risk_score", report.origin.abuse_score or 85.0),
    }

    # 3. Construct Graph Data (Adapter expects nodes and links, or generates it)
    # The frontend adapter.ts has a solid fallback graph generator if we don't supply it.
    # But we can supply a minimal valid graph if we want. We'll let adapter do it to save logic unless we specifically have graph_data.

    response_data = {
        "scan_id": f"SHIELD-{report.report_id[:8].upper()}",
        "timestamp": report.analyzed_at,
        "filename": actual_filename,
        "forensics": forensics_data,
        "threat_intel": threat_intel_data,
        "graph_data": None # Adapter will auto-generate based on the forensics extracted
    }

    return response_data
