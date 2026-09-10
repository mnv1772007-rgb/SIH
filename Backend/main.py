"""Unified FastAPI application for the Email Threat Forensics dashboard."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = PROJECT_ROOT / "Frontend"
SAMPLES_DIR = PROJECT_ROOT / "samples"
DATA_DIR = Path(__file__).resolve().parent / "data"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

from .api.schemas import (
    RawEmailRequest,
    ReportExportRequest,
    ThreatIntelBatchRequest,
    ThreatIntelLookupRequest,
)
from .services.analysis_service import AnalysisError, AnalysisService
from .services.case_store import CaseStore
from .services.report_service import build_html_report, build_markdown_report
from threat_intel import get_threat_intel_service



case_store = CaseStore(DATA_DIR / "cases.sqlite3")
analysis_service = AnalysisService(PROJECT_ROOT, case_store)
app = FastAPI(
    title="Email Threat Forensics",
    version="2.0.0",
    description="Evidence-based static analysis of RFC822 email messages.",
)
app.add_middleware(
    CORSMiddleware,
    # The dashboard is served by this application.  Localhost origins are kept
    # for API tooling, but file:// pages are intentionally not API clients.
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(AnalysisError)
async def analysis_error_handler(_: Any, error: AnalysisError) -> Any:
    return PlainTextResponse(str(error), status_code=422)


def _safe_source_name(value: str | None) -> str:
    name = Path(value or "raw-email.eml").name.strip()
    return name[:255] or "raw-email.eml"


def _report_or_404(case_id: str) -> dict[str, Any]:
    report = case_store.get(case_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return report


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy", "service": "email-threat-forensics", "version": "2.0.0"}


@app.get("/api/sample")
def load_sample() -> dict[str, str]:
    sample_path = SAMPLES_DIR / "sample.eml"
    if not sample_path.is_file():
        raise HTTPException(status_code=503, detail="The bundled sample email is unavailable.")
    return {"source_name": sample_path.name, "raw_email": sample_path.read_text(encoding="utf-8")}


@app.get("/api/samples")
def list_samples() -> dict[str, Any]:
    """List bundled RFC822 samples without returning their content."""
    samples = [
        {"name": path.name, "size_bytes": path.stat().st_size}
        for path in sorted(SAMPLES_DIR.glob("*.eml"))
    ]
    return {"samples": samples, "default": "sample.eml" if any(item["name"] == "sample.eml" for item in samples) else None}


@app.post("/api/analyze")
async def analyze_upload(file: UploadFile = File(...)) -> dict[str, Any]:
    source_name = _safe_source_name(file.filename)
    if not source_name.lower().endswith(".eml"):
        raise HTTPException(status_code=422, detail="Only RFC822 .eml files are accepted.")
    return analysis_service.analyze(await file.read(), source_name)


@app.post("/api/analyze/raw")
def analyze_raw(payload: RawEmailRequest) -> dict[str, Any]:
    return analysis_service.analyze(payload.raw_email.encode("utf-8"), _safe_source_name(payload.source_name))


@app.get("/api/cases")
def list_cases(
    query: str | None = Query(default=None, max_length=255),
    risk_level: str | None = Query(default=None, pattern="^(LOW|GUARDED|MEDIUM|HIGH|CRITICAL)$"),
) -> dict[str, Any]:
    return {"cases": case_store.list(query=query, risk_level=risk_level)}


@app.get("/api/cases/compare")
def compare_cases(case_ids: list[str] = Query(min_length=2, max_length=8)) -> dict[str, Any]:
    """Compare stored cases using concrete shared evidence, never attribution."""
    reports = [_report_or_404(case_id) for case_id in dict.fromkeys(case_ids)]

    def indicators(report: dict[str, Any]) -> set[str]:
        values = {
            f"domain:{item['domain']}" for item in report.get("urls", []) if item.get("domain")
        }
        values.update(f"url:{item['normalized_url'] or item['url']}" for item in report.get("urls", []) if item.get("url"))
        values.update(f"ip:{item['ip']}" for item in report.get("ip_analysis", []) if item.get("ip"))
        values.update(f"attachment:{item['sha256']}" for item in report.get("attachments", []) if item.get("sha256"))
        for field in ("from_address", "reply_to"):
            if report.get("email", {}).get(field):
                values.add(f"address:{str(report['email'][field]).lower()}")
        return values

    evidence = {report["case"]["case_id"]: indicators(report) for report in reports}
    shared = sorted(set.intersection(*evidence.values())) if evidence else []
    return {
        "case_ids": list(evidence),
        "shared_indicators": shared,
        "case_indicators": {case_id: sorted(values) for case_id, values in evidence.items()},
        "note": "Shared indicators show association for analyst review; they do not establish attribution.",
    }


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    return _report_or_404(case_id)


@app.delete("/api/cases/{case_id}")
def delete_case(case_id: str) -> dict[str, str]:
    if not case_store.delete(case_id):
        raise HTTPException(status_code=404, detail="Case not found.")
    return {"status": "deleted", "case_id": case_id}


@app.get("/api/reports/{case_id}", response_class=PlainTextResponse)
def export_report(case_id: str) -> PlainTextResponse:
    report = _report_or_404(case_id)
    return PlainTextResponse(
        build_markdown_report(report),
        headers={"Content-Disposition": f'attachment; filename="{case_id}.md"'},
    )


@app.post("/api/reports/{case_id}/export")
def export_report_format(case_id: str, payload: ReportExportRequest) -> Any:
    """Create a report response on demand without writing generated files."""
    report = _report_or_404(case_id)
    filename_root = case_id.replace('"', "")
    if payload.format == "json":
        return JSONResponse(
            report,
            headers={"Content-Disposition": f'attachment; filename="{filename_root}.json"'},
        )
    if payload.format == "html":
        return HTMLResponse(
            build_html_report(report),
            headers={"Content-Disposition": f'attachment; filename="{filename_root}.html"'},
        )
    return PlainTextResponse(
        build_markdown_report(report),
        headers={"Content-Disposition": f'attachment; filename="{filename_root}.md"'},
    )


@app.get("/api/graph/campaigns")
def campaign_graph() -> dict[str, Any]:
    reports = case_store.all_reports()
    campaigns = [report["campaign_correlation"] for report in reports if report.get("campaign_correlation", {}).get("campaign_id")]
    return {"campaigns": campaigns, "total_cases": len(reports)}


@app.get("/api/campaigns")
def campaigns() -> dict[str, Any]:
    """Compatibility-friendly campaign collection endpoint."""
    return campaign_graph()


@app.get("/api/graph/{case_id}")
def get_graph(case_id: str) -> dict[str, Any]:
    return _report_or_404(case_id).get("graph", {"nodes": [], "edges": []})


@app.get("/api/dashboard/stats")
def dashboard_stats() -> dict[str, Any]:
    return case_store.stats()


@app.get("/api/threat-intel/{indicator}")
def indicator_history(indicator: str) -> dict[str, Any]:
    """Return previously recorded local evidence; this does not fetch an indicator."""
    needle, matches = indicator.strip().lower(), []
    for report in case_store.all_reports():
        for url in report.get("urls", []):
            if needle in {str(url.get("url", "")).lower(), str(url.get("domain", "")).lower()}:
                matches.append({"case_id": report["case"]["case_id"], "type": "url", "classification": url.get("classification")})
        for ip in report.get("ip_analysis", []):
            if needle == str(ip.get("ip", "")).lower():
                matches.append({"case_id": report["case"]["case_id"], "type": "ip", "is_global": ip.get("is_global")})
    return {"indicator": indicator, "matches": matches, "note": "Local case-history lookup only; it does not fetch or visit the indicator."}


@app.post("/api/threat-intel/lookup")
def live_indicator_lookup(request: ThreatIntelLookupRequest) -> dict[str, Any]:
    """Perform normalized, multi-provider threat intelligence enrichment."""
    ti_service = get_threat_intel_service()
    return ti_service.lookup_ioc(
        value=request.indicator,
        ioc_type=request.ioc_type,
        force_refresh=request.force_refresh,
    )


@app.post("/api/threat-intel/batch")
def batch_indicator_lookup(request: ThreatIntelBatchRequest) -> dict[str, Any]:
    """Perform batch multi-provider threat intelligence enrichment."""
    ti_service = get_threat_intel_service()
    results = ti_service.lookup_batch(
        iocs=request.indicators,
        force_refresh=request.force_refresh,
    )
    return {"total": len(results), "results": results}


@app.get("/api/threat-intel/cache/stats")
def threat_intel_cache_stats() -> dict[str, Any]:
    """Return threat intelligence cache utilization statistics."""
    ti_service = get_threat_intel_service()
    return ti_service.cache.stats()



@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/style.css", include_in_schema=False)
def stylesheet() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "style.css", media_type="text/css")


@app.get("/script.js", include_in_schema=False)
def script() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "script.js", media_type="application/javascript")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("Backend.main:app", host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8000")))
