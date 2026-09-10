"""
Role 1 Pipeline Orchestrator — wires all sub-modules together.
SIH 26106 — IronPulse | Role 1

Usage:
  # CLI
  python -m role1_email_forensics.main --eml email.eml
  python -m role1_email_forensics.main --eml email.eml --output report.json

  # API server
  python -m role1_email_forensics.main --serve [--port 8000]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Auto-load environment variables (.env)
load_dotenv()

# ── Optional FastAPI types for type hints / Pydantic resolution ─────────────
try:
    from fastapi import UploadFile, File
except ImportError:
    UploadFile = None  # type: ignore
    File = None  # type: ignore

# ── Sub-modules ─────────────────────────────────────────────────────────────
from .parser.eml_parser       import parse_eml_file, parse_eml_bytes
from .parser.header_extractor import extract_headers
from .parser.body_extractor   import extract_body

from .auth.spf_checker   import SpfChecker
from .auth.dkim_checker  import DkimChecker
from .auth.dmarc_checker import DmarcChecker
from .auth.arc_checker   import ArcChecker

from .smtp.relay_reconstructor import reconstruct_relay_path

from .ioc.url_extractor    import UrlExtractor
from .ioc.ip_extractor     import IpExtractor
from .ioc.domain_extractor import DomainExtractor
from .ioc.hash_extractor   import HashExtractor

from .origin.origin_inferencer import OriginInferencer
from .risk.risk_signals        import generate_risk_signals
from .intelligence.threat_intel import enrich_report

from .schema.forensic_report import (
    ForensicReport, AuthResults, IocBundle,
    SpfResult_, DkimResult_, DmarcResult_, ArcResult_,
)
from .utils.helpers import get_domain


# ── Pipeline ────────────────────────────────────────────────────────────────

def analyze_eml_file(path: str | Path, filename: Optional[str] = None, enrich: Optional[bool] = None) -> ForensicReport:
    """Analyze a .eml file on disk and return a ForensicReport."""
    path = Path(path)
    raw  = path.read_bytes()
    return analyze_eml_bytes(raw, filename=filename or path.name, enrich=enrich)


def analyze_eml_bytes(raw: bytes, filename: Optional[str] = None, enrich: Optional[bool] = None) -> ForensicReport:
    """
    Full Role 1 pipeline: raw .eml bytes → ForensicReport.

    This is the integration entry point for Role 5 (Backend API).
    """
    report = ForensicReport(source_file=filename)

    # ── 1. Parse ────────────────────────────────────────────────────────────
    msg, sha256, size = parse_eml_bytes(raw)
    report.raw_email_sha256    = sha256
    report.raw_email_size_bytes = size

    # ── 2. Headers ──────────────────────────────────────────────────────────
    try:
        report.headers = extract_headers(msg)
    except Exception as e:
        report.processing_errors.append(f"header_extraction: {e}")

    # ── 3. Body + Attachments ───────────────────────────────────────────────
    try:
        body = extract_body(msg)
    except Exception as e:
        report.processing_errors.append(f"body_extraction: {e}")
        body = None

    # ── 4. SMTP Relay Path ──────────────────────────────────────────────────
    try:
        report.smtp_path = reconstruct_relay_path(msg)
    except Exception as e:
        report.processing_errors.append(f"smtp_reconstruction: {e}")

    # ── 5. Auth Validation ──────────────────────────────────────────────────
    sender_domain = get_domain(report.headers.from_address)

    # Determine sender IP from SMTP path
    sender_ip: Optional[str] = None
    for hop in report.smtp_path:
        if hop.from_ip:
            sender_ip = hop.from_ip
            break

    auth = AuthResults()

    # SPF
    try:
        if sender_domain and sender_ip:
            checker = SpfChecker()
            auth.spf = checker.check(sender_domain, sender_ip)
        else:
            auth.spf = SpfResult_()
            auth.spf.explanation = "Cannot check SPF: missing sender domain or IP"
    except Exception as e:
        report.processing_errors.append(f"spf_check: {e}")

    # DKIM
    try:
        checker = DkimChecker()
        auth.dkim = checker.check(msg, raw)
    except Exception as e:
        report.processing_errors.append(f"dkim_check: {e}")

    # DMARC
    try:
        if sender_domain:
            checker = DmarcChecker()
            auth.dmarc = checker.check(
                from_domain=sender_domain,
                spf_result=auth.spf.result,
                spf_domain=auth.spf.domain,
                dkim_result=auth.dkim.result,
                dkim_domain=auth.dkim.domain,
            )
    except Exception as e:
        report.processing_errors.append(f"dmarc_check: {e}")

    # ARC
    try:
        checker = ArcChecker()
        auth.arc = checker.check(msg)
    except Exception as e:
        report.processing_errors.append(f"arc_check: {e}")

    report.auth = auth

    # ── 6. IOC Extraction ───────────────────────────────────────────────────
    bundle = IocBundle()

    try:
        text_body = body.text_plain if body else None
        html_body = body.text_html  if body else None

        # URLs
        url_ex = UrlExtractor()
        bundle.urls = url_ex.extract(text_body, html_body)

        # IPs
        raw_header_str = "\n".join(f"{k}: {v}" for k, v in msg.items())
        ip_ex = IpExtractor()
        bundle.ips = ip_ex.extract(text_body, html_body, report.smtp_path, raw_header_str)

        # Domains
        dom_ex = DomainExtractor()
        bundle.domains = dom_ex.extract(report.headers, bundle.urls, text_body, html_body)

        # Hashes
        if body:
            hash_ex = HashExtractor()
            bundle = hash_ex.enrich_ioc_bundle(bundle, body)

    except Exception as e:
        report.processing_errors.append(f"ioc_extraction: {e}")

    report.iocs = bundle

    # ── 7. Origin Inference ─────────────────────────────────────────────────
    try:
        inferencer = OriginInferencer()
        report.origin = inferencer.infer(report.smtp_path)
    except Exception as e:
        report.processing_errors.append(f"origin_inference: {e}")

    # ── 8. Risk Signals ─────────────────────────────────────────────────────
    try:
        report.risk_signals = generate_risk_signals(report)
    except Exception as e:
        report.processing_errors.append(f"risk_signals: {e}")

    # ── 9. Optional Threat Intelligence & AI Enrichment ─────────────────────
    if enrich is None:
        enrich = os.getenv("THREAT_INTELLIGENCE_ENABLED", "false").lower() == "true"

    if enrich:
        try:
            report = enrich_report(report)
        except Exception as e:
            report.processing_errors.append(f"threat_intel_enrichment: {e}")

    return report


# ── CLI ─────────────────────────────────────────────────────────────────────

def _cli():
    # Ensure Windows console does not fail on international characters
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="SIH 26106 — Role 1: Email Forensics & Protocol Analyzer"
    )
    parser.add_argument("--eml",    required=False, help="Path to .eml file")
    parser.add_argument("--output", required=False, help="Output JSON path (default: stdout)")
    parser.add_argument("--serve",  action="store_true", help="Start FastAPI server")
    parser.add_argument("--port",   type=int, default=8000, help="Server port (default: 8000)")
    parser.add_argument("--enrich", action="store_true", help="Enrich with external Threat Intel and AI (VirusTotal, URLScan, AbuseIPDB, IPinfo, Nemotron, Gemini)")
    args = parser.parse_args()

    if args.serve:
        _start_server(port=args.port)
        return

    if not args.eml:
        parser.print_help()
        sys.exit(1)

    eml_path = Path(args.eml)
    if not eml_path.exists():
        print(f"[ERROR] File not found: {eml_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analyzing: {eml_path.name}", file=sys.stderr)
    report = analyze_eml_file(eml_path, enrich=args.enrich)

    json_output = report.to_json()

    if args.output:
        Path(args.output).write_text(json_output, encoding="utf-8")
        print(f"[✓] Report saved → {args.output}", file=sys.stderr)
        _print_summary(report)
    else:
        print(json_output)


def _print_summary(report: ForensicReport):
    """Print a human-readable summary to stderr."""
    h = report.headers
    a = report.auth
    print("\n" + "="*60, file=sys.stderr)
    print("  FORENSIC REPORT SUMMARY", file=sys.stderr)
    print("="*60, file=sys.stderr)
    print(f"  Report ID  : {report.report_id}", file=sys.stderr)
    print(f"  File       : {report.source_file}", file=sys.stderr)
    print(f"  SHA256     : {report.raw_email_sha256}", file=sys.stderr)
    print(f"  From       : {h.from_address}", file=sys.stderr)
    print(f"  Subject    : {h.subject}", file=sys.stderr)
    print(f"  Date       : {h.date}", file=sys.stderr)
    print(f"  SPF        : {a.spf.result.value}", file=sys.stderr)
    print(f"  DKIM       : {a.dkim.result.value}", file=sys.stderr)
    print(f"  DMARC      : {a.dmarc.result.value}", file=sys.stderr)
    print(f"  ARC        : {a.arc.result.value} (chain len: {a.arc.chain_length})", file=sys.stderr)
    print(f"  SMTP hops  : {len(report.smtp_path)}", file=sys.stderr)
    print(f"  URLs       : {len(report.iocs.urls)}", file=sys.stderr)
    print(f"  IPs        : {len(report.iocs.ips)}", file=sys.stderr)
    print(f"  Domains    : {len(report.iocs.domains)}", file=sys.stderr)
    print(f"  Attachments: {len(report.iocs.attachments)}", file=sys.stderr)
    print(f"  Origin IP  : {report.origin.probable_sending_ip} ({report.origin.country_code or report.origin.country_name or 'N/A'})", file=sys.stderr)
    if report.origin.city or report.origin.region:
        print(f"  Geolocation: {report.origin.city}, {report.origin.region} (ISP: {report.origin.isp or 'N/A'})", file=sys.stderr)
    if report.origin.abuse_score is not None:
        print(f"  Abuse Score: {report.origin.abuse_score}%", file=sys.stderr)
    if report.ai_assessment and report.ai_assessment.get("status") == "available":
        prov = report.ai_assessment.get("provider", "AI")
        cls_ = str(report.ai_assessment.get("classification", "N/A")).upper()
        score = report.ai_assessment.get("risk_score", "N/A")
        print(f"  AI Verdict : [{prov}] {cls_} (Score: {score})", file=sys.stderr)
        summary = report.ai_assessment.get("executive_summary")
        if summary:
            print(f"  AI Summary : {summary}", file=sys.stderr)
    print(f"  Risk Signals: {len(report.risk_signals)}", file=sys.stderr)
    if report.risk_signals:
        for sig in report.risk_signals:
            print(f"    [{sig.level.value.upper():8s}] {sig.description}", file=sys.stderr)
    if report.processing_errors:
        print(f"\n  ⚠ Processing errors:", file=sys.stderr)
        for err in report.processing_errors:
            print(f"    - {err}", file=sys.stderr)
    print("="*60, file=sys.stderr)


# ── FastAPI Server ───────────────────────────────────────────────────────────

def create_app():
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.middleware.cors import CORSMiddleware
    except ImportError:
        raise RuntimeError("FastAPI/uvicorn not installed. Run: pip install fastapi uvicorn")

    app = FastAPI(
        title="SIH 26106 — Email Forensics API (Role 1)",
        description=(
            "Role 1: Email Forensics & Protocol Module.\n\n"
            "Upload a .eml file to receive a comprehensive ForensicReport JSON "
            "covering header analysis, SPF/DKIM/DMARC/ARC validation, "
            "SMTP relay path reconstruction, IOC extraction, origin inference, "
            "and real-time Threat Intelligence & AI enrichment."
        ),
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/v1/health", tags=["Health"])
    async def health():
        return {"status": "ok", "module": "role1_email_forensics", "version": "1.0.0"}

    @app.post("/api/v1/analyze", tags=["Forensics"])
    async def analyze(
        file: UploadFile = File(..., description="Upload a .eml email file"),
        enrich: bool = False,
    ):
        """
        Analyze an uploaded .eml file.

        Returns a full **ForensicReport** JSON with:
        - Header analysis (From, Reply-To, Return-Path, Message-ID, ...)
        - Auth results (SPF, DKIM, DMARC, ARC)
        - SMTP relay path (hop-by-hop reconstruction)
        - IOCs (URLs, IPs, domains, attachment hashes)
        - Origin inference (probable sending MTA infrastructure)
        - Risk signals
        - Optional Threat Intelligence & AI enrichment (when ?enrich=true or THREAT_INTELLIGENCE_ENABLED=true)
        """
        if not file.filename or not file.filename.endswith(".eml"):
            raise HTTPException(status_code=400, detail="Please upload a .eml file")

        raw = await file.read()
        if not raw:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        try:
            report = analyze_eml_bytes(raw, filename=file.filename, enrich=enrich)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")

        return json.loads(report.to_json())

    return app


def _start_server(port: int = 8000):
    try:
        import uvicorn
    except ImportError:
        print("[ERROR] uvicorn not installed. Run: pip install uvicorn", file=sys.stderr)
        sys.exit(1)

    app = create_app()
    print(f"\n[*] Starting Role 1 API server on http://0.0.0.0:{port}", file=sys.stderr)
    print(f"[*] Swagger UI → http://localhost:{port}/docs\n", file=sys.stderr)
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    _cli()
