# SIH 26106 — AI-Powered Email Threat Detection Platform
## Role 1: Email Forensics & Protocol Module

**Team:** IronPulse | **SIH Problem Statement:** 26106

---

## Overview

This module is the **entry point of the entire pipeline**. It ingests raw `.eml` files and produces a comprehensive `ForensicReport` JSON consumed by all 6 roles.

```
.eml file
  → EML Parser           (MIME, attachments, encoded headers)
  → Header Extractor     (From/To/Reply-To/Return-Path/Message-ID/X-*)
  → Auth Validators      (SPF / DKIM / DMARC / ARC)
  → SMTP Reconstructor   (Received-header relay chain + anomaly flags)
  → IOC Extractor        (URLs / IPs / Domains / Attachment hashes)
  → Origin Inferencer    (Probable sending infrastructure)
  → ForensicReport JSON  ← consumed by Roles 2–6
```

---

## Directory Structure

```
role1_email_forensics/
├── __init__.py
├── main.py                     # CLI + FastAPI entrypoint
├── schema/
│   └── forensic_report.py      # Pydantic shared models (common API contract)
├── parser/
│   ├── eml_parser.py           # .eml ingestion
│   ├── header_extractor.py     # Header field parsing
│   └── body_extractor.py       # MIME body + attachment handling
├── auth/
│   ├── spf_checker.py          # SPF DNS validation
│   ├── dkim_checker.py         # DKIM signature verification
│   ├── dmarc_checker.py        # DMARC policy evaluation
│   └── arc_checker.py          # ARC chain validation
├── smtp/
│   └── relay_reconstructor.py  # Received-header chain parsing
├── ioc/
│   ├── url_extractor.py        # URL harvesting
│   ├── ip_extractor.py         # IP extraction + classification
│   ├── domain_extractor.py     # Domain extraction + homoglyph detection
│   └── hash_extractor.py       # MD5/SHA1/SHA256 of attachments + body
├── origin/
│   └── origin_inferencer.py    # Probable sending MTA detection
└── utils/
    └── helpers.py              # Shared regex, decoders, normalizers
tests/
├── sample_emails/
│   ├── phishing_sample.eml
│   ├── bec_sample.eml
│   └── legitimate_sample.eml
└── test_role1.py
```

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# CLI — analyze a single .eml
python -m role1_email_forensics.main --eml tests/sample_emails/phishing_sample.eml

# CLI — save report to JSON
python -m role1_email_forensics.main --eml tests/sample_emails/phishing_sample.eml --output report.json

# API server
python -m role1_email_forensics.main --serve
# → Visit http://localhost:8000/docs

# Tests
pytest tests/test_role1.py -v
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/analyze` | Upload `.eml` → returns ForensicReport JSON |
| `GET`  | `/api/v1/health`  | Health check |
| `GET`  | `/docs`           | Swagger UI |

---

## ForensicReport JSON Schema

All 6 roles share this schema. See `role1_email_forensics/schema/forensic_report.py`.

```json
{
  "report_id": "uuid4",
  "analyzed_at": "2024-01-15T10:30:00Z",
  "source_file": "email.eml",
  "raw_email_sha256": "abc123...",
  "headers": { ... },
  "auth": {
    "spf":   { "result": "pass|fail|softfail|neutral|none|temperror|permerror" },
    "dkim":  { "result": "pass|fail|none" },
    "dmarc": { "result": "pass|fail|none" },
    "arc":   { "result": "pass|fail|none" }
  },
  "smtp_path": [ { "hop": 1, "from_host": "...", "by_host": "...", ... } ],
  "iocs": {
    "urls": [], "ips": [], "domains": [], "attachments": []
  },
  "origin": {
    "probable_sending_ip": "...",
    "note": "Probable sending MTA infrastructure — not attacker identity"
  },
  "risk_signals": []
}
```

---

## Integration Points (Common API Contract)

- **Role 2 (AI/ML):** consumes `headers`, `iocs`, `auth`, `risk_signals`
- **Role 3 (Threat Intel):** consumes `iocs.ips`, `iocs.domains`, `iocs.urls`
- **Role 4 (Graph):** consumes `smtp_path`, `iocs`, `origin`, `headers`
- **Role 5 (Backend):** stores `ForensicReport` in PostgreSQL, indexes in Neo4j
- **Role 6 (Dashboard):** renders `auth`, `smtp_path`, `iocs`, `origin` visually

---

## ⚠️ Attribution Disclaimer

The `origin` field identifies the **probable sending mail server infrastructure** based on the first external hop in the SMTP relay chain. This is NOT the attacker's physical location or identity. IP geolocation and ASN data are probabilistic.

---

## Dependencies

| Library | Purpose |
|---------|---------|
| `fastapi` + `uvicorn` | REST API server |
| `pydantic v2` | Schema validation |
| `dnspython` | SPF/DKIM/DMARC DNS lookups |
| `dkimpy` | DKIM signature verification |
| `ipwhois` | IP → ASN/Org lookup |
| `tldextract` | Domain/TLD parsing |
| `validators` | URL validation |
| `cryptography` | RSA/Ed25519 operations |
| `python-dateutil` | Timezone-aware date parsing |
| `pytest` | Unit testing |
