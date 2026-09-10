# Role 1 — Email Forensics & Protocol — Build Tasks

## Setup
- [x] Project structure & requirements.txt
- [x] README.md
- [x] pytest.ini

## Schema
- [x] `role1_email_forensics/schema/forensic_report.py` — Pydantic shared models

## Parser
- [x] `role1_email_forensics/parser/eml_parser.py`
- [x] `role1_email_forensics/parser/header_extractor.py`
- [x] `role1_email_forensics/parser/body_extractor.py`

## Auth Validators
- [x] `role1_email_forensics/auth/spf_checker.py`
- [x] `role1_email_forensics/auth/dkim_checker.py`
- [x] `role1_email_forensics/auth/dmarc_checker.py`
- [x] `role1_email_forensics/auth/arc_checker.py`

## SMTP
- [x] `role1_email_forensics/smtp/relay_reconstructor.py`

## IOC Extraction
- [x] `role1_email_forensics/ioc/url_extractor.py`
- [x] `role1_email_forensics/ioc/ip_extractor.py`
- [x] `role1_email_forensics/ioc/domain_extractor.py`
- [x] `role1_email_forensics/ioc/hash_extractor.py`

## Risk Signals
- [x] `role1_email_forensics/risk/risk_signals.py`

## Origin
- [x] `role1_email_forensics/origin/origin_inferencer.py`

## Utils
- [x] `role1_email_forensics/utils/helpers.py`

## Entrypoint
- [x] `role1_email_forensics/main.py` (CLI + FastAPI)

## Tests & Samples
- [x] `tests/test_role1.py`
- [x] `tests/sample_emails/phishing_sample.eml`
- [x] `tests/sample_emails/bec_sample.eml`
- [x] `tests/sample_emails/legitimate_sample.eml`

## Verification
- [x] pip install -r requirements.txt (completed)
- [x] pytest tests/test_role1.py -v (41/41 tests passing)
- [x] CLI smoke test on phishing sample (verified report generation & summary)
- [x] CLI smoke test on BEC and Legitimate samples (verified)
