# Comprehensive Audit Report — Graph & Campaign Correlation Module (Role 4)
**Project**: SIH Problem Statement 26106 — AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform  
**Date**: September 10, 2026  
**Auditor**: Senior Python/FastAPI/Neo4j Graph & Cybersecurity Engineer  

---

## Executive Summary
A comprehensive line-by-line static and architectural audit was conducted across all source files, schemas, and configurations of the existing `graph-correlation/` project. The previous implementation demonstrated foundational intent but suffered from multiple **Critical** security vulnerabilities, Cypher syntax runtime errors, severe API route collisions, data loss/duplication issues, missing schema validation, and unsubstantiated claims regarding test coverage and endpoint counts.

---

## Endpoint Count Verification & Reality Check
- **Previous Claim**: Documentation claimed `graph_routes` has 8 routes, `campaign_routes` has 12 routes, and `test_api.py` tests "all 13 endpoints".
- **Audited Reality**:
  - `app/api/graph_routes.py`: Contains **9 endpoints** (`GET /stats`, `POST /email/{message_id}/build`, `POST /ingest`, `GET /email/{message_id}`, `GET /domain/{domain_name}`, `GET /ip/{ip}`, `GET /email/{message_id}/path`, `DELETE /all`, `POST /query`).
  - `app/api/campaign_routes.py`: Contains **9 endpoints** (`POST /cluster`, `GET ""`, `GET /{campaign_id}`, `GET /{campaign_id}/confidence`, `GET /{campaign_id}/report`, `GET /{campaign_id}/graph`, `GET /infrastructure/clusters`, `GET /ip/{ip}`, `GET /domain/{domain}`).
  - `app/main.py`: Contains **2 endpoints** (`GET /`, `GET /health`).
  - **Actual Total Endpoints**: **20 endpoints**.
  - **Test File Status**: `test_api.py` was **completely missing** from the repository despite claims of testing "all 13 endpoints".
  - **Sample Data Status**: `sample_analysis.json` was **completely missing**.

---

## Detailed Vulnerability & Defect Matrix

### 1. Critical Severity Issues

| Issue ID | File | Defect Explanation | Severity | Fix Required / Implemented |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | `app/api/graph_routes.py` | Arbitrary Cypher label injection in `/query` endpoint: `MATCH (n:{label}) WHERE ...` interpolates unsanitized input directly into Cypher. Dangerous unauthenticated query surface. | **Critical** | Remove or strictly guard `/query` behind an allowlisted query catalog using parameterized queries. Never interpolate user input into Cypher syntax. |
| **SEC-02** | `app/api/graph_routes.py` | Destructive `DELETE /all` endpoint runs `MATCH (n) DETACH DELETE n` unconditionally with only standard API key, risking catastrophic data wipe during demo or evaluation. | **Critical** | Add safety guard (`confirm=true` & dev/demo environment check), and replace default `GET /all` with bounded, read-only graph export with strict pagination/limits. |
| **SEC-03** | `app/main.py` | Dangerous CORS configuration: `allow_origins=["*"]` combined with `allow_credentials=True`. This is invalid per W3C CORS specification and opens the API to cross-origin credential leaks. | **Critical** | Restrict CORS origins via configuration (`CORS_ORIGINS` in `.env`), disable wildcard with credentials. |
| **SYN-01** | `app/services/infrastructure_correlation.py` | Invalid Cypher Syntax: `startNode(rel).{self._get_key(...)}` at line 204. Dynamic property bracket interpolation is invalid Cypher syntax and crashes at runtime when generating visualization graphs. | **Critical** | Rewrite graph extraction using standard Cypher `nodes(path)` and `relationships(path)` projection or client-side serialization to the standardized frontend contract. |
| **RTE-01** | `app/api/campaign_routes.py` | Dynamic route collision: `@router.get("/{campaign_id}")` is registered before `@router.get("/infrastructure/clusters")`, `@router.get("/ip/{ip}")`, and `@router.get("/domain/{domain}")`. Requests to `/infrastructure/clusters` are captured as `campaign_id="infrastructure"`, returning 404 or crashing. | **Critical** | Segregate infrastructure endpoints to dedicated `/api/v1/infrastructure/...` router and place static routes before parameterized dynamic routes. |
| **DAT-01** | `app/services/graph_builder.py` | Email and Hash node relationship omission: `_create_hash_nodes` creates `Hash` nodes in Neo4j but never creates `(:Email)-[:CONTAINS_HASH]->(:Hash)` relationships, severing forensic correlation. | **Critical** | Add explicit `CONTAINS_HASH` relationship creation between `Email` and `Hash` entities. |
| **DAT-02** | `app/services/neo4j_service.py` | Missing constraints & indexes: No unique constraints on `Email.email_id`, `Domain.name`, `IP.address`, `URL.normalized_url`, `Hash.value`, `Campaign.campaign_id`. Re-ingestion or concurrent ingestion causes duplicate orphan nodes and fragmented graphs. | **Critical** | Implement programmatic initialization of Neo4j UNIQUE constraints and indexes on startup. |

---

### 2. High Severity Issues

| Issue ID | File | Defect Explanation | Severity | Fix Required / Implemented |
| :--- | :--- | :--- | :--- | :--- |
| **ARCH-01** | `app/models/graph_models.py` | Schema contract violation: Models do not match the required SIH Common Integration Contract (`schema_version`, `analysis_id`, `email`, `authentication`, `iocs`, `threat_intel`, `detection`). | **High** | Implement strict Pydantic v2 models representing the unified SIH schema with normalization and backward compatibility for flat payloads. |
| **VAL-01** | `app/services/graph_builder.py` | Missing input normalization & validation: Domains are not lowercased, IPs are not validated via `ipaddress.ip_address`, URLs are not normalized, hashes are not validated for length/hex characters. Malformed inputs corrupt graph topology. | **High** | Implement robust normalization and validation pipeline for all IOC types. |
| **ALG-01** | `app/services/campaign_clustering.py` | Flawed clustering algorithm: `_get_emails_in_window` queries `WHERE ts > datetime() - duration(...)`. In any demo or historical analysis, if timestamps are older than 24 hours, zero emails are clustered. Furthermore, clustering ignores IPs, URLs, hashes, and ASNs, clustering solely on sender domain, recipients, and subject words. | **High** | Implement multi-feature weighted similarity clustering (IOC overlap: 35%, Infrastructure: 30%, Content: 15%, Temporal: 10%, Behavior: 10%) using explainable graph/NetworkX community or connected components, with configurable weights. |
| **ALG-02** | `app/services/confidence_analyzer.py` | Broken infrastructure score calculation: `_score_infrastructure_linkage` simply measures `len(ips)` and `len(domains)` in the campaign. A campaign with 10 emails each having a completely different IP gets a high score, when in reality there is zero shared infrastructure! | **High** | Rewrite infrastructure linkage scoring to measure true indicator overlap ratio across distinct emails in the campaign. |
| **LIF-01** | `app/main.py` | Deprecated FastAPI lifecycle: Uses `@app.on_event("startup")` and `@app.on_event("shutdown")` which are deprecated in current FastAPI/Starlette versions. Database connection failures crash server unhandled. | **High** | Migrate to `lifespan(app)` async context manager with graceful connection retry and degraded health state handling. |
| **SEC-04** | `.env` & `.gitignore` | Missing `.gitignore` and `.env.example`. `.env` was committed with hardcoded credentials in the repository root. | **High** | Remove tracked secrets, create `.gitignore` and `.env.example`, ensure real secrets are never committed. |

---

### 3. Medium Severity Issues

| Issue ID | File | Defect Explanation | Severity | Fix Required / Implemented |
| :--- | :--- | :--- | :--- | :--- |
| **API-01** | `app/api/*.py` | Non-standard API responses: Endpoints return ad-hoc dictionaries, lists, or `{status: "..."}`. Error responses return HTTP 200 with error messages or unhandled tracebacks instead of the unified envelope `{success, data, error, meta}`. | **Medium** | Implement standard response wrappers, custom exception handlers, and proper HTTP status codes (200, 201, 400, 404, 422, 500). |
| **API-02** | `app/api/*.py` | Missing API versioning: Routes are mounted under `/api/graph` and `/api/campaigns` instead of `/api/v1/...`. | **Medium** | Structure routes under `/api/v1/graph`, `/api/v1/campaigns`, and `/api/v1/infrastructure`. |
| **ROL-01** | `app/services/confidence_analyzer.py` | Attribution wording boundary: The module must only report probable infrastructure and correlation confidence. It must never state or imply that an IP or domain proves the physical identity of an attacker. | **Medium** | Enforce standardized defensive attribution disclaimers and explainable evidence listings across all confidence and report endpoints. |
| **PERF-01** | `app/services/infrastructure_correlation.py` | Unbounded graph queries: `get_graph_for_visualization` and `find_infrastructure_clusters` lack query depth guards and maximum limit clamps, creating DoS risk on dense graphs. | **Medium** | Enforce `max_depth` (default 2, hard max 4) and strict `LIMIT` on all Cypher queries. |
| **FNT-01** | `app/services/infrastructure_correlation.py` | Incompatible frontend visualization schema: Returns Neo4j internal `elementId` and raw property dictionaries instead of the unified `nodes: [{id: "type:val", label, type, properties}], edges: [{id, source, target, type}]` contract required by Role 6. | **Medium** | Format all graph endpoints to emit prefixed, JSON-serializable node and edge structures. |

---

### 4. Low Severity Issues

| Issue ID | File | Defect Explanation | Severity | Fix Required / Implemented |
| :--- | :--- | :--- | :--- | :--- |
| **DOC-01** | `README.md` | Inaccurate endpoint listing, out-of-date schema diagrams, outdated payload examples, and broken curl instructions. | **Low** | Rewrite `README.md` with complete architecture, exact endpoints, setup guides, and judging scripts. |
| **TST-01** | Root / Tests | Complete absence of automated tests (neither unit tests nor integration tests existed). | **Low** | Create comprehensive `pytest` test suite with mocks and integration tests. |
| **DEP-01** | `requirements.txt` | Missing `pytest`, `pytest-asyncio`, and includes unused `redis` dependency. | **Low** | Clean up `requirements.txt` to accurately reflect dependencies. |

---

## Remediation Roadmap
1. Standardize integration contract (`app/models/integration_contract.py`).
2. Fix Neo4j service with parameterized Cypher, connection resilience, constraints & indexes (`app/services/neo4j_service.py`).
3. Build idempotent graph ingestion with IOC normalization and all required relationships (`app/services/graph_builder.py`).
4. Implement explainable multi-feature campaign clustering with NetworkX fallback (`app/services/campaign_clustering.py`).
5. Implement infrastructure correlation with pivots and safe attribution wording (`app/services/infrastructure_correlation.py`).
6. Implement configurable confidence analyzer with evidence & limitations (`app/services/confidence_analyzer.py`).
7. Structure versioned API routes with standard response envelope and fix route collisions (`app/api/v1/...`).
8. Add frontend visualization formatting (`nodes` & `edges` with prefixed IDs).
9. Add realistic demo dataset (`demo/email_001.json`, `002`, `003`, `unrelated.json`).
10. Add one-click demo script (`scripts/demo.py`) and Docker Compose configuration.
11. Add automated `pytest` test suite with unit tests and mocks.
12. Generate full documentation (`README.md` and `docs/API_INTEGRATION.md`).
