# AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
## Problem Statement SIH-26106 | Role 4: Graph & Campaign Correlation

> [!IMPORTANT]
> **Forensic Attribution & Infrastructure Policy**:  
> Correlation identifies **probable/shared hosting infrastructure** and operational behavioral relationships. **IP ownership or geolocation must NEVER be interpreted as proof of an attacker's physical identity or location.**

---

## 1. Role 4 Scope & Responsibilities
As **Role 4: Graph & Campaign Correlation**, this module provides the graph intelligence core of the SIH 26106 platform:
- **Graph Modeling**: Neo4j knowledge graph connecting `Email`, `Domain`, `IP`, `URL`, `Hash`, `Campaign`, and `ASN` entities.
- **Idempotent Ingestion**: Ingests normalized threat analysis JSON from upstream modules without duplicating nodes or relationships.
- **Explainable Campaign Clustering**: Groups related phishing and malware messages into operational campaigns using multi-feature similarity (IOC overlap, shared hosting IPs, subject lexical similarity, temporal proximity, and auth failure profiles).
- **Infrastructure Correlation & Pivots**: Identifies shared infrastructure clusters (IPs hosting multiple threat domains, domain resolutions, hash reuse).
- **Attribution Confidence Analysis**: Computes multi-factor correlation confidence (0.0 to 1.0) with granular evidence reasons and explicit legal/forensic limitations.
- **Frontend Contract Hand-off (Role 6)**: Delivers JSON-serializable `{nodes: [...], edges: [...]}` graph schemas with type-prefixed IDs ready for UI canvas renderers (Cytoscape, D3, Vis.js, React Flow).

### What Role 4 Does NOT Do (Role Boundaries):
- Role 4 is **NOT** a `.eml` raw parser (handled by Role 1).
- Role 4 does **NOT** run VirusTotal/AbuseIPDB network calls (handled by Role 3).
- Role 4 does **NOT** manage platform authentication/RBAC or PostgreSQL tables (handled by Role 5).
- Role 4 consumes normalized threat analysis results and transforms them into explainable graph intelligence.

---

## 2. Architecture & Data Flow

```
+-------------------------------------------------------------------------+
|                  Upstream Analysis Telemetry (Roles 1 & 2)              |
+-------------------------------------------------------------------------+
                                    |
                                    v
                  POST /api/v1/graph/ingest
                                    |
                                    v
+-------------------------------------------------------------------------+
|                      1. Ingestion & Normalization                       |
|   - Lowercase domains, validate IPs (ipaddress), normalize URLs/hashes  |
|   - Enforce schema constraints and indexes in Neo4j                     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                     2. Neo4j Forensic Knowledge Graph                   |
|   (:Email)-[:SENT_FROM]->(:Domain)-[:RESOLVES_TO]->(:IP)-[:BELONGS]->(:ASN)
|   (:Email)-[:CONTAINS_DOMAIN]->(:Domain)                                |
|   (:Email)-[:CONTAINS_URL]->(:URL)-[:HOSTED_ON_DOMAIN]->(:Domain)       |
|   (:Email)-[:CONTAINS_HASH]->(:Hash)                                    |
+-------------------------------------------------------------------------+
                                    |
         +--------------------------+--------------------------+
         |                                                     |
         v                                                     v
+-----------------------------------+ +-----------------------------------+
|  3. Campaign Clustering (NetworkX)| |    4. Infrastructure Correlation  |
|  - Weighted multi-feature similarity | - IP -> Domains, Emails, Campaigns |
|  - Connected components clustering  | - Domain -> IPs, URLs, Campaigns  |
|  - Deterministic Campaign IDs       | - Hash -> Payload reuse pivot     |
|  - (:Email)-[:MEMBER_OF]->(Campaign) | - Infrastructure cluster detection|
+-----------------------------------+ +-----------------------------------+
         \                                                     /
          \                                                   /
           v                                                 v
+-------------------------------------------------------------------------+
|                    5. Attribution Confidence Analyzer                   |
|   - Evaluates: Infrastructure (35%), Temporal (25%), Behavior (25%),    |
|     Content (15%)                                                       |
|   - Generates explainable evidence checklist + forensic disclaimers     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                      6. REST API & UI Visualization                     |
|   - Standardized Envelope: {success, data, error, meta}                 |
|   - Role 6 Frontend Subgraphs: {nodes: [...], edges: [...]}             |
+-------------------------------------------------------------------------+
```

---

## 3. Graph Schema

### Entity Node Types:
| Node Label | Key Identifier | Description |
| :--- | :--- | :--- |
| `(:Email)` | `email_id` | Analyzed email message with subject, sender, timestamp, and risk score. |
| `(:Domain)` | `name` | Normalized fully-qualified domain name (sender, embedded, or hosted). |
| `(:IP)` | `address` | IPv4 or IPv6 hosting/infrastructure address. |
| `(:URL)` | `url_hash` | Normalized destination URL and SHA-256 hash representation. |
| `(:Hash)` | `value` | Lowercase cryptographic hash (SHA-256, MD5, SHA-1) of attachments. |
| `(:Campaign)`| `campaign_id` | Correlated threat campaign node clustering multiple related emails. |
| `(:ASN)` | `number` | Autonomous System Number of hosting provider. |

### Directed Relationships:
- `(:Email)-[:SENT_FROM]->(:Domain)`: Sender address domain linkage.
- `(:Email)-[:CONTAINS_DOMAIN]->(:Domain)`: Extracted/embedded domain within message body.
- `(:Email)-[:CONTAINS_URL]->(:URL)`: Embedded destination hyperlinks.
- `(:URL)-[:HOSTED_ON_DOMAIN]->(:Domain)`: Target domain hosting the URL.
- `(:Domain)-[:RESOLVES_TO]->(:IP)`: Observed DNS resolution from telemetry.
- `(:IP)-[:BELONGS_TO_ASN]->(:ASN)`: Autonomous system routing owner.
- `(:Email)-[:CONTAINS_HASH]->(:Hash)`: Cryptographic attachment/payload hash.
- `(:Email)-[:MEMBER_OF]->(:Campaign)`: Membership in a correlated campaign.
- `(:Campaign)-[:USES_DOMAIN]->(:Domain)`: Campaign infrastructure domain.
- `(:Campaign)-[:USES_IP]->(:IP)`: Campaign infrastructure IP.
- `(:Campaign)-[:USES_URL]->(:URL)`: Phishing/malicious campaign landing page.
- `(:Campaign)-[:USES_HASH]->(:Hash)`: Associated campaign payload hash.

---

## 4. Setup & Running

### Option A: Local Python Environment
```bash
# 1. Clone repository & enter directory
git clone https://github.com/YOUR_ORGANIZATION/graph-correlation.git
cd graph-correlation

# 2. Create virtual environment
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux / macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
copy .env.example .env

# 5. Start Neo4j (via Docker or local install)
# Default expects bolt://localhost:7687, user: neo4j, pass: change-me-to-your-secure-password

# 6. Run the FastAPI development server
uvicorn app.main:app --reload --port 8000
```

### Option B: Docker Compose (One-Click)
```bash
docker compose up -d --build
```
- **FastAPI API**: http://localhost:8000
- **Swagger Documentation**: http://localhost:8000/docs
- **Neo4j Browser GUI**: http://localhost:7474 (user: `neo4j`, pass: `password123`)

---

## 5. Automated Tests & One-Click Demo

### Running Automated Test Suite (Pytest)
```bash
# Run all unit and integration tests
python -m pytest tests/ -v

# Or use the convenience runner
python test_api.py
```

### Running the SIH Judge Demo Script
The one-click demo script executes an end-to-end simulation:
1. Verifies API & Neo4j health.
2. Ingests 4 synthetic email samples (3 coordinated phishing emails + 1 benign newsletter).
3. Verifies ingestion idempotency (zero duplicates on re-submission).
4. Runs campaign clustering (clusters the 3 phishing emails; leaves the benign email separate).
5. Discovers shared hosting infrastructure.
6. Calculates attribution confidence with evidence checklist.
7. Prints frontend visualization URLs.

```bash
python scripts/demo.py
```

---

## 6. API Reference (All 20 Endpoints)

All endpoints require header: `X-API-Key: dev-key` (except `/health`).

### Status & Management
| Method | URL | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Unauthenticated service and Neo4j connectivity status. |
| `GET` | `/` | Service overview, sitemap, and attribution policy. |

### Graph & Ingestion (`/api/v1/graph`)
| Method | URL | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/graph/stats` | High-level node and relationship counts. |
| `POST` | `/api/v1/graph/ingest` | Ingests analyzed email telemetry idempotently into Neo4j. |
| `GET` | `/api/v1/graph/email/{email_id}` | Bounded frontend visualization subgraph for Email node. |
| `GET` | `/api/v1/graph/email/{email_id}/path` | Traces full infrastructure path for an analyzed email. |
| `GET` | `/api/v1/graph/path?email_id=...` | Query-param path tracing endpoint. |
| `GET` | `/api/v1/graph/domain/{domain}` | Frontend visualization subgraph for Domain node. |
| `GET` | `/api/v1/graph/ip/{ip_address}` | Frontend visualization subgraph for IP node. |
| `GET` | `/api/v1/graph/hash/{hash_value}` | Frontend visualization subgraph for Hash node. |
| `GET` | `/api/v1/graph/all` | Bounded graph export for initial canvas rendering (`limit <= 100`). |
| `DELETE`| `/api/v1/graph/all?confirm=true`| Safe dev/demo graph reset requiring confirmation parameter. |

### Campaign Correlation (`/api/v1/campaigns`)
| Method | URL | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/campaigns/cluster` | Executes explainable multi-feature campaign clustering. |
| `GET` | `/api/v1/campaigns` | Lists all discovered threat campaigns. |
| `GET` | `/api/v1/campaigns/{campaign_id}` | Campaign details and shared indicator inventory. |
| `GET` | `/api/v1/campaigns/{campaign_id}/graph` | Frontend visualization subgraph for Campaign. |
| `GET` | `/api/v1/campaigns/{campaign_id}/confidence` | Attribution confidence score and evidence breakdown. |
| `GET` | `/api/v1/campaigns/{campaign_id}/report` | Full forensic intelligence report for campaign. |

### Infrastructure Correlation (`/api/v1/infrastructure`)
| Method | URL | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/infrastructure/clusters` | Finds hosting IPs serving multiple threat domains or emails. |
| `GET` | `/api/v1/infrastructure/ip/{ip}` | IP pivot: associated domains, emails, campaigns, ASN. |
| `GET` | `/api/v1/infrastructure/domain/{domain}`| Domain pivot: resolving IPs, hosted URLs, emails, campaigns. |
| `GET` | `/api/v1/infrastructure/asn/{asn}` | ASN pivot: associated IPs, domains, and campaigns. |

---

## 7. Frontend Integration Contract (Role 6)
All graph subgraph endpoints return standard JSON formatted for graph rendering engines:

```json
{
  "success": true,
  "data": {
    "nodes": [
      {
        "id": "email:email-001",
        "type": "email",
        "label": "Urgent: Verify Account Access",
        "risk_score": 0.92,
        "properties": { "sender": "security@phish-portal.com" }
      },
      {
        "id": "ip:198.51.100.25",
        "type": "ip",
        "label": "198.51.100.25",
        "risk_score": 0.92,
        "properties": { "asn": "64512" }
      }
    ],
    "edges": [
      {
        "id": "edge:email:email-001->domain:phish-portal.com:SENT_FROM",
        "source": "email:email-001",
        "target": "domain:phish-portal.com",
        "type": "SENT_FROM",
        "properties": {}
      }
    ]
  },
  "error": null,
  "meta": {
    "request_id": "8f3b60e9-b59a-412e-9d2a-4318357f12e8",
    "schema_version": "1.0",
    "timestamp": "2026-09-10T10:30:00Z"
  }
}
```

---

## 8. Attribution & Confidence Methodology
The attribution confidence score represents the **correlation confidence** between observed threat indicators, not real-world identity proof:
- **Infrastructure Weight (35%)**: Measures shared hosting IPs, domains, destination URLs, and payload hashes.
- **Temporal Weight (25%)**: Evaluates burstiness and transmission velocity within correlated windows.
- **Behavioral Weight (25%)**: Evaluates uniformity of SPF/DKIM/DMARC authentication failure profiles.
- **Content Weight (15%)**: Evaluates subject line lexical Jaccard similarity.

### Discrete Confidence Levels:
- `0.00 – 0.39`: **Low** (Limited or fragmented evidence)
- `0.40 – 0.69`: **Medium** (Moderate infrastructural or lexical overlap)
- `0.70 – 0.89`: **High** (Strong shared infrastructure and burst timing)
- `0.90 – 1.00`: **Very High** (Coordinated campaign with identical infrastructure and payload reuse)
