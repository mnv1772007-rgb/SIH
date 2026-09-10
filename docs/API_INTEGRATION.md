# API Integration Guide — Role 4: Graph & Campaign Correlation
**SIH Problem Statement 26106**: AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform  
**Target Modules**:
- **Role 1** (.eml & Header Parsing)
- **Role 2** (AI/ML Threat Detection)
- **Role 3** (Threat Intel & Geolocation Enrichment)
- **Role 5** (Platform Backend, Database & Orchestration)
- **Role 6** (Frontend Dashboard & Visualizations)

---

## 1. Overview & Service Contract
The Role 4 microservice transforms analyzed email threat events and IOC metadata into an actionable Neo4j knowledge graph. It automatically executes:
1. **Graph Entity Extraction & Normalization** (Email → Domain → IP → URL → Hash → ASN)
2. **Explainable Campaign Clustering** (Detects shared infrastructure, payload hashes, and burst timelines)
3. **Infrastructure Correlation & Pivots** (IP hosting clusters, domain-to-IP resolutions)
4. **Operational Attribution Confidence Scoring** (Probabilistic evidence scoring with explicit non-attribution disclaimers)
5. **Role 6 Visualization Hand-Off** (JSON-serializable `{nodes: [...], edges: [...]}` format with prefixed IDs)

---

## 2. Server Configuration & Authentication
- **Base URL**: `http://localhost:8000/api/v1`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **ReDoc Specification**: `http://localhost:8000/redoc`
- **Authentication**: All `/api/v1/*` endpoints require the header:
  ```http
  X-API-Key: dev-key
  Content-Type: application/json
  ```
- **Health Check (Unauthenticated)**: `GET http://localhost:8000/health`

---

## 3. Standard Response Envelope (Phase 11 Standard)
All responses strictly adhere to the unified envelope:

### Successful Response:
```json
{
  "success": true,
  "data": { ... },
  "error": null,
  "meta": {
    "request_id": "8f3b60e9-b59a-412e-9d2a-4318357f12e8",
    "schema_version": "1.0",
    "timestamp": "2026-09-10T10:30:00.123456+00:00"
  }
}
```

### Failed Request:
```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "ENTITY_NOT_FOUND",
    "message": "Campaign 'camp-xyz' not found",
    "details": null
  },
  "meta": {
    "request_id": "8f3b60e9-b59a-412e-9d2a-4318357f12e8",
    "schema_version": "1.0",
    "timestamp": "2026-09-10T10:30:00.123456+00:00"
  }
}
```

---

## 4. Backend Ingestion Contract (For Roles 2 & 5)
### `POST /api/v1/graph/ingest`
Idempotently merges analyzed threat telemetry into Neo4j. Re-submitting the same payload will never duplicate nodes or relationships.

#### Request Example:
```bash
curl -X POST "http://localhost:8000/api/v1/graph/ingest" \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "schema_version": "1.0",
    "analysis_id": "analysis-uuid-001",
    "email": {
      "email_id": "email-uuid-001",
      "message_id": "<msg-001@phish-portal.com>",
      "subject": "Urgent: Verify Your Account Credentials",
      "sender": "security@phish-portal.com",
      "sender_domain": "phish-portal.com",
      "recipient": "victim@target-enterprise.com",
      "recipients": ["victim@target-enterprise.com"],
      "timestamp": "2026-09-10T08:15:00Z"
    },
    "authentication": {
      "spf": "fail",
      "dkim": "fail",
      "dmarc": "fail"
    },
    "iocs": {
      "domains": [
        {"value": "phish-portal.com", "source": "sender"},
        {"value": "auth-gateway-relay.net", "source": "body"}
      ],
      "ips": [
        {"value": "198.51.100.25", "source": "received_header", "asn": "64512"}
      ],
      "urls": [
        {"value": "https://auth-gateway-relay.net/login/verify?session=abc1", "domain": "auth-gateway-relay.net"}
      ],
      "hashes": [
        {"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "type": "sha256", "filename": "statement.pdf"}
      ],
      "ip_domain_mapping": {
        "198.51.100.25": "auth-gateway-relay.net"
      }
    },
    "threat_intel": {
      "domains": {"phish-portal.com": {"malicious": true}},
      "ips": {"198.51.100.25": {"reputation": "suspicious"}}
    },
    "detection": {
      "classification": "phishing",
      "risk_score": 0.92,
      "confidence": 0.95
    }
  }'
```

#### Response Example (`HTTP 201 Created`):
```json
{
  "success": true,
  "data": {
    "analysis_id": "analysis-uuid-001",
    "email_id": "email-uuid-001",
    "nodes_created": 6,
    "nodes_matched": 0,
    "relationships_created": 7,
    "relationships_matched": 0
  },
  "error": null,
  "meta": { ... }
}
```

---

## 5. Campaign Correlation & Attribution Endpoints
### `POST /api/v1/campaigns/cluster`
Triggers community detection / connected component clustering across analyzed messages.
```bash
curl -X POST "http://localhost:8000/api/v1/campaigns/cluster" \
  -H "X-API-Key: dev-key" \
  -H "Content-Type: application/json" \
  -d '{"similarity_threshold": 0.45, "min_cluster_size": 2}'
```

### `GET /api/v1/campaigns`
Lists all detected campaigns.
```bash
curl -X GET "http://localhost:8000/api/v1/campaigns" \
  -H "X-API-Key: dev-key"
```

### `GET /api/v1/campaigns/{campaign_id}/confidence`
Calculates explainable attribution confidence with factor breakdown and forensic limitations.
```bash
curl -X GET "http://localhost:8000/api/v1/campaigns/camp-8f3b60e9d2a4/confidence" \
  -H "X-API-Key: dev-key"
```
#### Response:
```json
{
  "success": true,
  "data": {
    "campaign_id": "camp-8f3b60e9d2a4",
    "confidence": 0.88,
    "level": "high",
    "breakdown": {
      "infrastructure": 0.92,
      "temporal": 0.85,
      "behavioral": 0.83,
      "content": 0.90
    },
    "evidence": [
      "Observed shared hosting infrastructure: 1 IP address(es) reused across campaign",
      "Shared domain infrastructure: 2 domain(s) linked to campaign messages",
      "Coordinated high-velocity burst: all 3 messages sent within 0.5 hours",
      "Homogeneous email authentication failure profile: 3/3 SPF and 3/3 DMARC failures",
      "Strong lexical template alignment: subject line similarity 0.88"
    ],
    "limitations": [
      "Shared infrastructure (IPs/nameservers) may represent multi-tenant cloud hosting or compromised relays",
      "IP geolocation identifies routing infrastructure, not the physical location or identity of threat actors",
      "Correlation confidence indicates operational linkage between observations, not legal proof of authorship"
    ],
    "methodology_disclaimer": "Correlation identifies probable/shared infrastructure and behavioral relationships. IP ownership or geolocation must not be interpreted as proof of an attacker's physical identity."
  }
}
```

### `GET /api/v1/campaigns/{campaign_id}/report`
Returns full campaign intelligence report including email inventory, shared indicators, and attribution analysis.

---

## 6. Infrastructure Correlation Pivots
### `GET /api/v1/infrastructure/clusters`
Finds IPs hosting multiple suspicious domains or emails.
```bash
curl -X GET "http://localhost:8000/api/v1/infrastructure/clusters?limit=10" \
  -H "X-API-Key: dev-key"
```

### `GET /api/v1/infrastructure/ip/{ip_address}`
Performs IP pivot query.
```bash
curl -X GET "http://localhost:8000/api/v1/infrastructure/ip/198.51.100.25" \
  -H "X-API-Key: dev-key"
```

### `GET /api/v1/infrastructure/domain/{domain}`
Performs Domain pivot query.
```bash
curl -X GET "http://localhost:8000/api/v1/infrastructure/domain/phish-portal.com" \
  -H "X-API-Key: dev-key"
```

---

## 7. Frontend Graph Visualization Contract (For Role 6)
All graph visualization endpoints return a standardized, JSON-serializable schema designed specifically for frontend libraries like Cytoscape.js, Vis.js, D3.js, or React Flow.

### Endpoints:
- `GET /api/v1/graph/email/{email_id}?depth=2`
- `GET /api/v1/graph/domain/{domain}?depth=2`
- `GET /api/v1/graph/ip/{ip_address}?depth=2`
- `GET /api/v1/graph/hash/{hash_value}?depth=2`
- `GET /api/v1/campaigns/{campaign_id}/graph?depth=2`
- `GET /api/v1/graph/all?limit=50`

### Frontend JSON Schema:
```json
{
  "success": true,
  "data": {
    "nodes": [
      {
        "id": "email:email-001",
        "type": "email",
        "label": "Urgent: Verify Your Account Credentials",
        "risk_score": 0.92,
        "properties": {
          "sender": "security@phish-portal.com",
          "timestamp": "2026-09-10T08:15:00Z"
        }
      },
      {
        "id": "domain:phish-portal.com",
        "type": "domain",
        "label": "phish-portal.com",
        "risk_score": 0.92,
        "properties": {}
      },
      {
        "id": "ip:198.51.100.25",
        "type": "ip",
        "label": "198.51.100.25",
        "risk_score": 0.92,
        "properties": {
          "asn": "64512"
        }
      }
    ],
    "edges": [
      {
        "id": "edge:email:email-001->domain:phish-portal.com:SENT_FROM",
        "source": "email:email-001",
        "target": "domain:phish-portal.com",
        "type": "SENT_FROM",
        "properties": {}
      },
      {
        "id": "edge:domain:phish-portal.com->ip:198.51.100.25:RESOLVES_TO",
        "source": "domain:phish-portal.com",
        "target": "ip:198.51.100.25",
        "type": "RESOLVES_TO",
        "properties": {}
      }
    ]
  },
  "error": null,
  "meta": { ... }
}
```

### Prefix Conventions for Role 6:
- `email:<email_id>`
- `domain:<domain_name>`
- `ip:<ip_address>`
- `url:<url_hash>`
- `hash:<hash_value>`
- `campaign:<campaign_id>`
- `asn:<asn_number>`
