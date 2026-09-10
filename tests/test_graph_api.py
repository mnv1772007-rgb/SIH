from unittest.mock import patch
from app.models.graph_models import FrontendGraphResponse, FrontendNode, FrontendEdge


def test_auth_failure_missing_header(client):
    resp = client.get("/api/v1/graph/stats")
    assert resp.status_code == 401
    data = resp.json()
    assert data["success"] is False
    assert data["error"]["code"] == "UNAUTHORIZED"


def test_auth_failure_invalid_key(client):
    resp = client.get("/api/v1/graph/stats", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401
    data = resp.json()
    assert data["success"] is False
    assert data["error"]["code"] == "UNAUTHORIZED"


def test_get_stats_with_valid_key(client, api_headers):
    resp = client.get("/api/v1/graph/stats", headers=api_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "data" in data
    assert "total_nodes" in data["data"]
    assert "meta" in data
    assert data["meta"]["schema_version"] == "1.0"


def test_ingest_analysis_endpoint(client, api_headers):
    payload = {
        "schema_version": "1.0",
        "analysis_id": "analysis-test-01",
        "email": {
            "email_id": "email-test-01",
            "message_id": "<test01@example.com>",
            "subject": "Test Security Alert",
            "sender": "alert@phishing-test.com",
            "recipient": "user@corp.org",
            "timestamp": "2026-09-10T10:00:00Z",
        },
        "authentication": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "iocs": {
            "domains": [{"value": "phishing-test.com"}],
            "ips": [{"value": "198.51.100.30"}],
            "urls": [{"value": "https://phishing-test.com/login"}],
            "hashes": [{"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
        },
        "detection": {"classification": "phishing", "risk_score": 0.90, "confidence": 0.95},
    }

    resp = client.post("/api/v1/graph/ingest", json=payload, headers=api_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["success"] is True
    assert data["data"]["email_id"] == "email-test-01"


def test_route_collision_infrastructure_clusters(client, api_headers):
    """Verifies that /api/v1/infrastructure/clusters does not collide with /{campaign_id}."""
    resp = client.get("/api/v1/infrastructure/clusters", headers=api_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert isinstance(data["data"], list)


def test_nonexistent_email_returns_404(client, api_headers):
    resp = client.get("/api/v1/graph/email/nonexistent-id", headers=api_headers)
    assert resp.status_code == 404
    data = resp.json()
    assert data["success"] is False
    assert data["error"]["code"] == "ENTITY_NOT_FOUND"


def test_frontend_graph_schema_serialization():
    graph = FrontendGraphResponse(
        nodes=[
            FrontendNode(
                id="email:123",
                type="email",
                label="Test Subject",
                risk_score=0.85,
                properties={"sender": "test@evil.com"},
            )
        ],
        edges=[
            FrontendEdge(
                id="edge:1",
                source="email:123",
                target="domain:evil.com",
                type="SENT_FROM",
                properties={},
            )
        ],
    )
    serialized = graph.model_dump()
    assert len(serialized["nodes"]) == 1
    assert serialized["nodes"][0]["id"] == "email:123"
    assert serialized["edges"][0]["source"] == "email:123"
