def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["service"] == "Role 4 — Graph & Campaign Correlation"
    assert "schema_version" in data


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    res = response.json()
    assert res["success"] is True
    assert "data" in res
    assert "primary_endpoints" in res["data"]
    assert "attribution_policy" in res["data"]
