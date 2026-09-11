import os
import sys
from pathlib import Path
import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

# Ensure hermetic fast testing without external API stalls
os.environ["THREAT_INTELLIGENCE_ENABLED"] = "false"
os.environ["AI_FORENSIC_ENABLED"] = "false"

# Ensure app package is importable
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from app.main import app
from app.services.neo4j_service import neo4j_service
from app.config import API_KEY


@pytest.fixture
def api_headers():
    return {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json",
    }


@pytest.fixture
def mock_neo4j():
    """Mock Neo4j service for hermetic unit testing without live Neo4j daemon."""
    original_driver = neo4j_service.driver
    original_connected = neo4j_service.connected

    neo4j_service.connected = True
    neo4j_service.driver = MagicMock()
    mock_session = MagicMock()
    neo4j_service.driver.session.return_value.__enter__.return_value = mock_session

    yield mock_session

    neo4j_service.driver = original_driver
    neo4j_service.connected = original_connected


@pytest.fixture
def client(mock_neo4j):
    """TestClient configured with mocked Neo4j."""
    with TestClient(app) as test_client:
        yield test_client
