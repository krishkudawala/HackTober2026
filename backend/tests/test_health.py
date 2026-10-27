"""
Automated tests for health check and core endpoints.
"""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check_status_code():
    """Verify GET /health returns HTTP 200."""
    response = client.get("/health")
    assert response.status_code == 200


def test_health_check_payload():
    """Verify GET /health returns the exact expected schema and values."""
    response = client.get("/health")
    data = response.json()
    assert data == {
        "status": "ok",
        "service": "KavachX Bharat API",
        "version": "1.0.0"
    }


def test_root_endpoint():
    """Verify GET / returns HTTP 200 with service metadata."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "KavachX Bharat API"
    assert data["health_url"] == "/health"
    assert data["docs_url"] == "/docs"


def test_docs_accessible():
    """Verify FastAPI interactive documentation at /docs is accessible."""
    response = client.get("/docs")
    assert response.status_code == 200
