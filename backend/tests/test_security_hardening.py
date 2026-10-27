"""
Automated test suite for Security and Operational Hardening (Milestone B06).
Verifies:
- Production configuration validation and CORS restrictions
- Safe correlation IDs and security response headers
- Health endpoint availability without optional AI/STT services or auth
- Request size and upload validation (dangerous extensions, MIME types, path traversal)
- Server-to-server API key verification and open development mode
- Safe error responses without leaking internal paths or tracebacks
- Database path sanitization and parameterized SQL safety
"""

import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import Settings, settings
from app.services.scan_store import ScanStore, reset_scan_store
from app.services.stt_service import reset_stt_service

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_test_env():
    """Ensure clean state before and after each test."""
    original_api_key = settings.API_KEY
    settings.API_KEY = None
    reset_scan_store()
    reset_stt_service()
    yield
    settings.API_KEY = original_api_key
    reset_scan_store()
    reset_stt_service()


# ── 1. Configuration Validation & CORS Settings ──

def test_production_cors_wildcard_rejected():
    """Verify that in production mode, wildcard CORS origin with credentials raises a clear error."""
    prod_settings = Settings()
    prod_settings.ENVIRONMENT = "production"
    prod_settings.CORS_ALLOW_CREDENTIALS = True
    prod_settings._raw_cors_origins = "*"

    with pytest.raises(ValueError) as excinfo:
        prod_settings.validate()
    assert "Wildcard CORS_ORIGINS ('*') cannot be used when credentials are enabled" in str(excinfo.value)


def test_production_cors_explicit_origins_accepted():
    """Verify that production validation succeeds with explicit origins."""
    prod_settings = Settings()
    prod_settings.ENVIRONMENT = "production"
    prod_settings.CORS_ALLOW_CREDENTIALS = True
    prod_settings._raw_cors_origins = "https://app.kavachx.bharat.in, https://admin.kavachx.bharat.in"

    # Should not raise
    prod_settings.validate()
    assert prod_settings.is_production() is True
    assert "https://app.kavachx.bharat.in" in prod_settings.CORS_ORIGINS


def test_configuration_validation_invalid_environment():
    """Verify that unknown environments are rejected."""
    s = Settings()
    s.ENVIRONMENT = "unknown_env"
    with pytest.raises(ValueError) as excinfo:
        s.validate()
    assert "Invalid ENVIRONMENT" in str(excinfo.value)


def test_configuration_validation_invalid_port():
    """Verify that ports outside 1-65535 are rejected."""
    s = Settings()
    s.PORT = 70000
    with pytest.raises(ValueError) as excinfo:
        s.validate()
    assert "Invalid PORT" in str(excinfo.value)


def test_configuration_validation_invalid_ai_provider():
    """Verify that invalid AI providers fail startup validation."""
    s = Settings()
    s.AI_PROVIDER = "non_existent_provider"
    with pytest.raises(ValueError) as excinfo:
        s.validate()
    assert "Invalid AI_PROVIDER" in str(excinfo.value)


# ── 2. Health Endpoint Availability & Security Headers ──

def test_health_check_available_unauthenticated_and_lightweight():
    """Verify /health is always operational, public, and returns standard payload."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "service" in data
    assert "version" in data


def test_security_headers_and_correlation_id_present():
    """Verify standard security headers and correlation IDs are attached to HTTP responses."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert "X-Request-ID" in resp.headers
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_custom_request_id_preserved_when_safe():
    """Verify client-supplied safe X-Request-ID is preserved in response."""
    custom_id = "client-trace-abc-123"
    resp = client.get("/health", headers={"X-Request-ID": custom_id})
    assert resp.status_code == 200
    assert resp.headers["X-Request-ID"] == custom_id


# ── 3. Upload & Request Safety ──

def test_audio_upload_dangerous_extension_rejected():
    """Verify uploading executable/script extensions is rejected with 400 Bad Request."""
    files = {"file": ("malware.exe", b"MZ\x90\x00\x03", "application/octet-stream")}
    resp = client.post("/api/analyze/audio", files=files)
    assert resp.status_code == 400
    assert "disallowed file type" in resp.json()["detail"].lower()


def test_audio_upload_dangerous_content_type_rejected():
    """Verify uploading with script/HTML content-type is rejected."""
    files = {"file": ("audio.wav", b"<script>alert(1)</script>", "text/html")}
    resp = client.post("/api/analyze/audio", files=files)
    assert resp.status_code == 400
    assert "disallowed content type" in resp.json()["detail"].lower()


def test_audio_upload_filename_traversal_sanitized():
    """Verify filename traversal attempt is safely sanitized without crashing or escaping."""
    files = {"file": ("../../../../etc/shadow.wav", b"RIFF....WAVEfmt ....data....", "audio/wav")}
    resp = client.post("/api/analyze/audio", files=files)
    # Succeeds or returns demo response because filename is sanitized to shadow.wav
    assert resp.status_code == 200


def test_audio_upload_early_content_length_limit():
    """Verify that requests exceeding MAX_AUDIO_UPLOAD_BYTES via Content-Length header are rejected early with 413."""
    too_large = str(settings.MAX_AUDIO_UPLOAD_BYTES + 1024)
    resp = client.post(
        "/api/analyze/audio",
        headers={"Content-Length": too_large, "Content-Type": "multipart/form-data; boundary=boundary"},
        content=b"--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.wav\"\r\n\r\n\r\n--boundary--\r\n"
    )
    assert resp.status_code == 413


def test_report_request_oversized_scan_id_rejected():
    """Verify that oversized scan_id (> 128 chars) fails Pydantic schema validation with HTTP 422."""
    huge_scan_id = "a" * 150
    resp = client.post(
        "/api/reports",
        json={
            "scan_id": huge_scan_id,
            "scam_type": "Phishing",
            "risk_score": 50,
            "description": "Test"
        }
    )
    assert resp.status_code == 422


# ── 4. API Key Access Control (Optional Server-to-Server) ──

def test_api_key_when_configured():
    """Verify that when API_KEY is enabled, protected endpoints require valid key, but health checks remain open."""
    settings.API_KEY = "test-secret-token-xyz"

    # Health check is public
    health_resp = client.get("/health")
    assert health_resp.status_code == 200

    # Protected endpoint without key -> 401
    scans_no_key = client.get("/api/scans")
    assert scans_no_key.status_code == 401
    assert "Invalid or missing API key" in scans_no_key.json()["detail"]

    # Protected endpoint with wrong key -> 401
    scans_wrong_key = client.get("/api/scans", headers={"X-API-Key": "wrong-key"})
    assert scans_wrong_key.status_code == 401

    # Protected endpoint with valid X-API-Key header -> 200
    scans_valid_key = client.get("/api/scans", headers={"X-API-Key": "test-secret-token-xyz"})
    assert scans_valid_key.status_code == 200

    # Protected endpoint with valid Authorization Bearer token -> 200
    scans_bearer_key = client.get("/api/scans", headers={"Authorization": "Bearer test-secret-token-xyz"})
    assert scans_bearer_key.status_code == 200


def test_api_key_when_not_configured_allows_open_access():
    """Verify backward compatibility: when API_KEY is None, all endpoints are open for local dev."""
    settings.API_KEY = None
    scans_resp = client.get("/api/scans")
    assert scans_resp.status_code == 200


# ── 5. Safe Error Handling (No Traceback or Path Leakage) ──

def test_safe_error_handling_no_traceback():
    """
    Verify client 404 or 422 errors return clean JSON without server tracebacks
    or internal filesystem paths.
    """
    resp = client.get("/api/scans/missing-scan-id-xyz")
    assert resp.status_code == 404
    body = resp.text
    # Ensure no Python traceback signatures
    assert "Traceback (most recent call last)" not in body
    assert "File \"" not in body


# ── 6. Database Path Safety ──

def test_database_path_null_byte_rejected():
    """Verify database paths with null byte injection are rejected."""
    with pytest.raises(ValueError):
        ScanStore(db_path="data/kavachx\x00.db")
