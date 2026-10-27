"""
Automated test suite for Scan History, Reports, Dashboard Stats, and Demo Scenarios (Milestone B04).
Verifies scan persistence across all analysis paths, 404 handling, report validation,
deterministic statistical threshold derivations, and demo scenario execution.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models.schemas import AnalysisResult, RiskLevel, ScamType
from app.services.scan_store import get_scan_store, reset_scan_store
from app.services.stt_service import SpeechToTextService, set_stt_service, reset_stt_service

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_state():
    """Ensure in-memory scan store and STT service are isolated per test."""
    reset_scan_store()
    reset_stt_service()
    yield
    reset_scan_store()
    reset_stt_service()


# ── Scan Persistence Across Endpoints & History Listing ──

def test_scan_saved_via_message_endpoint():
    """Verify that analyzing a message automatically persists a scan record."""
    payload = {
        "message": "Your SBI account KYC is expired. Click http://fake-sbi.xyz to verify immediately.",
        "input_type": "sms"
    }
    resp = client.post("/api/analyze/message", json=payload)
    assert resp.status_code == 200
    scan_id = resp.json()["id"]

    # Retrieve all scans
    scans_resp = client.get("/api/scans")
    assert scans_resp.status_code == 200
    records = scans_resp.json()

    assert len(records) >= 1
    assert any(r["id"] == scan_id for r in records)

    # Check summary record schema
    record = next(r for r in records if r["id"] == scan_id)
    assert record["scam_type"] == "Phishing"
    assert record["risk_score"] >= 30
    assert record["input_type"] == "sms"
    assert "summary" in record
    assert "created_at" in record


def test_scan_saved_via_transcript_endpoint():
    """Verify that analyzing a transcript automatically persists a scan record."""
    payload = {
        "transcript": "CBI Officer: You are under digital arrest. Transfer Rs 25,000 right now.",
        "input_type": "call_transcript"
    }
    resp = client.post("/api/analyze/transcript", json=payload)
    assert resp.status_code == 200
    scan_id = resp.json()["id"]

    scans_resp = client.get("/api/scans")
    assert scans_resp.status_code == 200
    records = scans_resp.json()
    assert any(r["id"] == scan_id and r["input_type"] == "call_transcript" for r in records)


class MockSTTSuccess(SpeechToTextService):
    def is_available(self) -> bool:
        return True

    async def transcribe(self, audio_data: bytes, filename: str = "", language: str = "en"):
        return {
            "status": "success",
            "message": None,
            "provider": "mock",
            "transcript": "Urgent CBI warrant transfer Rs 50000 immediately.",
            "is_demo": False,
        }


def test_scan_saved_via_audio_endpoint_on_successful_transcription():
    """Verify that successful audio analysis automatically persists a scan record."""
    set_stt_service(MockSTTSuccess(provider="mock"))

    files = {"file": ("call.wav", b"AUDIO_BYTES", "audio/wav")}
    resp = client.post("/api/analyze/audio", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    scan_id = data["analysis"]["id"]

    scans_resp = client.get("/api/scans")
    assert scans_resp.status_code == 200
    records = scans_resp.json()
    assert any(r["id"] == scan_id and r["input_type"] == "audio" for r in records)


def test_scans_listed_newest_first():
    """Verify that scans are ordered newest first by timestamp."""
    # Analyze first message
    r1 = client.post("/api/analyze/message", json={"message": "First message"})
    # Analyze second message
    r2 = client.post("/api/analyze/message", json={"message": "Second message"})

    id1 = r1.json()["id"]
    id2 = r2.json()["id"]

    scans_resp = client.get("/api/scans")
    records = scans_resp.json()

    # Most recent scan should be first
    assert records[0]["id"] == id2
    assert records[1]["id"] == id1


# ── Single Scan Retrieval ──

def test_get_scan_by_id_success():
    """Verify fetching full scan details by ID."""
    resp = client.post("/api/analyze/message", json={"message": "Test analysis message"})
    scan_id = resp.json()["id"]

    fetch_resp = client.get(f"/api/scans/{scan_id}")
    assert fetch_resp.status_code == 200
    detail = fetch_resp.json()

    assert detail["id"] == scan_id
    assert "red_flags" in detail
    assert "recommended_actions" in detail
    assert "score_breakdown" in detail
    assert detail["input_text"] == "Test analysis message"


def test_get_scan_by_id_not_found():
    """Verify HTTP 404 for an unknown scan ID."""
    resp = client.get("/api/scans/non-existent-scan-uuid")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ── Incident Reports ──

def test_create_report_success():
    """Verify successful report recording for an existing scan."""
    # 1. Create a scan
    scan_resp = client.post("/api/analyze/message", json={
        "message": "CBI arrest threat transfer Rs 10000"
    })
    scan_id = scan_resp.json()["id"]

    # 2. Submit report
    report_payload = {
        "scan_id": scan_id,
        "scam_type": "Digital Arrest Scam",
        "risk_score": 75,
        "description": "Caller claimed to be police officer and demanded money.",
        "communication_source": "+91-9876543210"
    }
    report_resp = client.post("/api/reports", json=report_payload)
    assert report_resp.status_code == 200
    data = report_resp.json()

    assert "id" in data
    assert data["scan_id"] == scan_id
    assert data["status"] == "recorded"
    assert "1930" in data["message"]
    assert "created_at" in data


def test_create_report_nonexistent_scan_404():
    """Verify HTTP 404 when submitting a report for a nonexistent scan_id."""
    report_payload = {
        "scan_id": "non-existent-scan-id",
        "scam_type": "Phishing",
        "risk_score": 50,
        "description": "Fake SMS"
    }
    resp = client.post("/api/reports", json=report_payload)
    assert resp.status_code == 404
    assert "does not exist" in resp.json()["detail"].lower()


def test_create_report_validation_invalid_score():
    """Verify validation error when risk_score is outside 0-100."""
    report_payload = {
        "scan_id": "any-id",
        "scam_type": "Phishing",
        "risk_score": 150
    }
    resp = client.post("/api/reports", json=report_payload)
    assert resp.status_code == 422


# ── Dashboard Statistics & Boundary Thresholds ──

def test_dashboard_stats_boundary_thresholds():
    """
    Test dashboard stats counts at the exact boundary thresholds:
    - total_scans: total count
    - threats_detected: risk_score >= 30 (SAFE: 0-29, VERIFY: 30-64, HIGH_RISK: 65-100)
    - high_risk_alerts: risk_score >= 65
    - critical_alerts: risk_score >= 80
    """
    import asyncio
    store = get_scan_store()

    def make_scan(score: int, level: RiskLevel):
        return AnalysisResult(
            scam_type="Test",
            risk_score=score,
            risk_level=level,
            confidence=0.9,
            summary="Test",
            explanation="Test",
            input_text="Test"
        )

    # Boundary cases:
    # Score 29 (SAFE): not threat, not high, not critical
    asyncio.run(store.save_scan(make_scan(29, RiskLevel.SAFE)))
    # Score 30 (VERIFY boundary): threat, not high, not critical
    asyncio.run(store.save_scan(make_scan(30, RiskLevel.VERIFY)))
    # Score 64 (VERIFY boundary): threat, not high, not critical
    asyncio.run(store.save_scan(make_scan(64, RiskLevel.VERIFY)))
    # Score 65 (HIGH_RISK boundary): threat, high, not critical
    asyncio.run(store.save_scan(make_scan(65, RiskLevel.HIGH_RISK)))
    # Score 79 (HIGH_RISK): threat, high, not critical
    asyncio.run(store.save_scan(make_scan(79, RiskLevel.HIGH_RISK)))
    # Score 80 (Critical boundary): threat, high, critical
    asyncio.run(store.save_scan(make_scan(80, RiskLevel.HIGH_RISK)))

    stats_resp = client.get("/api/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()

    assert stats["total_scans"] == 6
    assert stats["threats_detected"] == 5  # scores 30, 64, 65, 79, 80
    assert stats["high_risk_alerts"] == 3  # scores 65, 79, 80
    assert stats["critical_alerts"] == 1   # score 80
    assert stats["protection_status"] == "active"



# ── Preset Demo Scenarios ──

def test_list_demo_scenarios():
    """Verify listing all preset demo scenarios."""
    resp = client.get("/api/demo/scenarios")
    assert resp.status_code == 200
    scenarios = resp.json()

    assert len(scenarios) >= 6
    expected_ids = {
        "demo_digital_arrest",
        "demo_fake_bank",
        "demo_investment",
        "demo_task_scam",
        "demo_phishing",
        "demo_upi_scam",
        "demo_legitimate"
    }
    actual_ids = {s["id"] for s in scenarios}
    assert expected_ids.issubset(actual_ids)

    # Verify scenario presentation fields
    for s in scenarios:
        assert "id" in s
        assert "name" in s
        assert "description" in s
        assert "input_text" in s
        assert "input_type" in s
        assert "expected_scam_type" in s
        assert "expected_risk_level" in s


def test_run_demo_scenario_success():
    """Verify running a demo scenario executes shared analysis and stores scan."""
    resp = client.post("/api/demo/run/demo_digital_arrest")
    assert resp.status_code == 200
    data = resp.json()

    assert data["scam_type"] == "Digital Arrest Scam"
    assert data["risk_score"] >= 65
    assert data["risk_level"] == "HIGH_RISK"
    assert data["input_type"] == "call_transcript"
    scan_id = data["id"]

    # Verify scan was stored
    scan_resp = client.get(f"/api/scans/{scan_id}")
    assert scan_resp.status_code == 200
    assert scan_resp.json()["id"] == scan_id


def test_run_demo_scenario_not_found_404():
    """Verify HTTP 404 for an invalid scenario ID."""
    resp = client.post("/api/demo/run/invalid_scenario_id")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()
