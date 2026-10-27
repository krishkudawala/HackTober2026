"""
Automated test suite for Call Transcript and Audio Upload analysis (Milestone B03).
Verifies transcript analysis contract, input_type coherence, upload size validation,
demo mode fallback, and mockable STT service pipeline execution.
"""

import io
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models.schemas import RiskLevel, ScamType
from app.services.stt_service import (
    SpeechToTextService,
    get_stt_service,
    set_stt_service,
    reset_stt_service,
)
from app.core.config import settings

client = TestClient(app)


@pytest.fixture(autouse=True)
def cleanup_stt_service():
    """Ensure STT service singleton is restored to default after every test."""
    yield
    reset_stt_service()


# ── Transcript Endpoint Tests ──

def test_transcript_endpoint_success():
    """Verify that POST /api/analyze/transcript executes the shared analysis pipeline."""
    payload = {
        "transcript": (
            "Caller: I am Senior Inspector Sharma from Mumbai Crime Branch. Your Aadhaar is linked to illegal narcotics. "
            "You are placed on digital arrest. Do not disconnect this call or tell anyone. Transfer Rs 25,000 to verify account."
        ),
        "source_info": "Phone +91-9876543210",
        "language": "en"
    }
    response = client.post("/api/analyze/transcript", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Reuses shared analysis schema
    assert "id" in data
    assert data["scam_type"] == "Digital Arrest Scam"
    assert data["risk_score"] >= 65
    assert data["risk_level"] == "HIGH_RISK"
    assert data["verdict"] == "likely_scam"

    # Input type coherence
    assert data["input_type"] == "call_transcript"
    assert data["input_text"] == payload["transcript"]
    assert len(data["red_flags"]) > 0
    assert len(data["recommended_actions"]) > 0


def test_transcript_endpoint_legitimate():
    """Verify that a normal conversational transcript is classified as SAFE."""
    payload = {
        "transcript": (
            "Hey Mom, just wanted to check if you reached home safely. "
            "Dinner was delicious, let's talk tomorrow morning. Take care!"
        ),
        "language": "en"
    }
    response = client.post("/api/analyze/transcript", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["scam_type"] == "Legitimate"
    assert data["risk_score"] < 30
    assert data["risk_level"] == "SAFE"
    assert data["input_type"] == "call_transcript"


def test_transcript_validation_empty():
    """Verify that empty transcript yields HTTP 422."""
    response = client.post("/api/analyze/transcript", json={"transcript": ""})
    assert response.status_code == 422


def test_transcript_validation_missing_field():
    """Verify that missing transcript field yields HTTP 422."""
    response = client.post("/api/analyze/transcript", json={"source_info": "+919999999999"})
    assert response.status_code == 422


def test_transcript_validation_oversized():
    """Verify that transcript exceeding 10000 characters yields HTTP 422."""
    huge_text = "Transcript line. " * 700  # > 10,000 characters
    response = client.post("/api/analyze/transcript", json={"transcript": huge_text})
    assert response.status_code == 422


# ── Audio Upload & Demo Mode Tests ──

def test_audio_endpoint_demo_mode_default():
    """
    Verify that in default demo mode, uploading audio returns a clear demo response
    with empty transcript and null analysis, asking user to paste manually.
    """
    fake_audio = b"RIFF....WAVEfmt ....data...."
    files = {"file": ("recording.wav", fake_audio, "audio/wav")}
    response = client.post("/api/analyze/audio", files=files)

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "demo_mode"
    assert data["provider"] == "demo"
    assert data["transcript"] == ""
    assert data["analysis"] is None
    assert "demo mode" in data["message"].lower()
    assert "paste" in data["message"].lower()


def test_audio_upload_empty_file():
    """Verify that uploading an empty audio file yields HTTP 400."""
    files = {"file": ("empty.wav", b"", "audio/wav")}
    response = client.post("/api/analyze/audio", files=files)
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_audio_upload_size_limit_exceeded(monkeypatch):
    """Verify that an audio file exceeding MAX_AUDIO_UPLOAD_BYTES yields HTTP 413."""
    # Temporarily set upload limit to 100 bytes for test
    monkeypatch.setattr(settings, "MAX_AUDIO_UPLOAD_BYTES", 100)

    oversized_data = b"X" * 150
    files = {"file": ("large_recording.wav", oversized_data, "audio/wav")}
    response = client.post("/api/analyze/audio", files=files)

    assert response.status_code == 413
    assert "maximum allowed size" in response.json()["detail"].lower()


# ── Mockable STT Service Integration Tests ──

class MockSuccessSTTService(SpeechToTextService):
    """Mock STT service simulating successful transcription."""
    def __init__(self, transcript_to_return: str):
        super().__init__(provider="mock_stt")
        self.mock_transcript = transcript_to_return

    def is_available(self) -> bool:
        return True

    async def transcribe(self, audio_data: bytes, filename: str = "", language: str = "en"):
        return {
            "status": "success",
            "message": None,
            "provider": "mock_stt",
            "transcript": self.mock_transcript,
            "is_demo": False,
        }


class MockFailingSTTService(SpeechToTextService):
    """Mock STT service simulating transcription failure."""
    def __init__(self):
        super().__init__(provider="failing_stt")

    def is_available(self) -> bool:
        return True

    async def transcribe(self, audio_data: bytes, filename: str = "", language: str = "en"):
        return {
            "status": "error",
            "message": "Audio decoder failed: corrupt bitstream",
            "provider": "failing_stt",
            "transcript": "",
            "is_demo": False,
        }


def test_audio_successful_transcription_and_shared_analysis():
    """Verify that successful transcription pipes through shared analysis with input_type='audio'."""
    suspicious_spoken_text = (
        "This is CBI Crime Branch. You are under digital arrest. "
        "Transfer Rs 50,000 immediately to avoid arrest warrant."
    )
    mock_service = MockSuccessSTTService(transcript_to_return=suspicious_spoken_text)
    set_stt_service(mock_service)

    fake_audio = b"MOCK_PCM_AUDIO_DATA_FOR_SPEECH_RECOGNITION"
    files = {"file": ("call_intercept.wav", fake_audio, "audio/wav")}
    response = client.post("/api/analyze/audio", files=files, data={"language": "en"})

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "success"
    assert data["provider"] == "mock_stt"
    assert data["transcript"] == suspicious_spoken_text
    assert data["analysis"] is not None

    # Verify analysis result contents
    analysis = data["analysis"]
    assert analysis["input_type"] == "audio"
    assert analysis["scam_type"] == "Digital Arrest Scam"
    assert analysis["risk_score"] >= 65
    assert analysis["risk_level"] == "HIGH_RISK"
    assert analysis["verdict"] == "likely_scam"


def test_audio_transcription_failure():
    """Verify that transcription errors return a clear error response without fabricating analysis."""
    mock_service = MockFailingSTTService()
    set_stt_service(mock_service)

    fake_audio = b"GARBLED_AUDIO_BYTES"
    files = {"file": ("corrupt.wav", fake_audio, "audio/wav")}
    response = client.post("/api/analyze/audio", files=files)

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "error"
    assert data["provider"] == "failing_stt"
    assert data["transcript"] == ""
    assert data["analysis"] is None
    assert "corrupt bitstream" in data["message"]
