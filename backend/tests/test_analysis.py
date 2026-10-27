"""
Comprehensive test suite for the message analysis endpoint (Milestone B02).
Verifies contract compliance, risk scoring thresholds, scam category detection,
input validation, multilingual support, and fallback behavior.
"""

import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models.schemas import RiskLevel, Verdict, ScamType
from app.ai.llm_provider import reset_llm_provider
from app.ai.engine import detect_language

client = TestClient(app)


# ── Response Contract & Field Verification ──

def test_analyze_message_response_contract():
    """Verify that POST /api/analyze/message returns all fields expected by AnalysisResultModel."""
    payload = {
        "message": "Your SBI account will be blocked today due to pending KYC. Click http://sbi-kyc-verify.online to update immediately.",
        "input_type": "sms",
        "language": "en"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Required contract fields
    assert "id" in data and isinstance(data["id"], str)
    assert "scam_type" in data and isinstance(data["scam_type"], str)
    assert "risk_score" in data and isinstance(data["risk_score"], int)
    assert "risk_level" in data and data["risk_level"] in ("SAFE", "VERIFY", "HIGH_RISK")
    assert "confidence" in data and isinstance(data["confidence"], (int, float))
    assert "summary" in data and isinstance(data["summary"], str)
    assert "explanation" in data and isinstance(data["explanation"], str)
    assert "red_flags" in data and isinstance(data["red_flags"], list)
    assert "recommended_actions" in data and isinstance(data["recommended_actions"], list)
    assert "detected_entities" in data and isinstance(data["detected_entities"], list)
    assert "score_breakdown" in data and isinstance(data["score_breakdown"], list)
    assert "input_type" in data and data["input_type"] == "sms"
    assert "input_text" in data and data["input_text"] == payload["message"]
    assert "ai_provider" in data and isinstance(data["ai_provider"], str)
    assert "verdict" in data and data["verdict"] in ("likely_scam", "suspicious", "likely_legitimate", "uncertain")
    assert "evidence" in data and isinstance(data["evidence"], list)
    assert "model_name" in data
    assert "language" in data and data["language"] == "en"
    assert "fallback_used" in data and isinstance(data["fallback_used"], bool)
    assert "fallback_reason" in data
    assert "created_at" in data and isinstance(data["created_at"], str)
    assert "disclaimer" in data and isinstance(data["disclaimer"], str)

    # Check red_flags item structure
    if data["red_flags"]:
        flag = data["red_flags"][0]
        assert "indicator" in flag
        assert "description" in flag
        assert "severity" in flag

    # Check score_breakdown item structure
    if data["score_breakdown"]:
        item = data["score_breakdown"][0]
        assert "signal" in item
        assert "points" in item
        assert "description" in item


# ── Risk Threshold Tests ──

def test_high_risk_message_threshold():
    """Verify that severe threats score >= 65 and produce HIGH_RISK."""
    payload = {
        "message": (
            "This is Deputy Commissioner of Police, Cyber Crime Branch. You are under digital arrest "
            "for money laundering. Transfer Rs 50,000 immediately to avoid arrest and stay on video call."
        ),
        "input_type": "text"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] >= 65
    assert data["risk_level"] == "HIGH_RISK"
    assert data["verdict"] == "likely_scam"
    assert data["scam_type"] == "Digital Arrest Scam"


def test_verify_medium_risk_threshold():
    """Verify that messages with some warning signals score 30–64 and produce VERIFY."""
    payload = {
        "message": "Your electricity power will be disconnected tonight at 9:30 PM. Pay bill immediately.",
        "input_type": "sms"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert 25 <= data["risk_score"] <= 64


def test_safe_legitimate_message_threshold():
    """Verify that legitimate messages score 0–29 and produce SAFE."""
    payload = {
        "message": "Hey Rahul, let's meet at the library at 5 PM to discuss the computer science project.",
        "input_type": "text"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] < 30
    assert data["risk_level"] == "SAFE"
    assert data["verdict"] == "likely_legitimate"
    assert data["scam_type"] == "Legitimate"
    assert len(data["red_flags"]) == 0


def test_legitimate_bank_transaction_dampener():
    """Verify that standard legitimate credit/debit alerts with safety advice remain SAFE."""
    payload = {
        "message": "Dear customer, your A/C ending with 4321 is credited with INR 5,000 on 26-Oct. Avail Bal: INR 24,500. Never share your OTP.",
        "input_type": "sms"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] == 0
    assert data["risk_level"] == "SAFE"
    assert data["scam_type"] == "Legitimate"


# ── Specific Scam Categories Detection ──

def test_detect_phishing():
    payload = {
        "message": "Your PAN card is unlinked with SBI bank account. Click http://bit.ly/sbi-pan-kyc to update.",
        "input_type": "sms"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scam_type"] == "Phishing"
    assert data["risk_score"] >= 30


def test_detect_fake_bank_support():
    payload = {
        "message": "SBI Customer Care: Your debit card is blocked. Call 9876543210 and share your card details and OTP.",
        "input_type": "text"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scam_type"] in ("Fake Bank Support", "Phishing")
    assert data["risk_score"] >= 40


def test_detect_investment_scam():
    payload = {
        "message": "Earn guaranteed returns of 300% within 15 days! Zero risk, 100% safe crypto trading group. Invest Rs 10000 now.",
        "input_type": "whatsapp"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scam_type"] == "Investment Scam"
    assert data["risk_score"] >= 20


def test_detect_prepaid_task_scam():
    payload = {
        "message": "Part time work from home! Like YouTube videos and earn Rs 3000 daily. Pay registration fee of Rs 999 to start.",
        "input_type": "whatsapp"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scam_type"] == "Prepaid Task / Job Scam"
    assert data["risk_score"] >= 30


def test_detect_lottery_scam():
    payload = {
        "message": "Congratulations! You have won Rs 25 Lakh in KBC Jio Lucky Draw. Call immediately to claim your prize.",
        "input_type": "sms"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scam_type"] == "Lottery / Prize Scam"
    assert data["risk_score"] >= 18


def test_detect_upi_payment_scam():
    payload = {
        "message": "Scan this QR code and enter your UPI PIN to receive refund of Rs 2500 in your bank account.",
        "input_type": "text"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scam_type"] in ("UPI / Payment Scam", "Phishing")
    assert data["risk_score"] >= 30


# ── Input Validation Tests ──

def test_validation_empty_message():
    """Verify that empty message produces 422 Unprocessable Entity."""
    response = client.post("/api/analyze/message", json={"message": ""})
    assert response.status_code == 422


def test_validation_missing_message_field():
    """Verify that omitting required message field produces 422."""
    response = client.post("/api/analyze/message", json={"input_type": "sms"})
    assert response.status_code == 422


def test_validation_oversized_message():
    """Verify that message exceeding 5000 characters produces 422."""
    huge_message = "A" * 5001
    response = client.post("/api/analyze/message", json={"message": huge_message})
    assert response.status_code == 422


def test_validation_invalid_input_type():
    """Verify that invalid input_type produces 422."""
    response = client.post("/api/analyze/message", json={"message": "Hello", "input_type": "carrier_pigeon"})
    assert response.status_code == 422


# ── Multilingual & Language Detection Tests ──

def test_language_detection_hindi():
    assert detect_language("आपका बैंक खाता बंद हो जाएगा तुरंत संपर्क करें") == "hi"


def test_language_detection_punjabi():
    assert detect_language("ਤੁਹਾਡਾ ਖਾਤਾ ਬੰਦ ਹੋ ਜਾਵੇਗਾ ਤੁਰੰਤ ਪੈਸੇ ਭੇਜੋ") == "pa"


def test_language_detection_hinglish():
    assert detect_language("Aapka account block ho gaya hai, apna OTP turant bhejo") == "hinglish"


def test_language_detection_english():
    assert detect_language("Please review the attached project schedule.") == "en"


def test_hindi_response_recommendations():
    """Verify that language='hi' yields Hindi guidance."""
    payload = {
        "message": "आपका एसबीआई खाता ब्लॉक हो जाएगा तुरंत केवाईसी अपडेट करें http://fake-sbi.xyz",
        "language": "hi"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["language"] == "hi"
    assert any("पैसे" in r or "साझा" in r or "1930" in r for r in data["recommended_actions"])


def test_punjabi_response_recommendations():
    """Verify that language='pa' yields Punjabi guidance."""
    payload = {
        "message": "ਤੁਹਾਡਾ ਬੈਂਕ ਖਾਤਾ ਬੰਦ ਹੋ ਜਾਵੇਗਾ http://fake-link.site 'ਤੇ ਕਲਿੱਕ ਕਰੋ",
        "language": "pa"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["language"] == "pa"
    assert any("ਪੈਸੇ" in r or "1930" in r for r in data["recommended_actions"])


def test_auto_language_resolution():
    """Verify that language='auto' correctly infers script and sets language field."""
    payload = {
        "message": "अपना आधार और ओटीपी तुरंत शेयर करें नहीं तो गिरफ्तारी होगी",
        "language": "auto"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["language"] == "hi"


# ── Provider Unavailable & Fallback Behavior ──

def test_fallback_behavior_when_ai_provider_unavailable():
    """When an AI provider is requested but absent, fallback engine runs safely."""
    os.environ["AI_PROVIDER"] = "litert"
    os.environ["LITERT_MODEL_PATH"] = "non_existent_weights.litertlm"
    reset_llm_provider()

    try:
        payload = {
            "message": "CBI police arrest warrant issued. Transfer Rs 25000 immediately.",
            "input_type": "text"
        }
        response = client.post("/api/analyze/message", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["fallback_used"] is True
        assert data["fallback_reason"] is not None
        assert "unavailable" in data["fallback_reason"] or "not found" in data["fallback_reason"]
        assert data["risk_score"] >= 65
        assert data["scam_type"] == "Digital Arrest Scam"
    finally:
        os.environ["AI_PROVIDER"] = "fallback"
        reset_llm_provider()


# ── Baseline Health & Root Regression ──

def test_health_check_remains_intact():
    """Ensure GET /health continues to return HTTP 200 and documented schema."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "KavachX Bharat API",
        "version": "1.0.0"
    }


def test_root_endpoint_remains_intact():
    """Ensure GET / continues to work properly."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "KavachX Bharat API"
    assert data["docs_url"] == "/docs"
