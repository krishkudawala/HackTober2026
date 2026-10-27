"""
Automated test suite for Durable Local Persistence (Milestone B05).
Verifies:
- Data surviving store re-instantiation using the same SQLite database file
- Complete serialization and deserialization fidelity for AnalysisResult
- Scan creation, newest-first ordering, and single retrieval
- Report persistence and rejection on missing scan ID
- Aggregate statistics calculation at exact risk thresholds (30, 65, 80)
- Duplicate ID handling and database initialization resilience
- API endpoint integration and health check preservation
"""

import asyncio
import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.schemas import (
    AnalysisResult,
    RiskLevel,
    ScamType,
    RedFlag,
    RiskScoreBreakdown,
    ReportRequest,
)
from app.services.scan_store import ScanStore, get_scan_store, reset_scan_store


@pytest.fixture
def temp_db_path():
    """Provides an isolated temporary database path within a temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_kavachx.db")
        yield db_path


# ── 1. Data Surviving Store Re-instantiation ──

def test_data_survives_new_store_instance(temp_db_path):
    """
    Verify that scan and report data written by one ScanStore instance
    remains durable and queryable by a brand new instance pointing to the same SQLite file.
    """
    store1 = ScanStore(db_path=temp_db_path)
    store1.initialize_sync()

    sample_scan = AnalysisResult(
        id="scan-persistence-test-01",
        scam_type=ScamType.DIGITAL_ARREST.value,
        risk_score=85,
        risk_level=RiskLevel.HIGH_RISK,
        confidence=0.95,
        summary="Digital arrest scam detected with aggressive police threats.",
        explanation="Impersonation of enforcement agency and demand for immediate fund transfer.",
        red_flags=[
            RedFlag(indicator="impersonation", description="Police agency claim", severity="critical")
        ],
        score_breakdown=[
            RiskScoreBreakdown(signal="authority_intimidation", points=50, description="Claims arrest warrant")
        ],
        evidence=["CBI Officer: Transfer money right now"],
        signals=["authority_intimidation", "threat_urgency"],
        input_type="call_transcript",
        input_text="Transfer 50000 immediately or face arrest.",
        ai_provider="fallback",
        verdict="likely_scam",
        language="en",
        fallback_used=True,
    )

    # Save using store1
    asyncio.run(store1.save_scan(sample_scan))

    # Add a report using store1
    report_req = ReportRequest(
        scan_id="scan-persistence-test-01",
        scam_type=ScamType.DIGITAL_ARREST.value,
        risk_score=85,
        description="Caller claimed to be a police officer demanding funds.",
        communication_source="Phone Call"
    )
    report_resp = asyncio.run(store1.save_report(report_req))
    assert report_resp.scan_id == "scan-persistence-test-01"

    # Dereference store1 and instantiate store2 on the same database file
    del store1

    store2 = ScanStore(db_path=temp_db_path)
    # Fetch scan with store2
    retrieved = asyncio.run(store2.get_scan("scan-persistence-test-01"))
    assert retrieved is not None
    assert retrieved.id == "scan-persistence-test-01"
    assert retrieved.scam_type == ScamType.DIGITAL_ARREST.value
    assert retrieved.risk_score == 85
    assert retrieved.risk_level == RiskLevel.HIGH_RISK
    assert len(retrieved.red_flags) == 1
    assert retrieved.red_flags[0].indicator == "impersonation"
    assert len(retrieved.score_breakdown) == 1
    assert retrieved.score_breakdown[0].points == 50

    # Verify stats persisted
    stats = store2.get_stats()
    assert stats.total_scans == 1
    assert stats.threats_detected == 1
    assert stats.high_risk_alerts == 1
    assert stats.critical_alerts == 1


# ── 2. Serialization & Deserialization Fidelity ──

def test_full_analysis_result_schema_fidelity(temp_db_path):
    """
    Verify 100% preservation of all fields, nested objects, enums,
    and metadata in AnalysisResult across persistence cycle.
    """
    store = ScanStore(db_path=temp_db_path)
    store.initialize_sync()

    complex_result = AnalysisResult(
        id="full-fidelity-test-id",
        scam_type=ScamType.PHISHING.value,
        risk_score=78,
        risk_level=RiskLevel.HIGH_RISK,
        confidence=0.89,
        summary="Phishing attempt targeting netbanking credentials.",
        explanation="Suspicious URL detected imitating official bank portal with urgent KYC demands.",
        red_flags=[
            RedFlag(indicator="fake_domain", description="Domain fake-sbi.xyz is not official", severity="high"),
            RedFlag(indicator="urgency", description="Urgent deadline threatened", severity="medium"),
        ],
        recommended_actions=[
            "Do not click the link",
            "Report to cybercrime portal 1930",
            "Contact your bank directly"
        ],
        detected_entities=["SBI", "http://fake-sbi.xyz", "Rs 10,000"],
        score_breakdown=[
            RiskScoreBreakdown(signal="suspicious_link", points=40, description="Non-official domain"),
            RiskScoreBreakdown(signal="kyc_expiry", points=38, description="Simulated urgency"),
        ],
        input_type="sms",
        input_text="Dear customer, your SBI KYC expired. Visit http://fake-sbi.xyz",
        ai_provider="ollama",
        verdict="likely_scam",
        evidence=["fake-sbi.xyz", "KYC expired"],
        model_name="qwen2.5:1.5b",
        language="en",
        fallback_used=False,
        fallback_reason=None,
        signals=["suspicious_link", "kyc_expiry"],
        analysis_mode="hybrid",
        analysis_complete=True,
        warnings=["Rate limit check passed"],
        created_at="2026-10-27T10:30:00+00:00",
        disclaimer="AI-generated risk assessment. Verify critical decisions through official channels."
    )

    asyncio.run(store.save_scan(complex_result))
    retrieved = asyncio.run(store.get_scan("full-fidelity-test-id"))

    assert retrieved is not None
    assert retrieved.id == complex_result.id
    assert retrieved.scam_type == complex_result.scam_type
    assert retrieved.risk_score == complex_result.risk_score
    assert retrieved.risk_level == RiskLevel.HIGH_RISK
    assert retrieved.confidence == 0.89
    assert retrieved.summary == complex_result.summary
    assert retrieved.explanation == complex_result.explanation
    assert len(retrieved.red_flags) == 2
    assert retrieved.red_flags[0].indicator == "fake_domain"
    assert retrieved.red_flags[1].severity == "medium"
    assert retrieved.recommended_actions == ["Do not click the link", "Report to cybercrime portal 1930", "Contact your bank directly"]
    assert retrieved.detected_entities == ["SBI", "http://fake-sbi.xyz", "Rs 10,000"]
    assert len(retrieved.score_breakdown) == 2
    assert retrieved.score_breakdown[0].points == 40
    assert retrieved.input_type == "sms"
    assert retrieved.input_text == complex_result.input_text
    assert retrieved.ai_provider == "ollama"
    assert retrieved.verdict == "likely_scam"
    assert retrieved.evidence == ["fake-sbi.xyz", "KYC expired"]
    assert retrieved.model_name == "qwen2.5:1.5b"
    assert retrieved.language == "en"
    assert retrieved.fallback_used is False
    assert retrieved.fallback_reason is None
    assert retrieved.signals == ["suspicious_link", "kyc_expiry"]
    assert retrieved.analysis_mode == "hybrid"
    assert retrieved.analysis_complete is True
    assert retrieved.warnings == ["Rate limit check passed"]
    assert retrieved.created_at == "2026-10-27T10:30:00+00:00"
    assert retrieved.disclaimer == complex_result.disclaimer


# ── 3. Scan History Ordering (Newest First) & Lookups ──

def test_scan_history_newest_first_and_lookup(temp_db_path):
    """
    Verify scan summary list is strictly sorted newest first, and
    retrieval by ID returns exact match or None.
    """
    store = ScanStore(db_path=temp_db_path)
    store.initialize_sync()

    scan1 = AnalysisResult(
        id="scan-oldest",
        scam_type=ScamType.LEGITIMATE.value,
        risk_score=10,
        risk_level=RiskLevel.SAFE,
        confidence=0.9,
        summary="Safe transactional alert",
        explanation="Standard bank debit notification.",
        created_at="2026-10-27T08:00:00+00:00"
    )
    scan2 = AnalysisResult(
        id="scan-middle",
        scam_type=ScamType.VERIFY if hasattr(ScamType, "VERIFY") else ScamType.UNKNOWN.value,
        risk_score=45,
        risk_level=RiskLevel.VERIFY,
        confidence=0.75,
        summary="Unverified promotional offer",
        explanation="Contains urgent call to action.",
        created_at="2026-10-27T09:00:00+00:00"
    )
    scan3 = AnalysisResult(
        id="scan-newest",
        scam_type=ScamType.UPI_PAYMENT_SCAM.value,
        risk_score=90,
        risk_level=RiskLevel.HIGH_RISK,
        confidence=0.98,
        summary="Fraudulent collect request",
        explanation="Asking to approve UPI collect request to receive cashback.",
        created_at="2026-10-27T10:00:00+00:00"
    )

    # Insert in non-chronological order
    asyncio.run(store.save_scan(scan2))
    asyncio.run(store.save_scan(scan1))
    asyncio.run(store.save_scan(scan3))

    all_scans = asyncio.run(store.get_all_scans())
    assert len(all_scans) == 3
    # First item must be newest
    assert all_scans[0].id == "scan-newest"
    assert all_scans[0].created_at == "2026-10-27T10:00:00+00:00"
    # Second item
    assert all_scans[1].id == "scan-middle"
    assert all_scans[1].created_at == "2026-10-27T09:00:00+00:00"
    # Third item
    assert all_scans[2].id == "scan-oldest"
    assert all_scans[2].created_at == "2026-10-27T08:00:00+00:00"

    # Non-existent scan lookup
    assert asyncio.run(store.get_scan("non-existent-scan-id")) is None


# ── 4. Report Persistence and Foreign Key Rejection ──

def test_report_persistence_and_rejection_on_missing_scan(temp_db_path):
    """
    Verify report saving succeeds for valid scan IDs and is rejected
    when referenced scan does not exist.
    """
    store = ScanStore(db_path=temp_db_path)
    store.initialize_sync()

    # Save legitimate scan first
    scan = AnalysisResult(
        id="scan-valid-01",
        scam_type=ScamType.INVESTMENT_SCAM.value,
        risk_score=75,
        risk_level=RiskLevel.HIGH_RISK,
        confidence=0.85,
        summary="Fake trading group offer",
        explanation="Guaranteed 200% return promise.",
    )
    asyncio.run(store.save_scan(scan))

    # Valid report submission
    valid_report = ReportRequest(
        scan_id="scan-valid-01",
        scam_type=ScamType.INVESTMENT_SCAM.value,
        risk_score=75,
        description="Received invitation on WhatsApp to join VIP Crypto signal group.",
        communication_source="whatsapp"
    )
    resp = asyncio.run(store.save_report(valid_report))
    assert resp.scan_id == "scan-valid-01"
    assert resp.status == "recorded"

    # Report submission referencing nonexistent scan
    invalid_report = ReportRequest(
        scan_id="non-existent-scan-999",
        scam_type="Phishing",
        risk_score=80,
        description="Invalid reference report",
    )
    with pytest.raises(ValueError) as excinfo:
        asyncio.run(store.save_report(invalid_report))
    assert "does not exist" in str(excinfo.value)


# ── 5. Stats Computed from Persisted Scans at Documented Thresholds ──

def test_dashboard_stats_sql_aggregation(temp_db_path):
    """
    Verify stats aggregation directly from SQLite table against documented thresholds:
    - threats_detected: risk_score >= 30
    - high_risk_alerts: risk_score >= 65
    - critical_alerts: risk_score >= 80
    """
    store = ScanStore(db_path=temp_db_path)
    store.initialize_sync()

    # Initially empty stats
    stats_empty = store.get_stats()
    assert stats_empty.total_scans == 0
    assert stats_empty.threats_detected == 0
    assert stats_empty.high_risk_alerts == 0
    assert stats_empty.critical_alerts == 0
    assert stats_empty.protection_status == "active"

    test_scores = [
        ("s1", 10),   # Safe (< 30)
        ("s2", 29),   # Safe boundary (< 30)
        ("s3", 30),   # Threats boundary (>= 30)
        ("s4", 50),   # Medium threat (>= 30, < 65)
        ("s5", 64),   # Medium boundary (< 65)
        ("s6", 65),   # High risk boundary (>= 65)
        ("s7", 79),   # High risk (>= 65, < 80)
        ("s8", 80),   # Critical boundary (>= 80)
        ("s9", 95),   # Critical (>= 80)
    ]

    for scan_id, score in test_scores:
        level = RiskLevel.SAFE if score < 30 else (RiskLevel.VERIFY if score < 65 else RiskLevel.HIGH_RISK)
        res = AnalysisResult(
            id=scan_id,
            scam_type="Test",
            risk_score=score,
            risk_level=level,
            confidence=0.8,
            summary=f"Score {score}",
            explanation=f"Testing threshold {score}",
        )
        asyncio.run(store.save_scan(res))

    stats = store.get_stats()
    assert stats.total_scans == 9
    # Threats >= 30: s3, s4, s5, s6, s7, s8, s9 = 7
    assert stats.threats_detected == 7
    # High risk >= 65: s6, s7, s8, s9 = 4
    assert stats.high_risk_alerts == 4
    # Critical >= 80: s8, s9 = 2
    assert stats.critical_alerts == 2


# ── 6. Duplicate ID Handling ──

def test_duplicate_scan_id_rejected(temp_db_path):
    """Verify that duplicate scan IDs are rejected and not silently overwritten."""
    store = ScanStore(db_path=temp_db_path)
    store.initialize_sync()

    scan1 = AnalysisResult(
        id="duplicate-test-id",
        scam_type="Initial Scam",
        risk_score=50,
        risk_level=RiskLevel.VERIFY,
        confidence=0.7,
        summary="Initial summary",
        explanation="Initial explanation",
    )
    asyncio.run(store.save_scan(scan1))

    scan2 = AnalysisResult(
        id="duplicate-test-id",
        scam_type="Overwriting Scam",
        risk_score=99,
        risk_level=RiskLevel.HIGH_RISK,
        confidence=0.99,
        summary="Overwriting summary",
        explanation="Overwriting explanation",
    )

    with pytest.raises(ValueError) as excinfo:
        asyncio.run(store.save_scan(scan2))
    assert "already exists" in str(excinfo.value)

    # Confirm original scan was NOT overwritten
    persisted = asyncio.run(store.get_scan("duplicate-test-id"))
    assert persisted.scam_type == "Initial Scam"
    assert persisted.risk_score == 50


# ── 7. Safe Initialization & Fault Isolation ──

def test_database_safe_initialization_idempotent(temp_db_path):
    """Verify that multiple initialize calls are safe and idempotent."""
    store = ScanStore(db_path=temp_db_path)
    assert store.initialize_sync() is True
    # Re-initialization on existing database
    assert store.initialize_sync() is True
    assert asyncio.run(store.initialize()) is True


def test_health_check_operational_with_clean_store():
    """Verify GET /health remains functional independently of persistence state."""
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_api_integration_demo_and_scans(temp_db_path):
    """
    Verify full API flow with the durable store singleton:
    Run demo scenario -> Check scan created -> Submit report -> Verify stats.
    """
    reset_scan_store()
    # Configure singleton to use temp DB
    store = get_scan_store(db_path=temp_db_path)
    store.initialize_sync()

    client = TestClient(app)

    # 1. Run demo scenario
    demo_resp = client.post("/api/demo/run/demo_digital_arrest")
    assert demo_resp.status_code == 200
    scan_data = demo_resp.json()
    scan_id = scan_data["id"]

    # 2. Retrieve scan by ID
    get_resp = client.get(f"/api/scans/{scan_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == scan_id
    assert get_resp.json()["scam_type"] == "Digital Arrest Scam"

    # 3. Submit report
    report_resp = client.post(
        "/api/reports",
        json={
            "scan_id": scan_id,
            "scam_type": "Digital Arrest Scam",
            "risk_score": scan_data["risk_score"],
            "description": "Caller threatened arrest over Skype call."
        }
    )
    assert report_resp.status_code == 200
    assert report_resp.json()["scan_id"] == scan_id

    # 4. Check dashboard stats
    stats_resp = client.get("/api/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_scans"] >= 1
    assert stats["threats_detected"] >= 1

    reset_scan_store()
