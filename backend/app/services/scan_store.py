"""
KavachX Bharat — Scan & Incident Report Storage Service
In-memory persistence service managing scan history, incident reports,
and dashboard statistics.
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone

from app.models.schemas import (
    AnalysisResult,
    ScanRecord,
    ReportRequest,
    ReportResponse,
    DashboardStats,
)

logger = logging.getLogger("kavachx.store")


class ScanStore:
    """
    In-memory storage for scan records, incident reports, and dashboard metrics.
    Data is retained in memory for the lifetime of the backend process.
    """

    def __init__(self):
        self._scans: Dict[str, AnalysisResult] = {}
        self._reports: Dict[str, dict] = {}

    async def save_scan(self, result: AnalysisResult) -> str:
        """
        Store an analysis result.
        Avoids logging sensitive message text or transcripts.
        """
        self._scans[result.id] = result
        logger.info(f"Scan record stored: id={result.id}, type={result.scam_type}, score={result.risk_score}")
        return result.id

    async def get_scan(self, scan_id: str) -> Optional[AnalysisResult]:
        """Retrieve full analysis result by scan ID."""
        return self._scans.get(scan_id)

    async def get_all_scans(self) -> List[ScanRecord]:
        """
        Retrieve all scans in summary format, sorted newest first.
        """
        # Sort by creation timestamp descending
        sorted_scans = sorted(
            self._scans.values(),
            key=lambda s: s.created_at,
            reverse=True
        )

        return [
            ScanRecord(
                id=scan.id,
                scam_type=scan.scam_type,
                risk_score=scan.risk_score,
                risk_level=scan.risk_level,
                input_type=scan.input_type,
                summary=scan.summary,
                created_at=scan.created_at,
            )
            for scan in sorted_scans
        ]

    async def save_report(self, report: ReportRequest) -> ReportResponse:
        """
        Record an incident report associated with an existing scan.
        Does not log report descriptions to protect privacy.
        """
        response = ReportResponse(scan_id=report.scan_id)
        self._reports[response.id] = {
            "id": response.id,
            "scan_id": report.scan_id,
            "scam_type": report.scam_type,
            "risk_score": report.risk_score,
            "description": report.description,
            "communication_source": report.communication_source,
            "status": response.status,
            "created_at": response.created_at,
        }
        logger.info(f"Incident report recorded: report_id={response.id}, scan_id={report.scan_id}")
        return response

    def get_stats(self) -> DashboardStats:
        """
        Derive dashboard statistics consistently from stored scans.
        Established Thresholds:
        - threats_detected: risk_score >= 30 (VERIFY or HIGH_RISK)
        - high_risk_alerts: risk_score >= 65 (HIGH_RISK)
        - critical_alerts: risk_score >= 80 (severe threats)
        """
        scans = list(self._scans.values())
        total = len(scans)
        threats = sum(1 for s in scans if s.risk_score >= 30)
        high_risk = sum(1 for s in scans if s.risk_score >= 65)
        critical = sum(1 for s in scans if s.risk_score >= 80)

        return DashboardStats(
            total_scans=total,
            threats_detected=threats,
            high_risk_alerts=high_risk,
            critical_alerts=critical,
            protection_status="active",
        )

    def clear(self) -> None:
        """Clear all in-memory records (used for test isolation)."""
        self._scans.clear()
        self._reports.clear()


# Singleton instance
_store: Optional[ScanStore] = None


def get_scan_store() -> ScanStore:
    """Retrieve or create the ScanStore singleton."""
    global _store
    if _store is None:
        _store = ScanStore()
    return _store


def reset_scan_store() -> None:
    """Reset the scan store singleton for clean test state."""
    global _store
    if _store is not None:
        _store.clear()
    _store = None
