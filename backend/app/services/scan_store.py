"""
KavachX Bharat — Scan & Incident Report Storage Service
Durable SQLite persistence service managing scan history, incident reports,
and dashboard statistics.
"""

import os
import sqlite3
import logging
from contextlib import contextmanager
from typing import List, Optional

from app.core.config import settings
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
    Durable SQLite storage for scan records, incident reports, and dashboard metrics.
    Keeps persistence behind a repository boundary so API routes remain independent
    of the underlying database implementation.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path if db_path is not None else settings.DATABASE_PATH
        self._initialized = False

    def _ensure_dir(self) -> None:
        """Ensure parent directory of the database file exists."""
        if self.db_path and self.db_path != ":memory:":
            dirname = os.path.dirname(self.db_path)
            if dirname:
                os.makedirs(dirname, exist_ok=True)

    @contextmanager
    def _get_connection(self):
        """Context manager providing a configured SQLite connection with foreign keys enabled."""
        self._ensure_dir()
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _ensure_initialized(self) -> None:
        """Ensure database schema is created before operations."""
        if not self._initialized:
            self.initialize_sync()

    def initialize_sync(self) -> bool:
        """
        Create tables and indices synchronously.
        Does not crash the application if initialization fails.
        """
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scans (
                        id TEXT PRIMARY KEY,
                        scam_type TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        risk_level TEXT NOT NULL,
                        input_type TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk_score ON scans(risk_score);")

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS reports (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT NOT NULL,
                        scam_type TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        description TEXT,
                        communication_source TEXT,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC);")

            self._initialized = True
            logger.info("Database initialized successfully at %s", self.db_path)
            return True
        except Exception as exc:
            self._initialized = False
            logger.error("Database initialization failed: %s. Application health check remains unaffected.", type(exc).__name__)
            return False

    async def initialize(self) -> bool:
        """Asynchronous initialization helper for application startup lifespan."""
        return self.initialize_sync()

    async def save_scan(self, result: AnalysisResult) -> str:
        """
        Persist full analysis result into the database.
        Avoids logging sensitive message text or transcripts.
        """
        self._ensure_initialized()
        risk_level_str = result.risk_level.value if hasattr(result.risk_level, "value") else str(result.risk_level)
        payload = result.model_dump_json()

        try:
            with self._get_connection() as conn:
                # Check for existing duplicate ID
                cur = conn.execute("SELECT id FROM scans WHERE id = ?", (result.id,))
                if cur.fetchone():
                    logger.warning("Duplicate scan insert rejected for ID: %s", result.id)
                    raise ValueError(f"Scan with ID '{result.id}' already exists.")

                conn.execute(
                    """
                    INSERT INTO scans (id, scam_type, risk_score, risk_level, input_type, summary, created_at, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.id,
                        str(result.scam_type),
                        int(result.risk_score),
                        risk_level_str,
                        str(result.input_type),
                        str(result.summary),
                        str(result.created_at),
                        payload,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            logger.warning("Integrity error inserting scan ID %s: %s", result.id, type(exc).__name__)
            raise ValueError(f"Scan with ID '{result.id}' already exists.") from exc
        except Exception as exc:
            logger.error("Failed to persist scan record ID %s: %s", result.id, type(exc).__name__)
            raise

        logger.info("Scan record stored: id=%s, type=%s, score=%d", result.id, result.scam_type, result.risk_score)
        return result.id

    async def get_scan(self, scan_id: str) -> Optional[AnalysisResult]:
        """Retrieve full analysis result by scan ID."""
        self._ensure_initialized()
        try:
            with self._get_connection() as conn:
                cur = conn.execute("SELECT payload_json FROM scans WHERE id = ?", (scan_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return AnalysisResult.model_validate_json(row["payload_json"])
        except Exception as exc:
            logger.error("Error retrieving scan ID %s: %s", scan_id, type(exc).__name__)
            raise

    async def get_all_scans(self) -> List[ScanRecord]:
        """
        Retrieve all scans in summary format, sorted newest first.
        """
        self._ensure_initialized()
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    """
                    SELECT id, scam_type, risk_score, risk_level, input_type, summary, created_at
                    FROM scans
                    ORDER BY created_at DESC
                    """
                )
                rows = cur.fetchall()
                return [
                    ScanRecord(
                        id=row["id"],
                        scam_type=row["scam_type"],
                        risk_score=row["risk_score"],
                        risk_level=row["risk_level"],
                        input_type=row["input_type"],
                        summary=row["summary"],
                        created_at=row["created_at"],
                    )
                    for row in rows
                ]
        except Exception as exc:
            logger.error("Error listing scan records: %s", type(exc).__name__)
            raise

    async def save_report(self, report: ReportRequest) -> ReportResponse:
        """
        Record an incident report associated with an existing scan.
        Does not log report descriptions to protect privacy.
        """
        self._ensure_initialized()
        response = ReportResponse(scan_id=report.scan_id)
        try:
            with self._get_connection() as conn:
                # Ensure referenced scan exists
                cur = conn.execute("SELECT id FROM scans WHERE id = ?", (report.scan_id,))
                if not cur.fetchone():
                    raise ValueError(f"Referenced scan '{report.scan_id}' does not exist.")

                conn.execute(
                    """
                    INSERT INTO reports (id, scan_id, scam_type, risk_score, description, communication_source, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        response.id,
                        report.scan_id,
                        report.scam_type,
                        int(report.risk_score),
                        report.description,
                        report.communication_source,
                        response.status,
                        response.created_at,
                    ),
                )
        except ValueError:
            raise
        except sqlite3.IntegrityError as exc:
            logger.warning("Integrity error recording report for scan ID %s: %s", report.scan_id, type(exc).__name__)
            raise ValueError(f"Referenced scan '{report.scan_id}' does not exist.") from exc
        except Exception as exc:
            logger.error("Error recording incident report for scan ID %s: %s", report.scan_id, type(exc).__name__)
            raise

        logger.info("Incident report recorded: report_id=%s, scan_id=%s", response.id, report.scan_id)
        return response

    def get_stats(self) -> DashboardStats:
        """
        Derive dashboard statistics consistently from stored scans.
        Established Thresholds:
        - threats_detected: risk_score >= 30 (VERIFY or HIGH_RISK)
        - high_risk_alerts: risk_score >= 65 (HIGH_RISK)
        - critical_alerts: risk_score >= 80 (severe threats)
        """
        self._ensure_initialized()
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    """
                    SELECT 
                        COUNT(*) AS total_scans,
                        COALESCE(SUM(CASE WHEN risk_score >= 30 THEN 1 ELSE 0 END), 0) AS threats_detected,
                        COALESCE(SUM(CASE WHEN risk_score >= 65 THEN 1 ELSE 0 END), 0) AS high_risk_alerts,
                        COALESCE(SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END), 0) AS critical_alerts
                    FROM scans
                    """
                )
                row = cur.fetchone()
                if row:
                    return DashboardStats(
                        total_scans=int(row["total_scans"]),
                        threats_detected=int(row["threats_detected"]),
                        high_risk_alerts=int(row["high_risk_alerts"]),
                        critical_alerts=int(row["critical_alerts"]),
                        protection_status="active",
                    )
        except Exception as exc:
            logger.error("Error computing dashboard stats: %s", type(exc).__name__)
            return DashboardStats(
                total_scans=0,
                threats_detected=0,
                high_risk_alerts=0,
                critical_alerts=0,
                protection_status="active",
            )

        return DashboardStats(
            total_scans=0,
            threats_detected=0,
            high_risk_alerts=0,
            critical_alerts=0,
            protection_status="active",
        )

    def clear(self) -> None:
        """Clear all stored records (used for test isolation)."""
        self._ensure_initialized()
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM reports;")
                conn.execute("DELETE FROM scans;")
        except Exception as exc:
            logger.error("Error clearing database tables: %s", type(exc).__name__)


# Singleton instance
_store: Optional[ScanStore] = None


def get_scan_store(db_path: Optional[str] = None) -> ScanStore:
    """Retrieve or create the ScanStore singleton."""
    global _store
    if _store is None or (db_path is not None and _store.db_path != db_path):
        _store = ScanStore(db_path=db_path)
    return _store


def reset_scan_store(db_path: Optional[str] = None) -> None:
    """Reset the scan store singleton for clean test state."""
    global _store
    if _store is not None:
        _store.clear()
    _store = None
