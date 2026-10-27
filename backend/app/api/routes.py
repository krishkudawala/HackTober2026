"""
KavachX Bharat — API Routes
Exposes message, call transcript, audio analysis, scan history,
incident reports, statistics, and demo scenario endpoints.
"""

import os
from typing import List, Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status, Request

from app.models.schemas import (
    AnalyzeMessageRequest,
    AnalyzeTranscriptRequest,
    ReportRequest,
    AudioAnalysisResponse,
    AnalysisResult,
    ScanRecord,
    ReportResponse,
    DashboardStats,
    DemoScenario,
    InputType,
)
from app.ai.engine import analyze_communication
from app.services.stt_service import get_stt_service
from app.services.scan_store import get_scan_store
from app.services.demo_scenarios import get_demo_scenarios, get_demo_scenario_by_id
from app.core.config import settings

router = APIRouter()


# ── Message Analysis (B02) ──

@router.post(
    "/analyze/message",
    response_model=AnalysisResult,
    tags=["Analysis"],
    summary="Analyze suspicious message for scam indicators",
    description=(
        "Submit a text message (SMS, WhatsApp, transcript, or plain text) for AI-powered scam analysis. "
        "Returns scam category, risk score (0-100), risk level (SAFE, VERIFY, HIGH_RISK), "
        "evidence, red flags, and actionable safety recommendations."
    )
)
async def analyze_message(request: AnalyzeMessageRequest) -> AnalysisResult:
    """
    Core remote message analysis endpoint.
    Evaluates message content against deterministic risk signals and local AI,
    persisting the result in the scan store.
    """
    result = await analyze_communication(
        text=request.message,
        input_type=request.input_type.value,
        language=request.language or "en"
    )
    result.input_type = request.input_type.value

    # Persist in scan history
    store = get_scan_store()
    await store.save_scan(result)

    return result


# ── Call Transcript Analysis (B03) ──

@router.post(
    "/analyze/transcript",
    response_model=AnalysisResult,
    tags=["Analysis"],
    summary="Analyze call transcript for scam indicators",
    description=(
        "Submit a call transcript for scam and digital arrest detection. "
        "Reuses the shared analysis pipeline, returning the same analysis response schema "
        "with input_type set to call_transcript."
    )
)
async def analyze_transcript(request: AnalyzeTranscriptRequest) -> AnalysisResult:
    """
    Call transcript analysis endpoint.
    Passes transcript through shared analysis pipeline with input_type='call_transcript',
    persisting the result in the scan store.
    """
    result = await analyze_communication(
        text=request.transcript,
        input_type=InputType.CALL_TRANSCRIPT.value,
        language=request.language or "en"
    )
    result.input_type = InputType.CALL_TRANSCRIPT.value
    result.input_text = request.transcript

    # Persist in scan history
    store = get_scan_store()
    await store.save_scan(result)

    return result


# ── Audio Upload Analysis (B03) ──

@router.post(
    "/analyze/audio",
    response_model=AudioAnalysisResponse,
    tags=["Analysis"],
    summary="Upload audio recording for transcription and scam analysis",
    description=(
        "Upload an audio file (e.g. WAV, MP3, M4A) for Speech-to-Text transcription followed by scam analysis. "
        "If STT is in demo mode, returns a transparent demo-mode response prompting manual transcript entry. "
        "Enforces upload size limits."
    )
)
async def analyze_audio(
    request: Request,
    file: UploadFile = File(..., description="Audio file to transcribe and analyze"),
    language: Optional[str] = Form(default="en", description="Optional language code (en, hi, pa, hinglish, auto)")
) -> AudioAnalysisResponse:
    """
    Audio analysis pipeline:
    1. Validate upload presence, sanitize filename, and enforce size limits.
    2. Transcribe via STT service abstraction.
    3. If demo mode or error, return transparent guidance without fabricating transcripts.
    4. If transcribed, pass text through shared analysis engine with input_type='audio',
       and persist successful analysis into the scan store.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No audio file was supplied."
        )

    # Sanitize filename (prevent directory traversal or malicious relative paths)
    raw_filename = file.filename.replace("\\", "/")
    safe_filename = os.path.basename(raw_filename)
    if not safe_filename or safe_filename in (".", ".."):
        safe_filename = "audio_upload.wav"

    # Reject dangerous executable and script file extensions
    _, ext = os.path.splitext(safe_filename.lower())
    DANGEROUS_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".sh", ".py", ".js", ".html", ".htm",
        ".php", ".vbs", ".dll", ".so", ".jar", ".ps1", ".scr", ".msi"
    }
    if ext in DANGEROUS_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Disallowed file type. Executable and script uploads are rejected."
        )

    # Reject disallowed dangerous content types
    content_type = (file.content_type or "").lower().strip()
    DISALLOWED_CONTENT_TYPES = {
        "text/html", "application/javascript", "application/x-msdownload",
        "application/x-sh", "application/x-executable", "text/javascript",
        "application/x-bat", "application/x-python"
    }
    if content_type in DISALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Disallowed content type for audio upload."
        )

    # Fail fast if Content-Length header exceeds limit
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.MAX_AUDIO_UPLOAD_BYTES:
                max_mb = settings.MAX_AUDIO_UPLOAD_BYTES // (1024 * 1024)
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"Audio file exceeds maximum allowed size of {max_mb}MB."
                )
        except ValueError:
            pass

    # Read audio content and validate upload size
    audio_data = await file.read()
    if len(audio_data) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded audio file is empty."
        )

    if len(audio_data) > settings.MAX_AUDIO_UPLOAD_BYTES:
        max_mb = settings.MAX_AUDIO_UPLOAD_BYTES // (1024 * 1024)
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Audio file exceeds maximum allowed size of {max_mb}MB."
        )

    # Transcribe via configured STT service
    stt = get_stt_service()
    stt_result = await stt.transcribe(
        audio_data=audio_data,
        filename=safe_filename,
        language=language or "en"
    )

    # Demo fallback mode
    if stt_result.get("is_demo", False):
        return AudioAnalysisResponse(
            status="demo_mode",
            message=stt_result.get("message", "Speech-to-Text is in demo mode."),
            provider=stt_result.get("provider", "demo"),
            transcript="",
            analysis=None
        )

    # Transcription failure
    if stt_result.get("status") == "error" or not stt_result.get("transcript"):
        return AudioAnalysisResponse(
            status="error",
            message=stt_result.get("message", "Could not transcribe audio."),
            provider=stt_result.get("provider", "unknown"),
            transcript="",
            analysis=None
        )

    # Successful transcription: process through shared analysis pipeline
    transcript_text = stt_result["transcript"]
    analysis = await analyze_communication(
        text=transcript_text,
        input_type=InputType.AUDIO.value,
        language=language or "en"
    )
    analysis.input_type = InputType.AUDIO.value

    # Persist in scan history
    store = get_scan_store()
    await store.save_scan(analysis)

    return AudioAnalysisResponse(
        status="success",
        message=None,
        provider=stt_result.get("provider", "stt"),
        transcript=transcript_text,
        analysis=analysis
    )


# ── Scan History (B04) ──

@router.get(
    "/scans",
    response_model=List[ScanRecord],
    tags=["Scans"],
    summary="List all scan summary records",
    description="Retrieve scan history sorted newest first."
)
async def list_scans() -> List[ScanRecord]:
    """Retrieve all stored scan summary records sorted by created_at descending."""
    store = get_scan_store()
    return await store.get_all_scans()


@router.get(
    "/scans/{scan_id}",
    response_model=AnalysisResult,
    tags=["Scans"],
    summary="Get full analysis result by scan ID",
    description="Retrieve the complete analysis result for a specific scan record."
)
async def get_scan(scan_id: str) -> AnalysisResult:
    """Retrieve complete analysis details for a specific scan ID."""
    store = get_scan_store()
    scan = await store.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found."
        )
    return scan


# ── Incident Reports (B04) ──

@router.post(
    "/reports",
    response_model=ReportResponse,
    tags=["Reports"],
    summary="Submit an incident report for an existing scan",
    description=(
        "Record an incident report associated with a valid existing scan record. "
        "Validates scan existence and stores report details in the backend."
    )
)
async def create_report(report: ReportRequest) -> ReportResponse:
    """Record an incident report linked to a valid existing scan."""
    store = get_scan_store()

    # Validate that the referenced scan exists
    scan = await store.get_scan(report.scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Referenced scan_id '{report.scan_id}' does not exist."
        )

    return await store.save_report(report)


# ── Dashboard Statistics (B04) ──

@router.get(
    "/stats",
    response_model=DashboardStats,
    tags=["Dashboard"],
    summary="Get dashboard fraud statistics",
    description=(
        "Retrieve aggregated metrics derived from scan history: total scans, "
        "threats detected, high-risk alerts, critical alerts, and protection status."
    )
)
async def get_dashboard_stats() -> DashboardStats:
    """Return aggregated fraud metrics derived from scan history."""
    store = get_scan_store()
    return store.get_stats()


# ── Demo Scenarios (B04) ──

@router.get(
    "/demo/scenarios",
    response_model=List[DemoScenario],
    tags=["Demo"],
    summary="List preset demo scenarios",
    description="Retrieve preset evaluation scenarios demonstrating various scam types and legitimate communications."
)
async def list_demo_scenarios() -> List[DemoScenario]:
    """Retrieve all available preset demo scenarios."""
    return get_demo_scenarios()


@router.post(
    "/demo/run/{scenario_id}",
    response_model=AnalysisResult,
    tags=["Demo"],
    summary="Execute a preset demo scenario",
    description=(
        "Run a preset scenario through the shared analysis engine, store the result in scan history, "
        "and return the full analysis result."
    )
)
async def run_demo_scenario(scenario_id: str) -> AnalysisResult:
    """
    Execute a preset demo scenario by ID.
    Routes input through shared analysis engine and persists result.
    """
    scenario = get_demo_scenario_by_id(scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Demo scenario '{scenario_id}' not found."
        )

    result = await analyze_communication(
        text=scenario.input_text,
        input_type=scenario.input_type
    )
    result.input_type = scenario.input_type

    # Persist in scan history
    store = get_scan_store()
    await store.save_scan(result)

    return result
