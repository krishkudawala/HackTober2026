"""
KavachX Bharat — API Routes
Exposes message, call transcript, and audio analysis endpoints
for the remote analysis pipeline.
"""

from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status

from app.models.schemas import (
    AnalyzeMessageRequest,
    AnalyzeTranscriptRequest,
    AudioAnalysisResponse,
    AnalysisResult,
    InputType,
)
from app.ai.engine import analyze_communication
from app.services.stt_service import get_stt_service
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
    Evaluates message content against deterministic risk signals and local AI.
    """
    result = await analyze_communication(
        text=request.message,
        input_type=request.input_type.value,
        language=request.language or "en"
    )
    result.input_type = request.input_type.value
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
    Passes transcript through shared analysis pipeline with input_type='call_transcript'.
    """
    result = await analyze_communication(
        text=request.transcript,
        input_type=InputType.CALL_TRANSCRIPT.value,
        language=request.language or "en"
    )
    result.input_type = InputType.CALL_TRANSCRIPT.value
    result.input_text = request.transcript
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
    file: UploadFile = File(..., description="Audio file to transcribe and analyze"),
    language: Optional[str] = Form(default="en", description="Optional language code (en, hi, pa, hinglish, auto)")
) -> AudioAnalysisResponse:
    """
    Audio analysis pipeline:
    1. Validate upload presence and enforce size limit.
    2. Transcribe via STT service abstraction.
    3. If demo mode or error, return transparent guidance without fabricating transcripts.
    4. If transcribed, pass text through shared analysis engine with input_type='audio'.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No audio file was supplied."
        )

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
        filename=file.filename,
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

    return AudioAnalysisResponse(
        status="success",
        message=None,
        provider=stt_result.get("provider", "stt"),
        transcript=transcript_text,
        analysis=analysis
    )
