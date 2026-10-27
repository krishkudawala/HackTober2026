"""
KavachX Bharat — API Routes
Exposes the core message analysis endpoint for the remote analysis mode.
"""

from fastapi import APIRouter
from app.models.schemas import AnalyzeMessageRequest, AnalysisResult
from app.ai.engine import analyze_communication

router = APIRouter()


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
    Core remote analysis endpoint (Milestone B02).
    Evaluates message content against deterministic risk signals and local AI.
    """
    result = await analyze_communication(
        text=request.message,
        input_type=request.input_type.value,
        language=request.language or "en"
    )
    result.input_type = request.input_type.value
    return result
