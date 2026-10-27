"""
KavachX Bharat API — Pydantic Schemas
Structured request and response models for message analysis.
Compatible with Flutter AnalysisResultModel.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class InputType(str, Enum):
    SMS = "sms"
    WHATSAPP = "whatsapp"
    CALL_TRANSCRIPT = "call_transcript"
    AUDIO = "audio"
    TEXT = "text"


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    VERIFY = "VERIFY"
    HIGH_RISK = "HIGH_RISK"

    # Compatibility aliases
    LOW = "SAFE"
    MEDIUM = "VERIFY"
    HIGH = "HIGH_RISK"
    CRITICAL = "HIGH_RISK"


class ScamType(str, Enum):
    PHISHING = "Phishing"
    FAKE_BANK_SUPPORT = "Fake Bank Support"
    DIGITAL_ARREST = "Digital Arrest Scam"
    UPI_PAYMENT_SCAM = "UPI / Payment Scam"
    INVESTMENT_SCAM = "Investment Scam"
    PREPAID_TASK_SCAM = "Prepaid Task / Job Scam"
    LOTTERY_PRIZE_SCAM = "Lottery / Prize Scam"
    GOVERNMENT_IMPERSONATION = "Government / Authority Impersonation"
    LEGITIMATE = "Legitimate"
    UNKNOWN = "Unknown Scam Type"


class Verdict(str, Enum):
    LIKELY_SCAM = "likely_scam"
    SUSPICIOUS = "suspicious"
    LIKELY_LEGITIMATE = "likely_legitimate"
    UNCERTAIN = "uncertain"


class ResponseLanguage(str, Enum):
    ENGLISH = "en"
    HINDI = "hi"
    PUNJABI = "pa"
    HINGLISH = "hinglish"
    AUTO = "auto"


# ── Request Models ──

class AnalyzeMessageRequest(BaseModel):
    """Request schema for analyzing a message."""
    message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="The message text to analyze (max 5000 chars)"
    )
    input_type: InputType = Field(
        default=InputType.TEXT,
        description="Source type of the communication: sms, whatsapp, call_transcript, audio, or text"
    )
    source_info: Optional[str] = Field(
        default=None,
        description="Optional source identifier or sender details"
    )
    language: Optional[str] = Field(
        default="en",
        description="Desired response language: en, hi, pa, hinglish, or auto"
    )


class AnalyzeTranscriptRequest(BaseModel):
    """Request schema for analyzing a call transcript."""
    transcript: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="The call transcript text to analyze (max 10000 chars)"
    )
    source_info: Optional[str] = Field(
        default=None,
        description="Optional source identifier or caller details"
    )
    language: Optional[str] = Field(
        default="en",
        description="Desired response language: en, hi, pa, hinglish, or auto"
    )


# ── Response Component Models ──

class RedFlag(BaseModel):
    """Individual suspicious indicator identified in the text."""
    indicator: str = Field(..., description="Red flag category name")
    description: str = Field(..., description="Explanation of why this indicator is suspicious")
    severity: str = Field(default="high", description="Severity level: low, medium, high, critical")


class RiskScoreBreakdown(BaseModel):
    """Signal contribution to the overall risk score."""
    signal: str = Field(..., description="Identified risk signal")
    points: int = Field(..., description="Points added to the score")
    description: str = Field(..., description="Contextual explanation for the point allocation")


# ── Full Analysis Result Model ──

class AnalysisResult(BaseModel):
    """
    Complete analysis result returned by the backend.
    Maintains 1:1 schema compatibility with the Flutter AnalysisResultModel.
    """
    model_config = {"protected_namespaces": ()}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique analysis record identifier")
    scam_type: str = Field(..., description="Classified category of scam or legitimate communication")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score bounded from 0 to 100")
    risk_level: RiskLevel = Field(..., description="SAFE (0-29), VERIFY (30-64), or HIGH_RISK (65-100)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence level between 0.0 and 1.0")
    summary: str = Field(..., description="Brief summary of findings")
    explanation: str = Field(..., description="Detailed explainable reasoning for the risk score")
    red_flags: List[RedFlag] = Field(default_factory=list, description="List of detected red flags")
    recommended_actions: List[str] = Field(default_factory=list, description="Immediate protective recommendations")
    detected_entities: List[str] = Field(default_factory=list, description="Identified entities, amounts, organizations")
    score_breakdown: List[RiskScoreBreakdown] = Field(default_factory=list, description="Deterministic score signals")
    input_type: str = Field(default="text", description="Input type analyzed")
    input_text: str = Field(default="", description="Original submitted text")
    ai_provider: str = Field(default="fallback", description="Provider used: fallback, litert-lm, or ollama")
    verdict: Optional[str] = Field(default=None, description="verdict: likely_scam, suspicious, likely_legitimate, uncertain")
    evidence: List[str] = Field(default_factory=list, description="Textual evidence quotes grounded in input")
    model_name: Optional[str] = Field(default=None, description="Model identifier used for analysis")
    language: str = Field(default="en", description="Resolved response language code")
    fallback_used: bool = Field(default=False, description="Whether rule-based fallback was executed")
    fallback_reason: Optional[str] = Field(default=None, description="Reason fallback was triggered")
    signals: List[str] = Field(default_factory=list, description="Summary list of detected signal names")
    analysis_mode: str = Field(default="rules-only", description="Mode executed: rules-only, hybrid, or ai")
    analysis_complete: bool = Field(default=True, description="Indicates complete pipeline execution")
    warnings: List[str] = Field(default_factory=list, description="Operational warnings or provider notes")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 creation timestamp"
    )
    disclaimer: str = Field(
        default="AI-generated risk assessment. Verify critical decisions through official channels.",
        description="Standard digital safety disclaimer"
    )


class AudioAnalysisResponse(BaseModel):
    """Response schema for audio file transcription and scam analysis."""
    status: str = Field(..., description="Status of audio processing: demo_mode, success, or error")
    message: Optional[str] = Field(default=None, description="Detailed guidance or error message")
    provider: str = Field(default="demo", description="Speech-to-Text provider used")
    transcript: str = Field(default="", description="Transcribed text if available")
    analysis: Optional[AnalysisResult] = Field(default=None, description="Analysis result if transcript available")

