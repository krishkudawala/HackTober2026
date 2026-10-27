"""
KavachX Bharat — AI Provider Manager
Manages optional local AI providers (LiteRT-LM Gemma 4 E4B, Ollama)
with seamless, deterministic fallback to rule-based classification.

Ensures zero startup blockage: missing models or unavailable services
safely trigger fallback without application interruption.
"""

import os
import json
import logging
from typing import Optional, Dict, Any
import httpx

from app.models.schemas import (
    AnalysisResult, RedFlag, RiskScoreBreakdown, RiskLevel, InputType, Verdict
)
from app.scoring.risk_engine import calculate_risk_score, get_risk_level_from_score

logger = logging.getLogger("kavachx.provider")

SUPPORTED_PROVIDERS = {"fallback", "litert", "litert-lm", "ollama"}


class LLMProvider:
    """Configurable AI provider manager for KavachX Bharat."""

    def __init__(self):
        raw_provider = os.getenv("AI_PROVIDER", "fallback")
        self.provider = raw_provider.lower().strip() if raw_provider else "fallback"
        if self.provider == "litert-lm":
            self.provider = "litert"

        if self.provider not in SUPPORTED_PROVIDERS:
            logger.warning(f"Unknown AI_PROVIDER '{self.provider}', defaulting to 'fallback'.")
            self.provider = "fallback"

        self.model_path = os.getenv("LITERT_MODEL_PATH")
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
        self.last_error: Optional[str] = None

        logger.info(f"AI Provider configured: {self.provider}")

    def is_available(self) -> bool:
        """
        Check if the configured AI provider is operational.
        Returns False for 'fallback' mode or if artifacts/services are absent.
        """
        if self.provider == "fallback":
            return False

        if self.provider == "litert":
            if not self.model_path:
                self.last_error = "LITERT_MODEL_PATH environment variable is not configured."
                return False
            if not os.path.exists(self.model_path):
                self.last_error = f"Model artifact not found at {self.model_path}"
                return False
            return True

        if self.provider == "ollama":
            # For Ollama, we attempt during request; availability can be probed
            return True

        return False

    async def analyze(
        self, text: str, input_type: str = "text", language: str = "en"
    ) -> Optional[AnalysisResult]:
        """
        Analyze communication using the configured provider.
        Returns AnalysisResult on success, or None on failure/unavailability.
        """
        self.last_error = None

        if self.provider == "fallback":
            return None

        if not self.is_available():
            return None

        if self.provider == "ollama":
            return await self._analyze_with_ollama(text, input_type, language)

        if self.provider == "litert":
            return await self._analyze_with_litert(text, input_type, language)

        return None

    async def _analyze_with_ollama(
        self, text: str, input_type: str, language: str
    ) -> Optional[AnalysisResult]:
        """Send message analysis prompt to local Ollama instance."""
        prompt = (
            f"You are KavachX Bharat AI, an expert scam detection system. "
            f"Analyze the following untrusted message for fraud patterns:\n"
            f"<untrusted_message>\n{text}\n</untrusted_message>\n\n"
            f"Respond with valid JSON containing: verdict, scam_type, risk_score (0-100), "
            f"confidence (0-1), summary, explanation, evidence, red_flags, recommended_actions."
        )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{self.ollama_base_url}/api/chat",
                    json={
                        "model": self.ollama_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "stream": False,
                        "format": "json"
                    }
                )

                if response.status_code != 200:
                    self.last_error = f"Ollama HTTP error {response.status_code}: {response.text[:200]}"
                    return None

                data = response.json()
                content = data.get("message", {}).get("content", "")
                parsed = json.loads(content)

                # Calibrate score and validate signals
                raw_score = int(parsed.get("risk_score", 0))
                det_score, risk_level, breakdown = calculate_risk_score(text)
                final_score = max(raw_score, det_score)
                final_level = get_risk_level_from_score(final_score)

                return AnalysisResult(
                    scam_type=parsed.get("scam_type", "Unknown Scam Type"),
                    risk_score=final_score,
                    risk_level=final_level,
                    confidence=float(parsed.get("confidence", 0.8)),
                    summary=parsed.get("summary", "Analysis completed."),
                    explanation=parsed.get("explanation", ""),
                    red_flags=[
                        RedFlag(
                            indicator=rf.get("indicator", "Indicator"),
                            description=rf.get("description", ""),
                            severity=rf.get("severity", "high")
                        )
                        for rf in parsed.get("red_flags", [])
                    ],
                    recommended_actions=parsed.get("recommended_actions", []),
                    detected_entities=parsed.get("detected_entities", []),
                    score_breakdown=breakdown,
                    input_type=input_type,
                    input_text=text,
                    ai_provider="ollama",
                    verdict=parsed.get("verdict", Verdict.SUSPICIOUS.value),
                    evidence=parsed.get("evidence", []),
                    model_name=self.ollama_model,
                    language=language,
                    fallback_used=False,
                    fallback_reason=None,
                    signals=[b.signal for b in breakdown],
                    analysis_mode="ai",
                    analysis_complete=True,
                )
        except Exception as e:
            self.last_error = f"Ollama connection error: {type(e).__name__} - {str(e)}"
            logger.warning(self.last_error)
            return None

    async def _analyze_with_litert(
        self, text: str, input_type: str, language: str
    ) -> Optional[AnalysisResult]:
        """LiteRT-LM provider placeholder (active when model artifact and runtime exist)."""
        self.last_error = "LiteRT runtime not initialized on host."
        return None


_llm_provider: Optional[LLMProvider] = None


def get_llm_provider() -> LLMProvider:
    """Retrieve or create the LLM provider singleton."""
    global _llm_provider
    if _llm_provider is None:
        _llm_provider = LLMProvider()
    return _llm_provider


def reset_llm_provider() -> None:
    """Reset LLM provider singleton (useful for testing)."""
    global _llm_provider
    _llm_provider = None
