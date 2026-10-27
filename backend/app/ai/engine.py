"""
KavachX Bharat — AI Engine Orchestrator
Coordinates input normalization, language resolution, provider routing,
and deterministic fallback classification.
"""

import re
import logging
from app.models.schemas import AnalysisResult, RiskLevel, Verdict, InputType, ScamType
from app.ai.llm_provider import get_llm_provider
from app.ai.fallback_classifier import analyze_with_fallback

logger = logging.getLogger("kavachx.engine")


def detect_language(text: str) -> str:
    """
    Detect whether text is primarily Hindi, Punjabi, Hinglish, or English.
    Checks Devanagari script (Hindi), Gurmukhi script (Punjabi),
    Roman Punjabi phrases, and Hinglish vocabulary.
    """
    if not text:
        return "en"

    # Count Gurmukhi and Devanagari characters
    gurmukhi_count = sum(1 for char in text if '\u0a00' <= char <= '\u0a7f')
    devanagari_count = sum(
        1 for char in text if ('\u0900' <= char <= '\u0963') or ('\u0966' <= char <= '\u097f')
    )

    if gurmukhi_count > devanagari_count and gurmukhi_count > 0:
        return "pa"
    if devanagari_count > 0:
        return "hi"

    text_lower = text.lower()

    # Roman Punjabi specific vocabulary
    punjabi_words = [
        "tussi", "saanu", "kiddan", "veere", "veerji", "chahida", "kar deo",
        "ditta", "assi", "karde", "hoya", "daso", "sunao", "gall", "thoda"
    ]
    if any(re.search(r'\b' + re.escape(w) + r'\b', text_lower) for w in punjabi_words):
        return "pa"

    # Hinglish vocabulary
    hinglish_words = [
        "aapka", "karein", "bhejo", "turant", "khata", "band", "hoga",
        "kripya", "jaldi", "dhanyawad", "apna", "paise", "karo", "nahi",
        "kare", "khatre", "gireftari", "police", "dhanrashi"
    ]
    matches = sum(1 for w in hinglish_words if re.search(r'\b' + re.escape(w) + r'\b', text_lower))
    if matches >= 2:
        return "hinglish"

    return "en"


def normalize_input(text: str) -> str:
    """
    Normalize message text for consistent security analysis.
    Preserves semantic content while cleaning encoding artifacts.
    """
    if not text:
        return ""

    text = text.strip()

    # Normalize unicode quotes and dashes
    replacements = {
        '\u201c': '"', '\u201d': '"',
        '\u2018': "'", '\u2019': "'",
        '\u2013': '-', '\u2014': '-',
        '\u00a0': ' ',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)

    # Collapse multiple whitespace
    text = re.sub(r'\s+', ' ', text)
    return text


async def analyze_communication(
    text: str, input_type: str = "text", language: str = "en"
) -> AnalysisResult:
    """
    Main analysis pipeline for KavachX Bharat.

    1. Normalize input text.
    2. Resolve target language (detect if 'auto' or unspecified).
    3. Attempt inference using configured local AI provider if available.
    4. Fall back seamlessly to deterministic rules-based classifier.
    """
    normalized_text = normalize_input(text)

    # Language resolution
    if not language or language.lower() == "auto":
        effective_language = detect_language(normalized_text)
    else:
        effective_language = language.lower()

    # Guard for empty or excessively short text
    if not normalized_text or len(normalized_text.strip()) < 3:
        return AnalysisResult(
            scam_type=ScamType.LEGITIMATE.value,
            risk_score=0,
            risk_level=RiskLevel.SAFE,
            confidence=0.95,
            summary="Input text too short for meaningful fraud analysis.",
            explanation="The provided text is too short to detect fraud indicators. Always exercise caution.",
            red_flags=[],
            recommended_actions=["Provide more message context for comprehensive analysis."],
            detected_entities=[],
            score_breakdown=[],
            input_type=input_type,
            input_text=text,
            ai_provider="fallback",
            verdict=Verdict.LIKELY_LEGITIMATE.value,
            evidence=[],
            signals=[],
            analysis_mode="rules-only",
            analysis_complete=True,
            warnings=["Input text too short for full risk pattern matching."],
            model_name="rule_engine",
            language=effective_language,
            fallback_used=True,
            fallback_reason="Input too short",
        )

    # Check AI Provider
    llm = get_llm_provider()
    fallback_reason = None

    if llm.is_available():
        logger.info(f"Invoking AI provider: {llm.provider}")
        try:
            result = await llm.analyze(normalized_text, input_type, language=effective_language)
            if result is not None:
                result.input_text = text
                return result
            fallback_reason = llm.last_error or f"AI provider '{llm.provider}' returned no output."
        except Exception as e:
            fallback_reason = f"Provider exception: {type(e).__name__}"
            logger.warning("AI provider failed (%s), engaging rules fallback.", fallback_reason)
    else:
        if llm.provider != "fallback":
            fallback_reason = llm.last_error or f"AI provider '{llm.provider}' is unavailable."

    # Execute deterministic rule-based analysis
    result = analyze_with_fallback(normalized_text, input_type, language=effective_language)
    result.input_text = text
    result.fallback_used = True
    result.fallback_reason = fallback_reason

    if fallback_reason:
        result.warnings = [f"AI model unavailable ({fallback_reason}). Rule-based analysis performed."]

    return result
