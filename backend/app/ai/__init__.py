"""
AI and Analysis package initialization.
"""

from app.ai.engine import analyze_communication, detect_language, normalize_input
from app.ai.fallback_classifier import analyze_with_fallback
from app.ai.llm_provider import get_llm_provider, reset_llm_provider

__all__ = [
    "analyze_communication",
    "detect_language",
    "normalize_input",
    "analyze_with_fallback",
    "get_llm_provider",
    "reset_llm_provider",
]
