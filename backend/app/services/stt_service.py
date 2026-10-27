"""
KavachX Bharat — Speech-to-Text (STT) Service Abstraction
Provides pluggable audio transcription with an out-of-the-box demo mode.
When no external STT provider is configured or credentials are absent,
returns a transparent demo-mode response instructing the user to paste the transcript.
"""

import os
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("kavachx.stt")


class SpeechToTextService:
    """
    Extensible Speech-to-Text service abstraction.
    Supports environment-configured providers:
    - 'demo' (default): returns explicit demo guidance requiring no credentials.
    - Custom / mock providers for testing and local integration.
    """

    def __init__(self, provider: Optional[str] = None):
        raw_provider = provider or os.getenv("STT_PROVIDER", "demo")
        self.provider = raw_provider.lower().strip() if raw_provider else "demo"
        logger.info(f"STT Service initialized with provider: {self.provider}")

    def is_available(self) -> bool:
        """Indicates whether a functional non-demo STT provider is configured."""
        return self.provider != "demo"

    async def transcribe(
        self, audio_data: bytes, filename: str = "", language: str = "en"
    ) -> Dict[str, Any]:
        """
        Transcribe audio bytes to text.

        Returns:
            Dict containing:
            - status: "demo_mode", "success", or "error"
            - message: Informational or error description
            - provider: Name of the provider used
            - transcript: Transcribed string (or empty if demo/error)
            - is_demo: Boolean flag
        """
        if self.provider == "demo":
            return self._demo_response()

        # Pluggable integration point for configured STT providers
        try:
            return await self._transcribe_configured_provider(audio_data, filename, language)
        except Exception as e:
            logger.error("STT transcription failed with provider '%s': %s", self.provider, type(e).__name__)
            return {
                "status": "error",
                "message": "Audio transcription failed.",
                "provider": self.provider,
                "transcript": "",
                "is_demo": False,
            }

    async def _transcribe_configured_provider(
        self, audio_data: bytes, filename: str, language: str
    ) -> Dict[str, Any]:
        """
        Execute transcription using configured provider.
        Override or extend this method when integrating specific offline or local engines.
        """
        raise NotImplementedError(
            f"Provider '{self.provider}' is not configured with runtime credentials or offline engine."
        )

    def _demo_response(self) -> Dict[str, Any]:
        """Returns standard demo-mode payload without fabricating transcripts."""
        return {
            "status": "demo_mode",
            "message": (
                "Speech-to-Text is in demo mode. Please paste the call transcript "
                "manually into the transcript analysis tool or configure an STT provider."
            ),
            "provider": "demo",
            "transcript": "",
            "is_demo": True,
        }


# Singleton instance
_stt_service: Optional[SpeechToTextService] = None


def get_stt_service() -> SpeechToTextService:
    """Retrieve or create the STT service singleton."""
    global _stt_service
    if _stt_service is None:
        _stt_service = SpeechToTextService()
    return _stt_service


def set_stt_service(service: Optional[SpeechToTextService]) -> None:
    """Explicitly inject an STT service instance (useful for unit testing)."""
    global _stt_service
    _stt_service = service


def reset_stt_service() -> None:
    """Reset the STT service singleton."""
    global _stt_service
    _stt_service = None
