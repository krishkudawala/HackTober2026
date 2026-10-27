"""
Configuration management for KavachX Bharat API.
Loads environment variables with sensible defaults.
"""

import os
from typing import List, Optional
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()


class Settings:
    APP_NAME: str = os.getenv("APP_NAME", "KavachX Bharat API")
    APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")
    APP_DESCRIPTION: str = (
        "AI-powered scam detection and digital safety API for Bharat — "
        "designed to identify fraudulent messages, phishing attempts, and scam tactics."
    )
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    # AI Provider Configuration
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "fallback")
    LITERT_MODEL_PATH: Optional[str] = os.getenv("LITERT_MODEL_PATH")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")

    # Speech-to-Text Configuration
    STT_PROVIDER: str = os.getenv("STT_PROVIDER", "demo")
    MAX_AUDIO_UPLOAD_BYTES: int = int(os.getenv("MAX_AUDIO_UPLOAD_BYTES", 25 * 1024 * 1024))  # 25 MB default


    # CORS Origins: comma-separated list of origins or "*"
    _raw_cors_origins: str = os.getenv("CORS_ORIGINS", "*")

    @property
    def CORS_ORIGINS(self) -> List[str]:
        if self._raw_cors_origins == "*":
            return ["*"]
        return [origin.strip() for origin in self._raw_cors_origins.split(",") if origin.strip()]


settings = Settings()
