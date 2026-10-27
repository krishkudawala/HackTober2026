"""
Configuration management for KavachX Bharat API.
Loads environment variables with sensible defaults and provides startup validation.
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

    # Database Persistence Configuration (B05)
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "data/kavachx.db")

    # Security & Access Control Configuration (B06)
    # Optional server-to-server API key (None by default: open for local dev)
    API_KEY: Optional[str] = os.getenv("API_KEY")

    # CORS Configuration
    _raw_cors_origins: str = os.getenv("CORS_ORIGINS", "*")
    CORS_ALLOW_CREDENTIALS: bool = os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() in ("true", "1", "yes")

    @property
    def CORS_ORIGINS(self) -> List[str]:
        if self._raw_cors_origins == "*":
            return ["*"]
        return [origin.strip() for origin in self._raw_cors_origins.split(",") if origin.strip()]

    def is_production(self) -> bool:
        """Indicate whether the application is configured in production mode."""
        return self.ENVIRONMENT.lower() == "production"

    def validate(self) -> None:
        """
        Validate configuration at application startup.
        Fails fast with clear descriptive messages without exposing secrets.
        """
        valid_envs = {"development", "staging", "production", "test"}
        if self.ENVIRONMENT.lower() not in valid_envs:
            raise ValueError(
                f"Invalid ENVIRONMENT '{self.ENVIRONMENT}'. Expected one of: {', '.join(sorted(valid_envs))}."
            )

        if not (1 <= self.PORT <= 65535):
            raise ValueError(f"Invalid PORT '{self.PORT}'. Must be between 1 and 65535.")

        if self.MAX_AUDIO_UPLOAD_BYTES <= 0 or self.MAX_AUDIO_UPLOAD_BYTES > 100 * 1024 * 1024:
            raise ValueError("MAX_AUDIO_UPLOAD_BYTES must be positive and not exceed 100MB.")

        # In production mode: reject wildcard CORS origins when credentials are enabled
        if self.is_production():
            if self.CORS_ALLOW_CREDENTIALS and ("*" in self.CORS_ORIGINS or self._raw_cors_origins == "*"):
                raise ValueError(
                    "Production configuration error: Wildcard CORS_ORIGINS ('*') cannot be used when "
                    "credentials are enabled (CORS_ALLOW_CREDENTIALS=true). "
                    "Please configure explicit trusted domain origins."
                )

        # AI provider checks
        valid_ai_providers = {"fallback", "litert", "ollama"}
        if self.AI_PROVIDER.lower() not in valid_ai_providers:
            raise ValueError(
                f"Invalid AI_PROVIDER '{self.AI_PROVIDER}'. Expected one of: {', '.join(sorted(valid_ai_providers))}."
            )

        if not self.STT_PROVIDER.strip():
            raise ValueError("STT_PROVIDER cannot be empty.")

        # Validate database path does not contain null bytes
        if "\x00" in self.DATABASE_PATH:
            raise ValueError("DATABASE_PATH cannot contain null bytes.")


settings = Settings()
