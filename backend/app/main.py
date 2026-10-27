"""
KavachX Bharat API — FastAPI Backend
AI-powered scam detection and digital safety for Bharat.

Main application entry point.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes import router as api_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger("kavachx")


# ── Application Lifespan ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handles startup and shutdown events for the application."""
    logger.info("=" * 60)
    logger.info(f"  {settings.APP_NAME} — Backend Initializing")
    logger.info(f"  Version: {settings.APP_VERSION}")
    logger.info(f"  Environment: {settings.ENVIRONMENT}")
    logger.info("  AI Model Loading: Deferred (No models loaded at startup)")
    logger.info("=" * 60)
    yield
    logger.info(f"  {settings.APP_NAME} — Backend Shutting Down")


# ── App Initialization ──

app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Health", "description": "Service health check and operational status"},
        {"name": "Analysis", "description": "AI-powered scam detection and message analysis (B02)"},
    ]
)

# ── CORS Middleware ──

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Include Routers ──

app.include_router(api_router, prefix="/api")


# ── Health Check Endpoint ──

@app.get(
    "/health",
    tags=["Health"],
    summary="Health check",
    description="Check if the KavachX Bharat API backend is operational."
)
async def health_check():
    """
    Returns the operational status of the KavachX Bharat API.
    Does not load AI models or depend on external services.
    """
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


# ── Root Endpoint ──

@app.get("/", tags=["Health"], summary="API Root")
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs_url": "/docs",
        "health_url": "/health",
    }
