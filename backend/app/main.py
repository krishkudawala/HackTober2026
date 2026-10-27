"""
KavachX Bharat API — FastAPI Backend
AI-powered scam detection and digital safety for Bharat.

Main application entry point with security and operational hardening (Milestone B06).
"""

import re
import uuid
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.security import verify_api_key
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
    # 1. Validate configuration at startup (B06)
    try:
        settings.validate()
    except Exception as exc:
        logger.error("Configuration validation failed during startup: %s", exc)
        raise

    logger.info("=" * 60)
    logger.info(f"  {settings.APP_NAME} — Backend Initializing")
    logger.info(f"  Version: {settings.APP_VERSION}")
    logger.info(f"  Environment: {settings.ENVIRONMENT}")
    logger.info("  AI Model Loading: Deferred (No models loaded at startup)")
    logger.info("=" * 60)

    # 2. Initialize durable database persistence safely during startup (B05)
    try:
        from app.services.scan_store import get_scan_store
        await get_scan_store().initialize()
    except Exception as exc:
        logger.warning(
            "Database initialization failed during startup: %s. Operational health check remains available.",
            type(exc).__name__,
        )

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
        {"name": "Analysis", "description": "AI-powered scam detection for messages, transcripts, and audio"},
        {"name": "Scans", "description": "Scan history and single scan retrieval"},
        {"name": "Reports", "description": "Incident report submission and recording"},
        {"name": "Dashboard", "description": "Aggregated scam detection statistics"},
        {"name": "Demo", "description": "Preset demo scenarios and evaluation runner"},
    ]
)

# ── Security & Correlation Middleware (B06) ──

@app.middleware("http")
async def security_and_correlation_middleware(request: Request, call_next):
    """
    HTTP middleware attaching a request/correlation ID, enforcing safe error
    boundaries, and applying security headers to every response.
    """
    incoming_id = request.headers.get("x-request-id")
    if incoming_id and re.match(r"^[a-zA-Z0-9_\-\.]{1,64}$", incoming_id):
        request_id = incoming_id
    else:
        request_id = str(uuid.uuid4())

    request.state.request_id = request_id

    try:
        response = await call_next(request)
    except Exception as exc:
        logger.error(
            "Unhandled server exception [req_id=%s] %s %s: %s",
            request_id,
            request.method,
            request.url.path,
            type(exc).__name__,
        )
        response = JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An unexpected internal server error occurred.",
                "request_id": request_id,
            },
        )

    # Attach correlation and security response headers
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if settings.is_production():
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


# ── Global Exception Handler (B06) ──

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Fallback exception handler ensuring no internal stack traces or paths leak."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.error("Unhandled exception caught by handler [req_id=%s]: %s", request_id, type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An unexpected internal server error occurred.",
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id},
    )


# ── CORS Middleware (B06) ──

# Intentional methods and headers for production vs development
if settings.is_production():
    cors_methods = ["GET", "POST", "OPTIONS", "HEAD"]
    cors_headers = [
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "X-Request-ID",
        "Accept",
        "Origin",
    ]
else:
    cors_methods = ["*"]
    cors_headers = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=cors_methods,
    allow_headers=cors_headers,
)


# ── Include Routers (With Optional Server-to-Server Auth) ──

app.include_router(api_router, prefix="/api", dependencies=[Depends(verify_api_key)])


# ── Health Check Endpoint (Public & Lightweight) ──

@app.get(
    "/health",
    tags=["Health"],
    summary="Health check",
    description="Check if the KavachX Bharat API backend is operational. Unauthenticated and requires no AI models."
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
