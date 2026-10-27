"""
FraudShield AI — FastAPI Backend
Real-Time AI Protection Against Digital Scams

Main application entry point.
"""

import os
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from app.api.routes import router
from app.models.schemas import HealthResponse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger("fraudshield")

# ── App Configuration ──

app = FastAPI(
    title="FraudShield AI",
    description=(
        "Real-Time AI Protection Against Digital Scams.\n\n"
        "FraudShield AI detects suspicious scam communication, analyzes the content using AI/NLP, "
        "identifies scam type and red flags, calculates a risk score, explains why the communication "
        "is dangerous, and provides immediate safety actions.\n\n"
        "**Pipeline:** DETECT → UNDERSTAND → CLASSIFY → PROTECT\n\n"
        "**Scam Categories:** Digital Arrest, Fake Bank Support, Investment Scam, "
        "Prepaid Task/Job Scam, Phishing, UPI/Payment Scam, Government Impersonation\n\n"
        "Built for the Maxim Code AI Software Innovation Competition."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "Analysis", "description": "Core scam analysis endpoints"},
        {"name": "Scan History", "description": "View previous scan results"},
        {"name": "Reports", "description": "Incident reporting"},
        {"name": "Dashboard", "description": "Dashboard statistics"},
        {"name": "Demo", "description": "Demo scenarios for demonstration"},
        {"name": "Health", "description": "Service health check"},
    ]
)

# ── CORS ──

cors_origins = os.getenv("CORS_ORIGINS", "*")
origins = cors_origins.split(",") if cors_origins != "*" else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

# Find the demo-web folder relative to main.py
current_dir = os.path.dirname(os.path.abspath(__file__))
demo_web_path = os.path.abspath(os.path.join(current_dir, "..", "..", "demo-web"))

# ── Include Routes ──

app.include_router(router, prefix="/api")

# ── Mount Web Demo (if available) ──
if os.path.exists(demo_web_path):
    app.mount("/demo", StaticFiles(directory=demo_web_path, html=True), name="demo")
    logger.info(f"Mounted demo-web static files from: {demo_web_path}")


# ── Health Check ──

@app.get("/health", response_model=HealthResponse, tags=["Health"],
         summary="Health check",
         description="Check if the FraudShield AI backend is running.")
async def health_check():
    return HealthResponse(
        ai_provider=os.getenv("AI_PROVIDER", "fallback"),
        stt_provider=os.getenv("STT_PROVIDER", "demo"),
        firebase_enabled=os.getenv("FIREBASE_ENABLED", "false").lower() == "true",
    )


@app.get("/", tags=["Health"])
async def root():
    return RedirectResponse(url="/demo/")


# ── Startup Event ──

@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info("  FraudShield AI — Backend Starting")
    logger.info("  Real-Time AI Protection Against Digital Scams")
    logger.info(f"  AI Provider: {os.getenv('AI_PROVIDER', 'fallback')}")
    logger.info(f"  STT Provider: {os.getenv('STT_PROVIDER', 'demo')}")
    logger.info(f"  Firebase: {os.getenv('FIREBASE_ENABLED', 'false')}")
    logger.info("=" * 60)
