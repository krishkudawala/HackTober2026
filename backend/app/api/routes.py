"""
API Route definitions for KavachX Bharat.

This router defines the top-level API endpoints and organizes sub-routers
for upcoming modules (e.g. B02: POST /api/analyze/message).
"""

from fastapi import APIRouter

router = APIRouter()

# Note: B02 will register the scam-analysis endpoint here:
# POST /api/analyze/message
