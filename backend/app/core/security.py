"""
KavachX Bharat — Security and Access Control Helpers (B06)
Provides API Key verification for optional private server-to-server deployments.
"""

import hmac
from fastapi import Request, HTTPException, status
from app.core.config import settings


def verify_api_key(request: Request) -> None:
    """
    Validate incoming requests against optional configured API_KEY.
    - If API_KEY is not set or empty: access is unauthenticated (open for local development).
    - If API_KEY is set: client must provide the key via 'X-API-Key' header or
      'Authorization: Bearer <key>'.
    - Timing-safe constant-time comparison is used to mitigate side-channel timing attacks.
    - Note: An API key embedded in a client-side mobile app (e.g. Flutter) is not secret
      and does not protect against reverse engineering or extraction. This control is intended
      for private server-to-server or gateway integrations.
    """
    configured_key = settings.API_KEY
    if not configured_key:
        return

    # Check X-API-Key header first
    client_key = request.headers.get("x-api-key")

    # Check Authorization header (Bearer token)
    if not client_key:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            client_key = auth_header[7:].strip()

    if not client_key or not hmac.compare_digest(client_key, configured_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
