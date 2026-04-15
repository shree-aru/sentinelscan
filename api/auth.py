"""
SentinelScan - API Key Authentication
=======================================
Provides a FastAPI dependency that enforces API key authentication
on protected endpoints.

Why API key auth?
  - Without auth, anyone who finds your Render URL can abuse your scanner
  - API keys are the standard auth method for security tool APIs
  - VirusTotal, Shodan, Censys all use API key auth for the same reason
  - This pattern is used in production at Microsoft, AWS, Google

How it works:
  - Clients pass their key in the X-API-Key request header
  - FastAPI dependency injection calls require_api_key() before the route runs
  - If the key is wrong or missing, a 401 is returned before any scan starts
  - If correct, the route function receives the validated key

Setting your API key:
  Development : key is 'sentinel-dev-key-2024' by default
  Production  : set SENTINEL_API_KEY environment variable on Render.com

Learning goals:
  - FastAPI dependency injection (the 'Depends' pattern)
  - Environment variables for config (never hardcode secrets)
  - HTTP 401/403 status codes and WWW-Authenticate headers
"""

import os
from fastapi import HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader

# FastAPI security scheme — tells OpenAPI/Swagger docs about the auth method
# This auto-adds an "Authorize" button to the /docs Swagger UI
API_KEY_HEADER = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
    description="Your SentinelScan API key. Default dev key: sentinel-dev-key-2024"
)

# The default development key
# In production: set SENTINEL_API_KEY env var on your hosting platform
_DEFAULT_DEV_KEY = "sentinel-dev-key-2024"


def get_configured_api_key() -> str:
    """
    Returns the configured API key from environment or falls back to dev key.

    Environment variables are the correct way to handle secrets in production.
    They are never committed to Git and can be rotated without code changes.
    """
    return os.environ.get("SENTINEL_API_KEY", _DEFAULT_DEV_KEY)


async def require_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    FastAPI dependency that validates the X-API-Key header.

    Usage in a route:
        @app.post("/scan")
        async def scan(request: ScanRequest, key: str = Depends(require_api_key)):
            ...

    If the key is wrong, FastAPI returns 401 before the route body runs.
    The route never sees invalid requests — this is what 'dependency injection' means.
    """
    valid_key = get_configured_api_key()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Missing API key",
                "message": "Pass your API key in the X-API-Key request header.",
                "example": "X-API-Key: sentinel-dev-key-2024"
            }
        )

    if api_key != valid_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Invalid API key",
                "message": "The provided API key is not valid.",
                "hint": "Default dev key is: sentinel-dev-key-2024"
            }
        )

    return api_key
