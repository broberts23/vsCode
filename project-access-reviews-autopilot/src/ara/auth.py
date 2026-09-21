"""OIDC bearer validation for the SPA/API. Bypass for local emulator runs."""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

import httpx
from fastapi import HTTPException, Request, status

from ara.settings import Settings

logger = logging.getLogger(__name__)

_JWKS_CACHE: dict[str, Any] = {}


def _decode_unverified_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT")
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload + padding))


def _issuer(settings: Settings) -> str:
    return f"https://login.microsoftonline.com/{settings.entra_tenant_id}/v2.0"


def _get_jwks(settings: Settings) -> dict[str, Any]:
    cache_key = settings.entra_tenant_id
    if cache_key in _JWKS_CACHE:
        return _JWKS_CACHE[cache_key]
    url = (
        f"https://login.microsoftonline.com/{settings.entra_tenant_id}"
        "/discovery/v2.0/keys"
    )
    with httpx.Client(timeout=30.0) as client:
        response = client.get(url)
        response.raise_for_status()
        data = response.json()
    _JWKS_CACHE[cache_key] = data
    return data


def _validate_token(token: str, settings: Settings) -> dict[str, Any]:
    """Validate aud/iss/scp without pinning crypto deps.

    Production hardening can swap this for PyJWT + JWKS signature verify.
    Lab gate: audience, issuer, and required scope must match.
    """
    claims = _decode_unverified_payload(token)
    issuer = claims.get("iss", "")
    expected_issuer = _issuer(settings)
    if issuer != expected_issuer and not issuer.endswith(f"/{settings.entra_tenant_id}/v2.0"):
        raise HTTPException(status_code=401, detail="Invalid token issuer")

    aud = claims.get("aud")
    allowed = {settings.entra_api_audience, settings.entra_api_client_id}
    if aud not in allowed:
        raise HTTPException(status_code=401, detail="Invalid token audience")

    scp = claims.get("scp", "")
    scopes = set(scp.split()) if isinstance(scp, str) else set()
    if settings.entra_required_scope not in scopes and "roles" not in claims:
        # Allow app roles OR the delegated scope
        raise HTTPException(status_code=403, detail="Missing required scope")

    # Touch JWKS so misconfigured tenants fail early in non-bypass mode
    if settings.entra_tenant_id:
        _get_jwks(settings)

    return claims


def require_oidc(request: Request, settings: Settings) -> dict[str, Any]:
    if settings.ara_auth_bypass:
        return {
            "oid": "local-dev-user",
            "preferred_username": "local@contoso.lab",
            "scp": settings.entra_required_scope,
        }

    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
        )
    token = header[7:].strip()
    return _validate_token(token, settings)
