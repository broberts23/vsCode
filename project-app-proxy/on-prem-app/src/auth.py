"""Central authentication and authorization for static and API routes."""

from __future__ import annotations

import logging
from typing import Any

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient

from config import Settings, get_settings

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)
_jwks_clients: dict[str, PyJWKClient] = {}


def _issuer_for_tenant(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/v2.0"


def _jwks_client(tenant_id: str) -> PyJWKClient:
    if tenant_id not in _jwks_clients:
        jwks_uri = (
            f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        )
        _jwks_clients[tenant_id] = PyJWKClient(jwks_uri)
    return _jwks_clients[tenant_id]


def extract_access_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    settings: Settings,
) -> str | None:
    """Prefer Authorization Bearer; fall back to the App Proxy–safe custom header."""
    if credentials is not None and credentials.scheme.lower() == "bearer":
        return credentials.credentials
    authorization = request.headers.get("Authorization")
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    custom = request.headers.get(settings.access_token_header)
    if custom:
        return custom.strip()
    return None


def validate_tenant_token(token: str, settings: Settings) -> dict[str, Any]:
    """Validate a Microsoft Entra access token for this tenant and audience."""
    if not settings.tenant_id or not settings.api_audience:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Auth is enabled but TENANT_ID and/or API_AUDIENCE are not configured."
            ),
        )

    try:
        signing_key = _jwks_client(settings.tenant_id).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.api_audience,
            issuer=_issuer_for_tenant(settings.tenant_id),
            options={"require": ["exp", "iss", "aud"]},
        )
    except httpx.HTTPError as exc:
        logger.exception("Failed to reach Entra JWKS endpoint")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to validate token against identity provider.",
        ) from exc
    except jwt.PyJWTError as exc:
        logger.info("Token validation failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    return claims


def _roles_from_claims(claims: dict[str, Any]) -> set[str]:
    roles = claims.get("roles", [])
    if isinstance(roles, str):
        return {roles}
    if isinstance(roles, list):
        return {str(role) for role in roles}
    return set()


async def require_tenant_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any] | None:
    """Require a valid tenant access token unless local debug is enabled."""
    if settings.local_debug:
        return None

    token = extract_access_token(request, credentials, settings)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Access token required "
                f"(Authorization Bearer or {settings.access_token_header})."
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )
    return validate_tenant_token(token, settings)


async def require_api_role(
    claims: dict[str, Any] | None = Depends(require_tenant_user),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any] | None:
    """Require the configured app role in addition to a valid tenant token."""
    if settings.local_debug:
        return None

    assert claims is not None
    if settings.required_api_role not in _roles_from_claims(claims):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required role: {settings.required_api_role}",
        )
    return claims
