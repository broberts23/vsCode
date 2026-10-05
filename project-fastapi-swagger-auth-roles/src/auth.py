"""Microsoft Entra JWT validation and role checks."""

from __future__ import annotations

import logging
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jwt import PyJWKClient

from src.config import ALLOWED_API_ROLES, Settings, get_settings

logger = logging.getLogger(__name__)

_jwks_client: PyJWKClient | None = None


def build_oauth2_scheme(settings: Settings | None = None) -> OAuth2AuthorizationCodeBearer:
    """Build the OpenAPI OAuth2 scheme (safe with placeholder tenant before .env is filled)."""
    settings = settings or get_settings()
    tenant = settings.tenant_id or "common"
    authority = f"https://login.microsoftonline.com/{tenant}"
    scope = (
        settings.access_as_user_scope
        if settings.api_client_id
        else "api://YOUR_API_CLIENT_ID/access_as_user"
    )
    return OAuth2AuthorizationCodeBearer(
        authorizationUrl=f"{authority}/oauth2/v2.0/authorize",
        tokenUrl=f"{authority}/oauth2/v2.0/token",
        scopes={scope: "Access the Identity API as a signed-in user"},
        scheme_name="EntraOAuth2",
    )


oauth2_scheme = build_oauth2_scheme()


def _get_jwks_client(settings: Settings) -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(settings.jwks_uri, cache_keys=True)
    return _jwks_client


def _unverified_claims(token: str) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
        )
        return claims if isinstance(claims, dict) else {}
    except jwt.PyJWTError:
        return {}


def decode_access_token(token: str, settings: Settings) -> dict[str, Any]:
    settings.require_entra()
    try:
        signing_key = _get_jwks_client(settings).get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.audience_values,
            issuer=settings.issuer,
            options={"require": ["exp", "iss", "aud"]},
        )
    except Exception as exc:
        preview = _unverified_claims(token)
        logger.warning(
            "Access token validation failed: %s (token iss=%r aud=%r ver=%r; expected issuer=%r)",
            exc,
            preview.get("iss"),
            preview.get("aud"),
            preview.get("ver"),
            settings.issuer,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Invalid or expired access token: {exc} "
                f"(token iss={preview.get('iss')!r}, aud={preview.get('aud')!r}, "
                f"ver={preview.get('ver')!r}; expected issuer={settings.issuer!r})"
            ),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_api_roles(claims: dict[str, Any]) -> dict[str, Any]:
    roles = claims.get("roles") or []
    if isinstance(roles, str):
        roles = [roles]
    if not ALLOWED_API_ROLES.intersection(roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token is missing required app role (role.admin or role.service)",
        )
    return claims


async def get_current_principal(
    token: Annotated[str, Depends(oauth2_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    try:
        claims = decode_access_token(token, settings)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    return require_api_roles(claims)
