import base64
import json
from typing import Any

from fastapi import HTTPException, Request, status

from app_vending.settings import get_auth_bypass, get_required_roles


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Token is not a valid JWT.")
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    decoded = base64.urlsafe_b64decode(payload + padding)
    return json.loads(decoded.decode("utf-8"))


def get_bearer_token(request: Request) -> str | None:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return None


def get_claims(request: Request) -> dict[str, Any]:
    if get_auth_bypass():
        return {"roles": get_required_roles(), "oid": "local-dev-user"}

    easy_auth_header = request.headers.get("X-MS-CLIENT-PRINCIPAL")
    if easy_auth_header:
        decoded = base64.b64decode(easy_auth_header)
        principal = json.loads(decoded.decode("utf-8"))
        claims = {claim["typ"]: claim["val"] for claim in principal.get("claims", [])}
        roles = claims.get("roles", "")
        if isinstance(roles, str):
            claims["roles"] = [role.strip() for role in roles.split(",") if role.strip()]
        return claims

    token = get_bearer_token(request)
    if not token:
        return {}

    try:
        return _decode_jwt_payload(token)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token could not be decoded.",
        ) from exc


def get_roles(claims: dict[str, Any]) -> list[str]:
    roles = claims.get("roles", [])
    if isinstance(roles, str):
        return [role.strip() for role in roles.split(",") if role.strip()]
    return list(roles)


def require_submitter_role(request: Request) -> dict[str, Any]:
    claims = get_claims(request)
    if get_auth_bypass():
        return claims

    allowed_roles = set(get_required_roles())
    caller_roles = set(get_roles(claims))
    if not caller_roles.intersection(allowed_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Caller must have one of: {', '.join(sorted(allowed_roles))}.",
        )
    return claims
