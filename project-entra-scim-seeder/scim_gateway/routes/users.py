"""SCIM User Endpoint CRUD engine."""

import logging
import re
import uuid

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from scim_gateway.database import get_db_session
from scim_gateway.models import LocalUser
from scim_gateway.schemas import (
    ListResponse,
    PatchRequest,
    ScimError,
    ScimMeta,
    ScimUserCreate,
    ScimUserResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["SCIM Users"])


def _user_to_scim(user: LocalUser) -> ScimUserResponse:
    """Convert a LocalUser ORM instance to a SCIM response payload."""
    return ScimUserResponse(
        id=str(user.id),
        userName=user.username,
        name={
            "formatted": f"{user.given_name} {user.family_name}",
            "givenName": user.given_name,
            "familyName": user.family_name,
        },
        displayName=user.display_name,
        active=user.active,
        meta=ScimMeta(
            resourceType="User",
            location=f"/scim/v2/Users/{user.id}",
        ),
    )


def _parse_scim_filter(filter_str: str) -> tuple[str, str] | None:
    """Parse a simple SCIM filter like `userName eq "value"`.

    Returns (attribute, value) or None if unparseable.
    """
    match = re.match(r'(\w+)\s+eq\s+"([^"]+)"', filter_str, re.IGNORECASE)
    if match:
        return match.group(1), match.group(2)
    return None


@router.get("/Users", response_model=ListResponse)
def get_users(
    filter: str | None = Query(None),
    db: Session = Depends(get_db_session),
) -> ListResponse:
    """Handle directory queries. Parses SCIM filter expressions."""
    query = db.query(LocalUser)

    if filter:
        parsed = _parse_scim_filter(filter)
        if parsed:
            attr, value = parsed
            if attr.lower() == "username":
                query = query.filter(LocalUser.username == value)
            elif attr.lower() == "externalid":
                query = query.filter(LocalUser.entra_id == value)
            elif attr.lower() == "displayname":
                query = query.filter(LocalUser.display_name == value)

    users = query.all()
    resources = [_user_to_scim(u) for u in users]

    return ListResponse(
        totalResults=len(resources),
        itemsPerPage=len(resources),
        startIndex=1,
        Resources=resources,
    )


@router.get("/Users/{user_id}", response_model=ScimUserResponse)
def get_user_by_id(
    user_id: str,
    db: Session = Depends(get_db_session),
) -> ScimUserResponse:
    """Lookup by ID. Returns 404 SCIM error if not found."""
    user = db.query(LocalUser).filter(LocalUser.id == int(user_id)).first()
    if not user:
        return ScimError(status="404", detail=f"User {user_id} not found")
    return _user_to_scim(user)


@router.post("/Users", response_model=ScimUserResponse, status_code=201)
def create_user(
    body: ScimUserCreate,
    db: Session = Depends(get_db_session),
) -> ScimUserResponse:
    """Provision a new user in the local SQLite store."""
    existing = db.query(LocalUser).filter(LocalUser.username == body.userName).first()
    if existing:
        return ScimError(
            status="409",
            detail=f"User with userName {body.userName} already exists",
            scimType="uniqueness",
        )

    user = LocalUser(
        username=body.userName,
        given_name=body.name.givenName,
        family_name=body.name.familyName,
        display_name=body.displayName or f"{body.name.givenName} {body.name.familyName}",
        active=body.active,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info("Created SCIM user: %s (id=%d)", body.userName, user.id)
    return _user_to_scim(user)


@router.patch("/Users/{user_id}", response_model=ScimUserResponse)
def patch_user(
    user_id: str,
    body: PatchRequest,
    db: Session = Depends(get_db_session),
) -> ScimUserResponse:
    """Process SCIM PATCH operations (e.g., active -> false)."""
    user = db.query(LocalUser).filter(LocalUser.id == int(user_id)).first()
    if not user:
        return ScimError(status="404", detail=f"User {user_id} not found")

    for operation in body.Operations:
        op = operation.op.lower()
        path = operation.path

        if op == "replace":
            if path == "active" or path is None:
                if isinstance(operation.value, bool):
                    user.active = operation.value
                elif isinstance(operation.value, dict):
                    user.active = operation.value.get("active", user.active)
            elif path == "displayName":
                user.display_name = str(operation.value)
            elif path == "name.givenName":
                user.given_name = str(operation.value)
            elif path == "name.familyName":
                user.family_name = str(operation.value)

    db.commit()
    db.refresh(user)

    logger.info("Patched SCIM user: %s", user_id)
    return _user_to_scim(user)


@router.delete("/Users/{user_id}", status_code=204)
def delete_user(
    user_id: str,
    db: Session = Depends(get_db_session),
) -> Response:
    """Deprovision user by removing from local store."""
    user = db.query(LocalUser).filter(LocalUser.id == int(user_id)).first()
    if user:
        db.delete(user)
        db.commit()
        logger.info("Deleted SCIM user: %s", user_id)

    return Response(status_code=204)
