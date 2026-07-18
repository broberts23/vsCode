"""SCIM User Endpoint CRUD engine backed by Azure Cosmos DB."""

import logging
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import JSONResponse

from scim_gateway.database import get_container
from scim_gateway.models import LocalUser
from scim_gateway.schemas import (
    ListResponse,
    PatchRequest,
    ScimUserCreate,
    ScimUserResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["SCIM Users"])


def _scim_error(status: int, detail: str, scim_type: str | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(status),
            "detail": detail,
            **({"scimType": scim_type} if scim_type else {}),
        },
    )


def _parse_scim_filter(filter_str: str) -> tuple[str, str] | None:
    """Parse a simple SCIM filter like `userName eq "value"`.

    Returns (attribute, value) or None if unparseable.
    """
    match = re.match(r'(\w+)\s+eq\s+"([^"]+)"', filter_str, re.IGNORECASE)
    if match:
        return match.group(1), match.group(2)
    return None


def _derive_names(body: ScimUserCreate) -> tuple[str, str, str]:
    """Derive (given_name, family_name, display_name) from a SCIM create payload.

    Entra ID frequently omits the structured `name` object, sending only
    `displayName`. Falls back through: name.givenName -> name.formatted ->
    displayName -> userName.
    """
    given_name = ""
    family_name = ""
    display_name = body.displayName or ""

    if body.name:
        given_name = body.name.givenName or ""
        family_name = body.name.familyName or ""
        if not given_name and not family_name and body.name.formatted:
            parts = body.name.formatted.split(None, 1)
            given_name = parts[0] if parts else ""
            family_name = parts[1] if len(parts) > 1 else ""

    if not given_name and not family_name and display_name:
        parts = display_name.split(None, 1)
        given_name = parts[0] if parts else ""
        family_name = parts[1] if len(parts) > 1 else ""

    if not display_name:
        display_name = f"{given_name} {family_name}".strip() or body.userName

    return given_name, family_name, display_name


def _query_user(container, attr: str, value: str) -> dict | None:
    """Run a point-lookup query against Cosmos by a SCIM attribute."""
    attr_map = {
        "username": "c.userName",
        "externalid": "c.entraId",
        "displayname": "c.displayName",
    }
    field = attr_map.get(attr.lower())
    if not field:
        return None
    query = f"SELECT * FROM c WHERE {field} = @value"
    items = list(
        container.query_items(
            query=query,
            parameters=[{"name": "@value", "value": value}],
            enable_cross_partition_query=True,
        )
    )
    return items[0] if items else None


@router.get("/Users", response_model=ListResponse)
def get_users(
    filter: str | None = Query(None),
    container=Depends(get_container),
) -> ListResponse:
    """Handle directory queries. Parses SCIM filter expressions."""
    if filter:
        parsed = _parse_scim_filter(filter)
        if not parsed:
            return ListResponse(totalResults=0, itemsPerPage=0, startIndex=1, Resources=[])
        attr, value = parsed
        doc = _query_user(container, attr, value)
        resources = [ScimUserResponse(**LocalUser(**doc).to_scim())] if doc else []
        return ListResponse(
            totalResults=len(resources),
            itemsPerPage=len(resources),
            startIndex=1,
            Resources=resources,
        )

    items = list(container.query_items(
        query="SELECT * FROM c",
        enable_cross_partition_query=True,
    ))
    resources = [ScimUserResponse(**LocalUser(**doc).to_scim()) for doc in items]
    return ListResponse(
        totalResults=len(resources),
        itemsPerPage=len(resources),
        startIndex=1,
        Resources=resources,
    )


@router.get("/Users/{user_id}", response_model=ScimUserResponse)
def get_user_by_id(
    user_id: str,
    userName: str = Query(..., description="Partition key (userName) for the target user"),
    container=Depends(get_container),
) -> ScimUserResponse:
    """Lookup by ID. Returns 404 SCIM error if not found."""
    try:
        doc = container.read_item(item=user_id, partition_key=userName)
    except Exception:
        raise HTTPException(
            status_code=404,
            detail={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "status": "404",
                "detail": f"User {user_id} not found",
            },
        )
    return ScimUserResponse(**LocalUser(**doc).to_scim())


@router.post("/Users", response_model=ScimUserResponse, status_code=201)
def create_user(
    body: ScimUserCreate,
    container=Depends(get_container),
) -> ScimUserResponse:
    """Provision a new user in Cosmos DB."""
    existing = _query_user(container, "userName", body.userName)
    if existing:
        return _scim_error(
            409,
            f"User with userName {body.userName} already exists",
            scim_type="uniqueness",
        )

    given_name, family_name, display_name = _derive_names(body)

    user = LocalUser(
        userName=body.userName,
        givenName=given_name,
        familyName=family_name,
        displayName=display_name,
        active=body.active,
        entraId=body.externalId,
    )
    container.create_item(body=user.model_dump())
    logger.info("Created SCIM user: %s (id=%s)", body.userName, user.id)
    return ScimUserResponse(**user.to_scim())


@router.patch("/Users/{user_id}", response_model=ScimUserResponse)
def patch_user(
    user_id: str,
    body: PatchRequest,
    userName: str = Query(..., description="Partition key (userName) for the target user"),
    container=Depends(get_container),
) -> ScimUserResponse:
    """Process SCIM PATCH operations (e.g., active -> false)."""
    try:
        doc = container.read_item(item=user_id, partition_key=userName)
    except Exception:
        return _scim_error(404, f"User {user_id} not found")

    user = LocalUser(**doc)

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
                user.displayName = str(operation.value)
            elif path == "name.givenName":
                user.givenName = str(operation.value)
            elif path == "name.familyName":
                user.familyName = str(operation.value)
            elif path == "userName":
                user.userName = str(operation.value)

    user.lastModified = datetime.now(timezone.utc).isoformat()
    container.upsert_item(body=user.model_dump())
    logger.info("Patched SCIM user: %s", user_id)
    return ScimUserResponse(**user.to_scim())


@router.delete("/Users/{user_id}", status_code=204)
def delete_user(
    user_id: str,
    userName: str = Query(..., description="Partition key (userName) for the target user"),
    container=Depends(get_container),
) -> Response:
    """Deprovision user by removing from Cosmos DB."""
    try:
        container.delete_item(item=user_id, partition_key=userName)
        logger.info("Deleted SCIM user: %s", user_id)
    except Exception:
        logger.warning("Delete failed for user %s (already absent?)", user_id)

    return Response(status_code=204)
