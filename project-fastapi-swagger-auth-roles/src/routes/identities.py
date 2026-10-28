"""HTTP routes for mock identity documents."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from src.auth import get_current_principal
from src.cosmos.identities import IdentityStore, get_identity_store
from src.models.identity import Identity, IdentityPatch

router = APIRouter(prefix="/identities", tags=["identities"])


def identity_store() -> IdentityStore:
    return get_identity_store()


@router.get("/{identity_id}", response_model=Identity)
def get_identity(
    identity_id: str,
    store: Annotated[IdentityStore, Depends(identity_store)],
    _: Annotated[dict[str, Any], Depends(get_current_principal)],
) -> Identity:
    identity = store.get(identity_id)
    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity '{identity_id}' not found",
        )
    return identity


@router.put("/{identity_id}", response_model=Identity)
def put_identity(
    identity_id: str,
    body: Identity,
    store: Annotated[IdentityStore, Depends(identity_store)],
    _: Annotated[dict[str, Any], Depends(get_current_principal)],
) -> Identity:
    if body.id != identity_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path id must match body id",
        )
    return store.put(body)


@router.patch("/{identity_id}", response_model=Identity)
def patch_identity(
    identity_id: str,
    body: IdentityPatch,
    store: Annotated[IdentityStore, Depends(identity_store)],
    _: Annotated[dict[str, Any], Depends(get_current_principal)],
) -> Identity:
    updated = store.patch(identity_id, body)
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Identity '{identity_id}' not found",
        )
    return updated
