"""Cosmos persistence for mock identity documents."""

from __future__ import annotations

import logging
from functools import lru_cache

from azure.cosmos import ContainerProxy, CosmosClient
from azure.cosmos.exceptions import CosmosResourceNotFoundError

from src.config import Settings, get_settings
from src.cosmos.client import create_cosmos_client, ensure_identity_container
from src.models.identity import Identity, IdentityPatch

logger = logging.getLogger(__name__)


class IdentityStore:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: CosmosClient = create_cosmos_client(settings)
        self._container: ContainerProxy = ensure_identity_container(self._client, settings)

    def get(self, identity_id: str) -> Identity | None:
        try:
            item = self._container.read_item(item=identity_id, partition_key=identity_id)
            return Identity.model_validate(item)
        except CosmosResourceNotFoundError:
            return None

    def put(self, identity: Identity) -> Identity:
        self._container.upsert_item(identity.to_cosmos_item())
        logger.debug("Upserted identity id=%s", identity.id)
        return identity

    def patch(self, identity_id: str, patch: IdentityPatch) -> Identity | None:
        existing = self.get(identity_id)
        if existing is None:
            return None
        if patch.display_name is None:
            return existing
        return self.put(Identity(id=existing.id, display_name=patch.display_name))


@lru_cache
def get_identity_store() -> IdentityStore:
    return IdentityStore(get_settings())
