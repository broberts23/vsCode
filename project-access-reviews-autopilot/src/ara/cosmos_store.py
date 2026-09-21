"""Cosmos correlation store. Emulator uses key; Azure uses DefaultAzureCredential."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from azure.cosmos import CosmosClient, PartitionKey
from azure.cosmos.exceptions import CosmosResourceNotFoundError
from azure.identity import DefaultAzureCredential

from ara.models import CorrelationDocument, ReviewStatus, ReviewWorkMessage
from ara.settings import Settings

logger = logging.getLogger(__name__)


class CosmosCorrelationStore:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        if settings.use_cosmos_emulator:
            # Docker emulator advertises container IPs; keep traffic on the host endpoint.
            self._client = CosmosClient(
                settings.cosmos_endpoint,
                credential=settings.cosmos_key,
                connection_verify=False,
                enable_endpoint_discovery=False,
            )
        else:
            if not settings.cosmos_endpoint:
                raise RuntimeError("COSMOS_ENDPOINT is required")
            self._client = CosmosClient(
                settings.cosmos_endpoint,
                credential=DefaultAzureCredential(),
            )
        self._ensure()
        db = self._client.get_database_client(settings.cosmos_database)
        self._container = db.get_container_client(settings.cosmos_container)

    def _ensure(self) -> None:
        db = self._client.create_database_if_not_exists(self._settings.cosmos_database)
        db.create_container_if_not_exists(
            id=self._settings.cosmos_container,
            partition_key=PartitionKey(path="/partition_key"),
            default_ttl=-1,
        )

    def upsert_from_work(self, work: ReviewWorkMessage) -> CorrelationDocument:
        doc = CorrelationDocument.from_work(work)
        self._container.upsert_item(doc.model_dump(mode="json"))
        return doc

    def get(self, correlation_id: str) -> CorrelationDocument | None:
        try:
            item = self._container.read_item(
                item=correlation_id,
                partition_key=correlation_id,
            )
            return CorrelationDocument.model_validate(item)
        except CosmosResourceNotFoundError:
            return None

    def mark_notified(
        self,
        correlation_id: str,
        *,
        channel_id: str,
        message_ts: str,
    ) -> CorrelationDocument:
        doc = self.get(correlation_id)
        if doc is None:
            raise KeyError(correlation_id)
        doc.status = ReviewStatus.NOTIFIED
        doc.slack_channel_id = channel_id
        doc.slack_message_ts = message_ts
        doc.updated_at = datetime.now(timezone.utc)
        self._container.upsert_item(doc.model_dump(mode="json"))
        return doc

    def mark_applied(
        self,
        correlation_id: str,
        *,
        decision: str,
        decided_by: str,
    ) -> CorrelationDocument:
        doc = self.get(correlation_id)
        if doc is None:
            raise KeyError(correlation_id)
        doc.status = ReviewStatus.APPLIED
        doc.decision = decision
        doc.decided_by = decided_by
        doc.decided_at = datetime.now(timezone.utc)
        doc.updated_at = datetime.now(timezone.utc)
        self._container.upsert_item(doc.model_dump(mode="json"))
        return doc

    def list_pending(self) -> list[CorrelationDocument]:
        query = (
            "SELECT * FROM c WHERE c.status = @pending OR c.status = @notified "
            "ORDER BY c.created_at DESC"
        )
        items = self._container.query_items(
            query=query,
            parameters=[
                {"name": "@pending", "value": ReviewStatus.PENDING.value},
                {"name": "@notified", "value": ReviewStatus.NOTIFIED.value},
            ],
            enable_cross_partition_query=True,
        )
        return [CorrelationDocument.model_validate(item) for item in items]

    def list_all(self, limit: int = 50) -> list[dict[str, Any]]:
        items = self._container.query_items(
            query="SELECT TOP @limit * FROM c ORDER BY c.updated_at DESC",
            parameters=[{"name": "@limit", "value": limit}],
            enable_cross_partition_query=True,
        )
        return list(items)
