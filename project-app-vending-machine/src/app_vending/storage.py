import json
from datetime import datetime, timezone
from typing import Any

from azure.data.tables import TableServiceClient, UpdateMode
from azure.storage.queue import QueueClient

from app_vending.settings import (
    QUEUE_NAME,
    TABLE_NAME,
    get_storage_connection_string,
)


def _table_client():
    return TableServiceClient.from_connection_string(
        get_storage_connection_string()
    ).get_table_client(TABLE_NAME)


def _queue_client():
    return QueueClient.from_connection_string(
        get_storage_connection_string(),
        QUEUE_NAME,
    )


def ensure_storage():
    table_service = TableServiceClient.from_connection_string(get_storage_connection_string())
    try:
        table_service.create_table(TABLE_NAME)
    except Exception:
        pass

    queue = _queue_client()
    try:
        queue.create_queue()
    except Exception:
        pass


def save_request(request_id: str, payload: dict[str, Any], status: str = "accepted") -> dict[str, Any]:
    ensure_storage()
    now = datetime.now(timezone.utc).isoformat()
    entity = {
        "PartitionKey": "requests",
        "RowKey": request_id,
        "Status": status,
        "Payload": json.dumps(payload),
        "CreatedAt": now,
        "CompletedAt": "",
        "Result": "",
        "Error": "",
    }
    _table_client().upsert_entity(mode=UpdateMode.MERGE, entity=entity)
    return entity


def enqueue_request(request_id: str):
    ensure_storage()
    _queue_client().send_message(json.dumps({"requestId": request_id}))


def get_request_payload(request_id: str) -> dict[str, Any] | None:
    ensure_storage()
    try:
        entity = _table_client().get_entity(partition_key="requests", row_key=request_id)
    except Exception:
        return None
    payload_raw = entity.get("Payload")
    if not payload_raw:
        return None
    return json.loads(payload_raw)


def get_request(request_id: str) -> dict[str, Any] | None:
    ensure_storage()
    try:
        entity = _table_client().get_entity(partition_key="requests", row_key=request_id)
    except Exception:
        return None

    result = {
        "requestId": request_id,
        "status": entity.get("Status", "unknown"),
        "createdAt": entity.get("CreatedAt"),
        "completedAt": entity.get("CompletedAt") or None,
        "error": entity.get("Error") or None,
    }

    payload_raw = entity.get("Payload")
    if payload_raw:
        payload = json.loads(payload_raw)
        result["offeringId"] = payload.get("offeringId")

    result_raw = entity.get("Result")
    if result_raw:
        result["result"] = json.loads(result_raw)

    execution_mode = entity.get("ExecutionMode")
    if execution_mode:
        result["executionMode"] = execution_mode

    return result


def update_request(
    request_id: str,
    *,
    status: str,
    result: dict[str, Any] | None = None,
    error: str | None = None,
    execution_mode: str | None = None,
):
    ensure_storage()
    entity: dict[str, Any] = {
        "PartitionKey": "requests",
        "RowKey": request_id,
        "Status": status,
        "CompletedAt": datetime.now(timezone.utc).isoformat(),
    }
    if result is not None:
        entity["Result"] = json.dumps(result)
    if error is not None:
        entity["Error"] = error
    if execution_mode is not None:
        entity["ExecutionMode"] = execution_mode
    _table_client().upsert_entity(mode=UpdateMode.MERGE, entity=entity)
