from typing import Any

from shared.models import InventoryResult, WindowsService


def service_from_dict(value: dict[str, Any]) -> WindowsService:
    return WindowsService(
        name=str(value.get("Name", value.get("name", ""))),
        display_name=str(value.get("DisplayName", value.get("display_name", ""))),
        start_name=str(value.get("StartName", value.get("start_name", ""))),
        state=str(value.get("State", value.get("state", ""))),
    )


def inventory_result_from_payload(host: str, payload: list[dict[str, Any]]) -> InventoryResult:
    return InventoryResult(host=host, services=[service_from_dict(item) for item in payload])
