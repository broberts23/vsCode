from typing import Any

from shared.models import ValidationResult


def validation_result_from_dict(value: dict[str, Any]) -> ValidationResult:
    return ValidationResult(
        service_name=str(value.get("Name", value.get("service_name", ""))),
        running=bool(value.get("Running", value.get("running", False))),
        account=str(value.get("StartName", value.get("account", ""))),
        message=str(value.get("Message", value.get("message", ""))),
    )
