import json
from typing import Protocol

from contracts.validation import validation_result_from_dict
from shared.models import ValidationResult
from shared.powershell import PowerShellResult, require_success


class ScriptRunner(Protocol):
    def run_script(self, script_name: str, parameters: dict[str, object] | None = None) -> PowerShellResult:
        ...


def validate_service(runner: ScriptRunner, service_name: str, expected_account: str | None = None) -> ValidationResult:
    result = runner.run_script(
        "Restart-ValidateService.ps1",
        {
            "ServiceName": service_name,
            "ExpectedAccount": expected_account,
        },
    )
    require_success(result)
    payload = json.loads(result.stdout or "{}")
    return validation_result_from_dict(payload)
