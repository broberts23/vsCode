import json
import re
from typing import Protocol

from contracts.inventory import inventory_result_from_payload
from shared.models import InventoryResult
from shared.powershell import PowerShellResult, require_success


class ScriptRunner(Protocol):
    def run_script(self, script_name: str, parameters: dict[str, object] | None = None) -> PowerShellResult:
        ...


def discover_services(runner: ScriptRunner, host: str) -> InventoryResult:
    result = runner.run_script(
        "Discover-WindowsServices.ps1", {"ComputerName": host})
    require_success(result)
    raw_payload = json.loads(result.stdout or "[]")
    if isinstance(raw_payload, dict):
        raw_payload = [raw_payload]
    per_user_svc_pattern = re.compile(r'_[a-f0-9]{5}$', re.IGNORECASE)
    filtered_payload = [
        svc for svc in raw_payload if not per_user_svc_pattern.search(svc.get("Name", ""))]
    return inventory_result_from_payload(host=host, payload=filtered_payload)
