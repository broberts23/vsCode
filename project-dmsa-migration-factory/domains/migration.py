from typing import Protocol

from shared.models import MigrationRequest, MigrationResult, RollbackRequest, RollbackResult
from shared.powershell import PowerShellResult, require_success


class ScriptRunner(Protocol):
    def run_script(self, script_name: str, parameters: dict[str, object] | None = None) -> PowerShellResult:
        ...


def create_dmsa(runner: ScriptRunner, request: MigrationRequest, unique_dmsa_name: str) -> MigrationResult:
    params: dict[str, object] = {
        "Name": unique_dmsa_name,
        "HostName": request.target_host,
        "DomainDnsName": request.domain_dns_name,
    }
    if request.superseded_account:
        params["SupersededAccount"] = request.superseded_account

    result = runner.run_script("Create-DMSA.ps1", params)
    require_success(result)
    return MigrationResult(request.service_name, unique_dmsa_name, True, result.stdout.strip() or "dMSA created")


def migrate_service(runner: ScriptRunner, request: MigrationRequest, unique_dmsa_name: str) -> MigrationResult:
    netbios_domain = request.domain_dns_name.split(".")[0].upper()

    params: dict[str, object] = {
        "ServiceName": request.service_name,
    }

    if not request.superseded_account:
        params["AccountName"] = f"{netbios_domain}\\{unique_dmsa_name}$"

    result = runner.run_script("Configure-WindowsService.ps1", params)
    require_success(result)
    return MigrationResult(request.service_name, unique_dmsa_name, True, result.stdout.strip() or "service migrated")


def rollback_service(runner: ScriptRunner, request: RollbackRequest) -> RollbackResult:
    result = runner.run_script(
        "Configure-WindowsService.ps1",
        {
            "ServiceName": request.service_name,
            "AccountName": request.previous_account,
            "ClearDMSA": True,
        },
    )
    require_success(result)
    return RollbackResult(request.service_name, request.previous_account, True, result.stdout.strip() or "service rolled back")