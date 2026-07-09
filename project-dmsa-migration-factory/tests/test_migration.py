from contracts.migration import migration_request_from_dict, rollback_request_from_dict
from domains.migration import create_dmsa, migrate_service, rollback_service
from shared.models import RollbackRequest
from shared.powershell import PowerShellResult


UNIQUE_DMSA_NAME = "svc-spooler-dmsa"


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list = []

    def run_script(self, script_name, parameters=None):
        self.calls.append((script_name, parameters))
        return PowerShellResult(stdout="ok", stderr="", status_code=0)


def _make_request(overrides: dict | None = None) -> dict:
    base = {
        "serviceName": "Spooler",
        "dmsaName": "svc-spooler-dmsa",
        "targetHost": "MEMBER-SRV",
        "domainController": "DC-01",
        "domainDnsName": "contoso.local",
    }
    if overrides:
        base.update(overrides)
    return base


def test_create_dmsa_calls_script_with_request_values():
    request = migration_request_from_dict(_make_request())
    runner = FakeRunner()

    result = create_dmsa(runner, request, UNIQUE_DMSA_NAME)

    assert result.changed is True
    assert result.dmsa_name == UNIQUE_DMSA_NAME
    assert runner.calls[0] == (
        "Create-DMSA.ps1",
        {
            "Name": UNIQUE_DMSA_NAME,
            "HostName": "MEMBER-SRV",
            "DomainDnsName": "contoso.local",
        },
    )


def test_create_dmsa_passes_superseded_account():
    request = migration_request_from_dict(
        _make_request({
            "supersededAccount": "CN=legacy-svc,CN=Users,DC=contoso,DC=local",
        })
    )
    runner = FakeRunner()

    create_dmsa(runner, request, UNIQUE_DMSA_NAME)

    assert runner.calls[0][1]["SupersededAccount"] == "CN=legacy-svc,CN=Users,DC=contoso,DC=local"


def test_migrate_service_standalone_passes_account_name():
    request = migration_request_from_dict(_make_request())
    runner = FakeRunner()

    migrate_service(runner, request, UNIQUE_DMSA_NAME)

    assert runner.calls == [
        (
            "Configure-WindowsService.ps1",
            {"ServiceName": "Spooler", "AccountName": f"CONTOSO\\{UNIQUE_DMSA_NAME}$"},
        ),
    ]


def test_migrate_service_superseding_skips_wmi_config():
    """Superseding migration: AD link already ran on DC. Member server only
    needs the registry key — no WMI logon change required."""
    request = migration_request_from_dict(
        _make_request({
            "supersededAccount": "CN=legacy-svc,CN=Users,DC=contoso,DC=local",
        })
    )
    runner = FakeRunner()

    migrate_service(runner, request, UNIQUE_DMSA_NAME)

    assert runner.calls == [
        (
            "Configure-WindowsService.ps1",
            {"ServiceName": "Spooler"},
        ),
    ]


def test_rollback_service_clears_dmsa_flag():
    runner = FakeRunner()
    request = RollbackRequest("Spooler", "LocalSystem", "MEMBER-SRV")

    rollback_service(runner, request)

    assert runner.calls == [
        (
            "Configure-WindowsService.ps1",
            {"ServiceName": "Spooler", "AccountName": "LocalSystem", "ClearDMSA": True},
        ),
    ]


def test_rollback_request_parses_optional_fields():
    request = rollback_request_from_dict({
        "serviceName": "Spooler",
        "previousAccount": "LocalSystem",
        "targetHost": "MEMBER-SRV",
        "dmsaName": "svc-spooler-dmsa",
        "domainController": "DC-01",
        "supersededAccount": "CN=legacy-svc,CN=Users,DC=contoso,DC=local",
        "domainControllerThumbprint": "dcthumb",
        "targetHostThumbprint": "memberthumb",
    })
    assert request.dmsa_name == "svc-spooler-dmsa"
    assert request.domain_controller == "DC-01"
    assert request.superseded_account == "CN=legacy-svc,CN=Users,DC=contoso,DC=local"
    assert request.domain_controller_thumbprint == "dcthumb"
    assert request.target_host_thumbprint == "memberthumb"


def test_migration_request_parses_thumbprints():
    request = migration_request_from_dict(
        _make_request({
            "domainControllerThumbprint": "dcthumb",
            "targetHostThumbprint": "memberthumb",
        })
    )
    assert request.domain_controller_thumbprint == "dcthumb"
    assert request.target_host_thumbprint == "memberthumb"
    assert request.domain_controller == "DC-01"