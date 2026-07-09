import json

from domains.inventory import discover_services
from shared.powershell import PowerShellResult


class FakeRunner:
    def __init__(self) -> None:
        self.calls = []

    def run_script(self, script_name, parameters=None):
        self.calls.append((script_name, parameters))
        return PowerShellResult(
            stdout=json.dumps(
                [
                    {
                        "Name": "Spooler",
                        "DisplayName": "Print Spooler",
                        "StartName": "LocalSystem",
                        "State": "Running",
                    }
                ]
            ),
            stderr="",
            status_code=0,
        )


def test_discover_services_maps_inventory_result():
    runner = FakeRunner()

    result = discover_services(runner, "server2025")

    assert result.host == "server2025"
    assert result.services[0].name == "Spooler"
    assert runner.calls == [("Discover-WindowsServices.ps1", {"ComputerName": "server2025"})]
