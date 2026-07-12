import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.hybridcompute import HybridComputeManagementClient
from azure.mgmt.hybridcompute.models import MachineRunCommand


class ArcOrchestrator:
    """Manages secure passwordless communication with Windows Server 2025 via Azure Arc."""

    def __init__(self):
        # DefaultAzureCredential automatically uses Managed Identity in Azure,
        # or local environment variables (Azure CLI, Env vars) when debugging locally.
        self.credential = DefaultAzureCredential()
        self.subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
        self.resource_group = os.environ["AZURE_RESOURCE_GROUP"]
        self.machine_name = os.environ["ARC_MACHINE_NAME"]
        

        self.client = HybridComputeManagementClient(
            self.credential, self.subscription_id, api_version="2026-06-16-preview")

    def execute_ad_change(self, dmsa_name: str, target_group: str, action: str) -> str:
        """
        Builds a dynamic PowerShell command and fires it via Azure Arc RunCommand.
        Avoids wrapper bloat and processes the request synchronously.
        """
        # Formulate simple operational logic depending on the intent
        if action == "elevate":
            ps_script = f"Add-ADGroupMember -Identity '{target_group}' -Members '{dmsa_name}$'"
        else:
            ps_script = f"Remove-ADGroupMember -Identity '{target_group}' -Members '{dmsa_name}$' -Confirm:$false"

        # Construct the minimal payload expected by the Arc SDK
        run_command_payload = MachineRunCommand(
            location=self.client.machines.get(
                self.resource_group, self.machine_name).location,
            source={"script": ps_script}
        )

        # Execute the command synchronously on the OS
        poller = self.client.machine_run_commands.begin_create_or_update(
            resource_group_name=self.resource_group,
            machine_name=self.machine_name,
            run_command_name=f"JIT-{action.upper()}",
            run_command_properties=run_command_payload
        )

        result = poller.result()
        return result.name
