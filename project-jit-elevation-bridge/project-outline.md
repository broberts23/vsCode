# TECHNICAL DESIGN DOCUMENT

## Project 1: Hybrid Zero-Trust JIT Bridge (dMSA Privilege Elevation)

---

## 1. Project Premise & Hook

Why are we meticulously locking down human engineers with Just-In-Time (JIT) access while leaving our most powerful service accounts with permanent, high-privileged global rights?

Windows Server 2025 introduces delegated Managed Service Accounts (dMSAs) to completely eliminate credential theft by binding the account to specific machines with no readable passwords. However, if a dMSA possesses permanent administrative privileges, a compromised server still allows widespread lateral movement.

**The Hook:** This project implements a serverless JIT access broker. Instead of giving a dMSA permanent standing privileges, an Azure Python Function App dynamically grants and revokes Active Directory group memberships via the passwordless **Azure Arc Control Plane**. Security is maintained with zero open inbound firewall ports and zero on-premises administrative credentials stored in the cloud.

---

## 2. Lab Requirements & Prerequisites

Before writing any Python code, the following hybrid lab infrastructure must be fully provisioned and configured:

### Azure Resources

* **Azure Function App:** Linux or Windows consumption/premium plan running Python 3.10+.
* **System-Assigned Managed Identity:** Enabled on the Azure Function App.
* **Azure Arc Onboarding:** The Windows Server 2025 VM must be registered as an Azure Arc-enabled server (`Microsoft.HybridCompute/machines`).
* **Role-Based Access Control (RBAC):** The Azure Function's Managed Identity must be granted the **Hybrid Compute Resource Administrator** (or a custom role allowing `Microsoft.HybridCompute/machines/runCommands/action`) over the Arc-enabled VM resource.

### Windows Server 2025 Active Directory Setup

Run the following PowerShell commands locally on the Domain Controller to establish the identity baseline:

```powershell
# 1. Create target OU and Privileged Admin Group
New-ADOrganizationalUnit -Name "dMSA_Management" -Path "DC=contoso,DC=local"
New-ADGroup -Name "JIT_AppAdmins" -GroupScope Global -Path "OU=dMSA_Management,DC=contoso,DC=local"

# 2. Create the Predecessor Account (The legacy account identity used for permissions mapping)
New-ADUser -Name "svc_deploy_legacy" -SamAccountName "svc_deploy_legacy" -Path "OU=dMSA_Management,DC=contoso,DC=local" -Enabled $true -PasswordNotRequired

# 3. Create the Windows Server 2025 dMSA linked to the predecessor account
New-ADServiceAccount -Name "dmsa_deploy_pr" -DNSHostname "dmsa_deploy_pr.contoso.local" -CreateDelegatedServiceAccount
```

Gotchas:
the arc HybridComputeManagementClient requires the `api_version="2026-06-16-preview"` to successfully invoke the `runCommand`. The default API version will fail with a 400 Bad Request error.
the arc HybridComputeManagementClient runs under the local `NT AUTHORITY\SYSTEM`, the Windows Server machine account must have delegated permissions to the Active Directory to add/remove group memberships.

---

## 3. Repository Structure

This project follows the **Azure Functions Python V2 Programming Model**, which utilizes a single flat layout with decorators instead of the legacy nested `function.json` files.

```text
jit_elevation_bridge/
│
├── function_app.py               # Main Function App routing and HTTP controllers
├── host.json                     # Global Azure Functions configuration
├── local.settings.json           # Local environment variables and secrets
├── requirements.txt              # Project library dependencies
│
└── services/
    ├── __init__.py               # Python package initialization
    └── arc_orchestrator.py       # Core Azure Arc SDK integration logic

```

---

## 4. Data Contracts

To strictly conform to the KISS (Keep It Simple, Stupid) principle, data exchanges will use native Python dictionaries parsed directly from JSON strings.

### HTTP POST Request Payload

```json
{
    "dmsa_name": "dmsa_deploy_pr",
    "target_group": "JIT_AppAdmins",
    "action": "elevate" 
}

```

*Note: `action` accepts exactly two string states: `"elevate"` or `"revoke"`.*

### HTTP Response Payload (Success - 200 OK)

```json
{
    "status": "success",
    "message": "Action 'elevate' successfully executed for dmsa_deploy_pr.",
    "execution_id": "c4d3b2a1-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
}

```

### HTTP Response Payload (Failure - 400/500 Error)

```json
{
    "status": "error",
    "error_code": "INVALID_ACTION",
    "details": "The action parameter must be either 'elevate' or 'revoke'."
}

```

---

## 5. Component & Code Design

### Dependencies (`requirements.txt`)

```text
azure-functions
azure-identity
azure-mgmt-hybridcompute
```

### Local Environment Variables (`local.settings.json`)

For local debugging, provide your own user context or a service principal credential that mimics the Managed Identity permissions.

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "AZURE_SUBSCRIPTION_ID": "your-subscription-uuid",
    "AZURE_RESOURCE_GROUP": "your-hybrid-rg",
    "ARC_MACHINE_NAME": "your-ws2025-arc-name"
  }
}

```

### Core Orchestration Service (`services/arc_orchestrator.py`)

This module handles all cloud-to-edge interactions via the native Azure SDK. It crafts a temporary, minimal PowerShell snippet and pushes it down to the Arc-enabled Domain Controller.

```python
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
        
        self.client = HybridComputeManagementClient(self.credential, self.subscription_id)

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
            location=self.client.machines.get(self.resource_group, self.machine_name).location,
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

```

### Main Controller (`function_app.py`)

This acts as the lightweight router and JSON parser. It coordinates the inputs, passes work off to the orchestrator, and presents clean responses.

```python
import azure.functions as func
import json
import logging
from services.arc_orchestrator import ArcOrchestrator

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="jit/modify", methods=["POST"])
def jit_modify_access(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing JIT Active Directory group adjustment request.")

    # 1. Parse Input Data Structure
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"status": "error", "error_code": "BAD_REQUEST", "details": "Invalid JSON payload format."}),
            status_code=400,
            mimetype="application/json"
        )

    dmsa_name = req_body.get('dmsa_name')
    target_group = req_body.get('target_group')
    action = req_body.get('action')

    # 2. Keep Input Validations Simple and Literal
    if not all([dmsa_name, target_group, action]):
        return func.HttpResponse(
            json.dumps({"status": "error", "error_code": "MISSING_FIELDS", "details": "dmsa_name, target_group, and action are mandatory fields."}),
            status_code=400,
            mimetype="application/json"
        )

    if action not in ["elevate", "revoke"]:
        return func.HttpResponse(
            json.dumps({"status": "error", "error_code": "INVALID_ACTION", "details": "Action must be strictly 'elevate' or 'revoke'."}),
            status_code=400,
            mimetype="application/json"
        )

    # 3. Direct Execution Logic without Excessive Layering
    try:
        orchestrator = ArcOrchestrator()
        execution_id = orchestrator.execute_ad_change(dmsa_name, target_group, action)
        
        response_data = {
            "status": "success",
            "message": f"Action '{action}' successfully executed for {dmsa_name}.",
            "execution_id": execution_id
        }
        return func.HttpResponse(json.dumps(response_data), status_code=200, mimetype="application/json")

    except Exception as e:
        # Catch unexpected infrastructure issues cleanly without losing context
        logging.error(f"Failed to execute Azure Arc deployment task: {str(e)}")
        return func.HttpResponse(
            json.dumps({"status": "error", "error_code": "EXECUTION_FAILURE", "details": str(e)}),
            status_code=500,
            mimetype="application/json"
        )
```

---

## 6. Local Debugging Instructions

To run and step through this codebase locally using the Azure Functions Core Tools:

1. **Open Project:** Open the root `jit_elevation_bridge` directory in VS Code.
2. **Authenticate Locally:** Run `az login` via your local terminal and select the subscription hosting the Arc-enabled VM. The `DefaultAzureCredential()` object in the Python script automatically intercepts your active Azure CLI login context to sign requests while debugging.
3. **Configure Environments:** Verify your local environment properties match your real-world identifiers inside `local.settings.json`.
4. **Launch Instance:** Press `F5` or execute `func start` in the directory. Core Tools builds the runtime server locally and exposes a target endpoint resembling: `http://localhost:7071/api/jit/elevate`.
5. **Simulate Request:** Use an API client (like Postman or cURL) to verify performance by passing an elevation block directly to your locally hosted instance.
