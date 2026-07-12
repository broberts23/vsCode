# JIT Elevation Bridge — Serverless dMSA Privilege Elevation via Azure Arc

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Azure Functions](https://img.shields.io/badge/Azure%20Functions-Python%20V2-blue)](https://learn.microsoft.com/en-us/azure/azure-functions/)

Eliminate standing privilege for Windows Server 2025 delegated Managed Service Accounts (dMSAs). An Azure Python Function App temporarily elevates a dMSA into an Active Directory group, records the grant in Table Storage, and automatically revokes it after 60 minutes — all over the passwordless Azure Arc control plane. No inbound firewall ports. No stored credentials. No standing anything.

## Architecture

Two independent Azure Functions blueprints share a single Table Storage table as their contract:

- **HTTP trigger** (`POST /jit/elevate`) — validates the payload, pushes `Add-ADGroupMember` to the Domain Controller via Arc RunCommand, writes a state entity with a 60-minute expiry.
- **Timer trigger** (`0 */5 * * * *`) — queries for expired entities, pushes `Remove-ADGroupMember` for each, deletes the record on success. Retries automatically on failure (convergent design).

```text
sequenceDiagram
    participant Caller as CI/CD / ITSM
    participant HTTP as HTTP Trigger<br/>(functions/elevate.py)
    participant Timer as Timer Trigger<br/>(functions/poll_revoke.py)
    participant Table as Azure Table Storage
    participant Arc as Arc Orchestrator<br/>(services/arc_orchestrator.py)
    participant DC as Domain Controller<br/>(Arc-Enabled WS2025)

    Note over HTTP,Timer: Two independent blueprints, one function app

    Caller->>HTTP: POST /jit/elevate<br/>{dmsa_name, target_group}
    HTTP->>Arc: execute_ad_change("elevate")
    Arc->>DC: Add-ADGroupMember via Arc RunCommand
    DC-->>Arc: OK
    Arc-->>HTTP: execution_id
    HTTP->>Table: create_entity(PartitionKey="JitActiveList",<br/>ExpirationTime=now+60min)
    Table-->>HTTP: 201 Created
    HTTP->>Caller: 200 OK {status, expiration_time}

    loop Every 5 minutes
        Timer->>Table: query: ExpirationTime le now
        Table-->>Timer: [expired entities]
        alt Entity found
            Timer->>Arc: execute_ad_change("revoke")
            Arc->>DC: Remove-ADGroupMember via Arc RunCommand
            DC-->>Arc: OK
            Arc-->>Timer: execution_id
            Timer->>Table: delete_entity(partition_key, row_key)
        end
    end
```

## Repository Structure

```text
jit_elevation_bridge/
├── function_app.py               # Blueprint registration (entry point)
├── host.json                     # Azure Functions extension bundle config
├── local.settings.json           # Local environment variables (gitignored)
├── requirements.txt              # Python dependencies
├── .funcignore                   # Deployment exclusions
│
├── clients/
│   ├── __init__.py
│   └── table.py                  # Azure Table Storage client factory
│
├── functions/
│   ├── __init__.py
│   ├── elevate.py                # HTTP-triggered JIT elevation blueprint
│   └── poll_revoke.py            # Timer-triggered sweep-and-revoke blueprint
│
└── services/
    ├── __init__.py
    └── arc_orchestrator.py       # Azure Arc SDK orchestration layer
```

## Prerequisites

### Azure Resources

| Resource | Purpose |
| -------- | ------- |
| Azure Function App (Python 3.10+) | Serverless compute host for the two blueprints |
| System-Assigned Managed Identity | Passwordless auth for the Function App |
| Arc-enabled Windows Server 2025 | Domain Controller registered as `Microsoft.HybridCompute/machines` |
| Azure Storage Account (Table) | State persistence and audit trail |

### RBAC Permissions

- Function App Managed Identity needs **Hybrid Compute Resource Administrator** (or custom role with `Microsoft.HybridCompute/machines/runCommands/action`) scoped to the Arc machine.
- If using RBAC auth for Storage (not Access Keys), the Managed Identity needs `Microsoft.Storage/storageAccounts/tableServices/tables/*` on the table.

### Active Directory

- The Domain Controller's machine account must be delegated permissions to modify the target group's membership. Arc RunCommand executes as `NT AUTHORITY\SYSTEM`, so this delegation is mandatory — without it, PowerShell runs successfully but produces zero AD effect.

### dMSA Setup (example)

```powershell
New-ADOrganizationalUnit -Name "dMSA_Management" -Path "DC=contoso,DC=local"
New-ADGroup -Name "JIT_AppAdmins" -GroupScope Global -Path "OU=dMSA_Management,DC=contoso,DC=local"
New-ADServiceAccount -Name "dmsa_deploy_prod" -DNSHostname "dmsa_deploy_prod.contoso.local"
```

## Local Development

### Environment Variables (`local.settings.json`)

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "<storage-connection-string>",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "AZURE_SUBSCRIPTION_ID": "<subscription-uuid>",
    "AZURE_RESOURCE_GROUP": "<resource-group>",
    "ARC_MACHINE_NAME": "<arc-machine-name>"
  }
}
```

### Running Locally

```bash
az login
func start
```

`DefaultAzureCredential` resolves to your `az login` session — no local secrets needed.

### Triggering an Elevation

```bash
curl -X POST http://localhost:7071/api/jit/elevate \
  -H "Content-Type: application/json" \
  -d '{"dmsa_name": "dmsa_deploy_prod", "target_group": "JIT_AppAdmins"}'
```

## API

### `POST /jit/elevate`

**Request body:**

```json
{
  "dmsa_name": "dmsa_deploy_prod",
  "target_group": "JIT_AppAdmins"
}
```

**Response `200 OK`:**

```json
{
  "status": "success",
  "message": "Elevation request for dmsa_deploy_prod to JIT_AppAdmins has been logged.",
  "expiration_time": "2026-07-12T03:51:00+00:00"
}
```

## How It Works

1. **Elevate** — The HTTP trigger calls `ArcOrchestrator.execute_ad_change()` which pushes `Add-ADGroupMember -Identity 'JIT_AppAdmins' -Members 'dmsa_deploy_prod$'` to the Domain Controller via Azure Arc RunCommand. Note the `$` suffix — Active Directory requires the trailing dollar sign for the dMSA name.

2. **Record** — After the Arc command succeeds, the function writes a state entity to Table Storage with `PartitionKey="JitActiveList"`, `RowKey="dmsa_deploy_prod_JIT_AppAdmins"`, and `ExpirationTime=now+60min`.

3. **Revoke** — Every 5 minutes, the timer trigger queries `ExpirationTime le now`. For each expired entity, it calls `Remove-ADGroupMember` via Arc, then deletes the record. If revocation fails, the entity stays in the table and the next cycle retries.

## Key Design Decisions

- **Blueprint isolation** — Each trigger is a separate `func.Blueprint`, registered in the 8-line `function_app.py`. Independent deployment and testing without touching the other trigger.
- **Table-backed state** — The timer sweep is convergent and self-healing. Revocation failures are retried automatically; no in-memory timers or orphaned grants.
- **`api_version="2026-06-16-preview"`** — The `HybridComputeManagementClient` constructor must explicitly pass this API version. The SDK default produces a `400 Bad Request` on `runCommand` operations.
- **Passwordless** — `DefaultAzureCredential` everywhere. Managed Identity in production, `az login` locally. No secrets to rotate.

## Dependencies

```text
azure-functions
azure-identity
azure-mgmt-hybridcompute>=9.1.0b4
azure-data-tables
```

## References

- [Azure Arc Run Command](https://learn.microsoft.com/en-us/azure/azure-arc/servers/run-command)
- [Azure Functions Python V2 Model](https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference-python?tabs=asgi%2Capplication-level#v2-programming-model)
- [Azure Hybrid Compute SDK](https://learn.microsoft.com/en-us/python/api/overview/azure/mgmt-hybridcompute-readme)
- [Azure Table Storage Python SDK](https://learn.microsoft.com/en-us/python/api/azure-data-tables/azure.data.tables.tableclient)
- [Windows Server 2025 dMSA](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/delegated-managed-service-accounts)
