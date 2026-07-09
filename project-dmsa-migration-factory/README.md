# dMSA Migration Factory

Python 3.12 Azure Functions v2 proof of concept for inventorying Windows services, creating delegated Managed Service Accounts, migrating service logons, validating service operation, and rolling back to the previous account.

## Structure

- `function_app.py`: Azure Functions app registration.
- `functions/`: HTTP-triggered function entry points.
- `domains/`: inventory, migration, validation, and rollback logic.
- `contracts/`: request and response parsing.
- `shared/`: configuration, logging, models, and WinRM PowerShell execution.
- `scripts/`: remote PowerShell scripts executed over WinRM/TLS.
- `tests/`: basic unit tests for domain logic.

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
func start
```

Configure local settings before running:

- `WINRM_ENDPOINT`: HTTPS WinRM endpoint, for example `https://server2025.contoso.local:5986/wsman`.
- `WINRM_USERNAME`: AD account with dMSA creation rights and local admin rights on the VM.
- `WINRM_PASSWORD`: local development secret.
- `WINRM_TRANSPORT`: `ntlm` or another pywinrm-supported transport.
- `WINRM_CERT_THUMBPRINT`: lab certificate thumbprint reference.

The PoC uses WinRM over TLS and disables CA validation for self-signed lab certificates. Pin the expected lab certificate at the environment or network boundary used by the lab.

## Endpoints

### GET `/api/inventory?host=server2025`

Returns enabled Windows services from the target host.

### POST `/api/migrate`

```json
{
  "serviceName": "Spooler",
  "dmsaName": "svc-spooler-dmsa",
  "targetHost": "server2025",
  "domainDnsName": "contoso.local",
  "previousAccount": "LocalSystem"
}
```

Creates the dMSA, installs it on the VM, configures the Windows service logon, restarts the service, and returns validation output.

### POST `/api/validate`

```json
{
  "serviceName": "Spooler",
  "expectedAccount": "contoso.local\\svc-spooler-dmsa$"
}
```

Restarts and validates that the service is running under the expected account.

### POST `/api/rollback`

```json
{
  "serviceName": "Spooler",
  "previousAccount": "LocalSystem",
  "targetHost": "server2025"
}
```

Restores the previous service account and validates operation.

## Testing

```powershell
pytest
```

## Blog series skeleton

### Part 1: Why dMSA migration matters

Introduce service account risk, dMSA benefits, and how both lab projects fit together as an end-to-end migration path.

### Part 2: Building the migration factory

Explain the Azure Functions API, WinRM over TLS, Active Directory cmdlets, service discovery, migration, validation, and rollback.

### Part 3: Operating the lab workflow

Narrate the prebuild lab setup, certificate handling, local debugging with `func start`, and how operators run a safe PoC migration.

### Part 4: Production hardening path

Discuss certificate validation, managed identity or Key Vault, approvals, inventory persistence, observability, retries, and governance across both projects.
