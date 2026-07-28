# Application Registration Vending Machine

Governed, catalog-driven provisioning of Microsoft Entra app registrations, credentials, app roles, Conditional Access policies, and UTCM monitor artifacts. Designed for ITSM integration with an async accept-and-callback contract.

## What it does

1. ITSM or admin client calls `POST /v1/requests` with a catalog SKU and instance details.
2. API writes the request to Table Storage, enqueues a job, and returns `202 Accepted`.
3. Queue-triggered worker processes the vend pipeline (DryRun or Live).
4. Worker updates Table Storage and optionally POSTs a completion callback to the ITSM webhook.

## Local development

### Prerequisites

- Python 3.11+
- [Azurite](https://learn.microsoft.com/azure/storage/common/storage-use-azurite) for queue and table emulation
- [Azure Functions Core Tools](https://learn.microsoft.com/azure/azure-functions/functions-run-local) v4
- VS Code extensions: Python, Azure Functions, Azurite (optional)

### Setup

```powershell
cd project-app-vending-machine
pip install -e .
pip install -e ".[worker]"
copy worker\local.settings.sample.json worker\local.settings.json
```

### Run locally

Terminal 1 — Azurite:

```powershell
azurite --silent --location .azurite
```

Terminal 2 — API (Swagger at http://localhost:8000/docs):

```powershell
$env:AUTH_BYPASS = "true"
$env:AzureWebJobsStorage = "UseDevelopmentStorage=true"
$env:APP_VENDING_EXECUTION_MODE = "DryRun"
uvicorn api.main:app --reload --port 8000
```

Terminal 3 — Worker:

```powershell
cd worker
func start
```

### Test a request

Use Swagger UI at `/docs` or:

```powershell
curl -X POST http://localhost:8000/v1/requests `
  -H "Content-Type: application/json" `
  -d "@samples/requests/internal-hr-spa.json"
```

Poll status:

```powershell
curl http://localhost:8000/v1/requests/{requestId}
```

### PKCE token for authenticated testing

```powershell
python scripts/get_token_pkce.py --tenant-id <tenant> --client-id <public-client-id>
```

Use the printed token as `Authorization: Bearer <token>` when `AUTH_BYPASS` is disabled.

## Catalog SKUs

| SKU | Use case |
|-----|----------|
| `internal-hr-spa` | SPA with PKCE, `HR.Read`/`HR.Write` app roles, compliant-device CA |
| `aks-graph-workload` | AKS workload identity, Graph API permissions, IP-restricted CA |

See [catalog/app-offerings.json](catalog/app-offerings.json).

## Execution modes

| Mode | Behavior |
|------|----------|
| `DryRun` (default) | Returns full plan without calling Microsoft Graph |
| `Live` | Creates app registration, service principal, credential, and CA policy via Graph using managed identity |

Set `APP_VENDING_EXECUTION_MODE` in app settings.

## Deploy to Azure

```powershell
az deployment group create `
  --resource-group <rg-name> `
  --template-file infra/main.bicep `
  --parameters @infra/parameters.dev.json
```

Grant the worker managed identity `Application.ReadWrite.OwnedBy` and `Policy.ReadWrite.ConditionalAccess` before enabling Live mode.

## Project layout

```
catalog/           Governed offering SKUs
src/app_vending/   Shared Python modules (plain functions)
api/               FastAPI ITSM-facing API with Swagger
worker/            Azure Functions queue worker
infra/             Bicep templates
samples/           Example requests and UTCM templates
scripts/           PKCE token helper
```

## Entra prerequisites

- API app registration with app roles: `AppVending.Submitter`, `AppVending.Admin`
- Public client for PKCE testing (redirect `http://localhost:8400`)
- Worker managed identity with Graph permissions (Live mode)
