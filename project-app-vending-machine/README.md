# Application Registration Vending Machine

Governed, catalog-driven provisioning of Microsoft Entra app registrations, credentials, app roles, Conditional Access policies, and UTCM monitor artifacts. Designed for ITSM integration with an async accept-and-callback contract.

## What it does

1. ITSM or admin client calls `POST /v1/requests` with a catalog SKU and instance details.
2. API writes the request to Table Storage, enqueues a job, and returns `202 Accepted`.
3. Queue-triggered worker processes the vend pipeline (DryRun or Live).
4. Worker updates Table Storage and optionally POSTs a completion callback to the ITSM webhook.

## Local development (DryRun)

### Prerequisites

* Python 3.11+
* [Azurite](https://learn.microsoft.com/azure/storage/common/storage-use-azurite) for queue and table emulation
* [Azure Functions Core Tools](https://learn.microsoft.com/azure/azure-functions/functions-run-local) v4
* VS Code extensions: Python, Azure Functions, Azurite (optional)

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
azurite --location .azurite --debug .azurite/debug.log
```

Or use VS Code: **Azurite: Start**.

Terminal 2 — API (Swagger at http://localhost:8000/docs):

```powershell
$env:AUTH_BYPASS = "true"
$env:AzureWebJobsStorage = "UseDevelopmentStorage=true"
$env:APP_VENDING_EXECUTION_MODE = "DryRun"
$env:PYTHONPATH = "src"
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

## Deploy to Azure (Live prerequisites as code)

Infrastructure now uses the **Microsoft Graph Bicep extension** to create Entra resources alongside Azure resources:

* API app registration with `AppVending.Submitter` and `AppVending.Admin` app roles
* API service principal
* User-assigned managed identity for the worker
* Graph application permission assignments on that identity (`Application.ReadWrite.OwnedBy`, `Policy.Read.All`, `Policy.ReadWrite.ConditionalAccess`)
* Easy Auth on the Web App wired to the generated app registration client ID

### Prerequisites for deployment

* Azure CLI logged into a tenant where you can create resource groups
* Permissions to create Entra applications and assign Graph app roles (Global Administrator or Cloud Application Administrator + Application Administrator is typical)
* Bicep CLI with Graph extension support (`az bicep upgrade`)

### Deploy

1. Edit [infra/parameters.dev.json](infra/parameters.dev.json) and set `tenantId` to your Entra tenant ID.
2. Create a resource group and deploy:

```powershell
az group create --name rg-appvend-dev --location australiaeast

az deployment group create `
  --resource-group rg-appvend-dev `
  --template-file infra/main.bicep `
  --parameters @infra/parameters.dev.json `
  --parameters tenantId=<your-tenant-id> executionMode=DryRun
```

3. Capture outputs:

```powershell
az deployment group show `
  --resource-group rg-appvend-dev `
  --name main `
  --query properties.outputs
```

Key outputs: `apiAppRegistrationClientId`, `workerIdentityPrincipalId`, `apiAppHostname`, `functionAppName`.

### If Graph role assignment fails during deploy

Some tenants restrict who can grant Graph application permissions. Redeploy with assignments disabled, then grant consent with a privileged account:

```powershell
az deployment group create `
  --resource-group rg-appvend-dev `
  --template-file infra/main.bicep `
  --parameters @infra/parameters.dev.json `
  --parameters tenantId=<your-tenant-id> assignWorkerGraphPermissions=false

./scripts/Grant-WorkerGraphPermissions.ps1 `
  -WorkerPrincipalId <workerIdentityPrincipalId-from-outputs>
```

### Switch to Live mode

```powershell
az webapp config appsettings set `
  --resource-group rg-appvend-dev `
  --name <functionAppName> `
  --settings APP_VENDING_EXECUTION_MODE=Live

az webapp config appsettings set `
  --resource-group rg-appvend-dev `
  --name <apiAppName> `
  --settings APP_VENDING_EXECUTION_MODE=Live
```

Then post a request using [samples/requests](samples/requests/) with real owner object IDs.

### PKCE token for authenticated testing

```powershell
python scripts/get_token_pkce.py `
  --tenant-id <tenant> `
  --client-id <public-client-id> `
  --scope api://<api-unique-name>/.default
```

Assign `AppVending.Submitter` to your test user or client against the API enterprise application before calling the deployed API with Easy Auth enabled.

## Portal validation checklist (screenshots)

After a Live vend, capture evidence in these blades:

| # | Portal | Blade | What you should see |
|---|--------|-------|---------------------|
| 1 | Azure | Resource group overview | Web App, Function App, Storage, App Insights, UAMI |
| 2 | Entra | App registrations → API app → App roles | `AppVending.Submitter`, `AppVending.Admin` |
| 3 | Entra | Enterprise apps / Managed identities → worker → Permissions | Graph permissions with admin consent |
| 4 | Local | Swagger `POST /v1/requests` | `202 Accepted` + `requestId` |
| 5 | Terminal | `func start` / Function logs | Queue dequeue of `vend-jobs` |
| 6 | Entra | App registrations → HR Internal Portal | SPA redirect + `HR.Read` / `HR.Write` |
| 7 | Entra | App registrations → AKS app → Federated credentials | AKS OIDC issuer + service account subject |
| 8 | Entra | Conditional Access → Policies | Report-only CA policy for the vended app |
| 9 | Azure | Web App → Authentication | Easy Auth Microsoft provider + 401 action |
| 10 | VS Code | `samples/utcm/generated/` | Emitted UTCM monitor JSON |
| 11 | Entra | CA policy → Session | 1-hour sign-in frequency + CAE strict enforcement |
| 12 | Entra | App registration → Token configuration | Optional claim `xms_cc` on payroll API |

## Catalog SKUs

| SKU | Use case |
|-----|----------|
| `internal-hr-spa` | SPA with PKCE, `HR.Read`/`HR.Write` app roles, compliant-device CA |
| `aks-graph-workload` | AKS workload identity, Graph API permissions, IP-restricted CA |
| `privileged-payroll-api` | CAE-capable payroll API, `Payroll.Read`/`Payroll.Write`, compliant device + 1-hour SIF + CAE strict enforcement |

See [catalog/app-offerings.json](catalog/app-offerings.json).

## Execution modes

| Mode | Behavior |
|------|----------|
| `DryRun` (default) | Returns full plan without calling Microsoft Graph |
| `Live` | Creates app registration, service principal, credential, and CA policy via Graph using managed identity |

Set `APP_VENDING_EXECUTION_MODE` in app settings.

## Project layout

```
catalog/           Governed offering SKUs
src/app_vending/   Shared Python modules (plain functions)
api/               FastAPI ITSM-facing API with Swagger
worker/            Azure Functions queue worker
infra/             Bicep + Microsoft Graph extension
samples/           Example requests and UTCM templates
scripts/           PKCE helper + Graph permission grant script
bicepconfig.json   Graph Bicep extension registration
```

## Entra resources created by Bicep

* API app registration with app roles: `AppVending.Submitter`, `AppVending.Admin`
* API service principal (enterprise application)
* Worker user-assigned managed identity
* Graph app role assignments on the worker identity for Live vending
* Easy Auth binding on the API Web App to the generated client ID

Optional for local PKCE testing: a separate public client with redirect `http://localhost:8400`.
