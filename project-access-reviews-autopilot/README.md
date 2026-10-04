# Access Reviews Autopilot — Slack as the access-review inbox

Lab pattern: inject Graph-shaped **Review Events**, notify in **Slack** (the only Inbox), and **Apply** Decisions into **Cosmos** (simulated). Operators inject via the OIDC-protected simulate API or the simulator CLI/job and inspect via Cosmos/logs. See [GLOSSARY.md](GLOSSARY.md) for domain language.

This is **not** live Microsoft Graph Access Review automation. The Entra tenant is a lab with no production users or recertification telemetry. Every trigger is a fixture. `SimulatedAccessReviewClient` updates Cosmos; `GraphAccessReviewClient` is a stub for delegated Reviewer-only Apply later.

Working blog title: **Stop mailing MyAccess into the void: access reviews that settle in Slack.** See [docs/blog.md](docs/blog.md).

## Architecture

```text
Simulator (cron / POST /api/simulate)
        │  fixtures (config/simulated-events)
        ▼
Service Bus topic review-work
   ├─ subscription slack-notify  → worker → Cosmos + Slack Block Kit
   └─ subscription apply-decision → worker → SimulatedAccessReviewClient + Slack update
Operator ──OIDC──► API POST /api/simulate (Container Apps)
Slack button ───────► API /slack/interactions ──► apply-decision
```

Azure data plane is **managed identity only**: Cosmos `disableLocalAuth`, Service Bus `disableLocalAuth`, ACR admin off. No storage account. No Functions / WebJobs keys.

## Repository layout

```text
project-access-reviews-autopilot/
├── README.md                 ← you are here (local first, then Azure)
├── GLOSSARY.md               ← domain language
├── docs/blog.md
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml        ← Cosmos + Service Bus emulators
├── .env.example
├── config/simulated-events/  ← ReviewPending, Overdue, Reminder, poison
├── src/ara/                  ← shared library
├── api/                      ← FastAPI (OIDC simulate + Slack interactivity)
├── worker/                   ← Service Bus consumers
├── simulator/                ← fixture publisher
├── infra/main.bicep
├── scripts/
├── docs/
└── tests/
```

***

## 1. Prerequisites

* Python 3.11+
* Docker Desktop
* PowerShell 7
* Azure CLI (`az`) for the Azure half only
* Slack [developer sandbox](https://docs.slack.dev/tools/developer-sandboxes/) (optional for dry-run; without tokens the worker logs Block Kit JSON)
* Entra lab tenant API app registration when you turn off auth bypass (see [docs/entra-app-registrations.md](docs/entra-app-registrations.md))

## 2. Local topology (no Azure deploy)

| Piece | Local stand-in |
| --- | --- |
| Cosmos | Emulator (`docker compose`) — **key allowed only here** |
| Service Bus | Emulator + SQL Edge |
| API / workers | `uvicorn` / `python -m worker.main` on the host, or compose profile `apps` |
| Slack interactivity | Socket Mode or dry-run logging |
| Entra OIDC | Real tenant tokens for Operator API, **or** `ARA_AUTH_BYPASS=true` |
| Access Reviews | Fixtures only — **no Graph** |
| Reviewer → Slack | Lab Identity Map (`LAB_IDENTITY_MAP_SLACK_USER_ID`); shared channel is lab scaffolding |

Emulator connection strings live in `.env` (gitignored). **Never** copy them into Bicep or Container Apps settings.

## 3. Local test steps (do these before Azure)

### 3.1 Unit tests

```powershell
cd project-access-reviews-autopilot
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest -q
```

Covers correlation keys, Slack signature HMAC, and fixture → `ReviewWorkMessage` mapping (including poison → `forcePoison` validation failure).

### 3.2 Copy env and start emulators

```powershell
Copy-Item .env.example .env
docker compose up -d cosmos sqledge servicebus
```

Wait until Cosmos explorer responds on `https://localhost:8081` and Service Bus emulator is up (port `5672`). The first Cosmos emulator start can take a few minutes.

### 3.3 Run API + workers on the host

Use the project venv from [3.1](#31-unit-tests) (`.\.venv\Scripts\Activate.ps1`). If `python` still resolves to a global install, call the venv interpreter explicitly:

```powershell
# terminal 1
.\.venv\Scripts\python.exe -m uvicorn api.main:app --reload --port 8080

# terminal 2
.\.venv\Scripts\python.exe -m worker.main --mode notify

# terminal 3
.\.venv\Scripts\python.exe -m worker.main --mode apply
```

With `ARA_AUTH_BYPASS=true` (default in `.env.example`) the API accepts calls without a bearer token.

### 3.4 Inject fixtures

```powershell
python -m simulator.main
# or
curl -X POST http://localhost:8080/api/simulate -H "Content-Type: application/json" -d "{}"
```

Expect worker-notify logs for `ReviewPending`, `ReviewOverdue`, `ReviewReminderDue`. If Slack tokens are empty, cards are logged (dry-run) and Cosmos documents move `received` → `notified`. Republishing the same Correlation ID refreshes open Review Work; Overdue/ReminderDue nudge the existing card instead of posting a stack of orphans.

### 3.5 Approve in Slack

With Slack configured, click **Approve** or **Deny** on the card. Cosmos `status` becomes `applied` with Decision, Decider, and lab Justification stub. Inspect documents in Cosmos or logs by `correlationId` — there is no second Inbox UI. Applied Review Work is not reopened if fixtures replay.

### 3.6 Poison / Failed path

```powershell
python -m simulator.main --fixture poison
```

Worker-notify should fail validation (`forcePoison`) and abandon the message for retries. When delivery count reaches `SERVICE_BUS_MAX_DELIVERY_COUNT` (default 10), the worker marks Review Status `failed` and completes the message.

### 3.7 Cosmos failure → retry

Stop the Cosmos container, inject a ReviewPending fixture, confirm the worker abandons/retries. Start Cosmos again and confirm eventual success, or Failed after delivery count is exhausted.

***

## 4. Deploy to Azure (after local green)

Hard rules in [infra/main.bicep](infra/main.bicep):

* Cosmos `disableLocalAuth: true`
* Service Bus `disableLocalAuth: true`
* ACR `adminUserEnabled: false`
* App Configuration `disableLocalAuth: true`
* Key Vault RBAC mode
* One user-assigned MI: AcrPull, Service Bus Data Owner, Cosmos Data Contributor, Key Vault Secrets User, App Configuration Data Reader
* **No** Graph `AccessReview.ReadWrite.All`
* ACA env vars are **endpoints/names only** — Slack secrets retrieved from Key Vault at runtime via MI

```powershell
# 1) Infra without apps (empty image)
.\scripts\Deploy-Infrastructure.ps1 -ResourceGroup rg-ara-dev -TenantId <tid>

# 2) Build image into ACR (no admin user)
.\scripts\Build-Image.ps1 -AcrName <acrName>

# 3) Register Entra apps
Register Entra apps per [docs/entra-app-registrations.md](docs/entra-app-registrations.md). 

# 4) Configure Slack
Configure Slack per [docs/slack-app.md](docs/slack-app.md). Point Interactivity Request URL to `https://<apiFqdn>/slack/interactions`.

# 5) Redeploy with image
.\scripts\Deploy-Infrastructure.ps1 -ResourceGroup rg-ara-dev -TenantId <tid> `
  -ContainerImage <loginServer>/ara:dev `
  -ApiClientId <api-app-id> `
  -SlackChannelId <channel-id>

# 6) Secrets (MI reads these — do not paste into ACA settings)
az keyvault secret set --vault-name <kv> --name slack-signing-secret --value <secret>
az keyvault secret set --vault-name <kv> --name slack-bot-token --value <xoxb-...>
```

### Azure smoke test

1. Portal: Cosmos local auth **Disabled**, Service Bus local auth **Disabled**, ACR admin **Disabled**.
2. ACA environment variables: **no** `AccountKey`, `SharedAccessKey`, `DefaultEndpointsProtocol`, or Cosmos key settings.
3. `POST /api/simulate` with a real OIDC token (or temporarily verify with a job run of the simulator).
4. Slack card appears → Approve → Cosmos document `status=applied` with the same `correlationId`.
5. App Insights / Log Analytics: query by `correlationId`.
6. **Do not** look for a Decision in MyAccess — nothing was written to Graph.

### Poison / Failed in Azure

```powershell
# from a one-off ACA exec or local machine using MI / Azure creds against the namespace
python -m simulator.main --fixture poison
```

Confirm retries, then `status=failed` on the correlation document after delivery exhaustion.

## 5. Configuration reference

| Setting | Local | Azure |
| --- | --- | --- |
| `COSMOS_ENDPOINT` | emulator HTTPS | account document endpoint |
| `COSMOS_KEY` | emulator key only | **unset** (MI) |
| `SERVICE_BUS_CONNECTION_STRING` | emulator | **unset** |
| `SERVICE_BUS_FULLY_QUALIFIED_NAMESPACE` | empty | `ns.servicebus.windows.net` |
| `KEY_VAULT_URI` | empty | vault URI |
| `ARA_AUTH_BYPASS` | `true` | `false` |
| `SLACK_CHANNEL_ID` | `.env` (shared channel = lab scaffolding) | ACA env (`-SlackChannelId`) |
| `LAB_IDENTITY_MAP_SLACK_USER_ID` | lab stub Reviewer→Slack map | same (not SSO Identity) |
| `LAB_APPLY_JUSTIFICATION` | Apply Justification stub | same until Inbox collects it |
| Slack tokens | `.env` or empty dry-run | Key Vault via MI |
| `ENTRA_API_AUDIENCE` | `.env` | `api://{apiClientId}` (Bicep default) |

## 6. Cost notes

* Service Bus **Standard** (topics/subscriptions/DLQ) — intentional small monthly bill
* ACR **Basic**
* Cosmos **serverless** + TTL
* Container Apps Consumption, min replicas **0**
* App Configuration Free, App Insights 30-day retention

## 7. Non-goals

* Live Graph Access Review create/Apply (delegated Reviewer-only Apply is future work)
* Slack workspace SAML / SSO Identity (sandbox cannot; Lab Identity Map is the lab stub)
* Access Package events or Graph Event Grid partner ingress for Decision Items
* Second human UI / pending-queue API (Slack is the only Inbox)
* Functions / Storage queues / Redis / PostgreSQL
* Easy Auth as the primary OIDC drill (app-code token validation instead)

Production Producer intent (not built here): Graph poller for Pending Decision Items plus a scheduler for Overdue/ReminderDue. See [docs/adr/0004-poller-and-scheduler-producer.md](docs/adr/0004-poller-and-scheduler-producer.md).
