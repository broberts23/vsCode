# project-eventgrid-partnerconfiguration

Receives Microsoft Graph change notifications through Azure Event Grid (partner events) and processes them with an Azure Function App (PowerShell). Includes:

- Event ingestion + queue buffering
- Table Storage dedupe/idempotency
- Subscription lifecycle handling (reauthorize + renew)
- Birthright group assignment for newly created users (policy-driven)

## Prerequisites

- PowerShell 7.4+
- Azure CLI (`az`) with an active login (`az login`)
- Permissions to deploy resources in the target subscription/resource group
- Entra permissions to create Microsoft Graph subscriptions (delegated) and grant Graph application permissions to the managed identity (admin consent)

## Quickstart (one command deploy)

From the repo root:

```powershell
pwsh ./scripts/Deploy-Infrastructure.ps1 `
  -SubscriptionId <subId> `
  -ResourceGroupName <rgName> `
  -Location <azureRegion>
```

What it does:

- Creates/uses a user-assigned managed identity (UAMI)
- Assigns required Azure RBAC (storage data-plane roles, etc.)
- Assigns Microsoft Graph app roles to the UAMI (defaults are in the script)
- Deploys `infra/main.bicep`
- Zip-deploys `src/FunctionApp`
- Bootstraps Graph → Event Grid (partner topic), activates it, and deploys `infra/link.bicep`

## Configure birthrights (policy.json)

Policy file: `src/FunctionApp/policy/policy.json`

Birthright group assignment is controlled by:

- `birthrights.enabled`
- `birthrights.mode` (`remediate` to actually add members)
- `birthrights.assignments[*].addToGroups`

Current default assigns newly created `userType: "Member"` users to:

- `928bd0ce-8abc-43dd-94a0-d350fe49e991`

## Important behavior notes

- Graph `/users` subscriptions do **not** emit a `created` changeType; user creation arrives as an `updated` notification.
- The Function gates “new user” by querying the user’s `createdDateTime` and only applying birthrights when it is within a small window of the event time.

## Required Graph permissions

To add users to groups via Graph, the managed identity needs a Graph **application** permission that can add group members:

- `GroupMember.ReadWrite.All` (least-privilege) or `Group.ReadWrite.All` (broader)

The deployment script assigns Graph app roles to the UAMI; adjust defaults via `-BootstrapGraphAppRoles` in `scripts/Deploy-Infrastructure.ps1`.

## Key runtime settings

These are set by Bicep/scripts and can be overridden as app settings:

- `POLICY_PATH` (default: `policy/policy.json`)
- `WORK_QUEUE_NAME` (queue trigger name)
- `DEDUPE_ENABLED`, `DEDUPE_TABLE_NAME`, `DEDUPE_STORAGE_ACCOUNT_NAME`
- `GRAPH_CLIENT_STATE` (used to validate lifecycle notifications)
- `BIRTHRIGHT_NEW_USER_WINDOW_MINUTES` (new-user gate)
- `BIRTHRIGHT_MARKER_TTL_HOURS` (logical TTL for birthright marker keys in the dedupe table)

Identity:

- The Function App uses a **user-assigned managed identity** and sets `MANAGED_IDENTITY_CLIENT_ID`.

## Repo layout

- `infra/` Bicep templates (`main.bicep`, `link.bicep`)
- `scripts/` deployment + bootstrap scripts
- `src/FunctionApp/` Azure Functions (PowerShell)
  - `GovernanceEventHandler/` Event Grid trigger (dedupe + enqueue)
  - `BirthrightWorker/` queue worker (birthright group assignment)
  - `SubscriptionLifecycleWorker/` lifecycle worker (reauthorize + renew)
  - `Modules/GovernanceAutomation/` shared helpers (Graph + Table Storage)

## Verify

1. Create a new user in Entra ID.
2. In App Insights logs, confirm `BirthrightWorker` logs include:
   - `Added newly created user to birthright group`
3. Update an existing user and confirm:
   - `User event is not treated as newly created; no birthright changes applied`
