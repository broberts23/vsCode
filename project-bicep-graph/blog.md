# Ephemeral PR Environment with Microsoft Graph Bicep: Scopes, App Roles & Minimal API Health Testing

## Introduction

This project demonstrates an end-to-end ephemeral pull request (PR) environment pattern using:

* Bicep + Microsoft Graph (beta extension) to provision an application, service principal, security group, custom OAuth2 permission scopes, and an application role.
* Azure resource deployment (Key Vault with RBAC, Storage, App Service Plan, Web App) as disposable per‑PR infrastructure.
* GitHub Actions OIDC workload identity federation (no client secrets) to deploy and test.
* PowerShell automation for post‑deploy Graph operations (federated credential, app role assignment, ephemeral test users lifecycle).

The design focus here is NOT deep functional testing of business endpoints. Instead, it highlights how identity artifacts (scopes, roles, group membership, users) can be created and wired programmatically as part of an ephemeral environment. The only required application test is a protected `/health` endpoint call to prove authentication/authorization plumbing works. Swagger/UI endpoints and role-gated API surface are intentionally optional and can be explored manually with the generated test identities while a PR is open.

## Goals vs Non‑Goals

| Aspect | Goal | Non‑Goal |
|--------|------|----------|
| Infrastructure | Rapid, reproducible PR environment spin-up & teardown | Long-lived shared dev environment |
| Identity Automation | Programmatically create app, service principal, scopes, role, group, test users | End‑user production auth flows |
| Testing Scope | Validate auth wiring via `/healthz` (unauth) & `/health` (auth) | Automated Swagger / scope matrix tests |
| App Roles | Demonstrate creation + assignment | Enforcing complex RBAC logic in code |
| Scopes | Show deterministic GUID-based scopes | Full delegated consent workflow automation |
| Users | Ephemeral test accounts for optional manual exploration | Persistent test directory population |

## Current Implementation Summary

### Identity Layer (Bicep Graph Beta)
* Application + Service Principal created via `Microsoft.Graph/*@beta` resources.
* Application identifier URI (audience) declared as `api://pr-<prNumber>-<uniqueSuffix>` deterministically; output as `appAudience` for token acquisition and API configuration.
* Two OAuth2 permission scopes defined: `Swagger.Read`, `Swagger.Write` (deterministic IDs via `guid()` seeding).
* One application role `Swagger.Admin` (allowed for User & Application principals) with deterministic ID.
* Security group `grp-<pr>-<suffix>-testers` created unconditionally for ephemeral test accounts; app is configured with `groupMembershipClaims: SecurityGroup` so role/group claims flow into user tokens (if requested interactively later).
* Outputs: `appId` (clientId), `appObjectId`, `servicePrincipalObjectId`, `appAudience` (identifier URI), scope IDs, role ID, group display name and objectId.

### Infrastructure Layer
* Storage Account (Standard_LRS, StorageV2 kind) and Key Vault (RBAC permission model, soft delete enabled) deployed.
* Web App (Minimal API .NET 8) + Basic App Service Plan (B1 tier).
* RBAC role assignments:
  * Service principal (API) granted "Key Vault Secrets User" on Key Vault.
  * GitHub runner service principal (OIDC workload identity) optionally granted "Key Vault Secrets User" for smoke test access.
* App settings: `AzureAd__TenantId` (subscription tenant), `AzureAd__Audience` (app audience URI from Bicep output).

### Application (Minimal API)
* Endpoints:
  * `/healthz` — unauthenticated heartbeat (also reports whether auth is configured).
  * `/health` — authenticated; requires any valid token for the application (no specific scope policy enforced here in CI).
  * `/api/mock` — requires `Swagger.Read` scope (policy keeps example of scope-based gating, but CI does not exercise it).
  * `/swagger` redirect — protected by `Swagger.Admin` role (demonstrates role-based policy enforcement; optional manual use).
* Authentication pipeline (JWT Bearer) configured via environment variables: `AzureAd__TenantId`, `AzureAd__Audience`.

### Automation Scripts (`scripts/`)
* **`Assign-AppRoleToGroup.ps1`** — Assigns the `Swagger.Admin` app role to the tester group using Graph REST API. Supports group lookup by display name or direct objectId (preferred). Safely handles pagination and property existence checks to avoid Graph API filter limitations. Also assigns application permission to the runner SP if provided.
* **`Create-TestUsers.ps1`** — Generates ephemeral test users with aliasing pattern `pr<PR_NUMBER>tester<index><6hex>`, sets SecureString passwords, adds each user to the tester group via Graph `/members/$ref`, outputs JSON with plaintext passwords for artifact (demo only; production should use Key Vault or avoid password-based auth).
* **`Delete-TestUsers.ps1`** — Cleans up users matching the PR prefix heuristic (mailNickname, displayName). Deletes users from directory; group membership implicitly removed.
* **`Cleanup-GraphEphemeral.ps1`** — Removes app role assignments (group + runner SP principals), deletes security group, service principal, and application. Uses client-side filtering to work around Graph filter limitations on relationship endpoints. Outputs JSON summary of deletion operations (type, id, status, error).
* **`SmokeTests.ps1`** — Dot-sourceable PowerShell module; `Invoke-EphemeralSmokeTests` function validates environment context, Key Vault access (Get-AzKeyVaultSecret), Storage access (Get-AzStorageAccountKey), and API endpoints (`/healthz` unauthenticated, `/health` with bearer token). Returns structured object; gracefully handles missing properties (stores null/error objects) and uses safe navigation to avoid StrictMode violations.

### GitHub Actions Workflow (`.github/workflows/ephemeral-env.yml`)
* Jobs: `provision` → `smoke-tests` → `destroy`.
* **Provision**: Checks out repo; logs in via OIDC; resolves runner service principal objectId; creates resource group; deploys Bicep (identity + infrastructure); builds and publishes .NET 8 Minimal API; zips and deploys to App Service; assigns `Swagger.Admin` app role to tester group; creates ephemeral test users; uploads artifacts.
* **Smoke Tests**: Downloads infra outputs; acquires application token for the app's audience URI; sources `SmokeTests.ps1` and runs `Invoke-EphemeralSmokeTests` to validate `/healthz` (unauthenticated), `/health` (authenticated), Key Vault access (RBAC), and Storage access (RBAC); generates summary markdown for PR job summary; outputs structured JSON; gracefully handles API call failures (returns "Error" for missing properties).
* **Destroy**: Triggered only when "Destroy" label is applied to the PR; downloads artifacts from `provision` job; logs in via OIDC; deletes test users; cleans up Graph objects (app role assignments, group, service principal, application); deletes resource group asynchronously.
* **Artifacts**: `env-outputs.json` (Bicep outputs), `test-users.json` (ephemeral account credentials), `smoke-results.json` (test results structure).
* **Triggers & Conditions**:
  - Runs on PR `opened`, `reopened`, and `labeled` events.
  - `provision` and `smoke-tests` run only on PR open/reopen (`github.event.action != 'labeled'`).
  - `destroy` runs only when "Destroy" label is added (`github.event.action == 'labeled' && contains(...labels...*.name, 'Destroy')`).
* **PR Merge Protection**: Configure branch protection rules in GitHub repository settings to require `provision` and `smoke-tests` status checks to pass before merging. This prevents merging until the pipeline completes successfully, ensuring resources are validated before integration. The pipeline can run independently of merge; resources persist until the "Destroy" label is applied.

## Clarification: App Roles & Swagger Scopes Are Demonstrative

The project intentionally provisions OAuth2 scopes and an app role to show how they can be:
1. Declared with deterministic GUIDs in Bicep (ensuring stability across redeployments so consent/assignments remain valid), and
2. Assigned programmatically (role to group) post-deployment.

However:
* CI pipelines do NOT depend on or validate `Swagger.Read` / `Swagger.Write` scopes today.
* The `/api/mock` and `/swagger` endpoints are not part of required automated tests.
* Test users exist so a human reviewer (during the PR window) could optionally sign in (via a chosen flow outside this repo) and verify roles/scopes manually.

This matches your statement: automated testing focuses solely on `/health` (and basic `/healthz`) while scopes, roles, users, and group membership are illustrative identity automation artifacts.

## Ephemeral Identity Lifecycle
* Group always created (no conditional logic) simplifying downstream steps.
* Test users generated with prefix `pr<PR_NUMBER>tester` and appended random hex for uniqueness.
* Users added to tester group enabling potential role claim emission if interactive delegated tokens are later acquired manually.
* Teardown removes users; group persists only for the life of the resource group (deleted at RG deletion).

## Security & Practical Notes
* Workload identity federation avoids storing client secrets (OIDC → Azure). See Azure OIDC guidance: https://learn.microsoft.com/azure/developer/github/connect-from-azure-openid-connect
* Scope & role IDs treated as sensitive outputs to limit accidental log exposure (though not secrets per se).
* Test user passwords are emitted to artifacts strictly for demo; production guidance would encrypt or store in Key Vault or avoid password-based flows entirely.
* Key Vault RBAC model (`enableRbacAuthorization=true`) allows future extension (e.g., storing ephemeral secrets per PR) without access policies.

## Current Capabilities Checklist
| Capability | Status | Notes |
|------------|--------|-------|
| App + SP creation via Graph Bicep | Implemented | Beta resource types; deterministic naming & tags |
| Application audience URI (`identifierUris`) | Implemented | Deterministic `api://pr-<prNumber>-<uniqueSuffix>`; stable for token requests |
| Custom OAuth2 scopes (Swagger.Read/Write) | Implemented | Deterministic GUIDs; declared in api.oauth2PermissionScopes |
| Application role (Swagger.Admin) | Implemented | Assigned to tester group post-deploy |
| Security group for test users | Implemented | Always created; objectId output for member management |
| Ephemeral test user creation & deletion | Implemented | Lifecycle integrated in workflow; pattern-based cleanup |
| Web API deployment (zip) | Implemented | .NET 8 Minimal API with JWT Bearer auth |
| `/healthz` (no auth) & `/health` (auth) | Implemented | Smoke test covers both; API returns auth status and user info |
| `/api/mock` (Swagger.Read scope) | Implemented | Policy-protected; not exercised in smoke tests |
| `/swagger` (Swagger.Admin role) | Implemented | Redirects to Swagger UI; protected by role; not tested in CI |
| Scope or role-based automated tests | Not in scope | Intentional—manual exploration only |
| Secure outputs for scope/role IDs | Not in recent change | Can be re-added if log leakage is a concern |
| Artifact publication (env/test users/smoke) | Implemented | JSON artifacts for traceability |
| Per-PR resource lifecycle control | Implemented | Provision on PR open/reopen; destroy on "Destroy" label |
| GitHub OIDC workload identity | Implemented | Runner SP auto-resolved and granted Key Vault access |
| API audience wiring | Implemented | `appAudience` output used in App Service config and token acquisition |
| StrictMode-compliant PowerShell | Implemented | Safe property checks; no null-conditional operator abuse |
| Error-resilient smoke tests | Implemented | Missing API properties handled gracefully; summary generation continues |

## Potential Future Enhancements (Optional)
* Add delegated token acquisition (device code flow) to validate `scp` claim presence in user tokens (if you later want automated scope testing).
* Implement preAuthorizedApplications in application manifest for zero-consent user token acquisition.
* Introduce TTL scan job to clean orphaned PR resource groups/users if a workflow run is interrupted or "Destroy" label is never applied.
* Encrypt or secret-manage test user credentials (Key Vault + GitHub OIDC retrieval) for improved hygiene; avoid emitting plaintext to artifacts.
* Pester unit tests for PowerShell scripts (Mock Graph calls, test error paths).
* PSScriptAnalyzer configuration file (`.pssad.json`) to suppress false positives and enforce coding standards.
* Federated credential creation in Bicep (if Microsoft.Graph.federatedIdentityCredential@beta becomes available).
* Conditional destroy (not just label-driven) to clean up on PR merge/close as fallback.

## Running Locally (Conceptual)
The workflow automates end-to-end; local reproduction would require:
1. Azure login: `az login`.
2. Deploy Bicep with a test RG.
3. Publish & deploy Web API (or run locally with `dotnet run` and manually set `AzureAd__TenantId` & `AzureAd__Audience`).
4. Run scripts individually (ensure you have `az account get-access-token --resource-type ms-graph`).

## Conclusion

This project emphasizes identity resource automation (app, SP, scopes, roles, group, users) and ephemeral infrastructure rather than broad functional API test coverage. The minimal smoke test (`/healthz` + authenticated `/health`) gives just enough validation that identity wiring and deployment succeeded. Everything else—the Swagger-related scopes, role policies, and test users—serves as demonstrative scaffolding that reviewers can manually exercise during a PR’s lifetime.

## Key References
* Graph app/service principal Bicep (beta): https://learn.microsoft.com/graph/templates/bicep/reference/applications?view=graph-bicep-beta
* Azure OIDC federation (GitHub): https://learn.microsoft.com/azure/developer/github/connect-from-azure-openid-connect
* Access tokens & claims: https://learn.microsoft.com/azure/active-directory/develop/access-tokens
* Key Vault RBAC: https://learn.microsoft.com/azure/key-vault/general/rbac-guide
