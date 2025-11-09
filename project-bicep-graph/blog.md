# Ephemeral PR Environment with Microsoft Graph Bicep: Scopes, App Roles & Minimal API Health Testing

## Introduction

This project demonstrates an end-to-end ephemeral pull request (PR) environment pattern using:

* Bicep + Microsoft Graph (beta extension) to provision an application, service principal, security group, custom OAuth2 permission scopes, and an application role.
* Azure resource deployment (Key Vault with RBAC, Storage, App Service Plan, Web App) as disposable per‑PR infrastructure.
* GitHub Actions OIDC workload identity federation (no client secrets) to deploy and test.
* PowerShell automation for post‑deploy Graph operations (federated credential, app role assignment, ephemeral test users lifecycle).

The design focus here is NOT deep functional testing of business endpoints. Instead, it highlights how identity artifacts (scopes, roles, group membership, users) can be created and wired programmatically as part of an ephemeral environment. The only required application tests are:

* A role-gated `/healthz` endpoint (requires `Swagger.Admin` application role) proving role claim emission and authorization works.
* An authenticated `/health` endpoint (accepts any valid v2 token for the application) proving basic bearer auth wiring works.

Swagger/UI endpoints and scope-gated API surface are intentionally optional and can be explored manually with the generated test identities while a PR is open.

## Project summary

This repository delivers a per‑PR ephemeral environment pattern that automates identity artifacts (application, service principal, scopes, roles, and a tester group) alongside disposable Azure resources (Key Vault, Storage, Web App). It standardizes on v2 tokens for the Minimal API using a single JwtBearer scheme (valid audiences include the identifier URI and clientId). CI provisions the environment, deploys the API, runs smoke tests against `/healthz` (role-gated) and `/health` (any authenticated token), and preserves results as artifacts. Resources remain until a PR is labeled Destroy, at which point a gated teardown removes the Graph objects and the resource group.

## Repository structure

```
project-bicep-graph/
  bicepconfig.json
  blog.md
  README.md
  infra/
    main.bicep
    modules/
      appInfra.bicep
      identity.bicep
  scripts/
    Assign-AppRoleToGroup.ps1
    Cleanup-GraphEphemeral.ps1
    Create-TestUsers.ps1
    Delete-TestUsers.ps1
    GraphFederation.ps1
    SmokeTests.ps1
  src/
    WebApi/
      appsettings.json
      Program.cs
      WebApi.csproj
  tests/
    SmokeTests.Tests.ps1
```

## Scenarios / use cases

- Validate identity wiring per PR: confirm role claims and authenticated access to the Minimal API before merging.
- Provide a safe sandbox for reviewers: optional test users and a tester group enable manual exploration of scopes/roles while the PR is open.
- Demonstrate Graph Bicep beta: author apps, service principals, roles, and scopes declaratively with deterministic IDs for repeatable deployments.
- Exercise RBAC data-plane checks: Key Vault and Storage access validated via Azure AD (no keys), useful as a template for adding more checks.
- Ephemeral environments for feature branches: spin up quickly, keep until explicitly destroyed, and ensure teardown cleans identity objects too.

## Architecture overview

Components

- Identity (Entra/Microsoft Graph Bicep beta): application, service principal, OAuth2 scopes (Swagger.Read/Write), and an app role (Swagger.Admin); tester security group.
- Azure resources: Key Vault (RBAC), Storage (V2), App Service Plan (B1), Web App with app settings for `AzureAd__TenantId`, `AzureAd__Audience`, and `AzureAd__ClientId`.
- Application: .NET 8 Minimal API; single v2 JwtBearer scheme; policies for `SwaggerAdmin`, `SwaggerRead`, and `AnyAuthenticated`.
- Automation: PowerShell scripts for role assignment and test user lifecycle; GitHub Actions workflow for provision → smoke-tests → destroy.

Flow (high level)

1) PR opened/reopened → OIDC login → Bicep deploys identity + infra → Web API published via zip deploy → role assigned to tester group; optional test users created.
2) Smoke tests acquire a v2 token via `<identifierUri>/.default` (fallback to `<clientId>/.default`), call `/healthz` with the admin token and `/health` with an authenticated token, and validate KV/Storage access.
3) Artifacts (`env-outputs.json`, `test-users.json`, `smoke-results.json`) are uploaded; tokens are not decoded or persisted in results.
4) When the PR is labeled Destroy, CI deletes test users, Graph objects (assignments, group, SP, app), and the resource group.

## Goals vs Non‑Goals

| Aspect | Goal | Non‑Goal |
|--------|------|----------|
| Infrastructure | Rapid, reproducible PR environment spin-up & teardown | Long-lived shared dev environment |
| Identity Automation | Programmatically create app, service principal, scopes, role, group, test users | End‑user production auth flows |
| Testing Scope | Validate auth wiring via `/healthz` (admin role) & `/health` (any authenticated token) | Automated Swagger / scope matrix tests |
| App Roles | Demonstrate creation + assignment | Enforcing complex RBAC logic in code |
| Scopes | Show deterministic GUID-based scopes | Full delegated consent workflow automation |
| Users | Ephemeral test accounts for optional manual exploration | Persistent test directory population |

## Implementation

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
* App settings: `AzureAd__TenantId` (subscription tenant), `AzureAd__Audience` (app audience URI from Bicep output), `AzureAd__ClientId` (application appId for secondary accepted audience).

### Application (Minimal API) — Standardized v2 Authentication
* Endpoints:
  * `/healthz` — role-protected heartbeat; requires `Swagger.Admin` role to authorize (verifies role assignment propagation in CI).
  * `/health` — requires any authenticated bearer token issued by the tenant for this application (no scope enforcement in CI).
  * `/api/mock` — requires `Swagger.Read` scope (demonstrates scope-based policy; not exercised automatically).
  * `/swagger` redirect — protected by `Swagger.Admin` role (manual exploration only).
* Authentication pipeline (single JWT Bearer scheme) configured via environment variables: `AzureAd__TenantId`, `AzureAd__Audience`, `AzureAd__ClientId`.
  * Uses v2 authority: `https://login.microsoftonline.com/<tenantId>/v2.0`.
  * Accepts either the identifier URI (`AzureAd__Audience`) or the `clientId` as valid audience (`ValidAudiences = [ audience, clientId ]`).
  * Explicit issuer validation (`https://login.microsoftonline.com/<tenantId>/v2.0`) prevents cross‑version token mismatches.
  * Policies:
    * `SwaggerAdmin` — role claim (`roles` or `http://schemas.microsoft.com/ws/2008/06/identity/claims/role`) contains `Swagger.Admin`.
    * `SwaggerRead` — scope claim (`scp`) contains `Swagger.Read`.
    * `AnyAuthenticated` — generic authenticated user (used for `/health`).
* Rationale for v2-only standardization: avoids issuer/audience ambiguity between v1 (`https://sts.windows.net/...`) and v2 (`https://login.microsoftonline.com/...`), simplifies smoke testing token acquisition, and ensures consistent claim shape (e.g., consolidated `scp` multi‑space scope string).

### Automation Scripts (`scripts/`)
* **`Assign-AppRoleToGroup.ps1`** — Assigns the `Swagger.Admin` app role to the tester group using Graph REST API. Supports group lookup by display name or direct objectId (preferred). Safely handles pagination and property existence checks to avoid Graph API filter limitations. Also assigns application permission to the runner SP if provided.
* **`Create-TestUsers.ps1`** — Generates ephemeral test users with aliasing pattern `pr<PR_NUMBER>tester<index><6hex>`, sets SecureString passwords, adds each user to the tester group via Graph `/members/$ref`, outputs JSON with plaintext passwords for artifact (demo only; production should use Key Vault or avoid password-based auth).
* **`Delete-TestUsers.ps1`** — Cleans up users matching the PR prefix heuristic (mailNickname, displayName). Deletes users from directory; group membership implicitly removed.
* **`Cleanup-GraphEphemeral.ps1`** — Removes app role assignments (group + runner SP principals), deletes security group, service principal, and application. Uses client-side filtering to work around Graph filter limitations on relationship endpoints. Outputs JSON summary of deletion operations (type, id, status, error).
* **`SmokeTests.ps1`** — Dot-sourceable PowerShell module; `Invoke-EphemeralSmokeTests` function validates environment context, Key Vault access (Get-AzKeyVaultSecret), Storage access (Get-AzStorageAccountKey), and API endpoints (`/healthz` with admin role token, `/health` with any app token). Returns structured object; captures HTTP status codes for diagnostics and gracefully handles missing properties (stores null/error objects) under StrictMode.

### GitHub Actions Workflow (`.github/workflows/ephemeral-env.yml`)
* Jobs: `provision` → `smoke-tests` → `destroy`.
* **Provision**: Checks out repo; logs in via OIDC; resolves runner service principal objectId; creates resource group; deploys Bicep (identity + infrastructure); builds and publishes .NET 8 Minimal API; zips and deploys to App Service; assigns `Swagger.Admin` app role to tester group; creates ephemeral test users; uploads artifacts.
* **Smoke Tests**: Downloads infra outputs; acquires a v2 access token using `<identifierUri>/.default` (fallback to `<clientId>/.default` if needed) ensuring correct issuer/audience; sources `SmokeTests.ps1` and runs `Invoke-EphemeralSmokeTests` to validate `/healthz` (role-gated via admin token), `/health` (any authenticated token), Key Vault access (RBAC), and Storage access (RBAC); generates a concise summary (auth/config and API/resource checks); outputs structured JSON and preserves artifacts even on failure. Tokens are not printed or decoded in logs/artifacts.
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
* CI pipelines do NOT depend on or validate `Swagger.Read` / `Swagger.Write` scopes today (scope policy is illustrative).
* The `/api/mock` and `/swagger` endpoints are not part of required automated tests.
* Test users exist so a human reviewer (during the PR window) could optionally sign in and verify roles/scopes manually.

Automated testing focuses solely on:
* Role claim propagation for `Swagger.Admin` (`/healthz` access).
* Basic bearer auth wiring (`/health` access) with v2 tokens.

## Ephemeral Identity Lifecycle
* Group always created (no conditional logic) simplifying downstream steps.
* Test users generated with prefix `pr<PR_NUMBER>tester` and appended random hex for uniqueness.
* Users added to tester group enabling potential role claim emission if interactive delegated tokens are later acquired manually.
* Teardown removes users; group persists only for the life of the resource group (deleted at RG deletion).

## Security and governance considerations
* Authentication: Use GitHub Actions OIDC for CI login (no secrets). Azure OIDC guidance: https://learn.microsoft.com/azure/developer/github/connect-from-azure-openid-connect
* Token hygiene: Tokens are used only in-memory to call protected endpoints; token contents are not written to `smoke-results.json` or job summaries.
* Least privilege: Prefer Key Vault Secrets User over broader roles; scope assignments to only what smoke tests require.
* RBAC model: Key Vault uses the RBAC permission model (`enableRbacAuthorization=true`) to align with identity-first, secretless automation.
* Governance: Protect main branches by requiring `provision` and `smoke-tests` checks. Use Destroy label to gate cleanup and preserve artifacts for audit.
* Secrets: Test user passwords are demo-only; in production, store in Key Vault or avoid password-based flows entirely.
* Preview note: Microsoft Graph Bicep beta types are subject to change; pin tooling versions and validate in a test tenant first.

## Demo / walkthrough — end-to-end PR flow

1. Open or reopen a PR.
  - CI logs into Azure via OIDC and deploys Bicep (identity + infra).
  - Builds and zips the Minimal API, deploys to the Web App.
  - Assigns `Swagger.Admin` app role to the tester group; optionally creates ephemeral test users and uploads artifacts.
2. Smoke tests run.
  - Acquire a v2 token for `<identifierUri>/.default` (fallback to `<clientId>/.default`).
  - Call `/healthz` with the admin token; call `/health` with an authenticated token.
  - Validate Key Vault and Storage access via Azure AD; upload `smoke-results.json` (no token contents).
3. Review results in the PR summary and artifacts. Merge when checks pass.
4. Apply the Destroy label when you’re done.
  - CI deletes test users, revokes app role assignments, deletes the tester group, service principal, application, and the resource group.

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
| `/healthz` (Swagger.Admin role) & `/health` (AnyAuthenticated) | Implemented | Smoke test covers role-gated + generic auth; returns status & user info |
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
