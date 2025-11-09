# Ephemeral PR Environment with Microsoft Graph Bicep

This project demonstrates an end-to-end ephemeral pull request (PR) environment pattern using:

* Microsoft Graph Bicep to provision an application, service principal, security group, test accounts, custom OAuth2 permission scopes, and an application role.
* Azure resource deployment (Key Vault with RBAC, Storage, App Service Plan, Web App) as disposable per‑PR infrastructure.
* .NET 8 Minimal API with standardized v2 JwtBearer authentication accepting both identifier URI and clientId audiences.
* GitHub Actions OIDC workload identity federation (no client secrets) to deploy and test.
* PowerShell automation for post‑deploy Graph operations (federated credential, app role assignment, ephemeral test users lifecycle).
* Smoke tests validating Web App (service) readiness, role claim propagation, authenticated access, and data-plane RBAC for Key Vault and Storage.

The design focus here is *NOT* deep functional testing of business endpoints, although the smoke tests could easily be extentended to include more comprehensive API surface validation.  Instead, it highlights how identity artifacts (scopes, roles, group membership, users) can be created and wired programmatically as part of an ephemeral environment. The only required application tests are:

* A role-gated `/healthz` endpoint (requires `Swagger.Admin` application role) proving role claim emission and authorization works.
* An authenticated `/health` endpoint (accepts any valid v2 token for the application) proving basic bearer auth wiring works.

Swagger/UI endpoints and scope-gated API surface are intentionally optional and can be explored manually with the generated test identities while a PR is open.

## Project summary

This repository delivers a per‑PR ephemeral environment pattern that automates identity artifacts (application, service principal, scopes, roles, and a tester group) alongside disposable Azure resources (Key Vault, Storage, Web App). It standardizes on v2 Graph tokens for the Minimal API using a single JwtBearer scheme (valid audiences include the identifier URI and clientId). CI provisions the environment, deploys the API, runs smoke tests against `/healthz` (role-gated) and `/health` (any authenticated token), and preserves results as artifacts. Resources remain until a PR is labeled `destroy`, at which point a gated teardown removes the Graph objects and the Azureresource group.

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

Below are practical, real-world scenarios where this pattern adds value:

- Feature-branch validation environments
  - Spin up a complete stack per PR, run smoke tests, and keep the environment available for iterative commits until explicitly destroyed.

- Identity wiring and RBAC regression checks
  - Prove role claim propagation (`Swagger.Admin` → `/healthz`) and audience/issuer correctness (`/health`) before merge; catch config drift early.

- Contract and SDK change verification
  - Validate changes to Minimal API endpoints or OpenAPI contracts with generated clients; exercise `Swagger.Read` policy gating (optionally) without impacting shared envs.

- Dependency upgrade confidence
  - Test .NET minor/patch upgrades, App Service runtime updates, Az CLI/PowerShell module bumps, and Graph API changes in isolation per PR.

- Cross-service integration tests
  - Verify Key Vault and Storage data‑plane RBAC using the workload identity; ensure least‑privilege roles still allow the required operations.

- Secrets rotation rehearsal
  - Rehearse secret or certificate rotation patterns (paired with a JIT RBAC activation workflow) and verify the app consumes new versions without downtime.

- Conditional Access and role policy previews
  - Trial tenant policy changes that may affect service‑to‑service flows; confirm protected endpoints still authorize correctly with v2 tokens.

- Multi-tenant app hardening
  - Exercise deterministic identifier URIs and dual accepted audiences (audience + clientId) to ensure consistent v2 auth in multi‑tenant setups.

- Performance smoke and cold‑start checks
  - Measure first‑hit latency and basic throughput after deploy; compare over time as dependencies change.

- Chaos/resiliency drills (lightweight)
  - Intentionally deny KV or Storage access (temporary RBAC change) to confirm the app and pipeline report actionable errors.

- PR demos and review sandboxes
  - Provide reviewers with test users and a safe, isolated environment for manual exploration during the review window.

- Bug reproduction and fix validation
  - Reproduce production issues in a throwaway env with the same identity wiring and app settings; validate fixes without risking shared dev/test.

- Bicep module canary testing
  - Validate changes to shared modules (identity/infra) behind a PR; confirm outputs, RBAC assignments, and app settings are correct end‑to‑end.

- Workflow and OIDC trust changes
  - Safely evolve GitHub Actions workflow steps (OIDC, artifact handling, smoke steps) and verify behavior in isolation before rolling to other repos.

- Testing team regression suites
  - Provide QA teams with ephemeral test accounts and a disposable environment to run regression test suites; each PR gets fresh test users with known credentials and role assignments, ensuring repeatable and isolated test runs.


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
* CI pipelines do NOT depend on or validate Swagger.Read / Swagger.Write scopes today (scope policy is illustrative).
* The /api/mock and /swagger endpoints are not part of the automated testing and are merely placeholders to demonstrate how the testing framework could be used.
* Test users exist so a human reviewer (during the PR window) could optionally sign in and verify roles/scopes manually. They could also be used for user-based delegated claim auth validation.

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

## Conclusion

This project emphasizes identity resource automation (app, SP, scopes, roles, group, users) and ephemeral infrastructure rather than broad functional API test coverage. The minimal smoke test (`/healthz` + authenticated `/health`) gives just enough validation that identity wiring and deployment succeeded. Everything else—the Swagger-related scopes, role policies, and test users—serves as demonstrative scaffolding that reviewers can manually exercise during a PR’s lifetime.

## Key References
* Graph app/service principal Bicep (beta): https://learn.microsoft.com/graph/templates/bicep/reference/applications?view=graph-bicep-beta
* Azure OIDC federation (GitHub): https://learn.microsoft.com/azure/developer/github/connect-from-azure-openid-connect
* Access tokens & claims: https://learn.microsoft.com/azure/active-directory/develop/access-tokens
* Key Vault RBAC: https://learn.microsoft.com/azure/key-vault/general/rbac-guide
