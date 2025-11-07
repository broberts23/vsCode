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
* Two OAuth2 permission scopes defined: `Swagger.Read`, `Swagger.Write` (deterministic IDs via `guid()` seeding).
* One application role `Swagger.Admin` (allowed for User & Application principals) with deterministic ID.
* Security group `grp-<pr>-<suffix>-testers` created unconditionally for ephemeral test accounts; app is configured with `groupMembershipClaims: SecurityGroup` so role/group claims flow into user tokens (if requested interactively later).
* Secure outputs (`@secure()`) applied to scope and role identifiers to avoid log leakage.

### Infrastructure Layer
* Storage Account (demo) and Key Vault (RBAC permission model) deployed.
* Web App (Minimal API) + Free App Service Plan.
* Minimal RBAC role assignment on Key Vault for the service principal (configurable role definition id parameter).

### Application (Minimal API)
* Endpoints:
  * `/healthz` — unauthenticated heartbeat (also reports whether auth is configured).
  * `/health` — authenticated; requires any valid token for the application (no specific scope policy enforced here in CI).
  * `/api/mock` — requires `Swagger.Read` scope (policy keeps example of scope-based gating, but CI does not exercise it).
  * `/swagger` redirect — protected by `Swagger.Admin` role (demonstrates role-based policy enforcement; optional manual use).
* Authentication pipeline (JWT Bearer) configured via environment variables: `AzureAd__TenantId`, `AzureAd__Audience`.

### Automation Scripts (`scripts/`)
* `GraphFederation.ps1` — Creates a federated credential binding GitHub pull_request OIDC subject to the app (workload identity).
* `Assign-AppRoleToGroup.ps1` — Assigns the `Swagger.Admin` app role to the tester group (role assignment path for users vs app principals demonstration).
* `Create-TestUsers.ps1` — Generates ephemeral test users, adds them to the tester group, outputs credentials (JSON artifact). Uses SecureString internally before emitting password for artifact (demo only; recommend stronger secret handling in production).
* `Delete-TestUsers.ps1` — Cleans up users with the PR-specific prefix on teardown.
* `SmokeTests.ps1` — Performs minimal health validation: obtains application token (client credential) and exercises `/healthz` and `/health` with/without auth.

### GitHub Actions Workflow (`workflows/ephemeral-env.yml`)
* Jobs: `provision` → `smoke-tests` → `destroy`.
* Provision: Deploys Bicep, builds/publishes API, deploys ZIP to Web App, creates federated credential, assigns app role, creates test users, uploads artifacts.
* Smoke Tests: Downloads infra outputs, obtains application token (no delegated scopes), calls health endpoints (only `/health` requires auth) and records summary.
* Destroy: Deletes ephemeral test users and resource group (asynchronously) when PR closes or merges.
* Artifacts: `env-outputs.json`, `federation.json`, `test-users.json`, `smoke-results.json`.

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
| Custom OAuth2 scopes (Swagger.Read/Write) | Implemented | Deterministic GUIDs |
| Application role (Swagger.Admin) | Implemented | Assigned to tester group post-deploy |
| Security group for test users | Implemented | Always created; objectId output |
| Ephemeral test user creation & deletion | Implemented | Lifecycle integrated in workflow |
| Federated credential (GitHub OIDC) | Implemented | Script-driven creation |
| Web API deployment (zip) | Implemented | Minimal API .NET 8 | 
| `/healthz` (no auth) & `/health` (auth) | Implemented | Smoke test covers both |
| Scope or role-based automated tests | Not in scope | Intentional—manual exploration only |
| Secure outputs for scope/role IDs | Implemented | `@secure()` in Bicep |
| Artifact publication (env/test users/federation/smoke) | Implemented | For traceability |
| Automatic per-PR teardown | Implemented | Resource group + users removed |

## Potential Future Enhancements (Optional)
* Add delegated token acquisition (device code) to validate `scp` claim presence (if you later want automated scope testing).
* Implement preAuthorizedApplications in manifest for zero-consent user token acquisition.
* Introduce TTL scan job to clean orphaned PR resource groups/users if a workflow run is interrupted.
* Encrypt or secret-manage test user credentials (Key Vault + GitHub OIDC retrieval) for improved hygiene.
* Pester tests for scripts (Mock Graph calls) + PSScriptAnalyzer configuration baseline.

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
