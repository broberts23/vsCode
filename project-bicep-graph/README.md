# Graph-Backed Ephemeral PR Environments (project-bicep-graph)

Lightweight pattern for spinning up (and explicitly tearing down) per‑pull‑request Azure environments plus Microsoft Entra application/service principal, scopes, app role, and a tester group using the Microsoft Graph Bicep beta extension.

> Preview: Microsoft Graph Bicep resource types are in beta; schemas may change. Validate in a test tenant before production use.

## ✨ Key Features
- Declarative identity layer: App + Service Principal + OAuth2 scopes (Swagger.Read/Write) + application role (Swagger.Admin) + tester security group in Bicep.
- Deterministic GUID seeding for scopes & role → stable across redeploys.
- Ephemeral infra: Key Vault (RBAC), Storage Account, App Service Plan, Minimal API Web App.
- v2-only JWT auth: Single bearer scheme accepting identifier URI & clientId as audiences.
- Role-gated `/healthz` and authenticated `/health` smoke validation (no token contents logged).
- GitHub Actions OIDC based workflow: provision → smoke-tests → label-gated destroy.
- PowerShell 7.4 scripts for role assignment, test user creation/deletion, and Graph cleanup.

## 📁 Repository Structure
```
bicepconfig.json            # Extensibility + Graph extension aliases
infra/
  main.bicep               # Orchestrator (identity + infra modules)
  modules/
    identity.bicep         # Graph app/SP, scopes, role, tester group (deterministic IDs)
    appInfra.bicep         # Key Vault, Storage, Web App, RBAC + app settings
scripts/
  Assign-AppRoleToGroup.ps1
  Create-TestUsers.ps1
  Delete-TestUsers.ps1
  Cleanup-GraphEphemeral.ps1
  GraphFederation.ps1       # (placeholder for federated credential)
  SmokeTests.ps1            # API, KV, Storage validation (no token output)
src/WebApi/                 # .NET 8 Minimal API (Program.cs)
tests/SmokeTests.Tests.ps1  # Pester placeholder
blog.md                     # Deep-dive technical article
README.md                   # (This file) concise overview
```

## 🧱 Architecture (High Level)
1. PR opened → workflow deploys Bicep: identity + infra.
2. Web API published (zip deploy) with app settings (`AzureAd__TenantId`, `AzureAd__Audience`, `AzureAd__ClientId`).
3. Role assignment script grants `Swagger.Admin` to tester group; optional test users created and added to group.
4. Smoke tests acquire v2 token (`<identifierUri>/.default` → fallback `<clientId>/.default`), validate `/healthz` (role) + `/health` (auth) + Key Vault & Storage access.
5. Artifacts uploaded: `env-outputs.json`, `test-users.json`, `smoke-results.json` (no tokens).
6. Label "Destroy" applied → cleanup job deletes users, role assignments, group, service principal, application, resource group.

## 🔍 Smoke Tests (What They Prove)
| Check | Purpose |
|-------|---------|
| /healthz (Swagger.Admin) | App role assignment & role claim propagation |
| /health (AnyAuthenticated) | Baseline token validation & audience config |
| Key Vault RBAC | Data-plane access under assigned role |
| Storage RBAC | Data-plane container list via AAD |

## 🔐 Security & Governance
- OIDC only (no client secrets) for GitHub Actions: https://learn.microsoft.com/azure/developer/github/connect-from-azure-openid-connect
- Key Vault RBAC model (`enableRbacAuthorization=true`); no access policies.
- Tokens not written to logs/artifacts; only success/status fields are stored.
- Least privilege roles (e.g., Key Vault Secrets User) recommended; sample uses roleDefinitionId parameter.
- Deterministic tags (`Env=pr-<n>`, `TTLHours`, `CreatedAt`) enable future TTL sweeps / scheduled cleanup.
- Preview caution: Pin Bicep & validate Graph beta types when upgrading.

## 🚀 Quick Start (Conceptual)
1. Ensure Azure login/OIDC secrets are configured (client-id, tenant-id, subscription-id) in repo.
2. Open a PR → workflow provisions environment automatically.
3. Review smoke test summary & artifacts.
4. (Optional) Use test users for manual scope/role exploration.
5. Apply "Destroy" label to trigger teardown when finished.

## 🧹 Teardown
Explicit label triggers cleanup: removes app role assignments → deletes group/SP/app → deletes resource group. No implicit auto-remove (keeps environment for iterative PR testing until explicitly destroyed).

## 📚 References
- Applications (Bicep): https://learn.microsoft.com/graph/templates/bicep/reference/applications?view=graph-bicep-beta
- Service Principals (Bicep): https://learn.microsoft.com/graph/templates/bicep/reference/serviceprincipals?view=graph-bicep-beta
- Access tokens & claims: https://learn.microsoft.com/azure/active-directory/develop/access-tokens
- Key Vault RBAC: https://learn.microsoft.com/azure/key-vault/general/rbac-guide
- Role assignments cmdlets: https://learn.microsoft.com/powershell/module/az.resources/new-azroleassignment?view=azps-latest
- Workload identity federation: https://learn.microsoft.com/azure/active-directory/develop/workload-identity-federation

## ⚠️ Disclaimer
This is a demonstration scaffold. Before production: harden logging, add Pester coverage, implement federated credentials (GraphFederation.ps1), enforce TTL sweeps, and review role scopes.

---
For a deeper architectural narrative, see `blog.md`.
