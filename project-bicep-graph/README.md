# Project: Graph-Backed Ephemeral Environment Scaffolding

This project demonstrates declarative creation of Microsoft Entra (Azure AD) application and service principal objects via the Microsoft Graph Bicep extension together with ephemeral Azure infrastructure for pull request (PR) validation environments.

Preview disclaimer: Microsoft Graph Bicep templates (applications/servicePrincipals) are in beta. APIs under `/beta` may change. Do not use this unmodified in production without validation.

## Objectives
- Per‑PR isolated identity (App + Service Principal) created in Bicep.
- Minimal RBAC scoped to just the resources provisioned for validation.
- Optional workload identity federation (GitHub Actions OIDC) via federated identity credential (currently created post‑deploy with Graph API if not exposed in Bicep).
- Smoke tests executed under the ephemeral identity; results surfaced to PR (simulating a ServiceNow ticket update).
- Deterministic teardown with audit of removed role assignments and deleted Entra objects.

## Structure
```
project-bicep-graph/
  bicepconfig.json               # Enables extensibility + Graph extension aliases.
  infra/
    main.bicep                   # Orchestrates modules.
    modules/
      identity.bicep             # Creates application + service principal.
      appInfra.bicep             # Demo infra (Key Vault, Storage) + RBAC (placeholder).
  scripts/
    SmokeTests.ps1               # Placeholder PowerShell smoke tests (7.4).
    GraphFederation.ps1          # Placeholder for federated identity credential creation.
  workflows/
    ephemeral-env.yml            # GitHub Actions workflow scaffold.
  tests/
    SmokeTests.Tests.ps1         # Pester tests scaffold.
```

## Microsoft Learn References
- Applications (Bicep): https://learn.microsoft.com/graph/templates/bicep/reference/applications?view=graph-bicep-beta
- Service Principals (Bicep): https://learn.microsoft.com/graph/templates/bicep/reference/serviceprincipals?view=graph-bicep-beta
- Federated identity credentials overview: https://learn.microsoft.com/graph/api/resources/federatedidentitycredentials-overview?view=graph-rest-1.0
- Workload identity federation concepts: https://learn.microsoft.com/azure/active-directory/develop/workload-identity-federation
- Bicep configuration: https://learn.microsoft.com/azure/azure-resource-manager/bicep/bicep-config
- Azure Login OIDC (GitHub): https://learn.microsoft.com/azure/developer/github/connect-from-azure-openid-connect
- Role assignments cmdlets: https://learn.microsoft.com/powershell/module/az.resources/new-azroleassignment?view=azps-latest

## Next Steps
1. Fill in `appInfra.bicep` with concrete resource definitions and role assignment logic.
2. Implement federated identity credential creation (Graph API) in `GraphFederation.ps1`.
3. Expand smoke tests to validate Key Vault and Storage permissions.
4. Integrate workflow steps to call the scripts and post PR comments.
5. Add cleanup workflow for stale PR environments.

## Cleanup Strategy
- Tag every resource and Entra object with `Env=pr-<number>`, `TTLHours=<n>`, `CreatedAt=<ISO8601>`.
- Nightly scheduled workflow queries for expired TTL environments and runs teardown.

## Security Notes
- Avoid storing secrets: use OIDC federation only.
- Use least privileged role definitions (e.g., Key Vault Secrets User vs Secrets Officer when possible).

## Disclaimer
This scaffold is intentionally minimal; adapt RBAC scopes and add logging, error handling, and compliance instrumentation before production use.
