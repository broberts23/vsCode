# Workload Identity Risk and Remediation Toolkit

This project provides a PowerShell 7.4 toolkit to help organizations locate and remediate high-risk Microsoft Entra applications and service principals, and to implement workload identity lifecycle management (WILM). It aligns with Microsoft Learn guidance for protecting identities, secrets, engineering systems, and monitoring risky workload identities.

Source guidance: Configure Microsoft Entra for increased security (Protect identities and secrets)
https://learn.microsoft.com/entra/fundamentals/configure-security#protect-identities-and-secrets

## Objectives
1. Discover risky workload identities (applications and service principals) and credential posture.
2. Inventory client secrets, certificates, expirations, rotation intervals, and flag long-lived (>180 days) or near-expiring (<30 days) credentials.
3. Recommend and assist migration from client secrets to federated identity credentials or short-lived certificates.
4. Detect and report privileged role assignments and high-privilege Microsoft Graph permissions (Directory.ReadWrite.All, Application.ReadWrite.All, etc.).
5. Assess tenant consent posture (user consent restrictions, admin consent workflow, authorization policy settings).
6. Produce machine-readable JSON/CSV reports, plus an optional remediation plan artifact.
7. Provide helper cmdlets to add federated identity credentials and certificate-based credentials, encouraging secretless patterns.

## Module Overview
Module name: `WorkloadIdentityTools`

Public cmdlets (initial wave):
| Cmdlet | Purpose |
|--------|---------|
| Connect-WiGraph | Auth wrapper for Microsoft Graph with explicit scopes. |
| Get-WiRiskyServicePrincipal | Retrieve risky service principals (Identity Protection). |
| Get-WiApplicationCredentialInventory | Inventory app secrets & certs, compute risk scores. |
| Get-WiServicePrincipalPrivilegedAssignments | Identify privileged directory role assignments. |
| Get-WiHighPrivilegeAppPermissions | Flag applications with high-privilege app permissions. |
| Get-WiTenantConsentSettings | Report consent and authorization policy posture. |
| New-WiFederatedCredential | Create federated identity credentials (OIDC workload identity). |
| Add-WiApplicationCertificateCredential | Add/rotate certificate credentials (short-lived). |

> Note: Some Microsoft Graph Identity Protection workload identity risk APIs are in preview; when beta endpoints are required, prefer Microsoft.Graph.Beta modules with clear preview disclaimers.

Preview/beta risky workload identity cmdlets:
| Cmdlet | Purpose |
|--------|---------|
| Get-WiBetaRiskyServicePrincipal | List risky workload identities (beta). Docs: https://learn.microsoft.com/en-us/graph/api/identityprotectionroot-list-riskyserviceprincipals?view=graph-rest-beta |
| Get-WiBetaRiskyServicePrincipalHistory | Get risk history for a risky service principal (beta). Docs: https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-list-history?view=graph-rest-beta |
| Confirm-WiRiskyServicePrincipalCompromised | Mark service principals as compromised (beta). Docs: https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-confirmcompromised?view=graph-rest-beta |
| Dismiss-WiRiskyServicePrincipal | Dismiss risk for service principals (beta). Docs: https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-dismiss?view=graph-rest-beta |
| Get-WiRiskyServicePrincipalTriageReport | Build a triage summary for risky workload identities. |

Approved-verb wrappers (preferred):
| Cmdlet | Purpose |
|--------|---------|
| Set-WiRiskyServicePrincipalCompromised | Preferred wrapper for confirming compromised risky SPs (replaces Confirm-WiRiskyServicePrincipalCompromised). |
| Clear-WiRiskyServicePrincipalRisk | Preferred wrapper for dismissing risk (replaces Dismiss-WiRiskyServicePrincipal). |

Deprecation notice:
- Confirm-WiRiskyServicePrincipalCompromised and Dismiss-WiRiskyServicePrincipal are deprecated and will be removed in a future release. Use the approved-verb wrappers above.

## Key Microsoft Learn References
Authentication: Connect-MgGraph — https://learn.microsoft.com/powershell/microsoftgraph/authentication/connect-mggraph?view=graph-powershell-1.0
Applications: Get-MgApplication — https://learn.microsoft.com/powershell/module/microsoft.graph.applications/get-mgapplication?view=graph-powershell-1.0
Federated Credentials: New-MgApplicationFederatedIdentityCredential — https://learn.microsoft.com/powershell/module/microsoft.graph.applications/new-mgapplicationfederatedidentitycredential?view=graph-powershell-1.0
Add Certificate Key: Add-MgApplicationKey — https://learn.microsoft.com/powershell/module/microsoft.graph.applications/add-mgapplicationkey?view=graph-powershell-1.0
Authorization Policy (Consent): Get-MgPolicyAuthorizationPolicy — https://learn.microsoft.com/powershell/module/microsoft.graph.identity.signins/get-mgpolicyauthorizationpolicy?view=graph-powershell-1.0

## Permissions (Least Privilege Baselines)
Read-only discovery:
- Application.Read.All, Directory.Read.All, Policy.Read.All, AuditLog.Read.All (optional), IdentityRiskyServicePrincipal.Read.All (preview)

Remediation (adding credentials, migrations):
Risk actions (beta risky workload identities):
- IdentityRiskyServicePrincipal.Read.All for read. For actions: IdentityRiskyServicePrincipal.ReadWrite.All. Supported roles include Security Administrator (for actions) and Security Reader/Operator/Global Reader (for read). See: list riskyServicePrincipals (beta) permissions: https://learn.microsoft.com/en-us/graph/api/identityprotectionroot-list-riskyserviceprincipals?view=graph-rest-beta#permissions and confirmCompromised: https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-confirmcompromised?view=graph-rest-beta#permissions

- Application.ReadWrite.All (or Application.ReadWrite.OwnedBy where feasible)
- Policy.ReadWrite.Authorization (if adjusting consent settings)

Privileged role and app permission enumeration may require Directory.Read.All.

## Security Principles
- Prefer managed identities or certificate-based service principals for automation pipelines.
- Avoid client secrets; migrate to federated credentials (OIDC) or short-lived certificates.
- Ensure periodic rotation (<180 days) and queue proactive rotation if <30 days remaining.
- No secrets stored in code. Use SecretManagement: https://learn.microsoft.com/powershell/utility-modules/secretmanagement/overview
- Enforce user/admin consent restrictions per guidance.

## Quick Start
```powershell
#!/usr/bin/env pwsh
Requires -Version 7.4
Import-Module ./src/WorkloadIdentityTools/WorkloadIdentityTools.psd1
Connect-WiGraph -Scopes @('Application.Read.All','Directory.Read.All') -TenantId '00000000-0000-0000-0000-000000000000'
$inventory = Get-WiApplicationCredentialInventory -All
$inventory | Where-Object { $_.RiskLevel -eq 'High' } | Format-Table DisplayName, CredentialType, DaysUntilExpiry, RiskReasons

# Risky workload identities (beta)
Connect-WiGraph -Scopes @('IdentityRiskyServicePrincipal.Read.All') -TenantId '00000000-0000-0000-0000-000000000000'
$triage = Get-WiRiskyServicePrincipalTriageReport
$triage.Distribution.ByRiskLevel | Format-Table
```

## Report Outputs
`Get-WiApplicationCredentialInventory` returns objects with fields:
- ApplicationId, DisplayName
- CredentialId, CredentialType (Secret|Certificate|Federated)
- StartDate, EndDate, DaysUntilExpiry
- LongLived (bool), NearExpiry (bool)
- RiskLevel (None|Low|Medium|High)
- RiskReasons (string[])

## Remediation Patterns
1. Replace client secret with federated credential (GitHub Actions, Azure Workload Identity Federation, etc.).
2. Shorten certificate lifetime; enforce rotation pipeline (Add-WiApplicationCertificateCredential).
3. Remove unused/high-privilege app permissions.
4. Remove privileged role assignments from workload identities (use PIM activation JIT, outside scope here but flagged).

## Roadmap (Next Iterations)
- Integration with Identity Protection risky workload identity APIs (beta) and risk triage automation.
- Advanced consent policy diff & recommended settings output.
- Optional Bicep IaC for federated credential onboarding pipelines.
- Pester test expansion with Mocks for Graph cmdlets.
- CSV and markdown executive summary generation.

## Testing
Basic Pester tests validate exported functions and risk scoring logic. Extend with Mocks for Graph calls.
Pester docs: https://learn.microsoft.com/powershell/scripting/testing/overview?view=powershell-7.4

## Disclaimer
Preview or beta Graph endpoints are subject to change. Always validate in a test tenant before production rollout. Apply least privilege and comply with organizational security policies.

## License
MIT
