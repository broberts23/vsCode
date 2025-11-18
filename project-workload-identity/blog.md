# Workload Identity Risk and Remediation with Microsoft Graph + PowerShell 7.4

## Introduction

Workload identities (applications and service principals) drive automation and integration—but they are often a silent risk vector: long‑lived client secrets, stale certificates, excessive Graph permissions, drifted consent policy, and unaddressed risky service principals in Microsoft Entra ID Protection. This article presents a pragmatic pattern for discovering, triaging, and remediating workload identity risk using a PowerShell 7.4 toolkit plus Microsoft Graph (v1.0 and beta). The design emphasizes “secretless first” (federated credentials and managed identities) and short‑lived certificates over periodic secret rotation.

Source guidance: Configure Microsoft Entra for increased security (Protect identities and secrets)
https://learn.microsoft.com/entra/fundamentals/configure-security#protect-identities-and-secrets

## Project summary

The `WorkloadIdentityTools` PowerShell module enables:
- Credential inventory with risk scoring (long‑lived >180 days, near expiry <30 days)
- High‑privilege Graph permission detection
- Privileged role enumeration for service principals
- Tenant consent posture reporting
- Risky workload identity (service principal) triage (beta Identity Protection APIs)
- Federated credential creation and short‑lived certificate add/rotation
- Machine‑readable JSON/CSV output for CI/CD, dashboards, or audit pipelines

Key deliverables: `Scan-And-Report.ps1` one‑shot scan script, module cmdlets for discovery and remediation, Pester tests for load and logic.

## Repository structure (abridged)

```
project-workload-identity/
  README.md
  blog.md               <-- this article
  scripts/
    Install-Dependencies.ps1
    Scan-And-Report.ps1
  src/WorkloadIdentityTools/
    WorkloadIdentityTools.psd1 / .psm1
    Public/*.ps1
    Private/*.ps1
  tests/Unit/*.Tests.ps1
```

## Scenarios / use cases

1. Credential hygiene & migration: Identify long‑lived secrets and migrate to federated or cert credentials.
2. Risky service principal review: Summarize Identity Protection risk states (atRisk, confirmedCompromised, dismissed) and prioritize action.
3. Privileged surface reduction: Flag applications with Directory.* and Application.* admin scopes, or SPs in elevated roles.
4. Consent posture auditing: Detect drift in user/admin consent restrictions via authorization policy.
5. Compliance evidence generation: Produce JSON artifacts suitable for archiving or SIEM ingestion.
6. CI integration: Automate daily or PR-triggered scans with artifact publishing.
7. Federated adoption tracking: Measure migration progress from secrets to OIDC federation.

## Why move away from secrets instead of adopting a rotation platform?

Enterprise secret rotation platforms (e.g., vault + scheduled rotation) treat symptoms—lifecycle management of a credential—but do not remove credential risk. Federated credentials and managed identities eliminate static secrets entirely. Benefits of secretless vs. rotation systems:

- Attack surface reduction: Nothing static to exfiltrate; ephemeral tokens issued on demand.
- Operational simplicity: No rotation schedules, vault sync jobs, or out-of-band renewal failures.
- Faster incident response: No broad invalidation campaign of secret copies—reconfigure trust instead.
- CI ergonomics: OIDC workload identity removes the need to distribute a secret to every environment.
- Policy-centric: Enforce least privilege and Conditional Access at identity layer rather than after-the-fact secret hardening.
- Cost efficiency: Fewer moving components (no secret lifecycle pipeline) and reduced audit overhead.

This toolkit accelerates secretless adoption: discover secrets, generate actionable migration recommendations, apply federated credentials, and shorten certificate lifetimes where secrets remain.

## Architecture overview

Components:
- PowerShell 7.4 module (`WorkloadIdentityTools`) with advanced functions and strict mode.
- Microsoft Graph PowerShell SDK (v1.0) for applications, auth policy, role enumeration.
- Microsoft Graph beta endpoints for risky workload identities.
- Reporting script `Scan-And-Report.ps1` generating JSON/CSV artifacts.

High-level flow:
1. Explicit Graph connection (Connect-WiGraph) with least privilege scopes.
2. Discovery: credentials, roles, permissions, consent posture, risky SPs.
3. Triage: aggregate risk distribution (Get-WiRiskyServicePrincipalTriageReport).
4. Remediation: federated credential creation or certificate credential rotation.
5. Output: structured artifacts saved under `./out` for downstream automation.

## Implementation details

Discovery cmdlets:
- `Get-WiApplicationCredentialInventory` (uses Get-MgApplication) flags long‑lived & near‑expiry credentials; recommends migration targets.
- `Get-WiServicePrincipalPrivilegedAssignments` enumerates SPs in privileged directory roles.
- `Get-WiHighPrivilegeAppPermissions` locates applications holding high‑privilege delegated/app perms.
- `Get-WiTenantConsentSettings` extracts key authorization policy posture fields.
- `Get-WiBetaRiskyServicePrincipal` / `Get-WiBetaRiskyServicePrincipalHistory` fetch risky SPs and history (beta).
- `Get-WiRiskyServicePrincipalTriageReport` summarizes distribution & recommendations.

Remediation helpers:
- `New-WiFederatedCredential` creates federated identity credentials (OIDC workload identity).
- `Add-WiApplicationCertificateCredential` adds short‑lived certificate credentials (<180 days default).
- Approved verbs for risk actions: `Set-WiRiskyServicePrincipalCompromised`, `Clear-WiRiskyServicePrincipalRisk` (WhatIf/Confirm supported).

Permission guidance:
- Discovery: Application.Read.All, Directory.Read.All, Policy.Read.All (AuditLog.Read.All optional).
- Risky SP read: IdentityRiskyServicePrincipal.Read.All.
- Risk actions: IdentityRiskyServicePrincipal.ReadWrite.All + Security Administrator role.

## Try it locally

```powershell
# Install modules
./project-workload-identity/scripts/Install-Dependencies.ps1

# Import and connect
Import-Module ./project-workload-identity/src/WorkloadIdentityTools/WorkloadIdentityTools.psd1
Connect-WiGraph -Scopes @('Application.Read.All','Directory.Read.All') -TenantId '<tenant-guid>'

# Credential inventory
$inventory = Get-WiApplicationCredentialInventory -All
$inventory | Where-Object { $_.RiskLevel -eq 'High' } | Format-Table DisplayName, CredentialType, DaysUntilExpiry, RiskReasons

# Risky workload identities (beta)
Connect-WiGraph -Scopes @('IdentityRiskyServicePrincipal.Read.All') -TenantId '<tenant-guid>'
$triage = Get-WiRiskyServicePrincipalTriageReport
$triage.Distribution.ByRiskLevel | Format-Table
```

## Lab data seeding (optional)

If your dev tenant does not yet have a rich set of workload identities, you can bootstrap a small, self-contained lab dataset for demonstrations:

- Run `scripts/Bootstrap-WiLab.ps1 -TenantId '<tenant-guid>'` to create several `wi-lab-*` applications and service principals that cover long-lived secrets, near-expiry secrets, certificate credentials, federated-only identities, and a small number of high-privilege examples. The script is idempotent and will reuse existing lab objects with the same prefix.
- Rerun `Scan-And-Report.ps1` to see how the lab objects appear in `credential-inventory.json`, `high-privilege-app-permissions.json`, and `privileged-roles.json`.
- When you are finished, run `scripts/Cleanup-WiLab.ps1 -TenantId '<tenant-guid>'` (with `-WhatIf` first if you prefer) to remove the `wi-lab-*` identities from your dev tenant.

These scripts are intended for **non-production** tenants only. They avoid manipulating Identity Protection risk state directly; in many dev tenants the risky workload identities reports will legitimately be empty, and that is an acceptable demonstration outcome.

## CI workflow example (scan + artifact)

The GitHub Actions workflow (`workload-identity-scan.yml`) performs:
1. OIDC login to Azure using workload identity (no client secret)
2. Module dependency installation
3. Scan execution with risky workload identities included
4. Artifact upload (`risky-service-principal-triage.json` and the full `out/` directory)

Minimal required GitHub secrets / environment configuration:
| Secret | Purpose |
|--------|---------|
| AZURE_CLIENT_ID | Federated workload identity application clientId |
| AZURE_TENANT_ID | Entra tenant ID |
| AZURE_SUBSCRIPTION_ID | Subscription ID for context (if using azure/login) |
| WI_SCAN_TENANT_ID | Tenant ID passed to the scan script (may match AZURE_TENANT_ID) |

Scopes requested are defined by the script invocation; ensure the federated credential / app has appropriate Graph application permissions consented.

## Outputs

Artifacts generated under `./out`:
- `credential-inventory.json` / `.csv`
- `privileged-roles.json`
- `high-privilege-app-permissions.json`
- `consent-settings.json`
- `risky-service-principals.json`
- `risky-service-principal-triage.json`
- `scan-summary.json`

## Goals vs Non‑Goals

| Aspect | Goal | Non‑Goal |
|--------|------|----------|
| Discovery | Consolidated risk + inventory snapshot | Full SIEM pipeline |
| Remediation | Federated credential & cert rotation helpers | Conditional Access policy automation |
| Risk Actions | Approved verb wrappers with WhatIf support | Complex risk enrichment ML |
| Reporting | Machine‑readable JSON/CSV | Interactive dashboards bundled |

## Security & governance considerations

- Favor federated credentials / managed identities to eliminate static secrets.
- Apply least privilege: restrict Graph scopes and directory roles to the minimal set.
- Treat beta APIs as preview; validate in non‑production tenants first.
- Store artifacts securely; they do not contain secrets but may reveal privilege posture.
- Integrate outputs with compliance evidence or periodic access review processes.

## References

PowerShell / Testing:
- Pester overview: https://learn.microsoft.com/powershell/scripting/testing/overview?view=powershell-7.4

Graph SDK (v1.0):
- Connect-MgGraph: https://learn.microsoft.com/powershell/microsoftgraph/authentication/connect-mggraph?view=graph-powershell-1.0
- Get-MgApplication: https://learn.microsoft.com/powershell/module/microsoft.graph.applications/get-mgapplication?view=graph-powershell-1.0
- New-MgApplicationFederatedIdentityCredential: https://learn.microsoft.com/powershell/module/microsoft.graph.applications/new-mgapplicationfederatedidentitycredential?view=graph-powershell-1.0
- Add-MgApplicationKey: https://learn.microsoft.com/powershell/module/microsoft.graph.applications/add-mgapplicationkey?view=graph-powershell-1.0
- Get-MgPolicyAuthorizationPolicy: https://learn.microsoft.com/powershell/module/microsoft.graph.identity.signins/get-mgpolicyauthorizationpolicy?view=graph-powershell-1.0

Graph Beta (Risky Workload Identities):
- List risky SPs: https://learn.microsoft.com/en-us/graph/api/identityprotectionroot-list-riskyserviceprincipals?view=graph-rest-beta
- Risk history: https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-list-history?view=graph-rest-beta
- Confirm compromised: https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-confirmcompromised?view=graph-rest-beta
- Dismiss risk: https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-dismiss?view=graph-rest-beta

## Conclusion

Workload identity risk is not solved by “rotate secrets faster”—it is solved by removing the underlying secret, constraining privilege windows, and continuously validating posture. This toolkit accelerates that journey: discover risks, generate actionable migration recommendations, and apply secretless patterns using federated credentials or short‑lived certificates. By integrating risky workload identity triage and privilege surface analysis into CI/CD, you create a feedback loop that keeps your identity layer continuously hardened. Extend the artifacts into dashboards or governance workflows and iterate toward a posture where standing secrets vanish, privileged assignments are deliberate and time‑bound, and compliance evidence is automatically produced every run. Secretless, least‑privilege, and automated remediation are achievable today—this project gives you a practical blueprint.

License: MIT
