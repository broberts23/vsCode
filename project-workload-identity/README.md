# Workload Identity Risk and Remediation Toolkit

PowerShell 7.4 toolkit for discovering and remediating risky workload identities in Microsoft Entra ID. Inventory credentials, detect privilege drift, migrate from secrets to federated credentials, and generate compliance artifacts.

Source: [Configure Microsoft Entra for increased security](https://learn.microsoft.com/entra/fundamentals/configure-security#protect-identities-and-secrets)

## Project Structure

```
project-workload-identity/
├── scripts/
│   ├── Install-Dependencies.ps1       # Install required PowerShell modules
│   ├── Scan-And-Report.ps1            # One-shot scan generating JSON/CSV artifacts
│   ├── Write-ScanReport.ps1           # Generate HTML report from scan artifacts
│   ├── Publish-ScanReportSummary.ps1  # Publish HTML to GitHub Actions summary
│   ├── Bootstrap-WiLab.ps1            # Seed dev tenant with test identities
│   └── Cleanup-WiLab.ps1              # Remove test identities
├── src/WorkloadIdentityTools/
│   ├── WorkloadIdentityTools.psd1     # Module manifest
│   ├── WorkloadIdentityTools.psm1     # Module loader
│   ├── Public/                        # Exported cmdlets
│   └── Private/                       # Internal helpers
├── tests/Unit/                        # Pester tests
├── README.md                          # This file
└── blog.md                            # Deep-dive article
```

## Key Cmdlets

**Discovery:** `Get-WiApplicationCredentialInventory`, `Get-WiServicePrincipalPrivilegedAssignments`, `Get-WiHighPrivilegeAppPermissions`, `Get-WiTenantConsentSettings`, `Get-WiBetaRiskyServicePrincipal`, `Get-WiRiskyServicePrincipalTriageReport`

**Remediation:** `New-WiFederatedCredential`, `Add-WiApplicationCertificateCredential`, `Set-WiRiskyServicePrincipalCompromised`, `Clear-WiRiskyServicePrincipalRisk`

**Auth:** `Connect-WiGraph` — delegates to interactive scopes locally; auto-detects Azure workload identity env vars for CI (OIDC service principal via `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE`)

## Required Permissions

**Discovery (read-only):** `Application.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `IdentityRiskyServicePrincipal.Read.All`

**Remediation:** `Application.ReadWrite.All`, `IdentityRiskyServicePrincipal.ReadWrite.All` (beta), Security Administrator role for risk actions

## Local Setup

1. **Install dependencies:** `./scripts/Install-Dependencies.ps1`
2. **Run a scan:** `./scripts/Scan-And-Report.ps1` (artifacts in `./out/`)
3. **Generate HTML report:** `./scripts/Write-ScanReport.ps1 -OutputFolder ./out`

Optional: `./scripts/Bootstrap-WiLab.ps1` seeds dev tenant with test identities.

## Interactive Usage

```powershell
#!/usr/bin/env pwsh
#Requires -Version 7.4

Import-Module ./src/WorkloadIdentityTools/WorkloadIdentityTools.psd1
Connect-WiGraph -TenantId 'your-tenant-id'

# Inventory credentials with risk scores
$inventory = Get-WiApplicationCredentialInventory -All
$inventory | Where-Object { $_.RiskLevel -eq 'High' } | Format-Table

# Identify privileged assignments
Get-WiServicePrincipalPrivilegedAssignments | Out-GridView

# Check risky service principals (beta)
$triage = Get-WiRiskyServicePrincipalTriageReport
$triage.Distribution.ByRiskLevel | Format-Table
```

> **CI/CD Note:** `Connect-WiGraph` auto-detects Azure workload identity environment variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE`) and uses `Connect-MgGraph -EnvironmentVariable` for OIDC authentication. Local runs use interactive delegated scopes.

## Scan Outputs

**Artifacts** (JSON/CSV in `./out/`)
- `credential-inventory.json/csv` — credential details, expiry, risk scores
- `privileged-roles.json/csv` — directory role assignments
- `high-privilege-app-permissions.json/csv` — dangerous app permissions
- `consent-settings.json` — tenant consent policies
- `risky-service-principals.json/csv` — Identity Protection flags (beta)
- `risky-service-principal-triage.json` — risk distribution summary
- `scan-summary.json` — aggregated counts
- `workload-identity-report.html` — formatted dashboard

## Testing

```powershell
Invoke-Pester -Path ./tests/Unit/
```

Pester docs: https://learn.microsoft.com/powershell/scripting/testing/overview?view=powershell-7.4

## CI/CD Setup

For GitHub Actions integration, see [TROUBLESHOOTING-CI.md](TROUBLESHOOTING-CI.md) for complete setup instructions including:
- Granting Graph application permissions to service principal
- Configuring federated credentials for OIDC authentication
- Common authentication errors and solutions

## References

- [Connect-MgGraph](https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0)
- [Azure Identity environment variables](https://learn.microsoft.com/dotnet/api/overview/azure/identity-readme?view=azure-dotnet#environment-variables)
- [Risky service principals (beta)](https://learn.microsoft.com/graph/api/identityprotectionroot-list-riskyserviceprincipals?view=graph-rest-beta)

## License

MIT — Preview/beta Graph APIs subject to change. Test in dev tenants before production.
