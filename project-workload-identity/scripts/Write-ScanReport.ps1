#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
Generate an HTML workload identity risk report from the JSON outputs created by Scan-And-Report.ps1.

.DESCRIPTION
Reads the structured artifacts (credential inventory, privileged roles, risky service principals, consent settings, etc.) and renders an
accessible HTML dashboard that summarizes the findings, provides contextual explanations for each dataset, and highlights next steps.

The tables follow the accessibility guidance published by MDN (https://developer.mozilla.org/en-US/docs/Learn_web_development/Core/Structuring_content/Table_accessibility)
so that captions, column headers, and semantic grouping remain intact when consumed by assistive technologies.

.PARAMETER OutputFolder
Directory that contains the JSON artifacts. Defaults to the local scripts/out folder when executed directly.

.PARAMETER ReportName
Name of the HTML file that will be created within the output folder. Defaults to workload-identity-report.html.

.EXAMPLE
./Write-ScanReport.ps1 -OutputFolder ./out
#>
[CmdletBinding()]
Param(
    [Parameter()][ValidateNotNullOrEmpty()][string]$OutputFolder = (Join-Path -Path $PSScriptRoot -ChildPath 'out'),
    [Parameter()][ValidateNotNullOrEmpty()][string]$ReportName = 'workload-identity-report.html'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-JsonArtifact {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        [Parameter()][object]$DefaultValue
    )
    $path = Join-Path -Path $OutputFolder -ChildPath $Name
    if (-not (Test-Path -Path $path)) {
        return $DefaultValue
    }
    $raw = Get-Content -Path $path -ErrorAction Stop -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $DefaultValue
    }
    try {
        return $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to parse ${Name}: $($_.Exception.Message)"
        return $DefaultValue
    }
}

function ConvertTo-HtmlEncode {
    Param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

$null = New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
$reportPath = Join-Path -Path $OutputFolder -ChildPath $ReportName

$scanSummary = Get-JsonArtifact -Name 'scan-summary.json' -DefaultValue $null
$credentialInventory = Get-JsonArtifact -Name 'credential-inventory.json' -DefaultValue @()
$privilegedRoles = Get-JsonArtifact -Name 'privileged-roles.json' -DefaultValue @()
$highPrivilegePermissions = Get-JsonArtifact -Name 'high-privilege-app-permissions.json' -DefaultValue @()
$consentSettings = Get-JsonArtifact -Name 'consent-settings.json' -DefaultValue $null
$riskyServicePrincipals = Get-JsonArtifact -Name 'risky-service-principals.json' -DefaultValue @()
$riskyTriage = Get-JsonArtifact -Name 'risky-service-principal-triage.json' -DefaultValue $null

$now = Get-Date

$cards = @()
if ($scanSummary) {
    $cards += @{ Label = 'Credentials Reviewed'; Value = $scanSummary.Counts.Credentials }
    $cards += @{ Label = 'Privileged Role Assignments'; Value = $scanSummary.Counts.PrivilegedServicePrincipals }
    $cards += @{ Label = 'High-Privilege Apps'; Value = $scanSummary.Counts.HighPrivilegeApplications }
    $cards += @{ Label = 'Risky Service Principals'; Value = $scanSummary.Counts.RiskyServicePrincipals }
}
else {
    $cards += @{ Label = 'Report Generated'; Value = $now.ToString('u') }
}

$credentialRows = if ($credentialInventory) {
    $credentialInventory | Sort-Object -Property RiskLevel, DaysUntilExpiry | ForEach-Object {
        $reasons = if ($_.RiskReasons) { ($_.RiskReasons -join ', ') } else { '—' }
        "<tr>
            <td>$(ConvertTo-HtmlEncode $_.DisplayName)</td>
            <td>$(ConvertTo-HtmlEncode $_.ApplicationId)</td>
            <td>$(ConvertTo-HtmlEncode $_.CredentialType)</td>
            <td>$(ConvertTo-HtmlEncode $_.CredentialId)</td>
            <td>$(ConvertTo-HtmlEncode $_.RiskLevel)</td>
            <td>$(ConvertTo-HtmlEncode $reasons)</td>
            <td>$(if ($_.DaysUntilExpiry) { [math]::Round($_.DaysUntilExpiry, 0) } else { '—' })</td>
        </tr>"
    } | Out-String
}
else {
    '<tr><td colspan="7">No workload identity credentials required attention in this scan.</td></tr>'
}

$privilegedRoleRows = if ($privilegedRoles) {
    $privilegedRoles | ForEach-Object {
        "<tr>
            <td>$(ConvertTo-HtmlEncode $_.RoleDisplayName)</td>
            <td>$(ConvertTo-HtmlEncode $_.DisplayName)</td>
            <td>$(ConvertTo-HtmlEncode $_.AppId)</td>
            <td>$(ConvertTo-HtmlEncode $_.ServicePrincipalId)</td>
        </tr>"
    } | Out-String
}
else {
    '<tr><td colspan="4">No privileged directory roles were assigned to application identities.</td></tr>'
}

$highPrivilegeRows = if ($highPrivilegePermissions) {
    $highPrivilegePermissions | ForEach-Object {
        $perms = if ($_.HighPrivilegePermissions) { ($_.HighPrivilegePermissions -join ', ') } else { '—' }
        "<tr>
            <td>$(ConvertTo-HtmlEncode $_.DisplayName)</td>
            <td>$(ConvertTo-HtmlEncode $_.ApplicationId)</td>
            <td>$(ConvertTo-HtmlEncode $perms)</td>
        </tr>"
    } | Out-String
}
else {
    '<tr><td colspan="3">No high-privilege delegated or application permissions were detected.</td></tr>'
}

$riskyRows = if ($riskyServicePrincipals) {
    $riskyServicePrincipals | ForEach-Object {
        "<tr>
            <td>$(ConvertTo-HtmlEncode $_.displayName)</td>
            <td>$(ConvertTo-HtmlEncode $_.appId)</td>
            <td>$(ConvertTo-HtmlEncode $_.riskLevel)</td>
            <td>$(ConvertTo-HtmlEncode $_.riskState)</td>
            <td>$(ConvertTo-HtmlEncode $_.riskDetail)</td>
            <td>$(ConvertTo-HtmlEncode $_.riskLastUpdatedDateTime)</td>
        </tr>"
    } | Out-String
}
else {
    '<tr><td colspan="6">Microsoft Entra ID Protection did not flag any risky service principals during this scan.</td></tr>'
}

$consentDetails = if ($consentSettings -and $consentSettings.DefaultUserRolePermissionsAllowed) {
    $defaults = $consentSettings.DefaultUserRolePermissionsAllowed
    $items = [System.Collections.Generic.List[string]]::new()
    $items.Add("<li><strong>Users can register applications:</strong> $(ConvertTo-HtmlEncode $defaults.AllowedToCreateApps)</li>")
    $items.Add("<li><strong>Users can create security groups:</strong> $(ConvertTo-HtmlEncode $defaults.AllowedToCreateSecurityGroups)</li>")
    $items.Add("<li><strong>Users can create tenants:</strong> $(ConvertTo-HtmlEncode $defaults.AllowedToCreateTenants)</li>")
    $items.Add("<li><strong>Users can read other users:</strong> $(ConvertTo-HtmlEncode $defaults.AllowedToReadOtherUsers)</li>")
    if ($defaults.PermissionGrantPoliciesAssigned) {
        $items.Add("<li><strong>Permission grant policies:</strong> $(ConvertTo-HtmlEncode ($defaults.PermissionGrantPoliciesAssigned -join ', '))</li>")
    }
    $items -join [Environment]::NewLine
}
else {
    '<li>Tenant-level consent settings could not be resolved.</li>'
}

$riskySummary = if ($riskyTriage -and $riskyTriage.Summary) {
    "<ul>
        <li><strong>Total risky identities:</strong> $(ConvertTo-HtmlEncode $riskyTriage.Summary.Total)</li>
        <li><strong>Distribution by level:</strong> $(ConvertTo-HtmlEncode (($riskyTriage.Distribution.ByRiskLevel | ForEach-Object { "$_ ($($_.Count))" }) -join ', '))</li>
        <li><strong>Distribution by state:</strong> $(ConvertTo-HtmlEncode (($riskyTriage.Distribution.ByRiskState | ForEach-Object { "$_ ($($_.Count))" }) -join ', '))</li>
    </ul>"
}
else {
    '<p>No risky service principal telemetry was available for triage.</p>'
}

$cardMarkup = ($cards | ForEach-Object {
    "<article class='card'>
        <p class='label'>$(ConvertTo-HtmlEncode $_.Label)</p>
        <p class='value'>$(ConvertTo-HtmlEncode $_.Value)</p>
    </article>"
}) -join [Environment]::NewLine

$tenantId = if ($scanSummary) { ConvertTo-HtmlEncode $scanSummary.TenantId } else { 'N/A' }
$timestamp = if ($scanSummary) { ConvertTo-HtmlEncode $scanSummary.Timestamp } else { ConvertTo-HtmlEncode $now.ToString('u') }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Workload Identity Risk Report</title>
    <style>
        :root {
            color-scheme: light dark;
            --bg: #f5f7fb;
            --card-bg: #ffffff;
            --border: #d5d8e3;
            --accent: #2563eb;
            font-family: 'Segoe UI', Roboto, sans-serif;
        }
        body {
            background: var(--bg);
            color: #111827;
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }
        header {
            margin-bottom: 1.5rem;
        }
        h1 {
            margin-bottom: 0.25rem;
            font-size: 2rem;
        }
        .meta {
            color: #4b5563;
        }
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1rem;
            box-shadow: 0 8px 20px rgba(15, 23, 42, 0.08);
        }
        .card .label {
            font-size: 0.9rem;
            color: #6b7280;
            margin: 0;
        }
        .card .value {
            font-size: 1.75rem;
            font-weight: 600;
            margin: 0.35rem 0 0;
        }
        section {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 1rem;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 15px 35px rgba(15, 23, 42, 0.08);
        }
        section h2 {
            margin-top: 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            font-size: 0.95rem;
        }
        caption {
            caption-side: top;
            font-weight: 600;
            text-align: left;
            margin-bottom: 0.25rem;
        }
        thead {
            background: #e0ebff;
        }
        th, td {
            border: 1px solid var(--border);
            padding: 0.5rem 0.65rem;
            text-align: left;
        }
        tbody tr:nth-child(even) {
            background: #f9fafb;
        }
        .context {
            margin: 0;
            color: #374151;
        }
        .list-inline {
            padding-left: 1.25rem;
        }
        @media (prefers-color-scheme: dark) {
            body { color: #e5e7eb; }
            .card, section { background: #1f2937; border-color: #374151; }
            table { color: #e5e7eb; }
            thead { background: #374151; }
            tbody tr:nth-child(even) { background: #111827; }
        }
    </style>
</head>
<body>
    <header>
        <h1>Workload Identity Risk Report</h1>
        <p class="meta">Tenant: $tenantId · Generated: $timestamp</p>
    </header>
    <div class="cards">
        $cardMarkup
    </div>
    <section>
        <h2>Scan Overview</h2>
        <p class="context">This summary mirrors the data emitted in <code>scan-summary.json</code> and helps correlate HTML artifacts with the raw machine-readable output.</p>
    </section>
    <section>
        <h2>Credential Inventory</h2>
        <p class="context">Pulled from <code>credential-inventory.json</code>. Each entry highlights workload identity secrets or certificates that violate rotation guidance (long-lived or near expiry) along with recommendations.</p>
        <table>
            <caption>Secrets and certificates that require review</caption>
            <thead>
                <tr>
                    <th scope="col">Application</th>
                    <th scope="col">App Id</th>
                    <th scope="col">Type</th>
                    <th scope="col">Credential Id</th>
                    <th scope="col">Risk Level</th>
                    <th scope="col">Reasons</th>
                    <th scope="col">Days Until Expiry</th>
                </tr>
            </thead>
            <tbody>
                $credentialRows
            </tbody>
        </table>
    </section>
    <section>
        <h2>Privileged Role Assignments</h2>
        <p class="context">Sourced from <code>privileged-roles.json</code>. These service principals hold Microsoft Entra RBAC assignments (for example Global Reader, Privileged Role Administrator) and should be reviewed for least privilege.</p>
        <table>
            <caption>Directory roles granted to workload identities</caption>
            <thead>
                <tr>
                    <th scope="col">Role</th>
                    <th scope="col">Service Principal</th>
                    <th scope="col">App Id</th>
                    <th scope="col">Service Principal Id</th>
                </tr>
            </thead>
            <tbody>
                $privilegedRoleRows
            </tbody>
        </table>
    </section>
    <section>
        <h2>High-Privilege Permissions</h2>
        <p class="context">Derived from <code>high-privilege-app-permissions.json</code>. Applications listed here request or have been granted powerful Microsoft Graph scopes (for example Application.ReadWrite.All). Prioritize conditional access policies and credential hygiene for these identities.</p>
        <table>
            <caption>Applications with impactful Microsoft Graph permissions</caption>
            <thead>
                <tr>
                    <th scope="col">Application</th>
                    <th scope="col">App Id</th>
                    <th scope="col">Permissions</th>
                </tr>
            </thead>
            <tbody>
                $highPrivilegeRows
            </tbody>
        </table>
    </section>
    <section>
        <h2>Tenant Consent & User Capabilities</h2>
        <p class="context">Summarizes <code>consent-settings.json</code> so operators understand who can create applications, security groups, or grant delegated permissions.</p>
        <ul class="list-inline">
            $consentDetails
        </ul>
    </section>
    <section>
        <h2>Risky Service Principals</h2>
        <p class="context">Combines <code>risky-service-principals.json</code> with the enriched triage data from <code>risky-service-principal-triage.json</code>. Use these insights to trigger investigation playbooks or dismissals.</p>
        $riskySummary
        <table>
            <caption>Service principals flagged by Microsoft Entra ID Protection</caption>
            <thead>
                <tr>
                    <th scope="col">Display Name</th>
                    <th scope="col">App Id</th>
                    <th scope="col">Risk Level</th>
                    <th scope="col">Risk State</th>
                    <th scope="col">Detail</th>
                    <th scope="col">Last Updated (UTC)</th>
                </tr>
            </thead>
            <tbody>
                $riskyRows
            </tbody>
        </table>
    </section>
    <footer>
        <p class="meta">Report generated on $($now.ToString('u')). For raw data, inspect the JSON artifacts located in $([System.Net.WebUtility]::HtmlEncode($OutputFolder)).</p>
    </footer>
</body>
</html>
"@

[System.IO.File]::WriteAllText($reportPath, $html, [System.Text.Encoding]::UTF8)
Write-Verbose "Report saved to $reportPath" -Verbose
