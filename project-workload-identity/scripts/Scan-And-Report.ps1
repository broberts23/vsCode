#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
<#
.SYNOPSIS
Run a full workload identity scan and generate JSON/CSV outputs.
#>

[CmdletBinding()] Param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter()][string[]]$Scopes = @('Application.Read.All','Directory.Read.All'),
    [Parameter()][string]$OutputPath = './out'
)
Import-Module (Join-Path $PSScriptRoot '../src/WorkloadIdentityTools/WorkloadIdentityTools.psd1')
Connect-WiGraph -Scopes $Scopes -TenantId $TenantId -NoWelcome

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }

Write-Information 'Collecting credential inventory...' -InformationAction Continue
$inventory = Get-WiApplicationCredentialInventory -All
Write-Information 'Collecting privileged role assignments...' -InformationAction Continue
$privRoles = Get-WiServicePrincipalPrivilegedAssignments
Write-Information 'Collecting high privilege app permissions...' -InformationAction Continue
$hiPerms = Get-WiHighPrivilegeAppPermissions
Write-Information 'Collecting consent settings...' -InformationAction Continue
$consent = Get-WiTenantConsentSettings
Write-Information 'Collecting risky service principals (if available)...' -InformationAction Continue
$risky = Get-WiRiskyServicePrincipal
Write-Information 'Collecting beta risky workload triage (if permissions allow)...' -InformationAction Continue
try {
    $riskyTriage = Get-WiRiskyServicePrincipalTriageReport
} catch {
    Write-Verbose "Beta triage unavailable: $($_.Exception.Message)"
    $riskyTriage = $null
}

$summary = [PSCustomObject]@{
    Timestamp = (Get-Date).ToUniversalTime()
    TenantId  = $TenantId
    Counts    = [PSCustomObject]@{
        Credentials = $inventory.Count
        PrivilegedServicePrincipals = $privRoles.Count
        HighPrivilegeApplications   = $hiPerms.Count
        RiskyServicePrincipals      = ($risky | Measure-Object).Count
    }
}

$inventory | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputPath 'credential-inventory.json') -Encoding UTF8
$inventory | Export-Csv -Path (Join-Path $OutputPath 'credential-inventory.csv') -NoTypeInformation
$privRoles | ConvertTo-Json -Depth 4 | Out-File (Join-Path $OutputPath 'privileged-roles.json') -Encoding UTF8
$hiPerms | ConvertTo-Json -Depth 4 | Out-File (Join-Path $OutputPath 'high-privilege-app-permissions.json') -Encoding UTF8
$consent | ConvertTo-Json -Depth 4 | Out-File (Join-Path $OutputPath 'consent-settings.json') -Encoding UTF8
$risky | ConvertTo-Json -Depth 4 | Out-File (Join-Path $OutputPath 'risky-service-principals.json') -Encoding UTF8
$riskyTriage | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputPath 'risky-service-principal-triage.json') -Encoding UTF8
$summary | ConvertTo-Json -Depth 4 | Out-File (Join-Path $OutputPath 'scan-summary.json') -Encoding UTF8

Write-Information "Scan complete. Output saved to $OutputPath" -InformationAction Continue
