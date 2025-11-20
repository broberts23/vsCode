#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Remove lab workload identities created by Bootstrap-WiLab.ps1.

.DESCRIPTION
    Deletes the application registrations and service principals created for
    WorkloadIdentityTools lab demonstrations. The script targets objects by
    name prefix and is intended for dev/test tenants only.

.PARAMETER TenantId
    The Microsoft Entra tenant ID to target.

.PARAMETER Prefix
    Name prefix for lab applications and service principals. Must match the
    prefix used when running Bootstrap-WiLab.ps1. Defaults to 'wi-lab'.

.EXAMPLE
    ./Cleanup-WiLab.ps1 -TenantId '00000000-0000-0000-0000-000000000000'

.EXAMPLE
    ./Cleanup-WiLab.ps1 -TenantId $env:WI_LAB_TENANT_ID -Prefix 'wi-lab' -WhatIf

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $TenantId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]
    $Prefix = 'wi-lab'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Verbose "Connecting to Microsoft Graph for tenant $TenantId"

if (-not (Get-Module -Name Microsoft.Graph.Authentication -ListAvailable)) {
    throw 'Microsoft.Graph PowerShell SDK is required. Run Install-Dependencies.ps1 first.'
}

if ($PSCmdlet.ShouldProcess("Tenant $TenantId", 'Connect-MgGraph')) {
    Connect-MgGraph -TenantId $TenantId -Scopes @('Application.ReadWrite.All','Directory.ReadWrite.All') | Out-Null
}

Write-Verbose "Locating lab applications with prefix '$Prefix'"

$filter = "startsWith(displayName,'$Prefix')"
$apps = Get-MgApplication -Filter $filter -ConsistencyLevel eventual -All -ErrorAction SilentlyContinue

foreach ($app in $apps) {
    if ($PSCmdlet.ShouldProcess("App $($app.DisplayName) ($($app.Id))", 'Remove-MgApplication')) {
        Remove-MgApplication -ApplicationId $app.Id
        Write-Verbose "Removed application $($app.DisplayName) ($($app.Id))"
    }
}

Write-Verbose "Lab cleanup complete for prefix '$Prefix'"
