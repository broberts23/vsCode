#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Grants Exchange Online permissions to the Function App managed identity.

.DESCRIPTION
    Idempotently assigns Exchange.ManageAsApp on the Office 365 Exchange Online
    resource via Microsoft Graph, then registers the identity for Exchange RBAC
    for Applications and assigns View-Only Configuration (covers Get-AcceptedDomain).

    Requires:
    - Azure CLI logged in (az login)
    - An existing Connect-ExchangeOnline session as an Exchange admin

.PARAMETER SubscriptionId
    Azure subscription containing the Function App.

.PARAMETER ResourceGroupName
    Resource group of the Function App.

.PARAMETER FunctionAppName
    Name of the Function App with a system-assigned managed identity.

.PARAMETER ManagedIdentityPrincipalId
    Optional object ID override. When omitted, resolved from the Function App.

.PARAMETER ExchangeRole
    Exchange management role to assign. Default: View-Only Configuration.

.EXAMPLE
    Connect-ExchangeOnline -Organization contoso.onmicrosoft.com
    ./Grant-ExchangeOnlinePermissions.ps1 `
      -SubscriptionId 00000000-0000-0000-0000-000000000000 `
      -ResourceGroupName rg-exomi-dev `
      -FunctionAppName exomi-func-dev-abc123

.LINK
    https://learn.microsoft.com/powershell/exchange/connect-exo-powershell-managed-identity
    https://learn.microsoft.com/exchange/permissions-exo/application-rbac
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$FunctionAppName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ManagedIdentityPrincipalId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExchangeRole = 'View-Only Configuration',

    [Parameter()]
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Office 365 Exchange Online resource appId (same in every tenant)
$script:ExchangeOnlineAppId = '00000002-0000-0ff1-ce00-000000000000'
# Exchange.ManageAsApp app role Id (same in every tenant)
$script:ExchangeManageAsAppRoleId = 'dc50a0fb-09a3-484d-be87-e023b12c6440'

function Assert-AzCliPresent {
    [CmdletBinding()]
    param()

    $az = Get-Command -Name 'az' -ErrorAction SilentlyContinue
    if ($null -eq $az) {
        throw "Azure CLI ('az') not found. Install Azure CLI and run 'az login' first."
    }
}

function Assert-AzLogin {
    [CmdletBinding()]
    param()

    $raw = & az account show --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Not logged into Azure CLI. Run 'az login' first. Details: $raw"
    }
}

function Assert-ExchangeOnlineSession {
    [CmdletBinding()]
    param()

    $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $connection) {
        throw @"
No active Exchange Online session. Connect as an Exchange admin first, for example:

  Connect-ExchangeOnline -Organization contoso.onmicrosoft.com

Then re-run this script.
"@
    }

    Write-Host "Using Exchange Online session for organization: $($connection.Organization)" -ForegroundColor Cyan
}

function Invoke-AzJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Arguments
    )

    $raw = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "az command failed: az $($Arguments -join ' ') :: $raw"
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }

    return ($raw | ConvertFrom-Json -Depth 64)
}

function Invoke-GraphJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,

        [Parameter()]
        [string]$BodyJson
    )

    $args = @('rest', '--method', $Method, '--url', $Url)
    if (-not [string]::IsNullOrWhiteSpace($BodyJson)) {
        $args += @('--headers', 'Content-Type=application/json', '--body', $BodyJson)
    }

    return (Invoke-AzJson -Arguments $args)
}

Assert-AzCliPresent
Assert-AzLogin
Assert-ExchangeOnlineSession

$null = Invoke-AzJson -Arguments @('account', 'set', '--subscription', $SubscriptionId, '--only-show-errors')

$miObjectId = $null
$miAppId = $null
$miDisplayName = $null

if (-not [string]::IsNullOrWhiteSpace($ManagedIdentityPrincipalId)) {
    $miObjectId = [string]$ManagedIdentityPrincipalId
}
else {
    $identity = Invoke-AzJson -Arguments @(
        'functionapp', 'identity', 'show',
        '--resource-group', $ResourceGroupName,
        '--name', $FunctionAppName,
        '--only-show-errors',
        '-o', 'json'
    )

    if ([string]::IsNullOrWhiteSpace($identity.principalId)) {
        throw 'Function App has no system-assigned managed identity principalId. Ensure identity is enabled in Bicep.'
    }

    $miObjectId = [string]$identity.principalId
}

$miSp = Invoke-GraphJson -Method GET -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$miObjectId`?`$select=id,appId,displayName"
$miAppId = [string]$miSp.appId
$miDisplayName = [string]$miSp.displayName

if ([string]::IsNullOrWhiteSpace($miAppId)) {
    throw "Unable to resolve appId for managed identity object Id $miObjectId."
}

Write-Host "Managed identity: $miDisplayName (objectId=$miObjectId, appId=$miAppId)" -ForegroundColor Cyan

$results = [System.Collections.Generic.List[object]]::new()

# --- Entra: Exchange.ManageAsApp ---
$exoSp = Invoke-GraphJson -Method GET -Url "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId%20eq%20'$script:ExchangeOnlineAppId'&`$select=id,appId,displayName"
$exoSpId = [string]$exoSp.value[0].id
if ([string]::IsNullOrWhiteSpace($exoSpId)) {
    throw 'Unable to resolve Office 365 Exchange Online service principal in this tenant.'
}

$existingAssignments = Invoke-GraphJson -Method GET -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$miObjectId/appRoleAssignments?`$select=id,resourceId,appRoleId"
$existingExo = @($existingAssignments.value | Where-Object {
        $_.resourceId -eq $exoSpId -and $_.appRoleId -eq $script:ExchangeManageAsAppRoleId
    })

if ($existingExo.Count -gt 0) {
    $results.Add([pscustomobject]@{
            step         = 'Exchange.ManageAsApp'
            status       = 'AlreadyAssigned'
            assignmentId = $existingExo[0].id
            resourceId   = $exoSpId
        })
}
else {
    $body = [ordered]@{
        principalId = $miObjectId
        resourceId  = $exoSpId
        appRoleId   = $script:ExchangeManageAsAppRoleId
    } | ConvertTo-Json -Depth 8

    $assignment = Invoke-GraphJson -Method POST -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$miObjectId/appRoleAssignments" -BodyJson $body
    $results.Add([pscustomobject]@{
            step         = 'Exchange.ManageAsApp'
            status       = 'Created'
            assignmentId = $assignment.id
            resourceId   = $exoSpId
        })
}

# --- Exchange Online: service principal + View-Only Configuration ---
$exoServicePrincipal = Get-ServicePrincipal -Identity $miObjectId -ErrorAction SilentlyContinue
if ($null -eq $exoServicePrincipal) {
    $exoServicePrincipal = New-ServicePrincipal -AppId $miAppId -ObjectId $miObjectId -DisplayName $miDisplayName
    $results.Add([pscustomobject]@{
            step   = 'New-ServicePrincipal'
            status = 'Created'
            appId  = $miAppId
        })
}
else {
    $results.Add([pscustomobject]@{
            step   = 'New-ServicePrincipal'
            status = 'AlreadyExists'
            appId  = $miAppId
        })
}

$existingRole = Get-ManagementRoleAssignment -RoleAssignee $miObjectId -Role $ExchangeRole -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($null -ne $existingRole) {
    $results.Add([pscustomobject]@{
            step   = 'ManagementRoleAssignment'
            status = 'AlreadyAssigned'
            role   = $ExchangeRole
            name   = $existingRole.Name
        })
}
else {
    $roleAssignment = New-ManagementRoleAssignment -App $miObjectId -Role $ExchangeRole
    $results.Add([pscustomobject]@{
            step   = 'ManagementRoleAssignment'
            status = 'Created'
            role   = $ExchangeRole
            name   = $roleAssignment.Name
        })
}

if ($AsJson.IsPresent) {
    $results | ConvertTo-Json -Depth 16
}
else {
    $results
}
