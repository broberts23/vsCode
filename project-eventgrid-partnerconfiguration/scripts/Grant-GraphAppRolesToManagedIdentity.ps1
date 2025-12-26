#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ManagedIdentityPrincipalId,

    [Parameter(Mandatory = $false)]
    [ValidateSet('User.Read.All', 'Directory.Read.All')]
    [string[]]$AppRoles = @('User.Read.All'),

    [Parameter(Mandatory = $false)]
    [switch]$AsJson
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-AzCliPresent {
    [CmdletBinding()]
    param()

    $az = Get-Command -Name 'az' -ErrorAction SilentlyContinue
    if ($null -eq $az) {
        throw "Azure CLI ('az') not found. Install Azure CLI and run 'az login' first. See https://learn.microsoft.com/cli/azure/install-azure-cli"
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

function Invoke-AzJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
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
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,

        [Parameter(Mandatory = $false)]
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

$null = Invoke-AzJson -Arguments @('account', 'set', '--subscription', $SubscriptionId, '--only-show-errors')

$miServicePrincipalObjectId = $null
if (-not [string]::IsNullOrWhiteSpace($ManagedIdentityPrincipalId)) {
    $miServicePrincipalObjectId = [string]$ManagedIdentityPrincipalId
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
        throw 'Function App has no system-assigned managed identity principalId. Ensure identity is enabled in Bicep (or pass -ManagedIdentityPrincipalId).'
    }

    $miServicePrincipalObjectId = [string]$identity.principalId
}

# Microsoft Graph service principal (multi-tenant) appId
$graphAppId = '00000003-0000-0000-c000-000000000000'
$graphSp = Invoke-GraphJson -Method GET -Url "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId%20eq%20'$graphAppId'&`$select=id,appId,displayName,appRoles"
$graphSpId = $graphSp.value[0].id

if ([string]::IsNullOrWhiteSpace($graphSpId)) {
    throw 'Unable to resolve Microsoft Graph service principal in this tenant.'
}

$graphAppRoles = @($graphSp.value[0].appRoles)

# Existing assignments (idempotency)
$existingAssignments = Invoke-GraphJson -Method GET -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$miServicePrincipalObjectId/appRoleAssignments?`$select=id,resourceId,appRoleId"
$existingForGraph = @($existingAssignments.value | Where-Object { $_.resourceId -eq $graphSpId })

$results = @()
foreach ($roleValue in $AppRoles) {
    $role = $graphAppRoles | Where-Object { $_.value -eq $roleValue -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
    if ($null -eq $role) {
        throw "App role '$roleValue' not found on Microsoft Graph service principal, or not an Application role."
    }

    $already = $existingForGraph | Where-Object { $_.appRoleId -eq $role.id } | Select-Object -First 1
    if ($null -ne $already) {
        $results += [pscustomobject]@{
            role                  = $roleValue
            appRoleId             = $role.id
            graphServicePrincipal = $graphSpId
            managedIdentitySpId   = $miServicePrincipalObjectId
            assignmentId          = $already.id
            status                = 'AlreadyAssigned'
        }
        continue
    }

    $body = [ordered]@{
        principalId = $miServicePrincipalObjectId
        resourceId  = $graphSpId
        appRoleId   = $role.id
    } | ConvertTo-Json -Depth 8

    # Create appRoleAssignment on the managed identity service principal
    $assignment = Invoke-GraphJson -Method POST -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$miServicePrincipalObjectId/appRoleAssignments" -BodyJson $body

    $results += [pscustomobject]@{
        role                  = $roleValue
        appRoleId             = $role.id
        graphServicePrincipal = $graphSpId
        managedIdentitySpId   = $miServicePrincipalObjectId
        assignmentId          = $assignment.id
        status                = 'Created'
    }
}

if ($AsJson.IsPresent) {
    $results | ConvertTo-Json -Depth 16
}
else {
    $results
}
