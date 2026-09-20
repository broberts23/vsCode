#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
Grants Microsoft Graph application permissions to the App Vending Machine worker managed identity.

.DESCRIPTION
Use this script when the Bicep Microsoft.Graph/appRoleAssignedTo resources cannot be
deployed because the caller lacks AppRoleAssignment.ReadWrite.All, or when you need to
re-apply consent after rotating the worker identity.

Required Graph application permissions (resolved by value from the Graph SP):
- Application.ReadWrite.OwnedBy
- Application.Read.All (required when CA policies target specific applications)
- Policy.Read.All
- Policy.ReadWrite.ConditionalAccess

.PARAMETER WorkerPrincipalId
Object ID (principal ID) of the worker user-assigned managed identity.

.PARAMETER WhatIf
Preview assignments without writing to Graph.

.EXAMPLE
./scripts/Grant-WorkerGraphPermissions.ps1 -WorkerPrincipalId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$WorkerPrincipalId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GraphAppId = '00000003-0000-0000-c000-000000000000'
$RequiredRoleValues = @(
    'Application.ReadWrite.OwnedBy'
    'Application.Read.All'
    'Policy.Read.All'
    'Policy.ReadWrite.ConditionalAccess'
)

function Get-GraphToken {
    $result = az account get-access-token --resource-type ms-graph --output json | ConvertFrom-Json
    if (-not $result.accessToken) {
        throw 'Unable to acquire a Microsoft Graph token via Azure CLI. Run az login first.'
    }
    return $result.accessToken
}

function Invoke-GraphGet {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Token
    )
    $headers = @{
        Authorization  = "Bearer $Token"
        'Content-Type' = 'application/json'
    }
    return Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
}

function Invoke-GraphPost {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)]$Body,
        [Parameter(Mandatory = $true)][string]$Token
    )
    $headers = @{
        Authorization  = "Bearer $Token"
        'Content-Type' = 'application/json'
    }
    $json = $Body | ConvertTo-Json -Depth 8
    return Invoke-RestMethod -Method Post -Uri $Uri -Headers $headers -Body $json
}

function Resolve-GraphServicePrincipal {
    param([Parameter(Mandatory = $true)][string]$Token)

    $filter = [System.Uri]::EscapeDataString("appId eq '$GraphAppId'")
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter"
    $response = Invoke-GraphGet -Uri $uri -Token $Token
    if (-not $response.value -or $response.value.Count -eq 0) {
        throw 'Microsoft Graph service principal was not found in this tenant.'
    }
    return $response.value[0]
}

function Resolve-AppRoleId {
    param(
        [Parameter(Mandatory = $true)]$GraphSp,
        [Parameter(Mandatory = $true)][string]$RoleValue
    )
    $role = $GraphSp.appRoles | Where-Object { $_.value -eq $RoleValue } | Select-Object -First 1
    if (-not $role) {
        throw "Graph app role '$RoleValue' was not found on the Microsoft Graph service principal."
    }
    return $role.id
}

function Get-ExistingAssignment {
    param(
        [Parameter(Mandatory = $true)][string]$ResourceSpId,
        [Parameter(Mandatory = $true)][string]$PrincipalId,
        [Parameter(Mandatory = $true)][string]$AppRoleId,
        [Parameter(Mandatory = $true)][string]$Token
    )

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ResourceSpId/appRoleAssignedTo"
    $assignments = @()
    $response = Invoke-GraphGet -Uri $uri -Token $Token
    if ($response.value) {
        $assignments += $response.value
    }

    $nextLink = $null
    if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
        $nextLink = $response.'@odata.nextLink'
    }
    while ($nextLink) {
        $response = Invoke-GraphGet -Uri $nextLink -Token $Token
        if ($response.value) {
            $assignments += $response.value
        }
        if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $nextLink = $response.'@odata.nextLink'
        }
        else {
            $nextLink = $null
        }
    }

    return $assignments | Where-Object {
        $_.principalId -eq $PrincipalId -and $_.appRoleId -eq $AppRoleId
    }
}

$token = Get-GraphToken
$graphSp = Resolve-GraphServicePrincipal -Token $token
$graphSpId = $graphSp.id

foreach ($roleValue in $RequiredRoleValues) {
    $appRoleId = Resolve-AppRoleId -GraphSp $graphSp -RoleValue $roleValue
    Write-Host "Resolved $roleValue -> $appRoleId"

    $existing = Get-ExistingAssignment `
        -ResourceSpId $graphSpId `
        -PrincipalId $WorkerPrincipalId `
        -AppRoleId $appRoleId `
        -Token $token

    if ($existing) {
        Write-Host "Already assigned: $roleValue"
        continue
    }

    if ($WhatIfPreference) {
        Write-Host "WhatIf: would assign $roleValue ($appRoleId) to principal $WorkerPrincipalId"
        continue
    }

    if ($PSCmdlet.ShouldProcess($WorkerPrincipalId, "Assign Graph app role $roleValue")) {
        $body = @{
            principalId = $WorkerPrincipalId
            resourceId  = $graphSpId
            appRoleId   = $appRoleId
        }
        $assignment = Invoke-GraphPost `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphSpId/appRoleAssignedTo" `
            -Body $body `
            -Token $token
        Write-Host "Assigned: $roleValue (assignmentId=$($assignment.id))"
    }
}

Write-Host 'Worker Graph permission grant complete.'
