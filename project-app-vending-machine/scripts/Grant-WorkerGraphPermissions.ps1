#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
Grants Microsoft Graph application permissions to the App Vending Machine worker managed identity.

.DESCRIPTION
Use this script when the Bicep Microsoft.Graph/appRoleAssignedTo resources cannot be
deployed because the caller lacks AppRoleAssignment.ReadWrite.All, or when you need to
re-apply consent after rotating the worker identity.

Required Graph application permissions:
- Application.ReadWrite.OwnedBy
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
    [string]$WorkerPrincipalId,

    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GraphAppId = '00000003-0000-0000-c000-000000000000'
$RequiredRoles = @(
    @{
        Value = 'Application.ReadWrite.OwnedBy'
        Id    = '18a4783c-866b-4cc7-a460-3d5e5662c884'
    }
    @{
        Value = 'Policy.Read.All'
        Id    = '246ddfdf-e6c3-4d72-b48f-42b9744a17ce'
    }
    @{
        Value = 'Policy.ReadWrite.ConditionalAccess'
        Id    = '01c0a623-fc9b-48e9-b794-0756f8e8f067'
    }
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

function Resolve-GraphServicePrincipalId {
    param([Parameter(Mandatory = $true)][string]$Token)

    $filter = [System.Uri]::EscapeDataString("appId eq '$GraphAppId'")
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter"
    $response = Invoke-GraphGet -Uri $uri -Token $Token
    if (-not $response.value -or $response.value.Count -eq 0) {
        throw 'Microsoft Graph service principal was not found in this tenant.'
    }
    return $response.value[0].id
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
$graphSpId = Resolve-GraphServicePrincipalId -Token $token

foreach ($role in $RequiredRoles) {
    $existing = Get-ExistingAssignment `
        -ResourceSpId $graphSpId `
        -PrincipalId $WorkerPrincipalId `
        -AppRoleId $role.Id `
        -Token $token

    if ($existing) {
        Write-Host "Already assigned: $($role.Value)"
        continue
    }

    if ($WhatIf) {
        Write-Host "WhatIf: would assign $($role.Value) ($($role.Id)) to principal $WorkerPrincipalId"
        continue
    }

    if ($PSCmdlet.ShouldProcess($WorkerPrincipalId, "Assign Graph app role $($role.Value)")) {
        $body = @{
            principalId = $WorkerPrincipalId
            resourceId  = $graphSpId
            appRoleId   = $role.Id
        }
        $assignment = Invoke-GraphPost `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphSpId/appRoleAssignedTo" `
            -Body $body `
            -Token $token
        Write-Host "Assigned: $($role.Value) (assignmentId=$($assignment.id))"
    }
}

Write-Host 'Worker Graph permission grant complete.'
