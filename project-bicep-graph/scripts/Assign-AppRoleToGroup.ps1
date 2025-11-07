#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
Assigns an application role (appRoleId) exposed by a resource service principal to a security group using Microsoft Graph.

.DESCRIPTION
Uses an Azure CLI-acquired Microsoft Graph access token to:
- Resolve the group objectId by display name (or accept GroupId directly)
- Check for an existing app role assignment
- Create the assignment if missing via POST /servicePrincipals/{resourceSpId}/appRoleAssignedTo

Returns the created or existing assignment as a typed PSCustomObject.

References:
- Graph Applications (Bicep): https://learn.microsoft.com/graph/templates/bicep/reference/applications?view=graph-bicep-beta
- Graph Service Principals (Bicep): https://learn.microsoft.com/graph/templates/bicep/reference/serviceprincipals?view=graph-bicep-beta
- Graph API create app role assignment: https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignedto?view=graph-rest-beta
- PowerShell about_ShouldProcess: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_ShouldProcess?view=powershell-7.4
#>


# Input acquisition via environment variables to simplify parsing in constrained environments.
$ResourceServicePrincipalObjectId = $env:RESOURCE_SP_OBJECTID
$AppRoleId = $env:APP_ROLE_ID
$GroupDisplayName = $env:GROUP_DISPLAY_NAME
$GroupObjectId = $env:GROUP_OBJECT_ID
$WhatIf = [bool]::Parse($env:WHATIF  ) 2>$null
$ConfirmFlag = [bool]::Parse($env:CONFIRM ) 2>$null

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


function Get-GraphToken {
    param()
    $result = az account get-access-token --resource-type ms-graph --output json | ConvertFrom-Json
    if (-not $result.accessToken) { throw 'Unable to acquire Microsoft Graph token via Azure CLI.' }
    return $result.accessToken
}

function Invoke-GraphGet {
    param(
        [string]$Uri,
        [string]$Token
    )
    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
    return Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
}

function Invoke-GraphPost {
    param(
        [string]$Uri,
        [object]$Body,
        [string]$Token
    )
    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
    $json = $Body | ConvertTo-Json -Depth 10
    return Invoke-RestMethod -Method Post -Uri $Uri -Headers $headers -Body $json
}

function Resolve-GroupIdByDisplayName {
    param(
        [string]$DisplayName,
        [string]$Token
    )
    # Note: displayName is not guaranteed unique; for ephemeral PR names this should be sufficiently distinct.
    $filter = [System.Web.HttpUtility]::UrlEncode("displayName eq '$DisplayName'")
    $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=$filter"
    $resp = Invoke-GraphGet -Uri $uri -Token $Token
    if (-not $resp.value -or $resp.value.Count -eq 0) { throw "Group '$DisplayName' not found." }
    if ($resp.value.Count -gt 1) { throw "Multiple groups found with displayName '$DisplayName'. Please specify GroupObjectId instead." }
    return $resp.value[0].id
}

function Get-ExistingAssignment {
    param(
        [string]$ResourceSpId,
        [string]$PrincipalId,
        [string]$AppRoleId,
        [string]$Token
    )
    $filter = [System.Web.HttpUtility]::UrlEncode("principalId eq $PrincipalId and appRoleId eq $AppRoleId")
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ResourceSpId/appRoleAssignedTo?`$filter=$filter"
    $resp = Invoke-GraphGet -Uri $uri -Token $Token
    return $resp.value
}

function New-AppRoleAssignment {
    param(
        [string]$ResourceSpId,
        [string]$PrincipalId,
        [string]$AppRoleId,
        [string]$Token
    )
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ResourceSpId/appRoleAssignedTo"
    $body = @{ principalId = $PrincipalId; resourceId = $ResourceSpId; appRoleId = $AppRoleId }
    return Invoke-GraphPost -Uri $uri -Body $body -Token $Token
}

try {
    if (-not $ResourceServicePrincipalObjectId) { throw 'ResourceServicePrincipalObjectId is required.' }
    if (-not $AppRoleId) { throw 'AppRoleId is required.' }
    if (-not $GroupObjectId -and -not $GroupDisplayName) { throw 'Provide GroupObjectId or GroupDisplayName.' }

    $token = Get-GraphToken
    $principalId = if ($GroupObjectId) { $GroupObjectId } else { Resolve-GroupIdByDisplayName -DisplayName $GroupDisplayName -Token $token }

    $shouldProcess = $true
    if ($WhatIf) { Write-Information 'WhatIf: Skipping actual assignment.'; $shouldProcess = $false }
    if ($ConfirmFlag) {
        $response = Read-Host "Confirm assignment of AppRole $AppRoleId to group $principalId? (y/n)"
        if ($response -ne 'y') { Write-Information 'Confirmation declined.'; $shouldProcess = $false }
    }
    if ($shouldProcess) {
        $existing = Get-ExistingAssignment -ResourceSpId $ResourceServicePrincipalObjectId -PrincipalId $principalId -AppRoleId $AppRoleId -Token $token
        if ($existing -and $existing.Count -gt 0) {
            Write-Verbose 'App role assignment already exists.'
            $existing | ForEach-Object { $_ }
        }
        else {
            $created = New-AppRoleAssignment -ResourceSpId $ResourceServicePrincipalObjectId -PrincipalId $principalId -AppRoleId $AppRoleId -Token $token
            $created
        }
    }
}
catch {
    throw
}
