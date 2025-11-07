#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
Cleans up Microsoft Graph objects for an ephemeral PR environment: tester group, app role assignments, service principal, and application.
Test users are removed earlier by Delete-TestUsers.ps1; resource group deletion handles Azure resources.

.DESCRIPTION
Inputs (env or parameters):
  ENV_OUTPUTS_PATH              Path to env-outputs.json (contains appObjectId, servicePrincipalObjectId, testGroupObjectId)
  APP_OBJECT_ID                 Override application objectId
  SERVICE_PRINCIPAL_OBJECT_ID   Override service principal objectId (resource API service principal)
  TEST_GROUP_OBJECT_ID          Override test group objectId
Process:
  1. Resolve identifiers.
  2. Delete app role assignments (group + runner application) referencing the resource service principal.
  3. Delete group.
  4. Delete service principal.
  5. Delete application.
Returns JSON summary of deletion operations (type, id, status, error).

REFERENCES
  Delete application: https://learn.microsoft.com/graph/api/application-delete?view=graph-rest-1.0
  Delete service principal: https://learn.microsoft.com/graph/api/serviceprincipal-delete?view=graph-rest-1.0
  Delete group: https://learn.microsoft.com/graph/api/group-delete?view=graph-rest-1.0
  App role assignment removal: https://learn.microsoft.com/graph/api/serviceprincipal-delete-approleassignedto?view=graph-rest-1.0
  Access tokens & Graph: https://learn.microsoft.com/azure/active-directory/develop/access-tokens
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
    [string]$EnvOutputsPath = $env:ENV_OUTPUTS_PATH,
    [string]$AppObjectId = $env:APP_OBJECT_ID,
    [string]$ServicePrincipalObjectId = $env:SERVICE_PRINCIPAL_OBJECT_ID,
    [string]$TestGroupObjectId = $env:TEST_GROUP_OBJECT_ID
)

function Get-GraphToken { (az account get-access-token --resource-type ms-graph --output json | ConvertFrom-Json).accessToken }
function Invoke-GraphDelete { param([string]$Uri, [string]$Token) $h = @{Authorization = "Bearer $Token" }; Invoke-RestMethod -Method DELETE -Uri $Uri -Headers $h }
function Invoke-GraphGet { param([string]$Uri, [string]$Token) $h = @{Authorization = "Bearer $Token" }; Invoke-RestMethod -Method GET -Uri $Uri -Headers $h }

if ($EnvOutputsPath -and (Test-Path $EnvOutputsPath)) {
    $o = Get-Content $EnvOutputsPath | ConvertFrom-Json
    if (-not $AppObjectId) { $AppObjectId = $o.appObjectId.value }
    if (-not $ServicePrincipalObjectId) { $ServicePrincipalObjectId = $o.servicePrincipalObjectId.value }
    if (-not $TestGroupObjectId) { $TestGroupObjectId = $o.testGroupObjectId.value }
}

$token = Get-GraphToken
$summary = @()
function Remove-AppRoleAssignmentsForPrincipals {
    param([string]$ResourceSpId, [string[]]$PrincipalIds)
    if (-not $ResourceSpId -or -not $PrincipalIds -or $PrincipalIds.Count -eq 0) { return }
    # Graph does not support OR in appRoleAssignedTo filter reliably; fetch all then filter client-side.
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ResourceSpId/appRoleAssignedTo"
    try {
        $resp = Invoke-GraphGet -Uri $uri -Token $token
        foreach ($a in $resp.value) {
            if ($PrincipalIds -contains $a.principalId) {
                $delUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ResourceSpId/appRoleAssignedTo/$($a.id)"
                $item = [pscustomobject]@{ type = 'AppRoleAssignment'; id = $a.id; principalId = $a.principalId; status = 'Skipped'; error = $null }
                try { Invoke-GraphDelete -Uri $delUri -Token $token; $item.status = 'Deleted' } catch { $item.status = 'Error'; $item.error = $_.Exception.Message }
                $summary += $item
            }
        }
    }
    catch {
        $summary += [pscustomobject]@{ type = 'AppRoleAssignmentList'; id = $ResourceSpId; status = 'Error'; error = $_.Exception.Message }
    }
}

function Remove-GraphObjectSafe {
    param([string]$Type, [string]$Id, [string]$UriTemplate)
    if (-not $Id) { return }
    $uri = $UriTemplate -f $Id
    $item = [pscustomobject]@{ type = $Type; id = $Id; status = 'Skipped'; error = $null }
    try {
        Invoke-GraphDelete -Uri $uri -Token $token
        $item.status = 'Deleted'
    }
    catch {
        $item.status = 'Error'
        $item.error = $_.Exception.Message
    }
    $summary += $item
}

# Attempt app role assignment removal first (group + runner) before deleting principals.
Remove-AppRoleAssignmentsForPrincipals -ResourceSpId $ServicePrincipalObjectId -PrincipalIds @($TestGroupObjectId, $ServicePrincipalObjectId)  # Include SP itself if any self-assignment patterns used

# Order: group -> service principal -> application (avoid orphan references warnings)
Remove-GraphObjectSafe -Type 'Group' -Id $TestGroupObjectId -UriTemplate 'https://graph.microsoft.com/v1.0/groups/{0}'
Remove-GraphObjectSafe -Type 'ServicePrincipal' -Id $ServicePrincipalObjectId -UriTemplate 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}'
Remove-GraphObjectSafe -Type 'Application' -Id $AppObjectId -UriTemplate 'https://graph.microsoft.com/v1.0/applications/{0}'

$summary | ConvertTo-Json -Depth 5
