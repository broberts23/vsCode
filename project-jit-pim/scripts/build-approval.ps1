#!/usr/bin/env pwsh
#Requires -Version 7.4

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Inputs via env:
# ROLE_IDS, RESOURCE_IDS, SUBSCRIPTION_ID, VAULT_NAME, GITHUB_WORKSPACE, GITHUB_OUTPUT, ASSIGNEE_OBJECT_ID, VAULT_RESOURCE_ID

$workspace = $env:GITHUB_WORKSPACE
if (-not $workspace) { throw 'GITHUB_WORKSPACE environment variable is required.' }

$modulePath = Join-Path $workspace 'project-jit-pim/scripts/PimAutomation.psm1'
Import-Module -Name $modulePath -Force

$subscriptionId = $env:SUBSCRIPTION_ID

$roleIdsJson = if ($env:ROLE_IDS) { $env:ROLE_IDS } else { '[]' }
$resourceIdsJson = if ($env:RESOURCE_IDS) { $env:RESOURCE_IDS } else { '[]' }

$pairs = Resolve-PimRoleResourcePairs -RoleIdsJson $roleIdsJson -ResourceIdsJson $resourceIdsJson -SubscriptionId $subscriptionId

# Build table
$table = "| RoleId | RoleName | ResourceId | ResourceName | ResourceType | RequestId |`n|---|---|---|---|---|---|`n"
$requests = @()

foreach ($pair in $pairs) {
  $roleId = $pair.RoleId; $resourceId = $pair.ResourceId
  $req = New-PimActivationRequest -RoleId $roleId -ResourceId $resourceId -Justification 'CI requested activation'
  $requests += $req

  # Resolve role name and resource details (best-effort)
  $roleName = $roleId
  try {
    $rj = $null
    if ($roleId -match '^/') {
      $rjJson = az role definition show --id $roleId -o json 2>$null
    }
    elseif ($roleId -match '^[0-9a-fA-F\-]{36}$') {
      if (-not [string]::IsNullOrEmpty($subscriptionId)) {
        $fqId = "/subscriptions/$subscriptionId/providers/Microsoft.Authorization/roleDefinitions/$roleId"
        $rjJson = az role definition show --id $fqId -o json 2>$null
      }
      else {
        $rjJson = az role definition list --query "[?roleName=='$roleId' || name=='$roleId'] | [0]" -o json 2>$null
      }
    }
    else {
      $rjJson = az role definition list --name "$roleId" -o json 2>$null
      if (-not $rjJson) { $rjJson = az role definition list --query "[?contains(roleName, '$roleId')] | [0]" -o json 2>$null }
    }
    if ($rjJson) { $rj = $rjJson | ConvertFrom-Json } else { $rj = $null }
    if ($rj -and $rj.roleName) { $roleName = $rj.roleName } elseif ($rj -and $rj.properties -and $rj.properties.roleName) { $roleName = $rj.properties.roleName }
  }
  catch { $rj = $null }

  $resName = $resourceId; $resType = ''
  try {
    $resj = az resource show --ids $resourceId -o json 2>$null | ConvertFrom-Json
    if ($resj) { $resName = $resj.name; $resType = $resj.type }
  }
  catch { }

  $escape = { param($s) if ($null -eq $s) { return '``' } else { return ('`' + ($s -replace '\|', '\\|') + '`') } }
  $rIdCell = & $escape $roleId
  $rNameCell = & $escape $roleName
  $resIdCell = & $escape $resourceId
  $resNameCell = & $escape $resName
  $resTypeCell = & $escape $resType

  $reqId = $req.requestId -or $req.id -or ([guid]::NewGuid()).Guid
  $reqIdCell = & $escape $reqId
  $table += "| $rIdCell | $rNameCell | $resIdCell | $resNameCell | $resTypeCell | $reqIdCell |`n"
}

# Export outputs
if ($env:GITHUB_OUTPUT) {
  Add-Content -Path $env:GITHUB_OUTPUT -Value "approvalTable<<EOF"
  Add-Content -Path $env:GITHUB_OUTPUT -Value $table
  Add-Content -Path $env:GITHUB_OUTPUT -Value "EOF"
  Add-Content -Path $env:GITHUB_OUTPUT -Value "assignee=$($env:ASSIGNEE_OBJECT_ID)"
  Add-Content -Path $env:GITHUB_OUTPUT -Value "vault=$($env:VAULT_RESOURCE_ID)"
}
else {
  Write-Output "approvalTable:"; Write-Output $table
  Write-Output "assignee: $env:ASSIGNEE_OBJECT_ID"; Write-Output "vault: $env:VAULT_RESOURCE_ID"
}

Write-Output "::set-output name=approvalTable::$table"
