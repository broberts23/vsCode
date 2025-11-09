#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
Deletes ephemeral PR test users using recorded object IDs or group membership rather than fragile displayName/mailNickname heuristics.

.DESCRIPTION
Inputs (environment variables):
  GROUP_OBJECT_ID  - Security group objectId containing ephemeral users (optional but recommended)
  PR_NUMBER        - PR number (informational only; no longer used for filtering)

Process:
  1. If test-users.json artifact present, parse user objectIds and delete directly.
  2. Else if GROUP_OBJECT_ID provided, enumerate group members and delete all user objects returned (assumes dedicated ephemeral group per PR).
  3. Else, exit with message (cannot safely determine users).

Outputs JSON array: upn, id (objectId), status, error.

Graph references:
  List group members: https://learn.microsoft.com/graph/api/group-list-members?view=graph-rest-1.0
  Delete user: https://learn.microsoft.com/graph/api/user-delete?view=graph-rest-1.0
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-GraphToken { (az account get-access-token --resource-type ms-graph --output json | ConvertFrom-Json).accessToken }
function Invoke-Graph {
  param([string]$Method, [string]$Uri, [object]$Body, [string]$Token)
  $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
  $json = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 10 } else { $null }
  Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json 
}

$groupId = $env:GROUP_OBJECT_ID
$testUsersPath = 'test-users.json'
$token = Get-GraphToken
$results = @()

function Remove-UserById {
  param([string]$UserId, [string]$Upn)
  $item = [pscustomobject]@{ upn = $Upn; id = $UserId; status = 'Skipped'; error = $null }
  try {
    Invoke-Graph -Method DELETE -Uri "https://graph.microsoft.com/v1.0/users/$UserId" -Body $null -Token $token
    $item.status = 'Deleted'
  } catch { $item.status = 'Error'; $item.error = $_.Exception.Message }
  $results += $item
}

if (Test-Path $testUsersPath) {
  $raw = Get-Content $testUsersPath -Raw | ConvertFrom-Json
  if ($raw -is [System.Array]) {
    foreach ($u in $raw) { if ($u.id) { Remove-UserById -UserId $u.id -Upn $u.upn } }
  } else {
    if ($raw.users) { foreach ($u in $raw.users) { if ($u.id) { Remove-UserById -UserId $u.id -Upn $u.upn } } }
  }
}
elseif ($groupId) {
  # Enumerate group members and delete each user (assumes dedicated ephemeral group)
  $membersUri = "https://graph.microsoft.com/v1.0/groups/$groupId/members?`$select=id,userPrincipalName"
  try {
    $members = Invoke-Graph -Method GET -Uri $membersUri -Body $null -Token $token
    foreach ($m in $members.value) { if ($m.id) { Remove-UserById -UserId $m.id -Upn $m.userPrincipalName } }
  } catch {
    $results += [pscustomobject]@{ upn = $null; id = $groupId; status = 'GroupMembersError'; error = $_.Exception.Message }
  }
} else {
  $results += [pscustomobject]@{ upn = $null; id = $null; status = 'NoAction'; error = 'No test-users artifact or group objectId available.' }
}

$results | ConvertTo-Json -Depth 4