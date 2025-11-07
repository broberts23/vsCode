#!/usr/bin/env pwsh
#Requires -Version 7.4
<#!
.SYNOPSIS
Deletes ephemeral PR test users and removes them from the test group.

.DESCRIPTION
ENV inputs:
- GROUP_OBJECT_ID (optional; if provided will remove members first)
- PR_NUMBER (required for name prefix) or USER_PREFIX override

Users created by Create-TestUsers.ps1 follow alias pattern: pr<PR_NUMBER>tester<index><6hex>
We query users with startswith(displayName,'PR <PR_NUMBER> Tester') as a heuristic + startswith(mailNickname,'pr<PR_NUMBER>tester').

Graph references:
- List users: https://learn.microsoft.com/graph/api/user-list?view=graph-rest-beta
- Delete user: https://learn.microsoft.com/graph/api/user-delete?view=graph-rest-beta
Note: Group member removal optional; deleting user implicitly removes membership.
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

$pr = $env:PR_NUMBER
$prefixOverride = $env:USER_PREFIX
if (-not $pr -and -not $prefixOverride) { throw 'PR_NUMBER or USER_PREFIX required.' }
$aliasPrefix = if ($prefixOverride) { $prefixOverride } else { "pr${pr}tester" }
$displayPrefix = if ($prefixOverride) { $prefixOverride } else { "PR $pr Tester" }

$token = Get-GraphToken
$filterNickname = [System.Web.HttpUtility]::UrlEncode("startsWith(mailNickname,'$aliasPrefix')")
$uri = "https://graph.microsoft.com/v1.0/users?`$filter=$filterNickname"
$users = Invoke-Graph -Method GET -Uri $uri -Body $null -Token $token
$deleted = @()
foreach ($u in $users.value) {
  # Extra safety: verify both conditions where possible
  if ($u.mailNickname -like "$aliasPrefix*" -or $u.displayName -like "$displayPrefix*") {
    Invoke-Graph -Method DELETE -Uri "https://graph.microsoft.com/v1.0/users/$($u.id)" -Body $null -Token $token
    $deleted += [pscustomobject]@{ upn = $u.userPrincipalName; id = $u.id }
  }
}
$deleted | ConvertTo-Json -Depth 4