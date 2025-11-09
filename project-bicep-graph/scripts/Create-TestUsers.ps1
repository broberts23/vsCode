#!/usr/bin/env pwsh
#Requires -Version 7.4
<#!
.SYNOPSIS
Creates ephemeral test users and adds them to a specified group using Microsoft Graph.

.DESCRIPTION
Inputs via environment variables for CI friendliness:
- GROUP_OBJECT_ID: ObjectId of the target Microsoft Entra security group
- USER_COUNT: Number of users to create (default 2)
- PR_NUMBER: Pull Request number for naming
- TENANT_DOMAIN: Optional tenant UPN domain; if not provided, discovers default verified domain

Outputs a JSON array to stdout with properties: upn, id, password.

Graph references:
- Add user: https://learn.microsoft.com/graph/api/user-post-users?view=graph-rest-beta
- Add group member: https://learn.microsoft.com/graph/api/group-post-members?view=graph-rest-1.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-GraphToken {
    $result = az account get-access-token --resource-type ms-graph --output json | ConvertFrom-Json
    if (-not $result.accessToken) { throw 'Unable to acquire Microsoft Graph token via Azure CLI.' }
    return $result.accessToken
}

function Invoke-Graph {
    param(
        [string]$Method,
        [string]$Uri,
        [object]$Body,
        [string]$Token
    )
    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
    if ($null -ne $Body) { $Body = $Body | ConvertTo-Json -Depth 10 }
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $Body
}

function Get-DefaultDomain {
    param([string]$Token)
    $org = Invoke-Graph -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains' -Token $Token -Body $null
    foreach ($d in $org.value[0].verifiedDomains) { if ($d.isDefault) { return $d.name } }
    throw 'Default verified domain not found.'
}

function New-RandomPassword {
    param([int]$Length = 16)
    $bytes = New-Object byte[] ($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    # base64 may include non-allowed chars, filter to a safe set
    $generated = [Convert]::ToBase64String($bytes).Replace('=', '').Replace('+', 'A').Replace('/', 'B')
    return $generated.Substring(0, [Math]::Min($generated.Length, $Length)) + '1a!'
}

function New-TestUser {
    param(
        [string]$Upn,
        [string]$DisplayName,
        [string]$MailNickname,
        [SecureString]$SecurePassword,
        [string]$Token
    )
    # Convert SecureString to plaintext for Graph payload (must be sent as JSON field)
    $plainPassword = ([System.Net.NetworkCredential]::new('', $SecurePassword)).Password
    $body = @{
        accountEnabled    = $true
        displayName       = $DisplayName
        mailNickname      = $MailNickname
        userPrincipalName = $Upn
        passwordProfile   = @{ forceChangePasswordNextSignIn = $false; password = $plainPassword }
        department        = 'ephemeral-pr'
        jobTitle          = 'ephemeral-pr-user'
    }
    return Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' -Token $Token -Body $body
}

function Add-GroupMember {
    param(
        [string]$GroupId,
        [string]$MemberObjectId,
        [string]$Token
    )
    $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$MemberObjectId" }
    # Use literal $ref segment; PowerShell tries to treat $ref as a variable inside double quotes.
    $memberRefUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref"
    return Invoke-Graph -Method POST -Uri $memberRefUri -Token $Token -Body $body
}

$groupId = $env:GROUP_OBJECT_ID
if (-not $groupId) { throw 'GROUP_OBJECT_ID is required.' }
$count = [int]::TryParse($env:USER_COUNT, [ref]0); if (-not $count) { $count = 2 } else { $count = [int]$env:USER_COUNT }
$pr = $env:PR_NUMBER; if (-not $pr) { $pr = '0' }

$token = Get-GraphToken
$domain = if ($env:TENANT_DOMAIN) { $env:TENANT_DOMAIN } else { Get-DefaultDomain -Token $token }
$results = @()

for ($i = 1; $i -le $count; $i++) {
    $suffix = ([System.Guid]::NewGuid().ToString('N')).Substring(0, 6)
    $alias = "pr${pr}tester${i}${suffix}"
    $upn = "$alias@$domain"
    $display = "PR $pr Tester $i"
    $generatedPassword = New-RandomPassword -Length 20 | ConvertTo-SecureString -AsPlainText -Force
    $user = New-TestUser -Upn $upn -DisplayName $display -MailNickname $alias -SecurePassword $generatedPassword -Token $token
    Add-GroupMember -GroupId $groupId -MemberObjectId $user.id -Token $token | Out-Null
    # Store plaintext password in results for artifact (avoid console output later)
    $plainOut = ([System.Net.NetworkCredential]::new('', $generatedPassword)).Password
    $results += [pscustomobject]@{ upn = $upn; id = $user.id; password = $plainOut }
}

$results | ConvertTo-Json -Depth 5
