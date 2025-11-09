#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
SmokeTests.ps1
Purpose: Placeholder smoke test script to validate ephemeral environment identity & resource access.
Returns: Structured objects (do NOT format output).
#>

function Test-EnvContext {
    [CmdletBinding()] [OutputType([pscustomobject])] param()
    $context = try { Get-AzContext -ErrorAction SilentlyContinue } catch { $null }
    $subscriptionId = $null
    $tenantId = $null
    $accountId = $null
    if ($null -ne $context) {
        # Use safe navigation for nested properties; avoid "$context?" token under StrictMode
        $subscriptionId = $context.Subscription?.Id
        $tenantId = $context.Tenant?.Id
        $accountId = $context.Account?.Id
    }
    [pscustomobject]@{
        SubscriptionId = $subscriptionId
        TenantId       = $tenantId
        Account        = $accountId
        RetrievedAt    = (Get-Date).ToString('o')
        ContextPresent = [bool]$context
    }
}

function New-Url {
    [CmdletBinding()] [OutputType([string])] param(
        [Parameter(Mandatory)][string]$BaseUrl,
        [Parameter(Mandatory)][string]$RelativePath
    )
    $b = $BaseUrl.TrimEnd('/')
    $p = $RelativePath.TrimStart('/')
    return "$b/$p"
}

function Invoke-AzCliJson {
    [CmdletBinding()] [OutputType([object])] param(
        [Parameter(Mandatory)][string]$CommandLine
    )
    # Execute az and parse JSON safely
    $output = & az $CommandLine.Split(' ') 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "az $CommandLine failed: $output"
    }
    try { return $output | ConvertFrom-Json } catch { return $null }
}

function Test-StorageAccess {
    [CmdletBinding()] [OutputType([pscustomobject])] param(
        [Parameter(Mandatory)][string]$StorageAccountName
    )
    $result = [pscustomobject]@{ StorageAccountName = $StorageAccountName; Accessible = $false; Error = $null; ContainerCount = $null }
    try {
        # Use data-plane check via Azure AD: list containers without keys
        $containers = Invoke-AzCliJson -CommandLine "storage container list --account-name $StorageAccountName --auth-mode login -o json"
        $count = if ($containers) { ($containers | Measure-Object).Count } else { 0 }
        $result.ContainerCount = $count
        $result.Accessible = $true
    }
    catch { $result.Error = $_.Exception.Message }
    return $result
}

function Test-KeyVaultAccess {
    [CmdletBinding()] [OutputType([pscustomobject])] param(
        [Parameter(Mandatory)][string]$VaultName
    )
    $result = [pscustomobject]@{ VaultName = $VaultName; Accessible = $false; Error = $null; SecretCount = $null }
    try {
        # Use az CLI data-plane operation with RBAC
        $secrets = Invoke-AzCliJson -CommandLine "keyvault secret list --vault-name $VaultName -o json"
        $result.Accessible = $true
        $result.SecretCount = if ($secrets) { ($secrets | Measure-Object).Count } else { 0 }
    }
    catch { $result.Error = $_.Exception.Message }
    return $result
}

function Invoke-EphemeralSmokeTests {
    [CmdletBinding()] [OutputType([pscustomobject])] param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$StorageAccountName,
        [Parameter()][string]$ApiBaseUrl,
        [Parameter()][string]$RoleBearerToken,
        [Parameter()][string]$TenantBearerToken
    )
    $env = Test-EnvContext
    $kv = Test-KeyVaultAccess -VaultName $VaultName
    $st = Test-StorageAccess -StorageAccountName $StorageAccountName
    $apiHealthz = $null
    $apiHealthProtected = $null
    if ($ApiBaseUrl) {
        $healthzUrl = New-Url -BaseUrl $ApiBaseUrl -RelativePath 'healthz'
        $healthUrl = New-Url -BaseUrl $ApiBaseUrl -RelativePath 'health'
        $attempts = 5
        $delaySec = 3
        for ($i = 1; $i -le $attempts; $i++) {
            try {
                $headers = if ($RoleBearerToken) { @{ Authorization = "Bearer $RoleBearerToken" } } else { @{} }
                $apiHealthz = Invoke-RestMethod -Uri $healthzUrl -Method GET -Headers $headers -ErrorAction Stop
                break
            }
            catch {
                $status = $_.Exception.Response.StatusCode.value__
                if ($i -eq $attempts) { $apiHealthz = [pscustomobject]@{ error = $_.Exception.Message; attempts = $attempts; statusCode = $status } }
                Start-Sleep -Seconds $delaySec
            }
        }
        $tokenToUse = if ($TenantBearerToken) { $TenantBearerToken } else { $RoleBearerToken }
        if ($tokenToUse) {
            for ($i = 1; $i -le $attempts; $i++) {
                try {
                    $apiHealthProtected = Invoke-RestMethod -Uri $healthUrl -Headers @{ Authorization = "Bearer $tokenToUse" } -Method GET -ErrorAction Stop
                    break
                }
                catch {
                    $status = $_.Exception.Response.StatusCode.value__
                    if ($i -eq $attempts) { $apiHealthProtected = [pscustomobject]@{ error = $_.Exception.Message; attempts = $attempts; statusCode = $status } }
                    Start-Sleep -Seconds $delaySec
                }
            }
        }
    }
    $healthzStatus = $null
    if ($apiHealthz -and ($apiHealthz | Get-Member -Name status -MemberType NoteProperty -ErrorAction SilentlyContinue)) {
        $healthzStatus = $apiHealthz.status
    }
    $healthStatus = $null
    if ($apiHealthProtected -and ($apiHealthProtected | Get-Member -Name status -MemberType NoteProperty -ErrorAction SilentlyContinue)) {
        $healthStatus = $apiHealthProtected.status
    }
    $primaryClaims = Decode-JwtClaims -Token $RoleBearerToken
    $alternateClaims = Decode-JwtClaims -Token $TenantBearerToken
    $success = [bool]($kv.Accessible -and $st.Accessible -and ($healthzStatus -eq 'ok') -and ($healthStatus -eq 'ok'))
    [pscustomobject]@{
        Environment = $env
        KeyVault    = $kv
        Storage     = $st
        Api         = [pscustomobject]@{ Healthz = $apiHealthz; Health = $apiHealthProtected; BaseUrl = $ApiBaseUrl; HealthStatus = $healthStatus }
        Token       = [pscustomobject]@{ Role = $primaryClaims; Tenant = $alternateClaims }
        Success     = $success
        CompletedAt = (Get-Date).ToString('o')
    }
}

function Decode-JwtClaims {
    param([string]$Token)
    if (-not $Token) { return $null }
    try {
        $parts = $Token.Split('.')
        if ($parts.Length -lt 2) { return $null }
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } 0 {} default { $payload += '===' } }
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return ($json | ConvertFrom-Json)
    } catch { return $null }
}

# Example local execution (commented):
# . "$PSScriptRoot/SmokeTests.ps1"
# $out = Invoke-EphemeralSmokeTests -VaultName 'kv-example' -StorageAccountName 'stexample'
# $out | ConvertTo-Json -Depth 5
