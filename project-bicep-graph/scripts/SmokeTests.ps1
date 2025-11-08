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

function Test-StorageAccess {
    [CmdletBinding()] [OutputType([pscustomobject])] param(
        [Parameter(Mandatory)][string]$StorageAccountName
    )
    $result = [pscustomobject]@{ StorageAccountName = $StorageAccountName; Accessible = $false; Error = $null }
    try {
        $keys = Get-AzStorageAccountKey -Name $StorageAccountName -ResourceGroupName (Get-AzResourceGroup | Select-Object -First 1 -ExpandProperty ResourceGroupName) -ErrorAction Stop
        if ($keys) { $result.Accessible = $true }
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
        $secrets = Get-AzKeyVaultSecret -VaultName $VaultName -ErrorAction Stop
        $result.Accessible = $true
        $result.SecretCount = ($secrets | Measure-Object).Count
    }
    catch { $result.Error = $_.Exception.Message }
    return $result
}

function Invoke-EphemeralSmokeTests {
    [CmdletBinding()] [OutputType([pscustomobject])] param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$StorageAccountName,
        [Parameter()][string]$ApiBaseUrl,
        [Parameter()][string]$BearerToken
    )
    $env = Test-EnvContext
    $kv = Test-KeyVaultAccess -VaultName $VaultName
    $st = Test-StorageAccess -StorageAccountName $StorageAccountName
    $apiHealthz = $null
    $apiHealthProtected = $null
    if ($ApiBaseUrl) {
        try {
            $apiHealthz = Invoke-RestMethod -Uri (Join-Path $ApiBaseUrl 'healthz') -Method GET -ErrorAction Stop
        }
        catch { $apiHealthz = [pscustomobject]@{ error = $_.Exception.Message } }
        if ($BearerToken) {
            try {
                $apiHealthProtected = Invoke-RestMethod -Uri (Join-Path $ApiBaseUrl 'health') -Headers @{ Authorization = "Bearer $BearerToken" } -Method GET -ErrorAction Stop
            }
            catch { $apiHealthProtected = [pscustomobject]@{ error = $_.Exception.Message } }
        }
    }
    [pscustomobject]@{
        Environment = $env
        KeyVault    = $kv
        Storage     = $st
        Api         = [pscustomobject]@{ Healthz = $apiHealthz; Health = $apiHealthProtected; BaseUrl = $ApiBaseUrl }
        CompletedAt = (Get-Date).ToString('o')
    }
}

# Example local execution (commented):
# . "$PSScriptRoot/SmokeTests.ps1"
# $out = Invoke-EphemeralSmokeTests -VaultName 'kv-example' -StorageAccountName 'stexample'
# $out | ConvertTo-Json -Depth 5
