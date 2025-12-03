#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    PowerShell profile for Azure Function App initialization
.DESCRIPTION
    Executes once per PowerShell worker instance when the function app starts.
    Used for global configuration and module imports.
.LINK
    https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell#powershell-profile
#>

# Retrieve AD service account credentials from Key Vault using Managed Identity
# Reference: https://learn.microsoft.com/azure/key-vault/general/overview
$global:ADServiceCredential = $null

if ($env:MSI_ENDPOINT -and $env:KEY_VAULT_URI) {
    Write-Information "Retrieving AD service account credentials from Key Vault"
    
    try {
        # Get Managed Identity token for Key Vault
        $tokenResponse = Invoke-RestMethod `
            -Uri "$($env:MSI_ENDPOINT)?resource=https://vault.azure.net&api-version=2019-08-01" `
            -Headers @{"X-IDENTITY-HEADER" = $env:MSI_SECRET } `
            -Method Get
        
        # Retrieve secret from Key Vault
        $secretName = 'ENTRA-PWDRESET-RW'
        $keyVaultUri = $env:KEY_VAULT_URI.TrimEnd('/')
        $secretUri = "$keyVaultUri/secrets/$secretName?api-version=7.4"
        
        $secretResponse = Invoke-RestMethod `
            -Uri $secretUri `
            -Headers @{"Authorization" = "Bearer $($tokenResponse.access_token)" } `
            -Method Get
        
        # Parse credential (format: {"username":"DOMAIN\\user","password":"pwd"})
        $credentialObject = $secretResponse.value | ConvertFrom-Json
        $securePassword = ConvertTo-SecureString -String $credentialObject.password -AsPlainText -Force
        $global:ADServiceCredential = New-Object System.Management.Automation.PSCredential(
            $credentialObject.username,
            $securePassword
        )
        
        Write-Information "Successfully retrieved AD service account: $($credentialObject.username)"
    }
    catch {
        Write-Error "Failed to retrieve AD credentials from Key Vault: $_"
        throw
    }
}
elseif ($env:AD_SERVICE_USERNAME -and $env:AD_SERVICE_PASSWORD) {
    Write-Information "Running locally - using AD credentials from environment variables"
    
    try {
        $securePassword = ConvertTo-SecureString -String $env:AD_SERVICE_PASSWORD -AsPlainText -Force
        $global:ADServiceCredential = New-Object System.Management.Automation.PSCredential(
            $env:AD_SERVICE_USERNAME,
            $securePassword
        )
        
        Write-Information "Successfully loaded AD service account: $env:AD_SERVICE_USERNAME"
    }
    catch {
        Write-Error "Failed to load AD credentials from environment variables: $_"
        throw
    }
}
else {
    Write-Warning "AD service account credentials not configured"
}

# Set strict mode for better error handling
# Reference: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_strict_mode
Set-StrictMode -Version Latest

# Set error action preference
$ErrorActionPreference = 'Stop'

Write-Information "Function App profile loaded successfully"
