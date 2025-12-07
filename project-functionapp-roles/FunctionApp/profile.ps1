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

# Retrieve AD service account credentials and LDAPS certificate from Key Vault using Managed Identity
# Reference: https://learn.microsoft.com/azure/key-vault/general/overview
$global:ADServiceCredential = $null
$global:LdapsCertificateCer = $null
$global:LdapsCertificateInstalled = $false

# Determine Managed Identity variables (preferring new IDENTITY_* over legacy MSI_*)
$miEndpoint = $env:IDENTITY_ENDPOINT
$miHeader = $env:IDENTITY_HEADER

# Fallback to MSI_* if IDENTITY_ENDPOINT is missing or whitespace
if ([string]::IsNullOrWhiteSpace($miEndpoint) -and -not [string]::IsNullOrWhiteSpace($env:MSI_ENDPOINT)) {
    Write-Information "Using legacy MSI_ENDPOINT"
    $miEndpoint = $env:MSI_ENDPOINT
    $miHeader = $env:MSI_SECRET
}

# Only proceed if we have a valid endpoint and Key Vault URI
if (-not [string]::IsNullOrWhiteSpace($miEndpoint) -and $env:KEY_VAULT_URI) {
    Write-Information "Retrieving AD service account credentials from Key Vault using Managed Identity"
    
    try {
        # Debug logging
        Write-Information "Raw IDENTITY_ENDPOINT: '$env:IDENTITY_ENDPOINT'"
        Write-Information "Raw KEY_VAULT_URI: '$env:KEY_VAULT_URI'"

        # Clean up endpoint: remove quotes, whitespace, trailing slash
        $miEndpoint = $miEndpoint.Trim().Trim('"').Trim("'").TrimEnd('/')
        
        # Validate URI format
        if (-not ($miEndpoint -as [System.Uri]) -or -not ([System.Uri]$miEndpoint).IsAbsoluteUri) {
            throw "Managed Identity Endpoint is not a valid absolute URI: '$miEndpoint'. (IDENTITY_ENDPOINT: '$env:IDENTITY_ENDPOINT', MSI_ENDPOINT: '$env:MSI_ENDPOINT')"
        }

        # Use UriBuilder to safely construct the token URI
        $uriBuilder = New-Object System.UriBuilder($miEndpoint)
        $uriBuilder.Query = "resource=https://vault.azure.net&api-version=2019-08-01"
        $tokenUri = $uriBuilder.Uri.AbsoluteUri
        
        Write-Information "Fetching Managed Identity token from: $tokenUri"

        $tokenResponse = Invoke-RestMethod `
            -Uri $tokenUri `
            -Headers @{"X-IDENTITY-HEADER" = $miHeader } `
            -Method Get
        
        # Clean up Key Vault URI
        $keyVaultUri = $env:KEY_VAULT_URI.Trim().Trim('"').Trim("'").TrimEnd('/')
        
        if (-not ($keyVaultUri -as [System.Uri]) -or -not ([System.Uri]$keyVaultUri).IsAbsoluteUri) {
            throw "Key Vault URI is not a valid absolute URI: '$keyVaultUri'"
        }

        $authHeader = @{"Authorization" = "Bearer $($tokenResponse.access_token)" }
        
        # Retrieve AD service account secret
        $secretName = 'ENTRA-PWDRESET-RW'
        $secretUri = "$keyVaultUri/secrets/${secretName}?api-version=7.4"
        
        Write-Information "Fetching secret from: $secretUri"

        $secretResponse = Invoke-RestMethod `
            -Uri $secretUri `
            -Headers $authHeader `
            -Method Get
        
        # Parse credential (format: {"username":"DOMAIN\\user","password":"pwd"})
        $secretValue = $secretResponse.value
        
        # Sanitize JSON: Fix unescaped backslashes in "DOMAIN\user" format (e.g. \s in \svc)
        if ($secretValue -match '\\(?![\\"/bfnrtu])') {
            Write-Information "Sanitizing invalid JSON escape sequences in secret value"
            $secretValue = $secretValue -replace '\\(?![\\"/bfnrtu])', '\\'
        }

        $credentialObject = $secretValue | ConvertFrom-Json
        $securePassword = ConvertTo-SecureString -String $credentialObject.password -AsPlainText -Force
        $global:ADServiceCredential = New-Object System.Management.Automation.PSCredential(
            $credentialObject.username,
            $securePassword
        )
        
        Write-Information "Successfully retrieved AD service account: $($credentialObject.username)"
        
        # Retrieve LDAPS certificate (public key for trust)
        $certSecretName = 'LDAPS-Certificate-CER'
        $certSecretUri = "$keyVaultUri/secrets/${certSecretName}?api-version=7.4"
        
        try {
            $certResponse = Invoke-RestMethod `
                -Uri $certSecretUri `
                -Headers $authHeader `
                -Method Get
            
            $global:LdapsCertificateCer = $certResponse.value
            Write-Information "Successfully retrieved LDAPS certificate from Key Vault"
        }
        catch {
            Write-Warning "Failed to retrieve LDAPS certificate from Key Vault: $_"
            # Non-fatal - connection may still work without explicit trust
        }
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
