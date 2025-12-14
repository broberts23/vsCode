#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    HTTP trigger function for resetting user passwords in on-premises Active Directory
.DESCRIPTION
    Validates JWT bearer token with Role.PasswordReset claim, generates a secure password,
    sets it in Active Directory Domain Services (ADDS), and returns the password to the caller
.PARAMETER Request
    The HTTP request object from Azure Functions
.PARAMETER TriggerMetadata
    Metadata about the trigger
.OUTPUTS
    HttpResponseContext
.EXAMPLE
    POST /api/ResetUserPassword
    Authorization: Bearer {jwt_token}
    Content-Type: application/json
    {
        "samAccountName": "jdoe"
    }
.LINK
    https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell
    https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountpassword
#>

using namespace System.Net

# Input bindings are passed in via param block
param($Request, $TriggerMetadata)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Import helper module
Import-Module (Join-Path $PSScriptRoot 'PasswordResetHelpers.psm1') -Force

try {
    Write-Information "HTTP trigger function 'ResetUserPassword' processing request"
    
    #region Validate Request
    
    # Extract X-MS-CLIENT-PRINCIPAL header (injected by App Service Authentication)
    $clientPrincipalHeader = $Request.Headers['X-MS-CLIENT-PRINCIPAL']
    if (-not $clientPrincipalHeader) {
        Write-Warning "Missing X-MS-CLIENT-PRINCIPAL header - authentication not configured or request not authenticated"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::Unauthorized
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Unauthorized'
                    message = 'Authentication required. Ensure App Service Authentication is enabled.'
                } | ConvertTo-Json
            })
        return
    }
    
    # Get configuration from environment variables
    $requiredRole = $env:REQUIRED_ROLE
    $domainControllerFqdn = $env:DOMAIN_CONTROLLER_FQDN
    if ([string]::IsNullOrWhiteSpace($domainControllerFqdn)) {
        $domainControllerFqdn = $env:DOMAIN_CONTROLLER
    }
    $domainName = $env:DOMAIN_NAME
    
    if (-not $requiredRole) {
        Write-Error "Missing required environment variable: REQUIRED_ROLE"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Configuration Error'
                    message = 'Function app is not configured correctly'
                } | ConvertTo-Json
            })
        return
    }
    
    if (-not $domainControllerFqdn -or -not $domainName) {
        Write-Error "Missing required environment variables: DOMAIN_CONTROLLER_FQDN or DOMAIN_NAME"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Configuration Error'
                    message = 'Domain controller configuration missing'
                } | ConvertTo-Json
            })
        return
    }
    
    #endregion
    
    #region Decode Client Principal
    
    Write-Information "Decoding client principal from App Service Authentication"
    
    try {
        $principal = Get-ClientPrincipal -HeaderValue $clientPrincipalHeader -ErrorAction Stop
        Write-Information "Principal decoded: $($principal.name_typ) - Auth type: $($principal.auth_typ)"
    }
    catch {
        Write-Warning "Failed to decode client principal: $_"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::Unauthorized
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Unauthorized'
                    message = 'Invalid authentication principal'
                } | ConvertTo-Json
            })
        return
    }
    
    #endregion
    
    #region Validate Role Claim
    
    Write-Information "Validating role claim"
    
    $hasRole = Test-RoleClaim -Principal $principal -RequiredRole $requiredRole
    
    if (-not $hasRole) {
        Write-Warning "Required role claim not found"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::Forbidden
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Forbidden'
                    message = "Insufficient permissions. Required role: $requiredRole"
                } | ConvertTo-Json
            })
        return
    }
    
    #endregion
    
    #region Extract and Validate Request Body
    
    Write-Information "Processing request body"
    
    try {
        # Handle case where host has already deserialized the body (Content-Type: application/json)
        if ($Request.Body -is [string]) {
            $requestBody = $Request.Body | ConvertFrom-Json -ErrorAction Stop
        }
        elseif ($Request.Body -is [System.Collections.Hashtable]) {
            # Convert Hashtable to PSCustomObject for consistent property access via PSObject.Properties
            $requestBody = [PSCustomObject]$Request.Body
        }
        else {
            $requestBody = $Request.Body
        }
        
        # Debug logging
        Write-Information "Body type: $($Request.Body.GetType().FullName)"
        Write-Information "Processed Body type: $($requestBody.GetType().FullName)"
    }
    catch {
        Write-Warning "Invalid JSON in request body: $_"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Bad Request'
                    message = "Invalid JSON format: $_"
                } | ConvertTo-Json
            })
        return
    }
    
    # Safely access properties (handle Set-StrictMode)
    $samAccountName = if ($requestBody.PSObject.Properties['samAccountName']) { $requestBody.samAccountName } else { $null }
    $domainController = if ($requestBody.PSObject.Properties['domainController']) { $requestBody.domainController } else { $null }
    
    if (-not $samAccountName) {
        Write-Warning "Missing samAccountName in request body"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Bad Request'
                    message = 'samAccountName is required in request body'
                } | ConvertTo-Json
            })
        return
    }

    # Retrieve AD service credential (Key Vault / Managed Identity, cached per runspace)
    $adServiceCredential = $null
    try {
        $adServiceCredential = Get-FunctionAdServiceCredential -ErrorAction Stop
    }
    catch {
        Write-Error "AD service account credential not available: $($_.Exception.Message)"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Configuration Error'
                    message = 'AD service account not configured'
                } | ConvertTo-Json
            })
        return
    }

    # Install LDAPS certificate (best-effort; non-fatal if already trusted)
    try {
        $installed = Get-LdapsTrustedCertificate
        if ($installed) {
            Write-Information "LDAPS certificate trust ensured"
        }
        else {
            Write-Warning "LDAPS certificate not available for installation; relying on existing trust"
        }
    }
    catch {
        Write-Warning "Failed to install LDAPS certificate: $($_.Exception.Message)"
    }
    
    #endregion
    
    #region Generate and Set Password
    
    Write-Information "Generating secure password"
    
    $newPassword = New-SecurePassword -Length 16
    $newPasswordSecure = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
    
    Write-Information "Setting password for AD user: $samAccountName"
    
    try {
        # Use LDAPS for password reset (no AD PowerShell module required)
        $setParams = @{
            SamAccountName        = $samAccountName
            Password              = $newPasswordSecure
            Credential            = $adServiceCredential
            DomainController      = $domainController ?? $domainControllerFqdn
            DomainName            = $domainName
            ChangePasswordAtLogon = $false
            ErrorAction           = 'Stop'
        }
        
        Write-Information "Using LDAPS connection to: $($setParams['DomainController'])"
        
        Set-ADUserPassword @setParams | Out-Null
    }
    catch {
        Write-Error "Failed to set AD user password: $_"
        
        $errorMessage = 'Failed to reset password in Active Directory'
        if ($_.Exception.Message -match 'Cannot find an object') {
            $errorMessage = "User not found in Active Directory: $samAccountName"
        }
        elseif ($_.Exception.Message -match 'Access is denied') {
            $errorMessage = "Insufficient permissions to reset password"
        }
        
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Password Reset Failed'
                    message = $errorMessage
                    details = $_.Exception.Message
                } | ConvertTo-Json
            })
        return
    }
    
    #endregion
    
    #region Return Success Response
    
    Write-Information "Password reset successful for AD user: $samAccountName"
    
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Headers    = @{ 
                'Content-Type'              = 'application/json'
                'Cache-Control'             = 'no-store, no-cache, must-revalidate'
                'Pragma'                    = 'no-cache'
                'X-Content-Type-Options'    = 'nosniff'
                'Strict-Transport-Security' = 'max-age=31536000; includeSubDomains'
            }
            Body       = @{
                samAccountName = $samAccountName
                password       = $newPassword
                resetTime      = (Get-Date).ToUniversalTime().ToString('o')
                message        = 'Password reset successful in Active Directory'
            } | ConvertTo-Json
        })
    
    #endregion
}
catch {
    Write-Error "Unexpected error in ResetUserPassword function: $_"
    Write-Error $_.ScriptStackTrace
    
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::InternalServerError
            Headers    = @{ 'Content-Type' = 'application/json' }
            Body       = @{
                error   = 'Internal Server Error'
                message = 'An unexpected error occurred'
            } | ConvertTo-Json
        })
}
