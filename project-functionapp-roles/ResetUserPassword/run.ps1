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
Import-Module (Join-Path $PSScriptRoot '../Modules/PasswordResetHelpers/PasswordResetHelpers.psm1') -Force

try {
    Write-Information "HTTP trigger function 'ResetUserPassword' processing request"
    
    #region Validate Request
    
    # Extract Authorization header
    $authHeader = $Request.Headers['Authorization']
    if (-not $authHeader) {
        Write-Warning "Missing Authorization header"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::Unauthorized
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Unauthorized'
                    message = 'Authorization header is required'
                } | ConvertTo-Json
            })
        return
    }
    
    # Extract Bearer token
    if ($authHeader -notmatch '^Bearer\s+(.+)$') {
        Write-Warning "Invalid Authorization header format"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::Unauthorized
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Unauthorized'
                    message = 'Authorization header must use Bearer scheme'
                } | ConvertTo-Json
            })
        return
    }
    
    $token = $Matches[1]
    
    # Get configuration from environment variables
    $tenantId = $env:TENANT_ID
    $expectedAudience = $env:EXPECTED_AUDIENCE
    $expectedIssuer = $env:EXPECTED_ISSUER -replace '\{TENANT_ID\}', $tenantId
    $requiredRole = $env:REQUIRED_ROLE
    
    if (-not $tenantId -or -not $expectedAudience -or -not $requiredRole) {
        Write-Error "Missing required environment variables"
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
    
    #endregion
    
    #region Validate JWT Token
    
    Write-Information "Validating JWT token"
    
    try {
        $principal = Test-JwtToken -Token $token -ExpectedIssuer $expectedIssuer -ExpectedAudience $expectedAudience -ErrorAction Stop
    }
    catch {
        Write-Warning "JWT token validation failed: $_"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::Unauthorized
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Unauthorized'
                    message = 'Invalid or expired token'
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
        $requestBody = $Request.Body | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Warning "Invalid JSON in request body"
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Headers    = @{ 'Content-Type' = 'application/json' }
                Body       = @{
                    error   = 'Bad Request'
                    message = 'Invalid JSON format'
                } | ConvertTo-Json
            })
        return
    }
    
    $samAccountName = $requestBody.samAccountName
    $domainController = $requestBody.domainController  # Optional
    
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
    
    # Get AD service account credential from global cache (loaded in profile.ps1)
    if (-not $global:ADServiceCredential) {
        Write-Error "AD service account credential not available"
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
    
    #endregion
    
    #region Generate and Set Password
    
    Write-Information "Generating secure password"
    
    $newPassword = New-SecurePassword -Length 16
    
    Write-Information "Setting password for AD user: $samAccountName"
    
    try {
        $setParams = @{
            SamAccountName        = $samAccountName
            Password              = $newPassword
            Credential            = $global:ADServiceCredential
            ChangePasswordAtLogon = $false
            ErrorAction           = 'Stop'
        }
        
        if ($domainController) {
            $setParams['DomainController'] = $domainController
            Write-Information "Using domain controller: $domainController"
        }
        
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
