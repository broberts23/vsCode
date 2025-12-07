#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Tests the Password Reset Function App using client credentials flow.

.DESCRIPTION
    This script demonstrates how to:
    1. Obtain an access token using client credentials (client ID + secret)
    2. Call the Password Reset Function App with the token
    3. Validate the response

.PARAMETER ClientId
    The Application ID of the client app registration.

.PARAMETER ClientSecret
    The client secret for authentication.

.PARAMETER TenantId
    The Azure AD tenant ID.

.PARAMETER ApiAppId
    The Application ID of the Password Reset API (for the audience/scope).

.PARAMETER FunctionAppUrl
    The URL of the Function App (e.g., https://your-function-app.azurewebsites.net).

.PARAMETER UserPrincipalName
    The UPN of the user to reset password for (e.g., testuser@contoso.com).

.PARAMETER NewPassword
    The new password to set (must meet complexity requirements).

.EXAMPLE
    ./Test-FunctionAppWithToken.ps1 `
        -ClientId "12345678-1234-1234-1234-123456789abc" `
        -ClientSecret "your-secret-here" `
        -TenantId "87654321-4321-4321-4321-cba987654321" `
        -ApiAppId "abcdef12-3456-7890-abcd-ef1234567890" `
        -FunctionAppUrl "https://pwdreset-func-dev.azurewebsites.net" `
        -UserPrincipalName "testuser@contoso.com" `
        -NewPassword "NewP@ssw0rd123!"

.LINK
    https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow

.LINK
    https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-restmethod
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientSecret,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ApiAppId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$FunctionAppUrl,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$NewPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-StatusMessage {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    
    $color = switch ($Type) {
        'Info' { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
    }
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host $Message -ForegroundColor $color
}

function Get-AccessToken {
    param(
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$TenantId,
        [string]$Scope
    )
    
    Write-StatusMessage "Requesting access token from Azure AD..." -Type Info
    
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = $Scope
        grant_type    = 'client_credentials'
    }
    
    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'
        
        Write-StatusMessage "Access token obtained successfully!" -Type Success
        Write-StatusMessage "Token expires in: $($response.expires_in) seconds" -Type Info
        
        return $response.access_token
    }
    catch {
        Write-StatusMessage "Failed to obtain access token: $_" -Type Error
        Write-StatusMessage "Response: $($_.ErrorDetails.Message)" -Type Error
        throw
    }
}

function Invoke-PasswordReset {
    param(
        [string]$FunctionAppUrl,
        [string]$AccessToken,
        [string]$UserPrincipalName,
        [string]$NewPassword
    )
    
    Write-StatusMessage "Calling Password Reset Function App..." -Type Info
    
    # Remove trailing slash from URL
    $FunctionAppUrl = $FunctionAppUrl.TrimEnd('/')
    
    $apiUrl = "$FunctionAppUrl/api/ResetPassword"
    
    $headers = @{
        'Authorization' = "Bearer $AccessToken"
        'Content-Type'  = 'application/json'
    }
    
    $body = @{
        userPrincipalName = $UserPrincipalName
        newPassword       = $NewPassword
    } | ConvertTo-Json
    
    Write-StatusMessage "API URL: $apiUrl" -Type Info
    Write-StatusMessage "User: $UserPrincipalName" -Type Info
    
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $body
        
        Write-StatusMessage "Password reset successful!" -Type Success
        Write-Host "`nResponse:" -ForegroundColor Cyan
        Write-Host ($response | ConvertTo-Json -Depth 5) -ForegroundColor White
        
        return $response
    }
    catch {
        Write-StatusMessage "Password reset failed: $_" -Type Error
        
        if ($_.ErrorDetails.Message) {
            Write-Host "`nError Details:" -ForegroundColor Red
            Write-Host $_.ErrorDetails.Message -ForegroundColor Yellow
        }
        
        Write-Host "`nStatus Code: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
        Write-Host "Status Description: $($_.Exception.Response.StatusDescription)" -ForegroundColor Red
        
        throw
    }
}

function Show-TokenClaims {
    param([string]$AccessToken)
    
    Write-StatusMessage "`nDecoding token claims..." -Type Info
    
    # JWT tokens have 3 parts separated by dots: header.payload.signature
    $parts = $AccessToken.Split('.')
    
    if ($parts.Count -ne 3) {
        Write-StatusMessage "Invalid JWT token format" -Type Warning
        return
    }
    
    # Decode the payload (second part)
    $payload = $parts[1]
    
    # Add padding if needed (JWT base64 encoding doesn't use padding)
    $padding = switch ($payload.Length % 4) {
        0 { '' }
        2 { '==' }
        3 { '=' }
        default { throw 'Invalid base64 string' }
    }
    
    $payloadJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload + $padding))
    $claims = $payloadJson | ConvertFrom-Json
    
    Write-Host "`nToken Claims:" -ForegroundColor Cyan
    Write-Host "  Audience (aud):  " -NoNewline -ForegroundColor Yellow
    Write-Host $claims.aud -ForegroundColor White
    Write-Host "  Issuer (iss):    " -NoNewline -ForegroundColor Yellow
    Write-Host $claims.iss -ForegroundColor White

    if ($claims.iss -notmatch "/v2\.0$") {
        Write-StatusMessage "WARNING: Token issuer is not v2.0. Function App validation may fail." -Type Warning
        Write-StatusMessage "Ensure the App Registration has 'accessTokenAcceptedVersion: 2' in its manifest." -Type Warning
    }
    
    Write-Host "  App ID (appid):  " -NoNewline -ForegroundColor Yellow
    $appId = if ($claims.PSObject.Properties.Match('appid').Count) { $claims.appid } elseif ($claims.PSObject.Properties.Match('azp').Count) { $claims.azp } else { "Unknown" }
    Write-Host $appId -ForegroundColor White
    Write-Host "  Roles:           " -NoNewline -ForegroundColor Yellow
    Write-Host ($claims.roles -join ', ') -ForegroundColor White
    Write-Host "  Expires (exp):   " -NoNewline -ForegroundColor Yellow
    $expiry = [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).LocalDateTime
    Write-Host "$expiry" -ForegroundColor White
    Write-Host ""
}

# ====================================
# Main Script
# ====================================

try {
    Write-StatusMessage "`n===== Test Password Reset Function App =====" -Type Info
    Write-Host ""
    
    # Step 1: Get access token
    $scope = "api://$ApiAppId/.default"
    Write-StatusMessage "Scope: $scope" -Type Info
    
    $accessToken = Get-AccessToken `
        -ClientId $ClientId `
        -ClientSecret $ClientSecret `
        -TenantId $TenantId `
        -Scope $scope
    
    # Show token claims
    Show-TokenClaims -AccessToken $accessToken
    
    # Step 2: Call Function App
    $result = Invoke-PasswordReset `
        -FunctionAppUrl $FunctionAppUrl `
        -AccessToken $accessToken `
        -UserPrincipalName $UserPrincipalName `
        -NewPassword $NewPassword
    
    Write-StatusMessage "`n===== Test Completed Successfully! =====" -Type Success
    
}
catch {
    Write-StatusMessage "`n===== Test Failed =====" -Type Error
    exit 1
}
