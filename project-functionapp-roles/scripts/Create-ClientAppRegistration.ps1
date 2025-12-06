#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Creates a client App Registration with permission to call the Password Reset API.

.DESCRIPTION
    This script creates an Entra ID App Registration that acts as a client for the Password Reset Function App.
    It assigns the Role.PasswordReset app role permission, creates a client secret, and outputs the credentials.
    
    The admin must manually grant consent for the API permission in the Azure Portal.

.PARAMETER DisplayName
    The display name for the client App Registration.

.PARAMETER ApiAppId
    The Application ID of the Password Reset API (the app registration created by Configure-AppRegistration.ps1).

.PARAMETER SecretExpirationMonths
    Number of months until the client secret expires (default: 12).

.EXAMPLE
    ./Create-ClientAppRegistration.ps1 -DisplayName "Password Reset Client" -ApiAppId "12345678-1234-1234-1234-123456789abc"

.EXAMPLE
    ./Create-ClientAppRegistration.ps1 -DisplayName "Password Reset Client" -ApiAppId "12345678-1234-1234-1234-123456789abc" -SecretExpirationMonths 24

.LINK
    https://learn.microsoft.com/powershell/module/microsoft.graph.applications/new-mgapplication
    https://learn.microsoft.com/powershell/module/microsoft.graph.applications/add-mgapplicationpassword

.NOTES
    After running this script, you MUST grant admin consent for the API permission in the Azure Portal:
    https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/<client-app-id>
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ApiAppId,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 24)]
    [int]$SecretExpirationMonths = 12
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ====================================
# Functions
# ====================================

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

function Test-MgGraphConnection {
    try {
        $context = Get-MgContext
        if (-not $context) {
            throw 'Not connected to Microsoft Graph'
        }
        
        $requiredScopes = @('Application.ReadWrite.All')
        $hasRequiredScopes = $requiredScopes | ForEach-Object {
            $context.Scopes -contains $_
        }
        
        if ($hasRequiredScopes -contains $false) {
            Write-StatusMessage "Missing required scopes. Please reconnect with: Application.ReadWrite.All" -Type Warning
            return $false
        }
        
        Write-StatusMessage "Connected to Microsoft Graph as: $($context.Account)" -Type Success
        return $true
    }
    catch {
        Write-StatusMessage 'Not connected to Microsoft Graph. Please run Connect-MgGraph first.' -Type Error
        return $false
    }
}

function Get-ApiAppRegistration {
    param([string]$AppId)
    
    Write-StatusMessage "Looking up API App Registration with AppId: $AppId" -Type Info
    
    $apiApp = Get-MgApplication -Filter "appId eq '$AppId'" -ErrorAction Stop
    
    if (-not $apiApp) {
        throw "API App Registration not found with AppId: $AppId. Please create it first using Configure-AppRegistration.ps1"
    }
    
    Write-StatusMessage "Found API App: $($apiApp.DisplayName)" -Type Success
    
    # Find the Role.PasswordReset app role
    $passwordResetRole = $apiApp.AppRoles | Where-Object { $_.Value -eq 'Role.PasswordReset' }
    
    if (-not $passwordResetRole) {
        throw "Role.PasswordReset app role not found in API App Registration. Please configure it first."
    }
    
    Write-StatusMessage "Found Role.PasswordReset app role (ID: $($passwordResetRole.Id))" -Type Success
    
    return @{
        Application = $apiApp
        RoleId      = $passwordResetRole.Id
    }
}

function New-ClientAppRegistration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$DisplayName,
        [string]$ApiAppId,
        [string]$RoleId
    )
    
    if ($PSCmdlet.ShouldProcess($DisplayName, 'Create Client App Registration')) {
        Write-StatusMessage "Creating client App Registration: $DisplayName" -Type Info
        
        # Define required resource access (API permission)
        $resourceAccess = @{
            ResourceAppId  = $ApiAppId
            ResourceAccess = @(
                @{
                    Id   = $RoleId
                    Type = 'Role'  # Application permission
                }
            )
        }
        
        $params = @{
            DisplayName            = $DisplayName
            SignInAudience         = 'AzureADMyOrg'
            RequiredResourceAccess = @($resourceAccess)
        }
        
        $clientApp = New-MgApplication -BodyParameter $params -ErrorAction Stop
        
        Write-StatusMessage "Client App Registration created successfully!" -Type Success
        Write-StatusMessage "Application ID: $($clientApp.AppId)" -Type Info
        Write-StatusMessage "Object ID: $($clientApp.Id)" -Type Info
        
        return $clientApp
    }
}

function New-ClientSecret {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$ApplicationId,
        [string]$DisplayName,
        [int]$ExpirationMonths
    )
    
    if ($PSCmdlet.ShouldProcess($DisplayName, 'Create client secret')) {
        Write-StatusMessage "Creating client secret..." -Type Info
        
        $endDateTime = (Get-Date).AddMonths($ExpirationMonths)
        
        $passwordCredential = @{
            DisplayName = "Auto-generated secret - $(Get-Date -Format 'yyyy-MM-dd')"
            EndDateTime = $endDateTime
        }
        
        $secret = Add-MgApplicationPassword -ApplicationId $ApplicationId -PasswordCredential $passwordCredential -ErrorAction Stop
        
        Write-StatusMessage "Client secret created successfully!" -Type Success
        Write-StatusMessage "Secret expires: $($secret.EndDateTime.ToString('yyyy-MM-dd HH:mm:ss UTC'))" -Type Info
        
        return $secret
    }
}

function Show-ClientCredentials {
    param(
        [object]$ClientApp,
        [object]$Secret,
        [string]$ApiAppId
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   CLIENT APP REGISTRATION CREDENTIALS" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "`n"
    
    Write-Host "Display Name:    " -NoNewline -ForegroundColor Yellow
    Write-Host $ClientApp.DisplayName -ForegroundColor White
    
    Write-Host "Client ID:       " -NoNewline -ForegroundColor Yellow
    Write-Host $ClientApp.AppId -ForegroundColor White
    
    Write-Host "Client Secret:   " -NoNewline -ForegroundColor Yellow
    Write-Host $Secret.SecretText -ForegroundColor White
    
    Write-Host "Tenant ID:       " -NoNewline -ForegroundColor Yellow
    $tenantId = (Get-MgContext).TenantId
    Write-Host $tenantId -ForegroundColor White
    
    Write-Host "Secret Expires:  " -NoNewline -ForegroundColor Yellow
    Write-Host $Secret.EndDateTime.ToString('yyyy-MM-dd HH:mm:ss UTC') -ForegroundColor White
    
    Write-Host "`n"
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "`n"
    
    Write-StatusMessage "IMPORTANT: Save the client secret now - it cannot be retrieved later!" -Type Warning
    Write-Host "`n"
}

function Show-NextSteps {
    param(
        [string]$ClientAppId,
        [string]$ApiAppId
    )
    
    Write-StatusMessage "Next Steps:" -Type Info
    Write-Host "`n"
    Write-Host "  1. Grant Admin Consent for API Permission (REQUIRED)" -ForegroundColor Yellow
    Write-Host "     Portal: " -NoNewline -ForegroundColor Yellow
    Write-Host "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$ClientAppId" -ForegroundColor White
    Write-Host "`n"
    Write-Host "  2. Use these credentials in your client application:" -ForegroundColor Yellow
    Write-Host "     - Set AZURE_CLIENT_ID=$ClientAppId" -ForegroundColor Gray
    Write-Host "     - Set AZURE_CLIENT_SECRET=<secret from above>" -ForegroundColor Gray
    Write-Host "     - Set AZURE_TENANT_ID=<tenant ID from above>" -ForegroundColor Gray
    Write-Host "`n"
    Write-Host "  3. Test the client credentials with a token request:" -ForegroundColor Yellow
    Write-Host "     POST https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token" -ForegroundColor Gray
    Write-Host "     Body: client_id=<client-id>&client_secret=<secret>&grant_type=client_credentials&scope=api://$ApiAppId/.default" -ForegroundColor Gray
    Write-Host "`n"
}

# ====================================
# Main Script
# ====================================

try {
    Write-StatusMessage "`n===== Create Client App Registration =====" -Type Info
    
    # Check Graph connection
    if (-not (Test-MgGraphConnection)) {
        Write-StatusMessage "Connecting to Microsoft Graph with required scopes..." -Type Info
        Connect-MgGraph -Scopes 'Application.ReadWrite.All' -ErrorAction Stop
    }
    
    # Get API App Registration and Role ID
    $apiInfo = Get-ApiAppRegistration -AppId $ApiAppId
    
    # Create client App Registration with API permission
    $clientApp = New-ClientAppRegistration `
        -DisplayName $DisplayName `
        -ApiAppId $ApiAppId `
        -RoleId $apiInfo.RoleId
    
    # Create client secret
    $secret = New-ClientSecret `
        -ApplicationId $clientApp.Id `
        -DisplayName $DisplayName `
        -ExpirationMonths $SecretExpirationMonths
    
    # Display credentials
    Show-ClientCredentials -ClientApp $clientApp -Secret $secret -ApiAppId $ApiAppId
    
    # Show next steps
    Show-NextSteps -ClientAppId $clientApp.AppId -ApiAppId $ApiAppId
    
    Write-StatusMessage "Client App Registration created successfully!" -Type Success
    
}
catch {
    Write-StatusMessage "Failed to create client App Registration: $_" -Type Error
    Write-StatusMessage $_.ScriptStackTrace -Type Error
    exit 1
}
