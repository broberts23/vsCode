#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
    Configures an Entra ID App Registration with the Role.PasswordReset app role.

.DESCRIPTION
    This script creates or updates an Entra ID App Registration with:
    - Role.PasswordReset app role
    - API permissions (optional)
    - App ID URI
    
    The App Registration is used to issue JWT tokens that the Function App validates.

.PARAMETER DisplayName
    The display name for the App Registration.

.PARAMETER CreateNew
    Creates a new App Registration instead of updating an existing one.

.PARAMETER AppId
    The Application ID of an existing App Registration to update. Required if not using -CreateNew.

.EXAMPLE
    ./Configure-AppRegistration.ps1 -DisplayName "Password Reset API" -CreateNew

.EXAMPLE
    ./Configure-AppRegistration.ps1 -AppId 12345678-1234-1234-1234-123456789abc

.LINK
    https://learn.microsoft.com/powershell/module/microsoft.graph.applications/new-mgapplication
    https://learn.microsoft.com/powershell/module/microsoft.graph.applications/update-mgapplication
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Update')]
param(
    [Parameter(ParameterSetName = 'Create', Mandatory)]
    [switch]$CreateNew,

    [Parameter(ParameterSetName = 'Create', Mandatory)]
    [Parameter(ParameterSetName = 'Update')]
    [string]$DisplayName = 'Password Reset API',

    [Parameter(ParameterSetName = 'Update', Mandatory)]
    [string]$AppId
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

function New-AppRoleDefinition {
    Write-StatusMessage "Creating App Role definition..." -Type Info
    
    $appRole = @{
        AllowedMemberTypes = @('Application', 'User')
        Description        = 'Allows the application or user to reset passwords for Entra ID users'
        DisplayName        = 'Password Reset Administrator'
        Id                 = (New-Guid).Guid
        IsEnabled          = $true
        Value              = 'Role.PasswordReset'
    }
    
    Write-StatusMessage "App Role created: Role.PasswordReset" -Type Success
    return $appRole
}

function New-AppRegistration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$DisplayName)
    
    if ($PSCmdlet.ShouldProcess($DisplayName, 'Create App Registration')) {
        Write-StatusMessage "Creating new App Registration: $DisplayName" -Type Info
        
        $appRole = New-AppRoleDefinition

        $params = @{
            DisplayName            = $DisplayName
            SignInAudience         = 'AzureADMyOrg'
            AppRoles               = @($appRole)
            RequiredResourceAccess = @()
            # Do not set IdentifierUris at creation; set after
        }

        $app = New-MgApplication -BodyParameter $params -ErrorAction Stop

        Write-StatusMessage "App Registration created successfully!" -Type Success
        Write-StatusMessage "Application ID: $($app.AppId)" -Type Info
        Write-StatusMessage "Object ID: $($app.Id)" -Type Info

        # Set IdentifierUris to api://<app-id> after creation
        $identifierUri = "api://$($app.AppId)"
        Update-MgApplication -ApplicationId $app.Id -BodyParameter @{ IdentifierUris = @($identifierUri) } -ErrorAction Stop
        Write-StatusMessage "Set Identifier URI: $identifierUri" -Type Info

        # Create Service Principal (required for other apps to request permissions)
        Write-StatusMessage "Creating Service Principal (Enterprise Application)..." -Type Info
        $spParams = @{
            AppId = $app.AppId
        }
        $servicePrincipal = New-MgServicePrincipal -BodyParameter $spParams -ErrorAction Stop
        Write-StatusMessage "Service Principal created successfully!" -Type Success
        Write-StatusMessage "Service Principal Object ID: $($servicePrincipal.Id)" -Type Info

        # Refresh app object
        $app = Get-MgApplication -ApplicationId $app.Id
        return $app
    }
}

function Update-ExistingAppRegistration {
    param(
        [string]$AppId,
        [string]$DisplayName
    )
    
    Write-StatusMessage "Finding App Registration with AppId: $AppId" -Type Info
    $app = Get-MgApplication -Filter "appId eq '$AppId'" -ErrorAction Stop
    
    if (-not $app) {
        throw "App Registration not found with AppId: $AppId"
    }
    
    Write-StatusMessage "Found: $($app.DisplayName) ($($app.Id))" -Type Success
    
    # Check if Role.PasswordReset already exists
    $existingRole = $app.AppRoles | Where-Object { $_.Value -eq 'Role.PasswordReset' }
    
    if ($existingRole) {
        Write-StatusMessage "Role.PasswordReset already exists in App Registration" -Type Warning
        return $app
    }
    
    if ($PSCmdlet.ShouldProcess($app.DisplayName, 'Add Role.PasswordReset app role')) {
        Write-StatusMessage "Adding Role.PasswordReset to existing App Registration..." -Type Info
        
        $newRole = New-AppRoleDefinition
        $updatedRoles = $app.AppRoles + $newRole
        
        $params = @{
            AppRoles = $updatedRoles
        }
        
        if ($DisplayName) {
            $params.DisplayName = $DisplayName
        }
        
        Update-MgApplication -ApplicationId $app.Id -BodyParameter $params -ErrorAction Stop
        
        Write-StatusMessage "App Registration updated successfully!" -Type Success
        
        # Refresh app object
        $app = Get-MgApplication -ApplicationId $app.Id
        return $app
    }
}

function Show-AppRegistrationSummary {
    param($Application)
    
    Write-StatusMessage "`n===== App Registration Summary =====" -Type Info
    Write-Host "  Display Name: " -NoNewline -ForegroundColor Cyan
    Write-Host $Application.DisplayName -ForegroundColor White
    Write-Host "  Application ID: " -NoNewline -ForegroundColor Cyan
    Write-Host $Application.AppId -ForegroundColor White
    Write-Host "  Object ID: " -NoNewline -ForegroundColor Cyan
    Write-Host $Application.Id -ForegroundColor White
    
    if ($Application.IdentifierUris) {
        Write-Host "  App ID URI: " -NoNewline -ForegroundColor Cyan
        Write-Host $Application.IdentifierUris[0] -ForegroundColor White
    }
    
    Write-Host "`n  App Roles:" -ForegroundColor Cyan
    foreach ($role in $Application.AppRoles) {
        Write-Host "    - $($role.Value)" -NoNewline -ForegroundColor Yellow
        Write-Host " ($($role.DisplayName))" -ForegroundColor Gray
    }
    
    Write-StatusMessage "====================================`n" -Type Info
}

# ====================================
# Main Script
# ====================================

try {
    Write-StatusMessage "`n===== Configure Entra ID App Registration =====" -Type Info
    
    # Check Graph connection
    if (-not (Test-MgGraphConnection)) {
        Write-StatusMessage "Connecting to Microsoft Graph with required scopes..." -Type Info
        Connect-MgGraph -Scopes 'Application.ReadWrite.All' -ErrorAction Stop
    }
    
    # Create or update App Registration
    if ($CreateNew) {
        $app = New-AppRegistration -DisplayName $DisplayName
    }
    else {
        $app = Update-ExistingAppRegistration -AppId $AppId -DisplayName $DisplayName
    }

    # Show summary
    Show-AppRegistrationSummary -Application $app

    Write-StatusMessage "Next Steps:" -Type Info
    Write-Host "  1. Update the parameter files with the Application ID:" -ForegroundColor Yellow
    Write-Host "     - expectedAudience: " -NoNewline -ForegroundColor Yellow
    Write-Host $app.IdentifierUris[0] -ForegroundColor White
    Write-Host "`n  2. Create a client app registration to call this API:" -ForegroundColor Yellow
    Write-Host "     Run: ./Create-ClientAppRegistration.ps1 -DisplayName 'My Client' -ApiAppId $($app.AppId)" -ForegroundColor Gray
    Write-Host "`n  3. Assign the Role.PasswordReset role to users or service principals" -ForegroundColor Yellow
    Write-Host "     - Portal: " -NoNewline -ForegroundColor Yellow
    Write-Host "https://portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Users/objectId/$($app.AppId)/appId/$($app.AppId)" -ForegroundColor White

    Write-StatusMessage "`nConfiguration completed successfully!" -Type Success
    Write-StatusMessage "Service Principal created - client apps can now request permissions to this API." -Type Info

    # Output the app object for caller scripts
    $app
}
catch {
    Write-StatusMessage "Configuration failed: $_" -Type Error
    Write-StatusMessage $_.ScriptStackTrace -Type Error
    exit 1
}
