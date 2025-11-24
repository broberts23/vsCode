#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
    Grants Microsoft Graph API permissions to the Function App Managed Identity.

.DESCRIPTION
    This script grants the User.ReadWrite.All permission to the Function App's
    Managed Identity so it can reset user passwords in Entra ID via Microsoft Graph.

    Requires Microsoft.Graph.Applications module.

.PARAMETER PrincipalId
    The Managed Identity Principal ID (Object ID) of the Function App.

.PARAMETER GraphAppId
    The Microsoft Graph Application ID. Default is 00000003-0000-0000-c000-000000000000.

.PARAMETER PermissionName
    The Graph permission to grant. Default is User.ReadWrite.All.

.EXAMPLE
    ./Grant-GraphPermissions.ps1 -PrincipalId 12345678-1234-1234-1234-123456789abc

.LINK
    https://learn.microsoft.com/powershell/microsoftgraph/authentication-commands
    https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$PrincipalId,

    [Parameter()]
    [string]$GraphAppId = '00000003-0000-0000-c000-000000000000',

    [Parameter()]
    [string]$PermissionName = 'User.ReadWrite.All'
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
        
        # Check for required scopes
        $requiredScopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')
        $hasRequiredScopes = $requiredScopes | ForEach-Object {
            $context.Scopes -contains $_
        }
        
        if ($hasRequiredScopes -contains $false) {
            Write-StatusMessage "Missing required scopes. Please reconnect with: AppRoleAssignment.ReadWrite.All" -Type Warning
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

function Get-GraphServicePrincipal {
    param([string]$AppId)
    
    Write-StatusMessage "Finding Microsoft Graph Service Principal..." -Type Info
    $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction Stop
    
    if (-not $sp) {
        throw "Microsoft Graph Service Principal not found with AppId: $AppId"
    }
    
    Write-StatusMessage "Found Service Principal: $($sp.DisplayName) ($($sp.Id))" -Type Success
    return $sp
}

function Get-AppRole {
    param(
        [Parameter(Mandatory)]
        $ServicePrincipal,
        
        [Parameter(Mandatory)]
        [string]$RoleName
    )
    
    Write-StatusMessage "Finding App Role: $RoleName" -Type Info
    $role = $ServicePrincipal.AppRoles | Where-Object { $_.Value -eq $RoleName }
    
    if (-not $role) {
        Write-StatusMessage "Available roles:" -Type Info
        $ServicePrincipal.AppRoles | ForEach-Object {
            Write-Host "  - $($_.Value)" -ForegroundColor Yellow
        }
        throw "App Role not found: $RoleName"
    }
    
    Write-StatusMessage "Found App Role: $($role.DisplayName) ($($role.Id))" -Type Success
    return $role
}

function Test-ExistingAssignment {
    param(
        [string]$PrincipalId,
        [string]$ResourceId,
        [string]$AppRoleId
    )
    
    Write-StatusMessage "Checking for existing role assignment..." -Type Info
    
    $existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PrincipalId -ErrorAction SilentlyContinue
    
    $existing = $existingAssignments | Where-Object {
        $_.ResourceId -eq $ResourceId -and $_.AppRoleId -eq $AppRoleId
    }
    
    if ($existing) {
        Write-StatusMessage "Role assignment already exists (ID: $($existing.Id))" -Type Warning
        return $true
    }
    
    Write-StatusMessage "No existing assignment found" -Type Info
    return $false
}

function New-AppRoleAssignment {
    param(
        [string]$PrincipalId,
        [string]$ResourceId,
        [string]$AppRoleId
    )
    
    if ($PSCmdlet.ShouldProcess($PrincipalId, "Grant $PermissionName permission")) {
        Write-StatusMessage "Creating App Role Assignment..." -Type Info
        
        $params = @{
            PrincipalId = $PrincipalId
            ResourceId  = $ResourceId
            AppRoleId   = $AppRoleId
        }
        
        $assignment = New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $PrincipalId `
            -BodyParameter $params `
            -ErrorAction Stop
        
        Write-StatusMessage "App Role Assignment created successfully!" -Type Success
        Write-StatusMessage "Assignment ID: $($assignment.Id)" -Type Info
        return $assignment
    }
}

# ====================================
# Main Script
# ====================================

try {
    Write-StatusMessage "`n===== Grant Microsoft Graph Permissions =====" -Type Info
    Write-StatusMessage "Principal ID: $PrincipalId" -Type Info
    Write-StatusMessage "Permission: $PermissionName`n" -Type Info
    
    # Check Graph connection
    if (-not (Test-MgGraphConnection)) {
        Write-StatusMessage "Connecting to Microsoft Graph with required scopes..." -Type Info
        Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All' -ErrorAction Stop
    }
    
    # Get Microsoft Graph Service Principal
    $graphSp = Get-GraphServicePrincipal -AppId $GraphAppId
    
    # Get the App Role
    $appRole = Get-AppRole -ServicePrincipal $graphSp -RoleName $PermissionName
    
    # Check for existing assignment
    $exists = Test-ExistingAssignment `
        -PrincipalId $PrincipalId `
        -ResourceId $graphSp.Id `
        -AppRoleId $appRole.Id
    
    if ($exists) {
        Write-StatusMessage "Permission already granted. No action needed." -Type Success
        exit 0
    }
    
    # Create new assignment
    $assignment = New-AppRoleAssignment `
        -PrincipalId $PrincipalId `
        -ResourceId $graphSp.Id `
        -AppRoleId $appRole.Id
    
    Write-StatusMessage "`nPermission granted successfully!" -Type Success
    Write-StatusMessage "The Function App Managed Identity now has $PermissionName permission." -Type Info
}
catch {
    Write-StatusMessage "Failed to grant permissions: $_" -Type Error
    Write-StatusMessage $_.ScriptStackTrace -Type Error
    exit 1
}
