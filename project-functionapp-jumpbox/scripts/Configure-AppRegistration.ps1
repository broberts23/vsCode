#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName = 'Legacy PowerShell Jumpbox API',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RequiredRole = 'Role.LegacyCommand.Invoke'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-StatusMessage {
    [CmdletBinding()]
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
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor DarkGray
    Write-Host $Message -ForegroundColor $color
}

function Assert-GraphCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
            throw "Required Microsoft Graph command '$name' was not found. Install the Microsoft.Graph PowerShell modules first."
        }
    }
}

function Ensure-MgGraphConnection {
    [CmdletBinding()]
    param()

    $requiredScopes = @(
        'Application.ReadWrite.All'
        'AppRoleAssignment.ReadWrite.All'
        'Directory.ReadWrite.All'
    )

    $context = Get-MgContext -ErrorAction SilentlyContinue
    $connected = $null -ne $context
    $grantedScopes = if ($connected -and $null -ne $context.Scopes) { @($context.Scopes) } else { @() }
    $missingScopes = if ($connected) { @($requiredScopes | Where-Object { $grantedScopes -notcontains $_ }) } else { @($requiredScopes) }
    $hasScopes = $connected -and (@($missingScopes).Count -eq 0)

    if (-not $hasScopes) {
        Write-StatusMessage 'Connecting to Microsoft Graph with application and app role assignment scopes...' -Type Info
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ContextScope Process -ErrorAction Stop | Out-Null
        $context = Get-MgContext -ErrorAction Stop
    }

    return $context
}

function ConvertTo-GraphFilterLiteral {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    return $Value.Replace("'", "''")
}

function Get-AppRoleDefinition {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$RequiredRole
    )

    return @{
        allowedMemberTypes = @('Application', 'User')
        description        = 'Allows invocation of legacy management commands through the jumpbox function app.'
        displayName        = 'Legacy Command Invoke'
        id                 = (New-Guid).Guid
        isEnabled          = $true
        value              = $RequiredRole
    }
}

function Get-ExistingApplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    $filterValue = ConvertTo-GraphFilterLiteral -Value $DisplayName
    $applications = @(Get-MgApplication -Filter "displayName eq '$filterValue'" -ConsistencyLevel eventual -ErrorAction Stop)
    return $applications | Select-Object -First 1
}

function Ensure-ServicePrincipal {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$AppId,

        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    $servicePrincipals = @(Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ConsistencyLevel eventual -ErrorAction Stop)
    $servicePrincipal = $servicePrincipals | Select-Object -First 1
    if ($servicePrincipal) {
        return $servicePrincipal
    }

    if ($PSCmdlet.ShouldProcess($DisplayName, 'Create service principal')) {
        Write-StatusMessage "Creating service principal for '$DisplayName'." -Type Info
        return New-MgServicePrincipal -BodyParameter @{ appId = $AppId } -ErrorAction Stop
    }
}

try {
    Assert-GraphCommand -Names @(
        'Connect-MgGraph'
        'Get-MgContext'
        'Get-MgApplication'
        'New-MgApplication'
        'Update-MgApplication'
        'Get-MgServicePrincipal'
        'New-MgServicePrincipal'
    )

    $context = Ensure-MgGraphConnection
    Write-StatusMessage "Connected to Microsoft Graph tenant '$($context.TenantId)'." -Type Success

    $application = Get-ExistingApplication -DisplayName $DisplayName
    if ($null -eq $application) {
        if ($PSCmdlet.ShouldProcess($DisplayName, 'Create API app registration')) {
            Write-StatusMessage "Creating API app registration '$DisplayName'." -Type Info
            $application = New-MgApplication -BodyParameter @{
                displayName    = $DisplayName
                signInAudience = 'AzureADMyOrg'
                api            = @{ requestedAccessTokenVersion = 2 }
                appRoles       = @((Get-AppRoleDefinition -RequiredRole $RequiredRole))
            } -ErrorAction Stop
        }
    }
    else {
        Write-StatusMessage "Reusing existing API app registration '$DisplayName'." -Type Warning

        $appRoles = @($application.AppRoles)
        $matchingRole = $appRoles | Where-Object { $_.Value -eq $RequiredRole } | Select-Object -First 1
        if (-not $matchingRole) {
            $appRoles += (Get-AppRoleDefinition -RequiredRole $RequiredRole)
        }

        $identifierUri = "api://$($application.AppId)"
        Update-MgApplication -ApplicationId $application.Id -BodyParameter @{
            api            = @{ requestedAccessTokenVersion = 2 }
            appRoles       = $appRoles
            identifierUris = @($identifierUri)
        } -ErrorAction Stop
        $application = Get-MgApplication -ApplicationId $application.Id -ErrorAction Stop
    }

    $desiredIdentifierUri = "api://$($application.AppId)"
    if (@($application.IdentifierUris) -notcontains $desiredIdentifierUri) {
        Update-MgApplication -ApplicationId $application.Id -BodyParameter @{ identifierUris = @($desiredIdentifierUri) } -ErrorAction Stop
        $application = Get-MgApplication -ApplicationId $application.Id -ErrorAction Stop
    }

    $servicePrincipal = Ensure-ServicePrincipal -AppId $application.AppId -DisplayName $application.DisplayName
    $appRole = @($application.AppRoles) | Where-Object { $_.Value -eq $RequiredRole } | Select-Object -First 1
    if (-not $appRole) {
        throw "Required role '$RequiredRole' was not found on API app registration '$DisplayName'."
    }

    Write-StatusMessage "API app registration ready. AppId: $($application.AppId)" -Type Success

    [pscustomobject]@{
        DisplayName        = $application.DisplayName
        AppId              = $application.AppId
        ObjectId           = $application.Id
        ServicePrincipalId = $servicePrincipal.Id
        IdentifierUri      = $desiredIdentifierUri
        RequiredRole       = $RequiredRole
        AppRoleId          = $appRole.Id
        TenantId           = $context.TenantId
    }
}
catch {
    Write-StatusMessage "Failed to configure API app registration: $($_.Exception.Message)" -Type Error
    throw
}