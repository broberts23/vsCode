#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ApiAppId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RequiredRole = 'Role.LegacyCommand.Invoke',

    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$SecretExpirationMonths = 12
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

function Wait-ForGraphApplication {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string]$AppId,

        [Parameter()]
        [int]$TimeoutSeconds = 120,

        [Parameter()]
        [int]$RetryIntervalSeconds = 5
    )

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $applications = @(Get-MgApplication -Filter "appId eq '$AppId'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue)
        $application = $applications | Select-Object -First 1
        if ($application) {
            return $application
        }

        Start-Sleep -Seconds $RetryIntervalSeconds
        $elapsed += $RetryIntervalSeconds
    }

    throw "API app registration with AppId '$AppId' was not found after waiting for Microsoft Graph replication."
}

function Wait-ForGraphServicePrincipal {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string]$AppId,

        [Parameter()]
        [int]$TimeoutSeconds = 120,

        [Parameter()]
        [int]$RetryIntervalSeconds = 5
    )

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $servicePrincipals = @(Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue)
        $servicePrincipal = $servicePrincipals | Select-Object -First 1
        if ($servicePrincipal) {
            return $servicePrincipal
        }

        Start-Sleep -Seconds $RetryIntervalSeconds
        $elapsed += $RetryIntervalSeconds
    }

    throw "Service principal for API app '$AppId' was not found after waiting for Microsoft Graph replication."
}

function Get-ApiInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ApiAppId,

        [Parameter(Mandatory)]
        [string]$RequiredRole
    )

    $apiApplication = Wait-ForGraphApplication -AppId $ApiAppId
    $apiServicePrincipal = Wait-ForGraphServicePrincipal -AppId $ApiAppId

    $appRole = @($apiApplication.AppRoles) | Where-Object { $_.Value -eq $RequiredRole } | Select-Object -First 1
    if (-not $appRole) {
        throw "Required app role '$RequiredRole' was not found on API app '$ApiAppId'."
    }

    return [pscustomobject]@{
        Application      = $apiApplication
        ServicePrincipal = $apiServicePrincipal
        AppRole          = $appRole
    }
}

function Ensure-RequiredResourceAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Application,

        [Parameter(Mandatory)]
        [string]$ApiAppId,

        [Parameter(Mandatory)]
        [string]$AppRoleId
    )

    $existingAccess = @($Application.RequiredResourceAccess)
    $apiAccess = $existingAccess | Where-Object { $_.ResourceAppId -eq $ApiAppId } | Select-Object -First 1
    $matchingApiAccess = if ($apiAccess) { @(@($apiAccess.ResourceAccess) | Where-Object { $_.Id -eq $AppRoleId }) } else { @() }
    if ($apiAccess -and @($matchingApiAccess).Count -gt 0) {
        return
    }

    $mergedAccess = @()
    $updatedCurrent = $false
    foreach ($entry in $existingAccess) {
        if ($entry.ResourceAppId -eq $ApiAppId) {
            $resourceAccess = @($entry.ResourceAccess)
            $matchingRoleAccess = @($resourceAccess | Where-Object { $_.Id -eq $AppRoleId })
            if (@($matchingRoleAccess).Count -eq 0) {
                $resourceAccess += @{ Id = $AppRoleId; Type = 'Role' }
            }

            $mergedAccess += @{
                ResourceAppId  = $entry.ResourceAppId
                ResourceAccess = $resourceAccess
            }
            $updatedCurrent = $true
        }
        else {
            $mergedAccess += @{
                ResourceAppId  = $entry.ResourceAppId
                ResourceAccess = @($entry.ResourceAccess)
            }
        }
    }

    if (-not $updatedCurrent) {
        $mergedAccess += @{
            ResourceAppId  = $ApiAppId
            ResourceAccess = @(@{ Id = $AppRoleId; Type = 'Role' })
        }
    }

    Update-MgApplication -ApplicationId $Application.Id -BodyParameter @{ requiredResourceAccess = $mergedAccess } -ErrorAction Stop
}

function Ensure-AppRoleAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ClientServicePrincipalId,

        [Parameter(Mandatory)]
        [string]$ApiServicePrincipalId,

        [Parameter(Mandatory)]
        [string]$AppRoleId
    )

    $existingAssignmentsResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ClientServicePrincipalId/appRoleAssignments" -OutputType PSObject -ErrorAction Stop
    $existingAssignments = @($existingAssignmentsResponse.value)
    $assignment = $existingAssignments | Where-Object {
        $_.resourceId -eq $ApiServicePrincipalId -and $_.appRoleId -eq $AppRoleId
    } | Select-Object -First 1

    if ($assignment) {
        return
    }

    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ClientServicePrincipalId/appRoleAssignments" -Body (@{
            principalId = $ClientServicePrincipalId
            resourceId  = $ApiServicePrincipalId
            appRoleId   = $AppRoleId
        } | ConvertTo-Json) -ContentType 'application/json' -ErrorAction Stop | Out-Null
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
        'Add-MgApplicationPassword'
        'Invoke-MgGraphRequest'
    )

    $context = Ensure-MgGraphConnection
    $apiInfo = Get-ApiInfo -ApiAppId $ApiAppId -RequiredRole $RequiredRole

    $callerApplication = Get-ExistingApplication -DisplayName $DisplayName
    if (-not $callerApplication) {
        if ($PSCmdlet.ShouldProcess($DisplayName, 'Create caller app registration')) {
            Write-StatusMessage "Creating caller app registration '$DisplayName'." -Type Info
            $callerApplication = New-MgApplication -BodyParameter @{
                displayName            = $DisplayName
                signInAudience         = 'AzureADMyOrg'
                requiredResourceAccess = @(@{
                        resourceAppId  = $ApiAppId
                        resourceAccess = @(@{
                                id   = $apiInfo.AppRole.Id
                                type = 'Role'
                            })
                    })
            } -ErrorAction Stop
        }
    }
    else {
        Write-StatusMessage "Reusing existing caller app registration '$DisplayName'." -Type Warning
        Ensure-RequiredResourceAccess -Application $callerApplication -ApiAppId $ApiAppId -AppRoleId $apiInfo.AppRole.Id
        $callerApplication = Get-MgApplication -ApplicationId $callerApplication.Id -ErrorAction Stop
    }

    $callerServicePrincipal = Ensure-ServicePrincipal -AppId $callerApplication.AppId -DisplayName $callerApplication.DisplayName
    Ensure-AppRoleAssignment -ClientServicePrincipalId $callerServicePrincipal.Id -ApiServicePrincipalId $apiInfo.ServicePrincipal.Id -AppRoleId $apiInfo.AppRole.Id

    $secret = Add-MgApplicationPassword -ApplicationId $callerApplication.Id -PasswordCredential @{
        displayName = "Auto-generated secret - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        endDateTime = (Get-Date).AddMonths($SecretExpirationMonths)
    } -ErrorAction Stop

    Write-Host ''
    Write-Host '============================================' -ForegroundColor Cyan
    Write-Host '   CALLER APP REGISTRATION CREDENTIALS' -ForegroundColor Cyan
    Write-Host '============================================' -ForegroundColor Cyan
    Write-Host ("Tenant ID:      {0}" -f $context.TenantId) -ForegroundColor White
    Write-Host ("Client ID:      {0}" -f $callerApplication.AppId) -ForegroundColor White
    Write-Host ("Client Secret:  {0}" -f $secret.SecretText) -ForegroundColor White
    Write-Host ("Scope:          api://{0}/.default" -f $ApiAppId) -ForegroundColor White
    Write-Host ("Expires:        {0}" -f $secret.EndDateTime.ToString('yyyy-MM-dd HH:mm:ss UTC')) -ForegroundColor White
    Write-Host '============================================' -ForegroundColor Cyan
    Write-Host ''

    [pscustomobject]@{
        DisplayName        = $callerApplication.DisplayName
        AppId              = $callerApplication.AppId
        ObjectId           = $callerApplication.Id
        ServicePrincipalId = $callerServicePrincipal.Id
        ClientSecret       = $secret.SecretText
        SecretExpiresOn    = $secret.EndDateTime
        TenantId           = $context.TenantId
        Scope              = "api://$ApiAppId/.default"
        ApiAppId           = $ApiAppId
    }
}
catch {
    Write-StatusMessage "Failed to create caller app registration: $($_.Exception.Message)" -Type Error
    throw
}