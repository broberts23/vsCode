#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Bootstrap lab workload identities for the WorkloadIdentityTools module.

.DESCRIPTION
    Creates a small, self-contained set of application registrations and service principals
    used to demonstrate the WorkloadIdentityTools discovery and triage cmdlets.

    The script is safe for dev/test tenants and is designed to be idempotent: running it
    multiple times will re-use existing lab objects based on a name prefix.

    Lab objects are intended for non-production tenants only.

.PARAMETER TenantId
    The Microsoft Entra tenant ID to target.

.PARAMETER Prefix
    Name prefix for lab applications and service principals. Defaults to 'wi-lab'.

.PARAMETER WhatIf
    Shows what would happen if the command runs. No changes are made.

.EXAMPLE
    ./Bootstrap-WiLab.ps1 -TenantId '00000000-0000-0000-0000-000000000000'

.EXAMPLE
    ./Bootstrap-WiLab.ps1 -TenantId $env:WI_LAB_TENANT_ID -Prefix 'wi-lab-demo' -WhatIf

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $TenantId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]
    $Prefix = 'wi-lab'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Verbose "Connecting to Microsoft Graph for tenant $TenantId"

if (-not (Get-Module -Name Microsoft.Graph -ListAvailable)) {
    throw 'Microsoft.Graph PowerShell SDK is required. Run Install-Dependencies.ps1 first.'
}

if ($PSCmdlet.ShouldProcess("Tenant $TenantId", 'Connect-MgGraph')) {
    Connect-MgGraph -TenantId $TenantId -Scopes @('Application.ReadWrite.All', 'Directory.ReadWrite.All', 'Directory.AccessAsUser.All') | Out-Null
}

Write-Verbose "Seeding lab applications and service principals with prefix '$Prefix'"

# NOTE: The implementation below is intentionally skeletal. It outlines the
#       structure you can fill in to create:
#       - Long-lived secret app
#       - Near-expiry secret app
#       - Long-lived certificate app
#       - Short-lived certificate app
#       - Federated-only app
#       - High-privilege permission app
#       - Privileged-role service principal

$labSummary = [System.Collections.Generic.List[pscustomobject]]::new()

function New-WiLabApplication {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string] $DisplayName,
        [Parameter()] [string] $Description
    )

    $existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ConsistencyLevel eventual -CountVariable null -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Write-Verbose "Reusing existing application '$DisplayName' ($($existing.Id))"
        return $existing
    }

    if (-not $PSCmdlet.ShouldProcess($DisplayName, 'New-MgApplication')) {
        return $null
    }

    return New-MgApplication -DisplayName $DisplayName -Description $Description
}

function Add-WiLabPassword {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string] $ApplicationId,
        [Parameter(Mandatory)] [datetime] $EndDateTime,
        [Parameter()] [string] $DisplayName = 'wi-lab-secret'
    )

    if (-not $PSCmdlet.ShouldProcess("App $ApplicationId", "Add-MgApplicationPassword ($DisplayName, $EndDateTime)")) {
        return $null
    }

    return Add-MgApplicationPassword -ApplicationId $ApplicationId -PasswordCredential @{ displayName = $DisplayName; endDateTime = $EndDateTime }
}

function Add-WiLabCertificateKey {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string] $ApplicationId,
        [Parameter(Mandatory)] [datetime] $EndDateTime,
        [Parameter()] [string] $DisplayName = 'wi-lab-cert'
    )

    # For simplicity we create a self-signed cert in-memory and upload the public key.
    $cert = New-SelfSignedCertificate -DnsName "${ApplicationId}.wi-lab" -CertStoreLocation Cert:\CurrentUser\My -NotAfter $EndDateTime

    try {
        $keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())

        if (-not $PSCmdlet.ShouldProcess("App $ApplicationId", "Add-MgApplicationKey ($DisplayName, $EndDateTime)")) {
            return $null
        }

        return Add-MgApplicationKey -ApplicationId $ApplicationId -KeyCredential @{
            displayName = $DisplayName
            type        = 'AsymmetricX509Cert'
            usage       = 'Verify'
            key         = $keyValue
            endDateTime = $EndDateTime
        }
    }
    finally {
        # Best-effort: remove the local cert so the private key is not left behind.
        if ($cert) {
            Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
        }
    }
}

function New-WiLabFederatedCredential {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string] $ApplicationId,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Issuer,
        [Parameter(Mandatory)] [string] $Subject,
        [Parameter(Mandatory)] [string] $Audience
    )

    if (-not $PSCmdlet.ShouldProcess("App $ApplicationId", "New-MgApplicationFederatedIdentityCredential ($Name)")) {
        return $null
    }

    return New-MgApplicationFederatedIdentityCredential -ApplicationId $ApplicationId -Name $Name -Issuer $Issuer -Subject $Subject -Audience $Audience
}

function Add-WiLabDirectoryRoleAssignment {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string] $ServicePrincipalId,
        [Parameter()] [string] $RoleTemplateId = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451' # Global Reader
    )

    $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$RoleTemplateId'" -ErrorAction SilentlyContinue
    if (-not $role) {
        Write-Warning "Directory role with templateId $RoleTemplateId is not available in this tenant. Skipping role assignment."
        return $null
    }

    if (-not $PSCmdlet.ShouldProcess("SP $ServicePrincipalId", "New-MgDirectoryRoleMemberByRef ($($role.DisplayName))")) {
        return $null
    }

    return New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -OdataId "https://graph.microsoft.com/v1.0/directoryObjects/$ServicePrincipalId"
}

# 1) Long-lived secret app
$longLivedAppName = "$Prefix-long-lived-secret"
$longLivedApp = New-WiLabApplication -DisplayName $longLivedAppName -Description 'Lab app with long-lived client secret for credential inventory demos.'
if ($longLivedApp) {
    $secretEnd = (Get-Date).AddYears(2)
    Add-WiLabPassword -ApplicationId $longLivedApp.Id -EndDateTime $secretEnd -DisplayName 'wi-lab-long-lived' | Out-Null

    $labSummary.Add([pscustomobject]@{
            Type        = 'Application'
            Scenario    = 'LongLivedSecret'
            DisplayName = $longLivedApp.DisplayName
            Id          = $longLivedApp.Id
        })
}

# 2) Near-expiry secret app
$nearExpiryAppName = "$Prefix-near-expiry-secret"
$nearExpiryApp = New-WiLabApplication -DisplayName $nearExpiryAppName -Description 'Lab app with a client secret expiring soon.'
if ($nearExpiryApp) {
    $secretEnd = (Get-Date).AddDays(7)
    Add-WiLabPassword -ApplicationId $nearExpiryApp.Id -EndDateTime $secretEnd -DisplayName 'wi-lab-near-expiry' | Out-Null

    $labSummary.Add([pscustomobject]@{
            Type        = 'Application'
            Scenario    = 'NearExpirySecret'
            DisplayName = $nearExpiryApp.DisplayName
            Id          = $nearExpiryApp.Id
        })
}

# 3) Long-lived certificate app
$longCertAppName = "$Prefix-long-lived-cert"
$longCertApp = New-WiLabApplication -DisplayName $longCertAppName -Description 'Lab app with long-lived certificate credential.'
if ($longCertApp) {
    $certEnd = (Get-Date).AddYears(2)
    Add-WiLabCertificateKey -ApplicationId $longCertApp.Id -EndDateTime $certEnd -DisplayName 'wi-lab-long-cert' | Out-Null

    $labSummary.Add([pscustomobject]@{
            Type        = 'Application'
            Scenario    = 'LongLivedCert'
            DisplayName = $longCertApp.DisplayName
            Id          = $longCertApp.Id
        })
}

# 4) Short-lived certificate app
$shortCertAppName = "$Prefix-short-lived-cert"
$shortCertApp = New-WiLabApplication -DisplayName $shortCertAppName -Description 'Lab app with short-lived certificate credential.'
if ($shortCertApp) {
    $certEnd = (Get-Date).AddDays(30)
    Add-WiLabCertificateKey -ApplicationId $shortCertApp.Id -EndDateTime $certEnd -DisplayName 'wi-lab-short-cert' | Out-Null

    $labSummary.Add([pscustomobject]@{
            Type        = 'Application'
            Scenario    = 'ShortLivedCert'
            DisplayName = $shortCertApp.DisplayName
            Id          = $shortCertApp.Id
        })
}

# 5) Federated-only app (no secrets/certs)
$federatedAppName = "$Prefix-federated-only"
$federatedApp = New-WiLabApplication -DisplayName $federatedAppName -Description 'Lab app using only federated identity credentials.'
if ($federatedApp) {
    # Example: GitHub Actions OIDC-style subject; adjust issuer/subject for your environment.
    $issuer = 'https://token.actions.githubusercontent.com'
    $subject = 'repo:contoso/example-repo:environment:wi-lab'
    $aud = 'api://AzureADTokenExchange'

    New-WiLabFederatedCredential -ApplicationId $federatedApp.Id -Name 'wi-lab-github' -Issuer $issuer -Subject $subject -Audience $aud | Out-Null

    $labSummary.Add([pscustomobject]@{
            Type        = 'Application'
            Scenario    = 'FederatedOnly'
            DisplayName = $federatedApp.DisplayName
            Id          = $federatedApp.Id
        })
}

# 6) High-privilege permission app
$privPermAppName = "$Prefix-high-priv-perms"
$privPermApp = New-WiLabApplication -DisplayName $privPermAppName -Description 'Lab app with elevated Graph app roles for permission surface demos.'
if ($privPermApp) {
    # Assign a couple of higher-privilege app roles such as Directory.Read.All and Application.ReadWrite.All
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($privPermApp.AppId)'" -ConsistencyLevel eventual -CountVariable null -ErrorAction SilentlyContinue
    if (-not $sp) {
        $sp = New-MgServicePrincipal -AppId $privPermApp.AppId
    }

    $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ConsistencyLevel eventual -CountVariable null -ErrorAction SilentlyContinue
    if ($graphSp) {
        $desiredRoles = @('Directory.Read.All', 'Application.ReadWrite.All')
        foreach ($roleValue in $desiredRoles) {
            $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $roleValue -and $_.AllowedMemberTypes -contains 'Application' }
            if ($appRole) {
                if ($PSCmdlet.ShouldProcess("SP $($sp.Id)", "Add-MgServicePrincipalAppRoleAssignment ($roleValue)")) {
                    Add-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $appRole.Id | Out-Null
                }
            }
        }
    }

    $labSummary.Add([pscustomobject]@{
            Type        = 'ServicePrincipal'
            Scenario    = 'HighPrivilegePermissions'
            DisplayName = $privPermApp.DisplayName
            Id          = $sp.Id
        })
}

# 7) Privileged-role service principal
$privRoleAppName = "$Prefix-priv-role-sp"
$privRoleApp = New-WiLabApplication -DisplayName $privRoleAppName -Description 'Lab service principal in a privileged directory role.'
if ($privRoleApp) {
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($privRoleApp.AppId)'" -ConsistencyLevel eventual -CountVariable null -ErrorAction SilentlyContinue
    if (-not $sp) {
        $sp = New-MgServicePrincipal -AppId $privRoleApp.AppId
    }

    Add-WiLabDirectoryRoleAssignment -ServicePrincipalId $sp.Id | Out-Null

    $labSummary.Add([pscustomobject]@{
            Type        = 'ServicePrincipal'
            Scenario    = 'PrivilegedRole'
            DisplayName = $privRoleApp.DisplayName
            Id          = $sp.Id
        })
}

Write-Output $labSummary
