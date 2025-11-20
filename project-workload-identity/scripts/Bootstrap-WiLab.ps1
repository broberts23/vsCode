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

if (-not (Get-Module -Name Microsoft.Graph.Authentication -ListAvailable)) {
    throw 'Microsoft.Graph PowerShell SDK is required. Run Install-Dependencies.ps1 first.'
}

if ($PSCmdlet.ShouldProcess("Tenant $TenantId", 'Connect-MgGraph')) {
    $scopes = @(
        'Application.ReadWrite.All',          # required for Add-MgApplicationKey / secrets & certs
        'Directory.ReadWrite.All',            # required for app/SP creation
        'Directory.AccessAsUser.All',         # required for certain write operations
        'AppRoleAssignment.ReadWrite.All',    # required for Add-MgServicePrincipalAppRoleAssignment
        'RoleManagement.ReadWrite.Directory'  # required for New-MgDirectoryRoleMemberByRef
    )

    Connect-MgGraph -TenantId $TenantId -Scopes $scopes | Out-Null
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

function New-WiLabSelfSignedCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Subject,
        [Parameter(Mandatory)] [datetime] $NotAfter
    )

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=$Subject",
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        $notBefore = Get-Date
        if ($NotAfter -le $notBefore) {
            throw "Certificate NotAfter must be greater than now. Provided: $NotAfter"
        }

        return $request.CreateSelfSigned($notBefore, $NotAfter)
    }
    finally {
        $rsa.Dispose()
    }
}

function Add-WiLabCertificateKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ApplicationId,
        [Parameter(Mandatory)] [datetime] $EndDateTime,
        [Parameter()] [string] $DisplayName = 'wi-lab-cert'
    )

    # Generate a self-signed certificate and export the public key to /tmp for manual upload.
    $subject = "${ApplicationId}.wi-lab"
    $cert = New-WiLabSelfSignedCertificate -Subject $subject -NotAfter $EndDateTime

    try {
        $safeDisplayName = ($DisplayName -replace '[^a-zA-Z0-9-]', '-')
        $safeAppId = ($ApplicationId -replace '[^a-zA-Z0-9-]', '-')
        $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
        $tempRoot = '/tmp'
        if (-not (Test-Path -Path $tempRoot)) {
            New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
        }

        $basePath = Join-Path -Path $tempRoot -ChildPath "${safeAppId}_${safeDisplayName}_${timestamp}"
        $cerPath = "$basePath.cer"
        $pemPath = "$basePath.pem"

        $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        [System.IO.File]::WriteAllBytes($cerPath, $certBytes)

        $builder = New-Object System.Text.StringBuilder
        $builder.AppendLine('-----BEGIN CERTIFICATE-----') | Out-Null
        $builder.AppendLine([System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)) | Out-Null
        $builder.AppendLine('-----END CERTIFICATE-----') | Out-Null
        [System.IO.File]::WriteAllText($pemPath, $builder.ToString())

        Write-Information "Exported certificate for $DisplayName to $cerPath (upload via portal) and $pemPath" -InformationAction Continue

        return [pscustomobject]@{
            PublicCertificatePath = $cerPath
            PemCertificatePath    = $pemPath
            Thumbprint            = $cert.Thumbprint
            NotAfter              = $cert.NotAfter
        }
    }
    finally {
        if ($cert) {
            $cert.Dispose()
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
        try {
            $role = Enable-MgDirectoryRole -DirectoryRoleTemplateId $RoleTemplateId -ErrorAction Stop
            Write-Verbose "Activated directory role template $RoleTemplateId"
        }
        catch {
            Write-Warning "Directory role with templateId $RoleTemplateId is not available and activation failed: $($_.Exception.Message). Skipping role assignment."
            return $null
        }
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
    $certificateInfo = Add-WiLabCertificateKey -ApplicationId $longCertApp.Id -EndDateTime $certEnd -DisplayName 'wi-lab-long-cert'

    $labSummary.Add([pscustomobject]@{
            Type           = 'Application'
            Scenario       = 'LongLivedCert'
            DisplayName    = $longCertApp.DisplayName
            Id             = $longCertApp.Id
            CertPath       = if ($certificateInfo) { $certificateInfo.PublicCertificatePath } else { $null }
            CertThumbprint = if ($certificateInfo) { $certificateInfo.Thumbprint } else { $null }
        })
}

# 4) Short-lived certificate app
$shortCertAppName = "$Prefix-short-lived-cert"
$shortCertApp = New-WiLabApplication -DisplayName $shortCertAppName -Description 'Lab app with short-lived certificate credential.'
if ($shortCertApp) {
    $certEnd = (Get-Date).AddDays(30)
    $certificateInfo = Add-WiLabCertificateKey -ApplicationId $shortCertApp.Id -EndDateTime $certEnd -DisplayName 'wi-lab-short-cert'

    $labSummary.Add([pscustomobject]@{
            Type           = 'Application'
            Scenario       = 'ShortLivedCert'
            DisplayName    = $shortCertApp.DisplayName
            Id             = $shortCertApp.Id
            CertPath       = if ($certificateInfo) { $certificateInfo.PublicCertificatePath } else { $null }
            CertThumbprint = if ($certificateInfo) { $certificateInfo.Thumbprint } else { $null }
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

# 6) High-privilege permission app (only Graph app permissions; no directory role)
$privPermAppName = "$Prefix-high-priv-perms"
$privPermApp = New-WiLabApplication -DisplayName $privPermAppName -Description 'Lab app with elevated Graph app roles for permission surface demos.'
if ($privPermApp) {
    # Ensure the application has high-privilege Graph roles in RequiredResourceAccess
    $graphResourceAppId = '00000003-0000-0000-c000-000000000000'
    $desiredGraphRoleValues = @('Directory.Read.All', 'Application.ReadWrite.All')

    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphResourceAppId'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue
    if ($graphSp) {
        $graphAppRoles = $graphSp.AppRoles | Where-Object { $_.AllowedMemberTypes -contains 'Application' -and $desiredGraphRoleValues -contains $_.Value }

        if ($graphAppRoles) {
            $required = @()
            if ($privPermApp.RequiredResourceAccess) {
                $required = @($privPermApp.RequiredResourceAccess)
            }

            $graphRequired = $required | Where-Object { $_.ResourceAppId -eq $graphResourceAppId }
            if (-not $graphRequired) {
                $graphRequired = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequiredResourceAccess]::new()
                $graphRequired.ResourceAppId = $graphResourceAppId
                $graphRequired.ResourceAccess = @()
                $required += $graphRequired
            }

            $existingIds = @()
            if ($graphRequired.ResourceAccess) {
                $existingIds = @($graphRequired.ResourceAccess | ForEach-Object { [string]$_.Id })
            }

            $updatedResourceAccess = @($graphRequired.ResourceAccess)
            foreach ($role in $graphAppRoles) {
                if ($existingIds -notcontains ([string]$role.Id)) {
                    $accessEntry = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphResourceAccess]::new()
                    $accessEntry.Id = $role.Id
                    $accessEntry.Type = 'Role'
                    $updatedResourceAccess += $accessEntry
                }
            }
            $graphRequired.ResourceAccess = $updatedResourceAccess

            if ($PSCmdlet.ShouldProcess($privPermApp.DisplayName, 'Update-MgApplication RequiredResourceAccess')) {
                Update-MgApplication -ApplicationId $privPermApp.Id -RequiredResourceAccess $required | Out-Null
                $privPermApp = Get-MgApplication -ApplicationId $privPermApp.Id -Property 'Id,AppId,DisplayName,RequiredResourceAccess'
            }
        }
    }

    $sp = Get-MgServicePrincipal -Filter "appId eq '$($privPermApp.AppId)'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue
    if (-not $sp) {
        $sp = New-MgServicePrincipal -AppId $privPermApp.AppId
    }

    $labSummary.Add([pscustomobject]@{
            Type        = 'ServicePrincipal'
            Scenario    = 'HighPrivilegePermissions-AppPermissionsOnly'
            DisplayName = $privPermApp.DisplayName
            Id          = $sp.Id
        })
}

# 7) Privileged-role service principal (only directory role; no explicit Graph app permissions seeded here)
$privRoleAppName = "$Prefix-priv-role-sp"
$privRoleApp = New-WiLabApplication -DisplayName $privRoleAppName -Description 'Lab service principal in a privileged directory role.'
if ($privRoleApp) {
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($privRoleApp.AppId)'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue
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
