#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Connect to Microsoft Graph with explicit scopes.

.DESCRIPTION
Wrapper around Connect-MgGraph enforcing explicit scopes, tenant, and recommended best practices.
Docs: https://learn.microsoft.com/powershell/microsoftgraph/authentication/connect-mggraph?view=graph-powershell-1.0

.PARAMETER Scopes
Array of Microsoft Graph permission scopes to request.

.PARAMETER TenantId
Target tenant ID (GUID) for connection.

.OUTPUTS
Microsoft.Graph.PowerShell.Models.IIdentityAccessToken

.NOTES
Ensures no implicit scope usage. Consider using certificate-based auth for automation.
#>
Function Connect-WiGraph {
    [CmdletBinding()] 
    [OutputType('Microsoft.Graph.PowerShell.Models.IIdentityAccessToken')]
    Param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Scopes,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
        [Parameter()][switch]$NoWelcome
    )
    Function Test-ModulePresent {
        Param([string]$Name)
        if (-not (Get-Module -ListAvailable -Name $Name)) {
            Throw "Required module '$Name' is not installed. Run scripts/Install-Dependencies.ps1 first."
        }
    }
    Function Get-WiEnvironmentCredentialContext {
        $clientId = $env:AZURE_CLIENT_ID
        $tenantId = $env:AZURE_TENANT_ID
        $hasSecret = -not [string]::IsNullOrWhiteSpace($env:AZURE_CLIENT_SECRET)
        $hasCertPath = -not [string]::IsNullOrWhiteSpace($env:AZURE_CLIENT_CERTIFICATE_PATH)
        $federatedTokenPath = $env:AZURE_FEDERATED_TOKEN_FILE
        $hasFederatedToken = -not [string]::IsNullOrWhiteSpace($federatedTokenPath) -and (Test-Path -Path $federatedTokenPath -PathType Leaf)
        $mode = if ($hasFederatedToken) {
            'WorkloadIdentity'
        }
        elseif ($hasCertPath) {
            'ClientCertificate'
        }
        elseif ($hasSecret) {
            'ClientSecret'
        }
        else {
            $null
        }
        return [PSCustomObject]@{
            Ready  = ($clientId -and $tenantId -and $mode)
            Mode   = $mode
            Tenant = $tenantId
        }
    }
    Test-ModulePresent -Name 'Microsoft.Graph.Authentication'
    $envContext = Get-WiEnvironmentCredentialContext
    $useEnvironmentAuth = $envContext.Ready
    if ($useEnvironmentAuth -and $TenantId -and $envContext.Tenant -and ($TenantId -ne $envContext.Tenant)) {
        Write-Warning "TenantId parameter ($TenantId) does not match AZURE_TENANT_ID ($($envContext.Tenant)). The environment variable value will be used for CI authentication."
    }
    try {
        if ($useEnvironmentAuth) {
            $connection = Connect-MgGraph -EnvironmentVariable -NoWelcome
        }
        else {
            $connection = Connect-MgGraph -Scopes $Scopes -TenantId $TenantId -NoWelcome
        }
    }
    catch {
        Throw "Failed to connect to Graph: $($_.Exception.Message)"
    }
    if (-not $NoWelcome) {
        if ($useEnvironmentAuth) {
            $tenantLabel = if ($envContext.Tenant) { $envContext.Tenant } else { 'environment default' }
            Write-Information "Connected to Graph using EnvironmentCredential mode '$($envContext.Mode)' for tenant $tenantLabel." -InformationAction Continue
        }
        else {
            Write-Information "Connected to Graph. Scopes: $($Scopes -join ', ') Tenant: $TenantId" -InformationAction Continue
        }
    }
    return $connection
}
