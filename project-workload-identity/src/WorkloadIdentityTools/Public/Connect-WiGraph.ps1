#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Connect to Microsoft Graph with explicit scopes.

.DESCRIPTION
Wrapper around Connect-MgGraph with support for both delegated (interactive) and application (CI/CD) authentication.

Local/Interactive Mode:
- Requires -Scopes parameter with delegated permissions
- Uses Connect-MgGraph with interactive consent flow
- Optionally specify -TenantId to target specific tenant

CI/CD Mode (auto-detected):
- Detects Azure workload identity environment variables (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_FEDERATED_TOKEN_FILE/SECRET/CERT)
- Uses Connect-MgGraph -EnvironmentVariable for service principal authentication
- Scopes parameter is ignored; service principal must have Graph application permissions pre-consented in Entra ID
- Typically set by 'azure/login@v1' action in GitHub Actions workflows

Docs: https://learn.microsoft.com/powershell/microsoftgraph/authentication/connect-mggraph?view=graph-powershell-1.0

.PARAMETER Scopes
Array of Microsoft Graph permission scopes to request (required for local/interactive mode).
Ignored in CI/CD mode when environment variables are present.

.PARAMETER TenantId
Target tenant ID (GUID) for connection. Optional for local mode if you have default tenant.
Compared against AZURE_TENANT_ID in CI/CD mode for validation.

.PARAMETER NoWelcome
Suppress the connection success message.

.OUTPUTS
Microsoft.Graph.PowerShell.Models.IIdentityAccessToken

.NOTES
CI/CD Prerequisites:
- Service principal must have Graph API application permissions (not delegated) granted and admin-consented
- Required permissions: Application.Read.All, Directory.Read.All, Policy.Read.All, IdentityRiskyServicePrincipal.Read.All
- Grant permissions in Entra ID portal under "API permissions" for the app registration
- Ensure permissions are of type "Application" not "Delegated"

.EXAMPLE
# Local interactive authentication
Connect-WiGraph -Scopes @('Application.Read.All','Directory.Read.All') -TenantId 'tenant-guid'

.EXAMPLE
# CI/CD authentication (auto-detected from environment variables set by azure/login)
Connect-WiGraph -TenantId 'tenant-guid'
#>
Function Connect-WiGraph {
    [CmdletBinding()] 
    [OutputType('Microsoft.Graph.PowerShell.Models.IIdentityAccessToken')]
    Param(
        [Parameter()][ValidateNotNullOrEmpty()][string[]]$Scopes,
        [Parameter()][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
        [Parameter()][switch]$NoWelcome
    )
    Function Test-ModulePresent {
        Param([string]$Name)
        if (-not (Get-Module -ListAvailable -Name $Name)) {
            Throw "Required module '$Name' is not installed. Run scripts/Install-Dependencies.ps1 first."
        }
    }
    Function Get-WiGraphAccessTokenFromAz {
        Param([string]$TenantId)
        if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
            Write-Verbose "Azure CLI not found; cannot perform fallback token acquisition."; return $null
        }
        try {
            $accessToken = az account get-access-token --resource https://graph.microsoft.com/ --tenant $TenantId --query accessToken -o tsv 2>$null
            if (-not $accessToken) { return $null }
            return $accessToken
        }
        catch {
            Write-Verbose "Azure CLI token acquisition failed: $($_.Exception.Message)"; return $null
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
    
    # Validate parameters based on auth mode
    if (-not $useEnvironmentAuth -and -not $Scopes) {
        Throw "Scopes parameter is required when not using environment variable authentication (CI mode). Provide -Scopes for delegated authentication."
    }
    
    if ($useEnvironmentAuth -and $TenantId -and $envContext.Tenant -and ($TenantId -ne $envContext.Tenant)) {
        Write-Warning "TenantId parameter ($TenantId) does not match AZURE_TENANT_ID ($($envContext.Tenant)). The environment variable value will be used for CI authentication."
    }
    
    try {
        if ($useEnvironmentAuth) {
            $connection = Connect-MgGraph -EnvironmentVariable -NoWelcome
        }
        else {
            # Attempt delegated interactive first (local dev), fallback to Azure CLI token if CI detected
            $ciMode = $env:GITHUB_ACTIONS -eq 'true'
            $connectParams = @{
                NoWelcome = $true
            }
            if ($Scopes) { $connectParams['Scopes'] = $Scopes }
            if ($TenantId) { $connectParams['TenantId'] = $TenantId }
            try {
                if (-not $ciMode) {
                    $connection = Connect-MgGraph @connectParams
                }
                else {
                    # CI without environment credential: try Azure CLI access token
                    $token = Get-WiGraphAccessTokenFromAz -TenantId ($TenantId ? $TenantId : $env:AZURE_TENANT_ID)
                    if ($token) {
                        $connection = Connect-MgGraph -AccessToken $token -NoWelcome
                        Write-Verbose "Connected using Azure CLI acquired Graph access token." -Verbose
                    }
                    else {
                        # As last resort attempt scopes (may fail)
                        $connection = Connect-MgGraph @connectParams
                    }
                }
            }
            catch {
                throw
            }
        }
    }
    catch {
        Throw "Failed to connect to Graph: $($_.Exception.Message)"
    }
    if (-not $NoWelcome) {
        if ($useEnvironmentAuth) {
            $tenantLabel = if ($envContext.Tenant) { $envContext.Tenant } else { 'environment default' }
            Write-Information "Connected to Graph using EnvironmentCredential mode '$($envContext.Mode)' for tenant $tenantLabel." -InformationAction Continue
            Write-Information "Note: Service principal must have Graph application permissions pre-consented. If subsequent cmdlets fail with 'Authentication needed', verify the service principal has Application.Read.All, Directory.Read.All, Policy.Read.All, IdentityRiskyServicePrincipal.Read.All granted in Entra ID." -InformationAction Continue
        }
        else {
            Write-Information "Connected to Graph. Scopes: $($Scopes -join ', ') Tenant: $TenantId" -InformationAction Continue
        }
    }
    return $connection
}
