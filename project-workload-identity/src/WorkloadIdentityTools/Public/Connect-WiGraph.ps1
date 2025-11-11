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
    Test-ModulePresent -Name 'Microsoft.Graph'
    try {
        $connection = Connect-MgGraph -Scopes $Scopes -TenantId $TenantId
    }
    catch {
        Throw "Failed to connect to Graph: $($_.Exception.Message)"
    }
    if (-not $NoWelcome) {
        Write-Information "Connected to Graph. Scopes: $($Scopes -join ', ') Tenant: $TenantId" -InformationAction Continue
    }
    return $connection
}
