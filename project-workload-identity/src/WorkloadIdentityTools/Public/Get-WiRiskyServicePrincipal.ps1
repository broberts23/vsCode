#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Retrieve risky service principals (preview Identity Protection workload identity risk).

.DESCRIPTION
Attempts to call preview/beta Graph cmdlet Get-MgBetaRiskyServicePrincipal if available.
If not available, returns an empty set with a warning.
Reference (Identity Protection risky workload identities – preview).

.OUTPUTS
PSCustomObject representing risky service principals or empty result.
#>
Function Get-WiRiskyServicePrincipal {
    [CmdletBinding()] 
    [OutputType([psobject])]
    Param()
    if (Get-Command -Name Get-MgBetaRiskyServicePrincipal -ErrorAction SilentlyContinue) {
        try {
            $sp = Get-MgBetaRiskyServicePrincipal
            return $sp
        }
        catch {
            Write-Warning "Failed to retrieve risky service principals: $($_.Exception.Message)"
            return @()
        }
    }
    else {
        Write-Warning 'Get-MgBetaRiskyServicePrincipal not found. Ensure Microsoft.Graph.Beta.Identity.SignIns module installed.'
        return @()
    }
}
