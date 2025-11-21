#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Retrieve risky service principals (preview Identity Protection workload identity risk).

.DESCRIPTION
Convenience wrapper around Get-WiBetaRiskyServicePrincipal to keep backward compatibility with existing scripts while standardizing on Microsoft.Graph.Beta.Identity.SignIns cmdlets.

.PARAMETER RiskLevel
Optional filter by riskLevel: low|medium|high|hidden|none.

.PARAMETER RiskState
Optional filter by riskState: none|confirmedSafe|remediated|dismissed|atRisk|confirmedCompromised.

.OUTPUTS
PSCustomObject representing risky service principals or empty result.
#>
Function Get-WiRiskyServicePrincipal {
    [CmdletBinding()] 
    [OutputType([psobject])]
    Param(
        [Parameter()][ValidateSet('low', 'medium', 'high', 'hidden', 'none')][string]$RiskLevel,
        [Parameter()][ValidateSet('none', 'confirmedSafe', 'remediated', 'dismissed', 'atRisk', 'confirmedCompromised')][string]$RiskState
    )
    if ($PSBoundParameters.Count -gt 0) {
        return Get-WiBetaRiskyServicePrincipal @PSBoundParameters
    }
    return Get-WiBetaRiskyServicePrincipal
}
