#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Get risk history for a risky service principal (beta).

.DESCRIPTION
Uses Get-MgBetaRiskyServicePrincipalHistory from Microsoft.Graph.Beta.Identity.SignIns to return risk history items.
Requires IdentityRiskyServicePrincipal.Read.All and Workload ID Premium license.

.NOTES
Cmdlet reference: https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.beta.identity.signins/get-mgbetariskyserviceprincipalhistory?view=graph-powershell-beta

.PARAMETER RiskyServicePrincipalId
The id of the risky service principal object.

.OUTPUTS
PSCustomObject with fields: RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime, Activity, InitiatedBy.

Docs:
- List history (beta): https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-list-history?view=graph-rest-beta
#>
Function Get-WiBetaRiskyServicePrincipalHistory {
    [CmdletBinding()] 
    [OutputType([psobject])]
    Param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RiskyServicePrincipalId
    )
    $results = Get-MgBetaRiskyServicePrincipalHistory -RiskyServicePrincipalId $RiskyServicePrincipalId -All -ErrorAction Stop
    $objects = foreach ($item in $results) {
        [PSCustomObject]@{
            RiskLevel               = $item.RiskLevel
            RiskState               = $item.RiskState
            RiskDetail              = $item.RiskDetail
            RiskLastUpdatedDateTime = $item.RiskLastUpdatedDateTime
            Activity                = $item.Activity
            InitiatedBy             = $item.InitiatedBy
        }
    }
    return $objects
}
