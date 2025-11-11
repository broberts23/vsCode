#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Get risk history for a risky service principal (beta).

.DESCRIPTION
Calls /beta/identityProtection/riskyServicePrincipals/{id}/history to return risk history items.
Requires IdentityRiskyServicePrincipal.Read.All and Workload ID Premium license.

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
    $base = "https://graph.microsoft.com/beta/identityProtection/riskyServicePrincipals/$RiskyServicePrincipalId/history?`$top=999"
    $items = New-Object System.Collections.Generic.List[object]
    $uri = $base
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($v in $resp.value) {
            $items.Add([PSCustomObject]@{
                RiskLevel               = $v.riskLevel
                RiskState               = $v.riskState
                RiskDetail              = $v.riskDetail
                RiskLastUpdatedDateTime = $v.riskLastUpdatedDateTime
                Activity                = $v.activity
                InitiatedBy             = $v.initiatedBy
            })
        }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    return $items
}
