#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
List risky workload identities (service principals) using Microsoft Graph beta.

.DESCRIPTION
Uses Invoke-MgGraphRequest against /beta/identityProtection/riskyServicePrincipals to retrieve risky service principals and their risk properties.
Requires IdentityRiskyServicePrincipal.Read.All (or ReadWrite for triage actions) and Microsoft Entra Workload ID Premium license.

.PARAMETER RiskLevel
Optional filter by riskLevel: low|medium|high|hidden|none.

.PARAMETER RiskState
Optional filter by riskState: none|confirmedSafe|remediated|dismissed|atRisk|confirmedCompromised.

.OUTPUTS
PSCustomObject with fields: Id, DisplayName, AppId, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime, AccountEnabled, IsProcessing, ServicePrincipalType.

Docs:
- List riskyServicePrincipals (beta): https://learn.microsoft.com/en-us/graph/api/identityprotectionroot-list-riskyserviceprincipals?view=graph-rest-beta
- riskyServicePrincipal resource: https://learn.microsoft.com/en-us/graph/api/resources/riskyserviceprincipal?view=graph-rest-beta
#>
Function Get-WiBetaRiskyServicePrincipal {
    [CmdletBinding()] 
    [OutputType([psobject])]
    Param(
        [Parameter()][ValidateSet('low','medium','high','hidden','none')][string]$RiskLevel,
        [Parameter()][ValidateSet('none','confirmedSafe','remediated','dismissed','atRisk','confirmedCompromised')][string]$RiskState
    )
    $base = 'https://graph.microsoft.com/beta/identityProtection/riskyServicePrincipals'
    $filters = @()
    if ($RiskLevel) { $filters += "riskLevel eq '$RiskLevel'" }
    if ($RiskState) { $filters += "riskState eq '$RiskState'" }
    $query = if ($filters.Count -gt 0) { "`$filter=" + ($filters -join ' and ') } else { $null }
    $uri = if ($query) { ('{0}?{1}&`$top=999' -f $base, $query) } else { ('{0}?`$top=999' -f $base) }
    $items = New-Object System.Collections.Generic.List[object]
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $value = $resp.value
        foreach ($v in $value) {
            $items.Add([PSCustomObject]@{
                Id                        = $v.id
                DisplayName               = $v.displayName
                AppId                     = $v.appId
                RiskLevel                 = $v.riskLevel
                RiskState                 = $v.riskState
                RiskDetail                = $v.riskDetail
                RiskLastUpdatedDateTime   = $v.riskLastUpdatedDateTime
                AccountEnabled            = $v.accountEnabled
                IsProcessing              = $v.isProcessing
                ServicePrincipalType      = $v.servicePrincipalType
            })
        }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    return $items
}
