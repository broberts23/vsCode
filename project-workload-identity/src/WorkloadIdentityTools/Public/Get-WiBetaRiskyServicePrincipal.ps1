#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
List risky workload identities (service principals) using Microsoft Graph beta.

.DESCRIPTION
Uses Get-MgBetaRiskyServicePrincipal from Microsoft.Graph.Beta.Identity.SignIns to list risky service principals and their risk properties.
Requires IdentityRiskyServicePrincipal.Read.All (or ReadWrite for triage actions) and Microsoft Entra Workload ID Premium license.

.NOTES
Cmdlet reference: https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.beta.identity.signins/get-mgbetariskyserviceprincipal?view=graph-powershell-beta

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
        [Parameter()][ValidateSet('low', 'medium', 'high', 'hidden', 'none')][string]$RiskLevel,
        [Parameter()][ValidateSet('none', 'confirmedSafe', 'remediated', 'dismissed', 'atRisk', 'confirmedCompromised')][string]$RiskState
    )
    $filters = @()
    if ($RiskLevel) { $filters += "riskLevel eq '$RiskLevel'" }
    if ($RiskState) { $filters += "riskState eq '$RiskState'" }
    $parameters = @{ All = $true }
    if ($filters.Count -gt 0) { $parameters.Filter = ($filters -join ' and ') }
    $results = Get-MgBetaRiskyServicePrincipal @parameters -ErrorAction Stop
    $objects = foreach ($sp in $results) {
        [PSCustomObject]@{
            Id                      = $sp.Id
            DisplayName             = $sp.DisplayName
            AppId                   = $sp.AppId
            RiskLevel               = $sp.RiskLevel
            RiskState               = $sp.RiskState
            RiskDetail              = $sp.RiskDetail
            RiskLastUpdatedDateTime = $sp.RiskLastUpdatedDateTime
            AccountEnabled          = $sp.AccountEnabled
            IsProcessing            = $sp.IsProcessing
            ServicePrincipalType    = $sp.ServicePrincipalType
        }
    }
    return $objects
}
