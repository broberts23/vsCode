#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Generate a triage report for risky workload identities (beta).

.DESCRIPTION
Builds a summary of risky service principals by risk level and state, lists top high-risk entities, and suggests next actions.
Uses Get-WiBetaRiskyServicePrincipal internally.

.OUTPUTS
PSCustomObject with Summary, Distribution, TopHighRisk, Recommendations.
#>
Function Get-WiRiskyServicePrincipalTriageReport {
    [CmdletBinding()] 
    [OutputType([psobject])]
    Param()
    $risky = Get-WiBetaRiskyServicePrincipal
    if (-not $risky) { $risky = @() }
    elseif ($risky -isnot [System.Collections.IEnumerable]) { $risky = @($risky) }
    $total = ($risky | Measure-Object).Count
    $byLevel = if ($total -gt 0) { $risky | Group-Object RiskLevel | ForEach-Object { [PSCustomObject]@{ RiskLevel = $_.Name; Count = $_.Count } } } else { @() }
    $byState = if ($total -gt 0) { $risky | Group-Object RiskState | ForEach-Object { [PSCustomObject]@{ RiskState = $_.Name; Count = $_.Count } } } else { @() }
    $topHigh = if ($total -gt 0) { $risky | Where-Object { $_.RiskLevel -eq 'high' } | Sort-Object RiskLastUpdatedDateTime -Descending | Select-Object -First 50 Id, DisplayName, AppId, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime } else { @() }
    $recs = @()
    if ($total -gt 0) {
        if ((($risky | Where-Object { $_.RiskLevel -eq 'high' -and $_.RiskState -eq 'atRisk' }) | Measure-Object).Count -gt 0) { $recs += 'Investigate high-risk service principals; restrict tokens and rotate credentials if compromise suspected.' }
        if ((($risky | Where-Object { $_.RiskState -eq 'dismissed' }) | Measure-Object).Count -gt 0) { $recs += 'Review dismissed items for correctness and monitor for reoccurrence.' }
        if ((($risky | Where-Object { $_.RiskState -eq 'confirmedCompromised' }) | Measure-Object).Count -gt 0) { $recs += 'Ensure remediations complete: rotate creds, remove unnecessary permissions, enforce CA policies.' }
    }
    return [PSCustomObject]@{
        Summary         = [PSCustomObject]@{ Total = $total }
        Distribution    = [PSCustomObject]@{
            ByRiskLevel = $byLevel
            ByRiskState = $byState
        }
        TopHighRisk     = $topHigh
        Recommendations = $recs
    }
}
