#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../../src/WorkloadIdentityTools/WorkloadIdentityTools.psd1') -Force

Describe 'Risky Service Principal Triage Report' {
    It 'Has expected top-level properties' {
        InModuleScope WorkloadIdentityTools {
            Mock -CommandName Get-WiBetaRiskyServicePrincipal -MockWith {
                @(
                    [PSCustomObject]@{ Id='1'; DisplayName='App1'; AppId='a1'; RiskLevel='high'; RiskState='atRisk'; RiskDetail='none'; RiskLastUpdatedDateTime=(Get-Date) },
                    [PSCustomObject]@{ Id='2'; DisplayName='App2'; AppId='a2'; RiskLevel='low'; RiskState='dismissed'; RiskDetail='none'; RiskLastUpdatedDateTime=(Get-Date).AddDays(-1) }
                )
            }
            $report = Get-WiRiskyServicePrincipalTriageReport
            $report | Should -Not -BeNullOrEmpty
            $report | Get-Member -Name Summary | Should -Not -BeNullOrEmpty
            $report | Get-Member -Name Distribution | Should -Not -BeNullOrEmpty
            $report | Get-Member -Name TopHighRisk | Should -Not -BeNullOrEmpty
            $report | Get-Member -Name Recommendations | Should -Not -BeNullOrEmpty
        }
    }
}
